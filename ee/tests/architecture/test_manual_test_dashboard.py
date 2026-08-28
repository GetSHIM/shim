from __future__ import annotations

import asyncio
import base64
import json
import re
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

from fastapi import FastAPI, Response
from httpx import ASGITransport, AsyncClient
import pytest
from starlette.types import Scope

from shim_enterprise.core.config import settings
from shim.core.http import install_http_middleware
from shim.core.middleware import (
    BodySizeLimitMiddleware,
    GlobalRateLimitMiddleware,
    SecurityHeadersMiddleware,
    _client_ip,
)
from shim_enterprise.manual_test_dashboard import (
    DASHBOARD_PATH,
    install_manual_test_dashboard,
)
import shim_enterprise.application as main_module


def _application() -> FastAPI:
    application = FastAPI()
    application.add_middleware(SecurityHeadersMiddleware)
    application.add_api_route("/ordinary", lambda: {"status": "ok"})
    install_manual_test_dashboard(application)
    return application


def _legacy_supabase_key(role: str) -> str:
    claims = (
        base64.urlsafe_b64encode(json.dumps({"role": role}).encode("utf-8"))
        .decode("ascii")
        .rstrip("=")
    )
    return f"header.{claims}.signature"


class _UnavailableSession:
    async def __aenter__(self):
        raise OSError("database unavailable")

    async def __aexit__(self, *_args):
        return None


@pytest.mark.asyncio
async def test_dashboard_route_is_absent_by_default(monkeypatch) -> None:
    monkeypatch.setattr(settings, "MANUAL_TEST_DASHBOARD_ENABLED", False)

    async with AsyncClient(
        transport=ASGITransport(app=_application()),
        base_url="http://testserver",
    ) as client:
        response = await client.get(DASHBOARD_PATH)

    assert response.status_code == 404
    assert response.headers["content-security-policy"] == (
        "default-src 'none'; frame-ancestors 'none'"
    )


@pytest.mark.asyncio
async def test_health_is_not_ready_without_postgres(monkeypatch) -> None:
    monkeypatch.setattr(main_module, "AsyncSessionLocal", _UnavailableSession)
    cache = SimpleNamespace(redis=SimpleNamespace(ping=AsyncMock(return_value=True)))
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(cache=cache)))

    response = Response()
    health = await main_module._health(request, response)

    assert response.status_code == 503
    assert health["database"] == "error"


@pytest.mark.asyncio
async def test_api_lifespan_does_not_start_continuous_reconciliation(
    monkeypatch,
) -> None:
    cache = SimpleNamespace(close=AsyncMock())
    kernel = SimpleNamespace()
    create_gateway_kernel = Mock(return_value=kernel)
    engine = SimpleNamespace(dispose=AsyncMock())
    connect_cache = AsyncMock()
    create_task = Mock()
    shutdown_tracing = Mock()
    monkeypatch.setattr(main_module, "_create_gateway_kernel", create_gateway_kernel)
    monkeypatch.setattr(main_module, "_connect_cache", connect_cache)
    monkeypatch.setattr(main_module, "engine", engine)
    monkeypatch.setattr(main_module, "shutdown_tracing", shutdown_tracing)
    monkeypatch.setattr(asyncio, "create_task", create_task)
    application = FastAPI()
    application.state.cache = cache

    async with main_module._lifespan(application):
        assert application.state.gateway_service.kernel is kernel
        assert not hasattr(application.state, "gateway_reconciliation_stop")
        assert not hasattr(application.state, "gateway_reconciliation_task")

    create_gateway_kernel.assert_called_once()
    assert create_gateway_kernel.call_args.args[0] is cache
    assert create_gateway_kernel.call_args.args[1].is_closed
    connect_cache.assert_awaited_once_with(cache)
    create_task.assert_not_called()
    cache.close.assert_awaited_once()
    engine.dispose.assert_awaited_once()
    shutdown_tracing.assert_called_once()


def test_global_rate_limit_middleware_receives_the_composed_limiter() -> None:
    application = FastAPI()
    limiter = SimpleNamespace(allow=AsyncMock())

    install_http_middleware(
        application,
        settings=settings,
        rate_limiter=limiter,
        allow_cors=True,
    )

    middleware = next(
        item
        for item in application.user_middleware
        if item.cls is GlobalRateLimitMiddleware
    )
    assert middleware.kwargs["limiter"] is limiter


@pytest.mark.asyncio
async def test_gateway_boundary_middleware_use_native_error_envelopes() -> None:
    oversized = FastAPI()
    oversized.add_api_route("/v1/responses", lambda: {}, methods=["POST"])
    oversized.add_middleware(BodySizeLimitMiddleware, max_body_size=4)
    rate_limited = FastAPI()
    rate_limited.add_api_route("/v1/messages", lambda: {}, methods=["POST"])
    rate_limited.add_middleware(
        GlobalRateLimitMiddleware,
        limit=1,
        window_seconds=60,
        limiter=SimpleNamespace(allow=AsyncMock(return_value=False)),
    )

    async with AsyncClient(
        transport=ASGITransport(app=oversized), base_url="http://testserver"
    ) as client:
        body_response = await client.post("/v1/responses", content=b"12345")
    async with AsyncClient(
        transport=ASGITransport(app=rate_limited), base_url="http://testserver"
    ) as client:
        rate_response = await client.post(
            "/v1/messages",
            headers={"anthropic-version": "2023-06-01"},
        )

    assert body_response.status_code == 413
    assert set(body_response.json()) == {"error"}
    assert rate_response.status_code == 429
    assert rate_response.json()["type"] == "error"
    assert rate_response.headers["retry-after"] == "60"


def _scope(client_ip: str, **headers: str) -> Scope:
    return {
        "type": "http",
        "client": (client_ip, 1234),
        "headers": [
            (name.replace("_", "-").encode(), value.encode())
            for name, value in headers.items()
        ],
    }


def test_untrusted_peer_cannot_spoof_forwarding_headers() -> None:
    scope = _scope(
        "198.51.100.7",
        x_forwarded_for="203.0.113.1",
        cf_connecting_ip="203.0.113.2",
        x_real_ip="203.0.113.3",
    )

    assert _client_ip(scope, frozenset({"192.0.2.10"})) == "198.51.100.7"


def test_single_trusted_proxy_returns_forwarded_client() -> None:
    scope = _scope("192.0.2.10", x_forwarded_for="203.0.113.1")

    assert _client_ip(scope, frozenset({"192.0.2.10"})) == "203.0.113.1"


def test_trusted_proxy_chain_returns_first_untrusted_valid_ip() -> None:
    scope = _scope(
        "192.0.2.10",
        x_forwarded_for="203.0.113.1, 192.0.2.20",
    )

    assert (
        _client_ip(
            scope,
            frozenset({"192.0.2.10", "192.0.2.20"}),
        )
        == "203.0.113.1"
    )


def test_malformed_trusted_proxy_chain_falls_back_to_direct_peer() -> None:
    scope = _scope(
        "192.0.2.10",
        x_forwarded_for="203.0.113.1, malformed, 192.0.2.20",
    )

    assert (
        _client_ip(
            scope,
            frozenset({"192.0.2.10", "192.0.2.20"}),
        )
        == "192.0.2.10"
    )


@pytest.mark.asyncio
async def test_enabled_dashboard_is_hardened_and_excludes_privileged_secrets(
    monkeypatch,
) -> None:
    password = "fixture-password-</script>"
    api_key = "sk-shim-fixture-api-key"
    privileged_supabase_key = _legacy_supabase_key("service_role")
    monkeypatch.setattr(settings, "MANUAL_TEST_DASHBOARD_ENABLED", True)
    monkeypatch.setattr(settings, "SUPABASE_URL", "https://project.supabase.co/path")
    monkeypatch.setattr(settings, "SUPABASE_KEY", privileged_supabase_key)
    monkeypatch.setattr(settings, "SHIM_TEST_USER_EMAIL", "developer@example.com")
    monkeypatch.setenv("OPENAI_API_KEY", "global-provider-secret")

    async with AsyncClient(
        transport=ASGITransport(app=_application()),
        base_url="http://testserver",
    ) as client:
        response = await client.get(DASHBOARD_PATH)
        ordinary = await client.get("/ordinary")
        openapi = (await client.get("/openapi.json")).json()

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store, max-age=0"
    assert response.headers["pragma"] == "no-cache"
    assert response.headers["x-robots-tag"] == "noindex, nofollow, noarchive"
    assert '<meta name="robots" content="noindex,nofollow,noarchive">' in response.text
    assert DASHBOARD_PATH not in openapi["paths"]
    assert ordinary.headers["content-security-policy"] == (
        "default-src 'none'; frame-ancestors 'none'"
    )

    nonce_match = re.search(r'<script nonce="([A-Za-z0-9_-]+)">', response.text)
    assert nonce_match is not None
    nonce = nonce_match.group(1)
    policy = response.headers["content-security-policy"]
    assert f"script-src 'nonce-{nonce}'" in policy
    assert f"style-src 'nonce-{nonce}'" in policy
    assert response.text.count(f'nonce="{nonce}"') == 3
    assert "connect-src 'self' https://project.supabase.co" in policy
    assert "frame-ancestors 'none'" in policy
    assert "base-uri 'none'" in policy
    assert "form-action 'none'" in policy

    assert password not in response.text
    assert "fixture-password-\\u003c/script\\u003e" not in response.text
    assert api_key not in response.text
    assert '<input id="password" type="password"' in response.text
    assert '<input id="api-key" type="password"' in response.text
    assert privileged_supabase_key not in response.text
    assert "global-provider-secret" not in response.text
    assert "OPENAI_API_KEY" not in response.text
    assert "ANTHROPIC_API_KEY" not in response.text


@pytest.mark.asyncio
async def test_dashboard_accepts_only_public_supabase_keys(monkeypatch) -> None:
    publishable_key = "sb_publishable_fixture"
    monkeypatch.setattr(settings, "MANUAL_TEST_DASHBOARD_ENABLED", True)
    monkeypatch.setattr(settings, "SUPABASE_KEY", publishable_key)

    async with AsyncClient(
        transport=ASGITransport(app=_application()),
        base_url="http://testserver",
    ) as client:
        publishable_response = await client.get(DASHBOARD_PATH)

    assert publishable_key in publishable_response.text

    monkeypatch.setattr(settings, "SUPABASE_KEY", _legacy_supabase_key("anon"))
    async with AsyncClient(
        transport=ASGITransport(app=_application()),
        base_url="http://testserver",
    ) as client:
        anon_response = await client.get(DASHBOARD_PATH)

    assert _legacy_supabase_key("anon") in anon_response.text
