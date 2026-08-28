from __future__ import annotations

from io import StringIO
import json
import os
from pathlib import Path
import subprocess
import sys
import tomllib
from types import SimpleNamespace
from unittest.mock import Mock

import httpx
from openai import AsyncOpenAI
import pytest

import shim.cli as cli
from shim.application import create_community_app
from shim.core.community_config import CommunitySettings
from shim.core.middleware import GlobalRateLimitMiddleware


ROOT = Path(__file__).resolve().parents[2]
MODEL = "gpt-5.6-luna"
GATEWAY_KEY = "shim-gateway-key-123"
PROVIDER_KEY = "sk-provider-secret-123"
EMAIL = "alice@example.com"


def _settings(**overrides: object) -> CommunitySettings:
    return CommunitySettings(
        OPENAI_BASE_URL="https://upstream.test/v1",
        BACKEND_CORS_ORIGINS=[],
        SHIM_API_KEY=GATEWAY_KEY,
        _env_file=None,
        **overrides,
    )


def _completion(content: str) -> dict[str, object]:
    return {
        "id": "chatcmpl_community",
        "object": "chat.completion",
        "created": 1,
        "model": MODEL,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": 5,
            "completion_tokens": 3,
            "total_tokens": 8,
        },
    }


@pytest.mark.asyncio
async def test_community_chat_json_scrubs_and_restores_without_leaking_keys() -> None:
    attempts: list[httpx.Request] = []
    upstream_payload: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(request)
        upstream_payload.update(json.loads(request.content))
        messages = upstream_payload["messages"]
        assert isinstance(messages, list)
        safe_content = messages[0]["content"]
        assert isinstance(safe_content, str)
        assert EMAIL not in safe_content
        return httpx.Response(200, json=_completion(f"Received {safe_content}"))

    events = StringIO()
    upstream = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    application = create_community_app(
        _settings(),
        http_client=upstream,
        event_stream=events,
    )

    async with application.router.lifespan_context(application):
        limiter = next(
            item.kwargs["limiter"]
            for item in application.user_middleware
            if item.cls is GlobalRateLimitMiddleware
        )
        assert application.state.gateway_service.kernel.rate_limiter is limiter
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application),
            base_url="http://shim.test",
        ) as gateway_http:
            health = await gateway_http.get("/health")
            client = AsyncOpenAI(
                api_key=GATEWAY_KEY,
                base_url="http://shim.test/v1",
                http_client=gateway_http,
                max_retries=0,
            )
            completion = await client.chat.completions.create(
                model=MODEL,
                messages=[{"role": "user", "content": f"Contact {EMAIL}"}],
                extra_headers={"x-provider-key": PROVIDER_KEY},
            )

    assert health.json() == {"status": "ok", "version": "0.1.0"}
    assert completion.id == "chatcmpl_community"
    assert completion.choices[0].message.content == f"Received Contact {EMAIL}"
    assert len(attempts) == 1
    assert attempts[0].headers["authorization"] == f"Bearer {PROVIDER_KEY}"
    assert "x-provider-key" not in attempts[0].headers
    assert GATEWAY_KEY not in str(dict(attempts[0].headers))
    assert upstream.is_closed is False
    await upstream.aclose()

    lines = events.getvalue().splitlines()
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["outcome"] == "completed"
    assert event["privacy_counts"] == {"EMAIL_ADDRESS": 1}
    assert EMAIL not in lines[0]
    assert GATEWAY_KEY not in lines[0]
    assert PROVIDER_KEY not in lines[0]


class _SplitStream(httpx.AsyncByteStream):
    def __init__(self, content: bytes) -> None:
        self.content = content
        self.closed = False

    async def __aiter__(self):
        for index in range(0, len(self.content), 7):
            yield self.content[index : index + 7]

    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_community_chat_stream_preserves_native_sse_and_finalizes_once() -> None:
    attempts = 0
    provider_stream: _SplitStream | None = None
    placeholder = ""

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts, placeholder, provider_stream
        attempts += 1
        payload = json.loads(request.content)
        placeholder = payload["messages"][0]["content"]
        assert EMAIL not in placeholder
        split = len(placeholder) // 2
        chunks = [
            {
                "id": "chatcmpl_stream",
                "object": "chat.completion.chunk",
                "created": 1,
                "model": MODEL,
                "choices": [
                    {
                        "index": 0,
                        "delta": {"role": "assistant", "content": placeholder[:split]},
                        "finish_reason": None,
                    }
                ],
            },
            {
                "id": "chatcmpl_stream",
                "object": "chat.completion.chunk",
                "created": 1,
                "model": MODEL,
                "choices": [
                    {
                        "index": 0,
                        "delta": {"content": placeholder[split:]},
                        "finish_reason": None,
                    }
                ],
            },
            {
                "id": "chatcmpl_stream",
                "object": "chat.completion.chunk",
                "created": 1,
                "model": MODEL,
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
            },
        ]
        wire = (
            b"".join(
                f"data: {json.dumps(chunk, separators=(',', ':'))}\n\n".encode()
                for chunk in chunks
            )
            + b"data: [DONE]\n\n"
        )
        provider_stream = _SplitStream(wire)
        return httpx.Response(
            200,
            stream=provider_stream,
            headers={"content-type": "text/event-stream"},
        )

    events = StringIO()
    upstream = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    application = create_community_app(
        _settings(),
        http_client=upstream,
        event_stream=events,
    )
    async with application.router.lifespan_context(application):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application),
            base_url="http://shim.test",
        ) as gateway_http:
            response = await gateway_http.post(
                "/v1/chat/completions",
                headers={
                    "authorization": f"Bearer {GATEWAY_KEY}",
                    "x-provider-key": PROVIDER_KEY,
                },
                json={
                    "model": MODEL,
                    "messages": [{"role": "user", "content": EMAIL}],
                    "stream": True,
                },
            )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.content.count(b"data: [DONE]") == 1
    assert b"event:" not in response.content
    assert EMAIL.encode() in response.content
    assert placeholder.encode() not in response.content
    assert attempts == 1
    assert provider_stream is not None and provider_stream.closed is True
    assert upstream.is_closed is False
    await upstream.aclose()
    lines = events.getvalue().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["outcome"] == "completed"


@pytest.mark.asyncio
async def test_community_lifespan_closes_only_its_owned_http_client() -> None:
    external = httpx.AsyncClient()
    external_application = create_community_app(
        _settings(),
        http_client=external,
        event_stream=StringIO(),
    )
    async with external_application.router.lifespan_context(external_application):
        assert external_application.state.http_client is external
    assert external.is_closed is False
    await external.aclose()

    owned_application = create_community_app(_settings(), event_stream=StringIO())
    async with owned_application.router.lifespan_context(owned_application):
        owned = owned_application.state.http_client
        assert owned.is_closed is False
    assert owned.is_closed is True


@pytest.mark.asyncio
async def test_open_local_mode_does_not_allow_browser_origins() -> None:
    application = create_community_app(
        CommunitySettings(SHIM_API_KEY=None, _env_file=None),
        event_stream=StringIO(),
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="http://127.0.0.1",
    ) as client:
        response = await client.options(
            "/v1/chat/completions",
            headers={
                "origin": "https://app.getshim.tech",
                "access-control-request-method": "POST",
                "access-control-request-headers": "x-provider-key",
            },
        )

    assert "access-control-allow-origin" not in response.headers


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("host", "expected_status"),
    [
        ("localhost:8000", 200),
        ("127.23.45.67:8000", 200),
        ("[::1]:8000", 200),
        ("attacker.example:8000", 400),
    ],
)
async def test_open_local_mode_rejects_dns_rebinding_hosts(
    host: str,
    expected_status: int,
) -> None:
    application = create_community_app(
        CommunitySettings(SHIM_API_KEY=None, _env_file=None),
        event_stream=StringIO(),
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="http://127.0.0.1",
    ) as client:
        response = await client.get("/health", headers={"host": host})

    assert response.status_code == expected_status


def test_community_routes_are_an_initial_subset_of_the_documented_profile() -> None:
    application = create_community_app(_settings(), event_stream=StringIO())
    actual = {
        (method.upper(), path)
        for path, path_item in application.openapi()["paths"].items()
        for method in path_item
    }
    profile_document = tomllib.loads(
        (ROOT / "architecture/route_profiles.toml").read_text(encoding="utf-8")
    )
    documented = {
        (route["method"], route["path"])
        for route in profile_document["profiles"]["community"]
    }
    required = {
        ("GET", "/health"),
        ("GET", "/v1/models"),
        ("GET", "/v1/models/{model_id}"),
        ("POST", "/v1/chat/completions"),
        ("POST", "/v1/messages"),
        ("POST", "/v1/responses"),
        ("POST", "/v1/scan"),
        ("POST", "/v1beta/models/{model}:generateContent"),
        ("POST", "/v1beta/models/{model}:streamGenerateContent"),
    }

    assert required <= actual <= documented
    assert "/metrics" not in application.openapi()["paths"]


def test_community_factory_has_no_enterprise_import_or_environment_dependency() -> None:
    script = """
import sys
from shim.application import create_community_app
from shim.core.community_config import CommunitySettings

application = create_community_app(CommunitySettings(_env_file=None))
assert set(application.openapi()["paths"]) == {
    "/health",
    "/v1/chat/completions",
    "/v1/messages",
    "/v1/models",
    "/v1/models/{model_id}",
    "/v1/responses",
    "/v1/scan",
    "/v1beta/models/{model}:generateContent",
    "/v1beta/models/{model}:streamGenerateContent",
}
forbidden = (
    "redis",
    "shim_enterprise",
    "sqlalchemy",
    "supabase",
)
loaded = sorted(
    name for name in sys.modules
    if any(name == prefix or name.startswith(prefix + ".") for prefix in forbidden)
)
assert loaded == [], loaded
"""
    environment = os.environ.copy()
    for name in ("DATABASE_URL", "REDIS_URL", "SECRET_KEY", "SUPABASE_URL"):
        environment.pop(name, None)

    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("host", ["localhost", "127.23.45.67", "::1"])
def test_cli_serves_loopback_without_a_gateway_key(monkeypatch, host: str) -> None:
    run = Mock()
    monkeypatch.setattr(
        cli, "CommunitySettings", lambda: SimpleNamespace(SHIM_API_KEY=None)
    )
    monkeypatch.setattr(cli.uvicorn, "run", run)

    cli.main(["serve", "--host", host, "--port", "8080"])

    run.assert_called_once_with(
        "shim.application:create_community_app",
        factory=True,
        host=host,
        port=8080,
        workers=1,
    )


@pytest.mark.parametrize(
    "host",
    ["0.0.0.0", "::", "192.0.2.10", "unknown.internal"],
)
def test_cli_rejects_non_loopback_without_a_gateway_key(
    monkeypatch,
    host: str,
) -> None:
    run = Mock()
    monkeypatch.setattr(
        cli, "CommunitySettings", lambda: SimpleNamespace(SHIM_API_KEY=None)
    )
    monkeypatch.setattr(cli.uvicorn, "run", run)

    with pytest.raises(SystemExit):
        cli.main(["serve", "--host", host])

    run.assert_not_called()


def test_cli_allows_external_bind_with_a_validated_gateway_key(monkeypatch) -> None:
    run = Mock()
    monkeypatch.setattr(
        cli,
        "CommunitySettings",
        lambda: SimpleNamespace(SHIM_API_KEY=object()),
    )
    monkeypatch.setattr(cli.uvicorn, "run", run)

    cli.main(["serve", "--host", "0.0.0.0"])

    assert run.call_args.kwargs["host"] == "0.0.0.0"
