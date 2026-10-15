from __future__ import annotations

from importlib.metadata import version
from io import StringIO
import json
import os
import re
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
                extra_headers={
                    "x-provider-key": PROVIDER_KEY,
                    "X-Shim-Tag": "risk,batch",
                },
            )

    assert health.json() == {"status": "ok", "version": version("shim-gateway")}
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
    assert event["provider_finish_reasons"] == {"choices.0.finish_reason": "stop"}
    assert event["ttft_ms"] is None
    assert event["repeat_chain_length"] == 1
    assert event["cost_center"] == "risk"
    assert event["tags"] == ["risk", "batch"]
    assert event["deployment_kind"] == "unknown"
    assert event["system_prompt_hash"] is None
    assert EMAIL not in lines[0]
    assert GATEWAY_KEY not in lines[0]
    assert PROVIDER_KEY not in lines[0]


_IDENTIFIERS = {
    "TR_NATIONAL_ID": "10000000146",
    "TR_VKN": "Vergi no 1234567890",
    "IBAN_CODE": "TR33 0006 1005 1978 6457 8413 26",
    "CREDIT_CARD": "4111 1111 1111 1111",
    "PHONE_NUMBER": "+90 532 123 45 67",
}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("zero", "mark"),
    [
        (0x0660, ""),
        (0x06F0, ""),
        (0x0966, ""),
        (0x09E6, ""),
        (0xFF10, ""),
        (0x30, "\u0301"),
        (0x30, "\u0301\u0323"),
        (0x30, "\ufe0f"),
        (0x30, "\ufe0f\u20e3"),
        (0x30, "\u034f"),
        (0x30, "\u200d"),
        (0x0660, "\u0301"),
    ],
    ids=[
        "arabic-indic",
        "extended-arabic-indic",
        "devanagari",
        "bengali",
        "fullwidth",
        "acute-on-each-digit",
        "two-marks-on-each-digit",
        "variation-selector",
        "keycap",
        "grapheme-joiner",
        "zero-width-joiner",
        "arabic-indic-with-acute",
    ],
)
async def test_identifiers_in_any_script_s_digits_never_reach_the_provider(
    zero: int,
    mark: str,
) -> None:
    def written(value: str) -> str:
        return "".join(chr(zero + int(c)) + mark if c.isdigit() else c for c in value)

    values = [written(value) for value in _IDENTIFIERS.values()]
    prompt = "Müşteri: " + ", ".join(values) + "."
    sent: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        content = json.loads(request.content)["messages"][0]["content"]
        sent.append(content)
        return httpx.Response(200, json=_completion(content))

    events = StringIO()
    upstream = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    application = create_community_app(
        _settings(
            PII_ENTITY_ACTIONS=json.dumps({kind: "mask" for kind in _IDENTIFIERS})
        ),
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
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
    await upstream.aclose()

    assert response.status_code == 200, response.text
    [upstream_text] = sent
    assert (
        re.sub(r"<[A-Z_]+_[0-9a-f]{32}>", "", upstream_text)
        == "Müşteri: , Vergi no , , , ."
    ), upstream_text
    # Masked at the right offsets: the answer restores the original characters.
    assert response.json()["choices"][0]["message"]["content"] == prompt
    assert json.loads(events.getvalue())["privacy_counts"] == dict.fromkeys(
        _IDENTIFIERS, 1
    )


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
    event = json.loads(lines[0])
    assert event["outcome"] == "completed"
    assert event["provider_finish_reasons"] == {"choices.0.finish_reason": "stop"}
    assert event["ttft_ms"] >= 0
    assert event["repeat_chain_length"] == 1


@pytest.mark.asyncio
async def test_a_model_id_that_is_not_id_shaped_is_refused_and_never_recorded() -> None:
    models = [
        "gpt-5.6-luna-" + "x" * 13_000,
        f"gpt-5.6-luna-{EMAIL}",
        "gpt-5.6-luna-alice smith",
        "gpt-5.6-luna-\nx",
    ]
    attempts: list[httpx.Request] = []
    events = StringIO()
    upstream = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: (
                attempts.append(request)
                or httpx.Response(200, json=_completion("unexpected"))
            )
        )
    )
    application = create_community_app(
        _settings(), http_client=upstream, event_stream=events
    )
    async with application.router.lifespan_context(application):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application),
            base_url="http://shim.test",
        ) as gateway_http:
            responses = [
                await gateway_http.post(
                    "/v1/chat/completions",
                    headers={
                        "authorization": f"Bearer {GATEWAY_KEY}",
                        "x-provider-key": PROVIDER_KEY,
                    },
                    json={
                        "model": model,
                        "messages": [{"role": "user", "content": "hi"}],
                    },
                )
                for model in models
            ]
    await upstream.aclose()

    assert [response.status_code for response in responses] == [400] * len(models)
    assert {response.json()["error"]["code"] for response in responses} == {
        "MODEL_NOT_PRICED"
    }
    assert attempts == []
    recorded = events.getvalue()
    assert [json.loads(line)["model"] for line in recorded.splitlines()] == [
        "unsupported"
    ] * len(models)
    assert "xxxxxxxx" not in recorded and EMAIL not in recorded
    assert "alice smith" not in recorded


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
        ("POST", "/v1/embeddings"),
        ("POST", "/v1/messages"),
        ("POST", "/v1/responses"),
        ("POST", "/v1/scan"),
        ("POST", "/v1beta/models/{model}:batchEmbedContents"),
        ("POST", "/v1beta/models/{model}:embedContent"),
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
    "/v1/embeddings",
    "/v1/messages",
    "/v1/messages/count_tokens",
    "/v1/models",
    "/v1/models/{model_id}",
    "/v1/responses",
    "/v1/scan",
    "/v1beta/models/{model}:batchEmbedContents",
    "/v1beta/models/{model}:embedContent",
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


@pytest.mark.asyncio
async def test_browsers_can_read_the_gateway_error_code() -> None:
    origin = "https://dashboard.example.test"
    application = create_community_app(
        CommunitySettings(
            SHIM_API_KEY=GATEWAY_KEY, BACKEND_CORS_ORIGINS=[origin], _env_file=None
        ),
        event_stream=StringIO(),
    )

    async with (
        application.router.lifespan_context(application),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application),
            base_url="http://127.0.0.1",
        ) as client,
    ):
        response = await client.post(
            "/v1/chat/completions",
            headers={"origin": origin},
            json={"model": MODEL, "messages": [{"role": "user", "content": "hi"}]},
        )

    assert response.status_code == 401
    assert response.headers["x-shim-error-code"] == "MISSING_API_KEY"
    exposed = response.headers["access-control-expose-headers"].lower().split(",")
    assert {"x-shim-error-code", "x-shim-warnings"} <= {
        name.strip() for name in exposed
    }


@pytest.mark.asyncio
async def test_browsers_may_send_trace_context_and_a_task_id() -> None:
    origin = "https://dashboard.example.test"
    application = create_community_app(
        CommunitySettings(
            SHIM_API_KEY=GATEWAY_KEY, BACKEND_CORS_ORIGINS=[origin], _env_file=None
        ),
        event_stream=StringIO(),
    )

    async with (
        application.router.lifespan_context(application),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application),
            base_url="http://127.0.0.1",
        ) as client,
    ):
        response = await client.options(
            "/v1/chat/completions",
            headers={
                "origin": origin,
                "access-control-request-method": "POST",
                "access-control-request-headers": "traceparent,tracestate,x-shim-task-id",
            },
        )

    assert response.status_code == 200
    allowed = response.headers["access-control-allow-headers"].lower()
    assert {"traceparent", "tracestate", "x-shim-task-id"} <= {
        name.strip() for name in allowed.split(",")
    }


def test_global_rate_limit_comes_from_the_setting() -> None:
    application = create_community_app(
        _settings(GLOBAL_RATE_LIMIT_PER_MINUTE=7),
        event_stream=StringIO(),
    )

    limit = next(
        item.kwargs["limit"]
        for item in application.user_middleware
        if item.cls is GlobalRateLimitMiddleware
    )
    assert limit == 7


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", [None, "http://127.0.0.1:4318"])
async def test_community_traces_only_when_an_endpoint_is_set(
    monkeypatch: pytest.MonkeyPatch,
    endpoint: str | None,
) -> None:
    configure_tracing = Mock()
    shutdown_tracing = Mock()
    monkeypatch.setattr("shim.application.configure_tracing", configure_tracing)
    monkeypatch.setattr("shim.application.shutdown_tracing", shutdown_tracing)
    configured = _settings(OTEL_EXPORTER_OTLP_ENDPOINT=endpoint)
    application = create_community_app(configured, event_stream=StringIO())

    async with application.router.lifespan_context(application):
        pass

    assert configured.OTEL_SERVICE_NAME == "shim"
    if endpoint is None:
        configure_tracing.assert_not_called()
        shutdown_tracing.assert_not_called()
    else:
        configure_tracing.assert_called_once_with(
            endpoint=endpoint, service_name="shim"
        )
        shutdown_tracing.assert_called_once_with()


# "\ud800" as a client sends it: a JSON escape that decodes to a lone surrogate.
_LONE = '"hi \\ud800"'


@pytest.mark.asyncio
@pytest.mark.parametrize("pii", ["scrub", "disabled"])
@pytest.mark.parametrize(
    ("path", "body"),
    [
        (
            "/v1/chat/completions",
            f'{{"model": "{MODEL}", "messages": [{{"role": "user", "content": {_LONE}}}]}}',
        ),
        (
            "/v1/embeddings",
            f'{{"model": "text-embedding-3-small", "input": {_LONE}}}',
        ),
        (
            "/v1/responses",
            f'{{"model": "{MODEL}", "input": {_LONE}}}',
        ),
        (
            "/v1/messages",
            '{"model": "claude-sonnet-4-6", "max_tokens": 16, '
            f'"messages": [{{"role": "user", "content": {_LONE}}}]}}',
        ),
        (
            "/v1/messages/count_tokens",
            '{"model": "claude-sonnet-4-6", '
            f'"messages": [{{"role": "user", "content": {_LONE}}}]}}',
        ),
        (
            "/v1beta/models/gemini-3.5-flash:generateContent",
            f'{{"contents": [{{"role": "user", "parts": [{{"text": {_LONE}}}]}}]}}',
        ),
        (
            "/v1beta/models/gemini-embedding-001:embedContent",
            f'{{"content": {{"parts": [{{"text": {_LONE}}}]}}}}',
        ),
    ],
)
async def test_a_lone_surrogate_is_a_native_400_before_privacy_or_the_provider(
    path: str, body: str, pii: str
) -> None:
    from shim.privacy.policies import effective_entity_actions

    attempts: list[httpx.Request] = []
    upstream = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: attempts.append(request) or httpx.Response(500)
        )
    )
    actions = (
        {}
        if pii == "scrub"
        else {kind: "off" for kind in effective_entity_actions(None, None)}
    )
    application = create_community_app(
        _settings(PII_ENTITY_ACTIONS=actions), http_client=upstream
    )
    async with application.router.lifespan_context(application):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application),
            base_url="http://shim.test",
        ) as gateway_http:
            response = await gateway_http.post(
                path,
                headers={
                    "authorization": f"Bearer {GATEWAY_KEY}",
                    "x-provider-key": PROVIDER_KEY,
                    "content-type": "application/json",
                },
                content=body.encode(),
            )
    await upstream.aclose()

    assert response.status_code == 400, response.text
    assert response.headers["x-shim-error-code"] == "INVALID_REQUEST"
    assert attempts == []


@pytest.mark.asyncio
async def test_a_lone_surrogate_scan_is_a_validation_error() -> None:
    application = create_community_app(_settings())
    async with application.router.lifespan_context(application):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application),
            base_url="http://shim.test",
        ) as gateway_http:
            response = await gateway_http.post(
                "/v1/scan",
                headers={
                    "authorization": f"Bearer {GATEWAY_KEY}",
                    "content-type": "application/json",
                },
                content=f'{{"text": {_LONE}}}'.encode(),
            )

    # The scan's text is a typed string, which pydantic already refuses, as it
    # refuses any other invalid scan input; the input is never echoed.
    assert response.status_code == 422, response.text
    [error] = response.json()["detail"]
    assert (error["type"], error["loc"]) == ("string_unicode", ["body", "text"])
    assert "input" not in error


# Every settings and transform switch on; whitespace json_compaction would remove.
_EVERY_TRANSFORM = {
    "SHIM_ANTHROPIC_AUTO_CACHE": "5m",
    "SHIM_OPENAI_PROMPT_CACHE_KEY": "tenant",
    "SHIM_TOOL_SEARCH": "regex",
    "SHIM_TOOL_SEARCH_MIN_TOOLS": 2,
    "SHIM_ANTHROPIC_KEEP_THINKING_TURNS": 1,
    "SHIM_OPENAI_REASONING_CONTEXT": "current_turn",
    "SHIM_JSON_COMPACTION": "on",
    "SHIM_IMAGE_DOWNSCALE": "on",
    "SHIM_IMAGE_DETAIL_OPENAI": "low",
    "SHIM_IMAGE_DETAIL_GEMINI": "low",
}
_SPACED_JSON = '{ "city": "Ankara", "items": [ 1, 2, 3 ], "note": "kept as sent" }'


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("path", "body", "sent"),
    [
        (
            "/v1/embeddings",
            {"model": "text-embedding-3-small", "input": _SPACED_JSON},
            ("input",),
        ),
        (
            "/v1beta/models/gemini-embedding-001:embedContent",
            {"content": {"parts": [{"text": _SPACED_JSON}]}},
            ("content",),
        ),
        (
            "/v1beta/models/gemini-embedding-001:batchEmbedContents",
            {"requests": [{"content": {"parts": [{"text": _SPACED_JSON}]}}]},
            ("requests", 0, "content"),
        ),
    ],
    ids=["embeddings", "embed-content", "batch-embed-contents"],
)
async def test_embeddings_with_every_transform_on_pass_through_untouched(
    path: str, body: dict[str, object], sent: tuple[str | int, ...]
) -> None:
    seen: list[dict] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        if request.url.path.endswith(":batchEmbedContents"):
            return httpx.Response(200, json={"embeddings": [{"values": [0.5]}]})
        if request.url.path.endswith(":embedContent"):
            return httpx.Response(200, json={"embedding": {"values": [0.5]}})
        return httpx.Response(
            200,
            json={
                "object": "list",
                "data": [{"object": "embedding", "index": 0, "embedding": [0.5]}],
                "model": "text-embedding-3-small",
                "usage": {"prompt_tokens": 20, "total_tokens": 20},
            },
        )

    events = StringIO()
    async with httpx.AsyncClient(transport=httpx.MockTransport(upstream)) as outbound:
        application = create_community_app(
            _settings(**_EVERY_TRANSFORM), http_client=outbound, event_stream=events
        )
        async with application.router.lifespan_context(application):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=application),
                base_url="http://shim.test",
            ) as gateway_http:
                response = await gateway_http.post(
                    path,
                    headers={
                        "authorization": f"Bearer {GATEWAY_KEY}",
                        "x-provider-key": PROVIDER_KEY,
                    },
                    json=body,
                )

    assert response.status_code == 200, response.text
    [upstream_body] = seen
    expected: object = body
    received: object = upstream_body
    for step in sent:
        expected, received = expected[step], received[step]  # type: ignore[index]
    assert received == expected
    [event] = [json.loads(line) for line in events.getvalue().splitlines()]
    assert event["outcome"] == "completed"
    assert event.get("transforms_applied", []) == []
    assert "settings_applied" not in event
