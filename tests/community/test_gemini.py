from __future__ import annotations

from collections.abc import AsyncIterator
from io import StringIO
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

from google import genai
from google.genai import types
import httpx
import pytest
from starlette.requests import Request

import shim.api.deps as deps
from shim.application import create_community_app
from shim.core.community_config import CommunitySettings
from shim.secrets.credentials import extract_provider_credential


MODEL = "gemini-3.5-flash"
GATEWAY_KEY = "shim-gateway-key-123"
PROVIDER_KEY = "google-provider-secret-123"
EMAIL = "alice@example.com"


def _settings() -> CommunitySettings:
    return CommunitySettings(
        BACKEND_CORS_ORIGINS=[],
        GOOGLE_BASE_URL="https://upstream.test",
        SHIM_API_KEY=GATEWAY_KEY,
        _env_file=None,
    )


def _sdk_client(
    gateway_http: httpx.AsyncClient,
    api_key: str = GATEWAY_KEY,
    base_url: str = "http://shim.test",
) -> genai.Client:
    return genai.Client(
        api_key=api_key,
        http_options=types.HttpOptions(
            base_url=base_url,
            api_version="v1beta",
            retry_options=types.HttpRetryOptions(attempts=1),
            httpx_async_client=gateway_http,
        ),
    )


@pytest.mark.asyncio
async def test_gemini_json_works_with_official_sdk_and_restores_privacy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GOOGLE_API_KEY", PROVIDER_KEY)
    attempts: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(request)
        payload = json.loads(request.content)
        safe_text = payload["contents"][0]["parts"][0]["text"]
        assert EMAIL not in safe_text
        return httpx.Response(
            200,
            json={
                "candidates": [
                    {
                        "content": {
                            "parts": [{"text": f"Received {safe_text}"}],
                            "role": "model",
                        },
                        "finishReason": "STOP",
                    }
                ],
                "modelVersion": MODEL,
                "responseId": "gemini_json_1",
                "usageMetadata": {
                    "promptTokenCount": 1,
                    "candidatesTokenCount": 1,
                    "totalTokenCount": 2,
                },
            },
            headers={"x-goog-request-id": "google_request_1"},
        )

    terminal_events = StringIO()
    upstream = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    application = create_community_app(
        _settings(),
        http_client=upstream,
        event_stream=terminal_events,
    )
    async with application.router.lifespan_context(application):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application),
            base_url="http://shim.test",
        ) as gateway_http:
            with _sdk_client(gateway_http) as client:
                async with client.aio as async_client:
                    response = await async_client.models.generate_content(
                        model=MODEL,
                        contents=f"Contact {EMAIL}",
                    )

    assert response.text == f"Received Contact {EMAIL}"
    assert len(attempts) == 1
    assert attempts[0].headers["x-goog-api-key"] == PROVIDER_KEY
    assert "x-provider-key" not in attempts[0].headers
    assert GATEWAY_KEY not in str(dict(attempts[0].headers))
    assert upstream.is_closed is False
    await upstream.aclose()

    lines = terminal_events.getvalue().splitlines()
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

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for index in range(0, len(self.content), 9):
            yield self.content[index : index + 9]

    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_gemini_stream_is_data_only_sse_and_finishes_candidates() -> None:
    attempts: list[httpx.Request] = []
    provider_stream: _SplitStream | None = None
    placeholder = ""

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal placeholder, provider_stream
        attempts.append(request)
        payload = json.loads(request.content)
        placeholder = payload["contents"][0]["parts"][0]["text"]
        assert EMAIL not in placeholder
        split = len(placeholder) // 2
        chunks = [
            {
                "candidates": [
                    {
                        "index": 0,
                        "content": {
                            "parts": [{"text": placeholder[:split]}],
                            "role": "model",
                        },
                    }
                ],
                "responseId": "gemini_stream_1",
            },
            {
                "candidates": [
                    {
                        "index": 0,
                        "content": {
                            "parts": [{"text": placeholder[split:]}],
                            "role": "model",
                        },
                        "finishReason": "STOP",
                    }
                ],
                "responseId": "gemini_stream_1",
                "usageMetadata": {
                    "promptTokenCount": 1,
                    "candidatesTokenCount": 1,
                    "totalTokenCount": 2,
                },
            },
        ]
        wire = "".join(
            f"data: {json.dumps(chunk, separators=(',', ':'))}\n\n" for chunk in chunks
        ).encode()
        provider_stream = _SplitStream(wire)
        return httpx.Response(
            200,
            stream=provider_stream,
            headers={
                "content-type": "text/event-stream",
                "x-goog-request-id": "google_stream_request_1",
            },
        )

    terminal_events = StringIO()
    upstream = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    application = create_community_app(
        _settings(),
        http_client=upstream,
        event_stream=terminal_events,
    )
    async with application.router.lifespan_context(application):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application),
            base_url="http://shim.test",
        ) as gateway_http:
            response = await gateway_http.post(
                f"/v1beta/models/{MODEL}:streamGenerateContent",
                params={"alt": "sse"},
                headers={
                    "x-shim-key": GATEWAY_KEY,
                    "x-provider-key": PROVIDER_KEY,
                    "x-goog-api-key": "must-not-reach-provider",
                },
                json={"contents": [{"role": "user", "parts": [{"text": EMAIL}]}]},
            )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert b"event:" not in response.content
    assert b"[DONE]" not in response.content
    assert EMAIL.encode() in response.content
    assert placeholder.encode() not in response.content
    payloads = [
        json.loads(line.removeprefix("data: "))
        for line in response.text.splitlines()
        if line.startswith("data: ")
    ]
    assert payloads[-1]["candidates"][0]["finishReason"] == "STOP"
    assert len(attempts) == 1
    assert attempts[0].url.query == b"alt=sse"
    assert attempts[0].headers["x-goog-api-key"] == PROVIDER_KEY
    assert "x-provider-key" not in attempts[0].headers
    assert "must-not-reach-provider" not in str(dict(attempts[0].headers))
    assert provider_stream is not None and provider_stream.closed is True
    assert upstream.is_closed is False
    await upstream.aclose()

    lines = terminal_events.getvalue().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["outcome"] == "completed"


@pytest.mark.asyncio
async def test_gemini_validation_precedes_one_sanitized_provider_attempt() -> None:
    attempts = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(
            500,
            json={"error": {"message": "secret upstream detail"}},
            headers={"x-goog-request-id": "google_failed_1"},
        )

    upstream = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    application = create_community_app(
        _settings(),
        http_client=upstream,
        event_stream=StringIO(),
    )
    headers = {
        "x-shim-key": GATEWAY_KEY,
        "x-provider-key": PROVIDER_KEY,
    }
    async with application.router.lifespan_context(application):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application),
            base_url="http://shim.test",
        ) as gateway_http:
            invalid = await gateway_http.post(
                f"/v1beta/models/{MODEL}:generateContent",
                headers=headers,
                json={
                    "contents": [{"parts": [{"text": "hello"}]}],
                    "stream": True,
                },
            )
            failed = await gateway_http.post(
                f"/v1beta/models/{MODEL}:generateContent",
                headers=headers,
                json={"contents": [{"parts": [{"text": "hello"}]}]},
            )

    assert invalid.status_code == 422
    assert "detail" not in invalid.json()
    assert invalid.json()["error"]["status"] == "INVALID_ARGUMENT"
    assert failed.status_code == 500
    assert failed.json() == {
        "error": {
            "code": 500,
            "message": "The Google request failed.",
            "status": "INTERNAL",
            "details": [
                {
                    "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                    "reason": "PROVIDER_UNAVAILABLE",
                    "domain": "getshim.tech",
                }
            ],
        }
    }
    assert failed.headers["x-shim-error-code"] == "PROVIDER_UNAVAILABLE"
    assert failed.headers["x-goog-request-id"] == "google_failed_1"
    assert attempts == 1
    assert "secret upstream detail" not in failed.text
    assert GATEWAY_KEY not in failed.text
    assert PROVIDER_KEY not in failed.text
    assert upstream.is_closed is False
    await upstream.aclose()


@pytest.mark.asyncio
async def test_a_google_key_in_the_sdk_header_is_never_a_provider_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    attempts: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(request)
        return httpx.Response(500)

    upstream = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    application = create_community_app(
        CommunitySettings(
            BACKEND_CORS_ORIGINS=[],
            GOOGLE_BASE_URL="https://upstream.test",
            SHIM_API_KEY=None,
            _env_file=None,
        ),
        http_client=upstream,
        event_stream=StringIO(),
    )
    async with application.router.lifespan_context(application):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application),
            base_url="http://127.0.0.1",
        ) as gateway_http:
            client = _sdk_client(gateway_http, PROVIDER_KEY, "http://127.0.0.1")
            with pytest.raises(genai.errors.ServerError) as raised:
                await client.aio.models.generate_content(model=MODEL, contents="hi")
    await upstream.aclose()

    assert raised.value.code == 503
    assert raised.value.response.headers["x-shim-error-code"] == (
        "PROVIDER_NOT_CONFIGURED"
    )
    assert attempts == []


@pytest.mark.asyncio
async def test_gemini_x_goog_api_key_is_a_gateway_key_never_a_provider_key() -> None:
    principal = SimpleNamespace()
    authenticator = SimpleNamespace(resolve=AsyncMock(return_value=principal))

    def gemini_request(*headers: tuple[bytes, bytes]) -> Request:
        return Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/v1beta/models/gemini-3.5-flash:generateContent",
                "headers": list(headers),
                "app": SimpleNamespace(
                    state=SimpleNamespace(gateway_authenticator=authenticator)
                ),
            }
        )

    only_google = gemini_request((b"x-goog-api-key", b"sk-shim-tenant-key"))
    mixed = gemini_request(
        (b"x-shim-key", b"sk-shim-tenant-key"),
        (b"x-goog-api-key", b"another-value"),
    )
    for request in (only_google, mixed):
        assert (
            await deps.get_google_authenticated_principal(request, None, None, None)
            is principal
        )
    forwarded, credential = extract_provider_credential(mixed.headers, "google")

    assert [call.args for call in authenticator.resolve.await_args_list] == [
        ("sk-shim-tenant-key",),
        ("sk-shim-tenant-key",),
    ]
    assert credential is None
    assert "another-value" not in forwarded.values()
