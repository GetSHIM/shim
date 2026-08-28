from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID

import httpx
import pytest
from pydantic import ValidationError

from shim.api.v1.gemini import GenerateContentRequest
from shim.core.circuit_breaker import InMemoryCircuitBreaker
from shim.core.community_config import CommunitySettings
from shim.gateway.contracts.ids import TenantId
from shim.gateway.pipeline.google_execution import GoogleExecution
from shim.gateway.pipeline.privacy import scrub_payload
from shim.gateway.pipeline.provider_execution import (
    ProviderCallError,
    ProviderNonStream,
    ProviderStream,
)
from shim.privacy.policies import PrivacyAction, PrivacyOutcome
from shim.privacy.pii_scrubber import PIIScrubberService
from shim.secrets.credentials import (
    EnvironmentProviderCredentialResolver,
    EphemeralProviderCredential,
)


settings = CommunitySettings(_env_file=None)


def _prepared(
    payload: dict,
    *,
    stream: bool = False,
    mapping: dict[str, str] | None = None,
):
    return SimpleNamespace(
        payload=payload,
        tenant_id=TenantId(UUID("11111111-1111-1111-1111-111111111111")),
        provider="google",
        protocol="generate_content",
        model="gemini-3.5-flash",
        stream=stream,
        privacy=PrivacyOutcome(
            action=PrivacyAction.SCRUBBED if mapping else PrivacyAction.DISABLED,
            pii_detected=bool(mapping),
            verification_map=mapping or {},
        ),
    )


def _execution(http_client: httpx.AsyncClient) -> GoogleExecution:
    return GoogleExecution(
        credential_resolver=EnvironmentProviderCredentialResolver("google", {}),
        circuit=InMemoryCircuitBreaker(),
        settings=settings,
        http_client=http_client,
    )


def _invocation(key: str = "google-secret") -> SimpleNamespace:
    return SimpleNamespace(
        db=object(),
        provider_credential=EphemeralProviderCredential("google", key),
    )


def test_google_scrubbing_covers_native_json_schemas() -> None:
    email = "alice@example.com"
    payload = GenerateContentRequest.model_validate(
        {
            "contents": [{"role": "user", "parts": [{"text": "hello"}]}],
            "tools": [
                {
                    "functionDeclarations": [
                        {
                            "name": "lookup",
                            "parametersJsonSchema": {"default": email},
                            "responseJsonSchema": {"examples": [email]},
                        }
                    ]
                }
            ],
            "generationConfig": {"responseJsonSchema": {"default": email}},
        }
    ).model_dump(mode="json", exclude_none=True, by_alias=True)

    safe, mapping = scrub_payload(payload, None, PIIScrubberService())

    assert mapping
    assert email not in json.dumps(safe)
    assert safe["tools"][0]["functionDeclarations"][0]["name"] == "lookup"


@pytest.mark.asyncio
async def test_nonstream_preserves_native_wire_store_and_restores_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "GOOGLE_BASE_URL", "https://upstream.test")
    placeholder = "<EMAIL_ADDRESS_deadbeef>"
    seen: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["api_key"] = request.headers.get("x-goog-api-key")
        seen["authorization"] = request.headers.get("authorization")
        seen["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "candidates": [
                    {
                        "content": {
                            "parts": [{"text": f"hello {placeholder}"}],
                            "role": "model",
                        },
                        "finishReason": "STOP",
                    }
                ],
                "usageMetadata": {
                    "promptTokenCount": 1,
                    "candidatesTokenCount": 1,
                    "totalTokenCount": 2,
                },
                "modelVersion": "gemini-3.5-flash",
                "responseId": "resp_google_1",
            },
            headers={"x-request-id": "google_request_1"},
        )

    payload = {
        "contents": [{"role": "user", "parts": [{"text": placeholder}]}],
        "generationConfig": {"temperature": 0.2, "maxOutputTokens": 17},
        "serviceTier": "PRIORITY",
        "store": False,
    }
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        credential = _invocation()
        result = await _execution(http).execute(
            invocation=credential,
            prepared=_prepared(
                payload,
                mapping={placeholder: "alice@example.com"},
            ),
            provider_start_callback=AsyncMock(),
        )

        assert isinstance(result, ProviderNonStream)
        assert result.request_id == "google_request_1"
        assert result.payload["candidates"][0]["content"]["parts"][0]["text"] == (
            "hello alice@example.com"
        )
        assert "sdkHttpResponse" not in result.payload
        assert "automaticFunctionCallingHistory" not in result.payload
        assert seen == {
            "url": (
                "https://upstream.test/v1beta/models/gemini-3.5-flash:generateContent"
            ),
            "api_key": "google-secret",
            "authorization": None,
            "body": payload,
        }
        assert credential.provider_credential.available() is False
        assert http.is_closed is False


@pytest.mark.asyncio
async def test_stream_uses_native_sse_and_restores_split_placeholder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "GOOGLE_BASE_URL", "https://upstream.test")
    placeholder = "<EMAIL_ADDRESS_deadbeef>"
    midpoint = len(placeholder) // 2
    requests: list[httpx.Request] = []
    chunks = [
        {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {"text": placeholder[:midpoint]},
                            {
                                "functionCall": {
                                    "name": "lookup",
                                    "args": {"email": placeholder[:midpoint]},
                                }
                            },
                        ],
                        "role": "model",
                    }
                }
            ],
            "responseId": "resp_google_stream",
        },
        {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {"text": placeholder[midpoint:]},
                            {
                                "functionCall": {
                                    "name": "lookup",
                                    "args": {"email": placeholder[midpoint:]},
                                }
                            },
                        ],
                        "role": "model",
                    },
                    "finishReason": "STOP",
                }
            ],
            "usageMetadata": {
                "promptTokenCount": 1,
                "candidatesTokenCount": 1,
                "totalTokenCount": 2,
            },
            "responseId": "resp_google_stream",
        },
    ]

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        wire = "".join(
            f"data: {json.dumps(chunk, separators=(',', ':'))}\n\n" for chunk in chunks
        )
        return httpx.Response(
            200,
            content=wire,
            headers={
                "content-type": "text/event-stream",
                "x-request-id": "google_stream_request_1",
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        execution = _execution(http)
        execution.circuit = SimpleNamespace(
            acquire_call=AsyncMock(return_value=True),
            record_success=AsyncMock(),
            record_failure=AsyncMock(),
            release_probe=AsyncMock(),
        )
        result = await execution.execute(
            invocation=_invocation(),
            prepared=_prepared(
                {"contents": [{"role": "user", "parts": [{"text": "hello"}]}]},
                stream=True,
                mapping={placeholder: "alice@example.com"},
            ),
            provider_start_callback=AsyncMock(),
        )
        assert isinstance(result, ProviderStream)
        assert result.request_id == "google_stream_request_1"
        wire = b"".join([event async for event in result.events])

        assert str(requests[0].url) == (
            "https://upstream.test/v1beta/models/"
            "gemini-3.5-flash:streamGenerateContent?alt=sse"
        )
        assert b"event:" not in wire
        assert b"[DONE]" not in wire
        assert b"alice@example.com" in wire
        assert placeholder.encode() not in wire
        assert b'"email":"alice@example.com"' in wire
        assert b'"finishReason":"STOP"' in wire
        assert b'"usageMetadata"' in wire
        assert http.is_closed is False
    execution.circuit.record_success.assert_awaited_once()
    execution.circuit.record_failure.assert_not_awaited()


@pytest.mark.asyncio
async def test_stream_requires_every_requested_candidate_to_finish(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "GOOGLE_BASE_URL", "https://upstream.test")

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=('data: {"candidates":[{"index":0,"finishReason":"STOP"}]}\n\n'),
            headers={"content-type": "text/event-stream"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        execution = _execution(http)
        execution.circuit = SimpleNamespace(
            acquire_call=AsyncMock(return_value=True),
            record_success=AsyncMock(),
            record_failure=AsyncMock(),
            release_probe=AsyncMock(),
        )
        result = await execution.execute(
            invocation=_invocation(),
            prepared=_prepared(
                {
                    "contents": [{"role": "user", "parts": [{"text": "hello"}]}],
                    "generationConfig": {"candidateCount": 2},
                },
                stream=True,
            ),
            provider_start_callback=AsyncMock(),
        )
        wire = b"".join([event async for event in result.events])

    assert b'"status":"PROVIDER_UNAVAILABLE"' in wire
    execution.circuit.record_failure.assert_awaited_once()
    execution.circuit.record_success.assert_not_awaited()


@pytest.mark.asyncio
async def test_nonstream_rejects_an_incomplete_success_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "GOOGLE_BASE_URL", "https://upstream.test")

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        execution = _execution(http)
        execution.circuit = SimpleNamespace(
            acquire_call=AsyncMock(return_value=True),
            record_success=AsyncMock(),
            record_failure=AsyncMock(),
            release_probe=AsyncMock(),
        )
        with pytest.raises(ProviderCallError) as error:
            await execution.execute(
                invocation=_invocation(),
                prepared=_prepared(
                    {"contents": [{"role": "user", "parts": [{"text": "hi"}]}]}
                ),
                provider_start_callback=AsyncMock(),
            )

    assert error.value.status_code == 502
    execution.circuit.record_failure.assert_awaited_once()
    execution.circuit.record_success.assert_not_awaited()


@pytest.mark.asyncio
async def test_one_attempt_error_is_typed_and_sanitized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "GOOGLE_BASE_URL", "https://upstream.test")
    attempts = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(
            500,
            json={"error": {"code": 500, "message": "secret upstream detail"}},
            headers={"x-goog-request-id": "google_failed_1"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        with pytest.raises(ProviderCallError) as error:
            await _execution(http).execute(
                invocation=_invocation("key-never-expose"),
                prepared=_prepared(
                    {"contents": [{"role": "user", "parts": [{"text": "hello"}]}]}
                ),
                provider_start_callback=AsyncMock(),
            )

    assert attempts == 1
    assert error.value.provider == "google"
    assert error.value.request_id == "google_failed_1"
    assert str(error.value) == "PROVIDER_UNAVAILABLE"
    assert "secret upstream detail" not in repr(error.value)
    assert "key-never-expose" not in repr(error.value)


def test_native_request_schema_forbids_translation_fields() -> None:
    with pytest.raises(ValidationError):
        GenerateContentRequest.model_validate(
            {
                "contents": [{"role": "user", "parts": [{"text": "hello"}]}],
                "model": "gemini-3.5-flash",
                "stream": True,
            }
        )
