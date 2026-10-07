from __future__ import annotations

import json
import ssl
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import UUID

import httpx
import pytest
from pydantic import ValidationError

import shim.gateway.pipeline.google_execution as google_execution
from shim.api.v1.gemini import GenerateContentRequest
from shim.core.circuit_breaker import InMemoryCircuitBreaker
from shim.core.community_config import CommunitySettings
from shim.gateway.contracts.ids import TenantId
from shim.gateway.kernel.result import InferenceTiming
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
        timing=InferenceTiming(),
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
        sync_http_client=httpx.Client(),
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

    error = json.loads(wire.splitlines()[-2].removeprefix(b"data: "))["error"]
    assert error["status"] == "UNAVAILABLE"
    assert error["details"][0]["reason"] == "PROVIDER_UNAVAILABLE"
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


def _circuit() -> SimpleNamespace:
    return SimpleNamespace(
        acquire_call=AsyncMock(return_value=True),
        record_success=AsyncMock(),
        record_failure=AsyncMock(),
        release_probe=AsyncMock(),
    )


_HELLO = {"contents": [{"role": "user", "parts": [{"text": "hello"}]}]}


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [429, 503])
async def test_rate_limit_releases_the_probe_and_forwards_retry_after(
    monkeypatch: pytest.MonkeyPatch,
    status_code: int,
) -> None:
    monkeypatch.setattr(settings, "GOOGLE_BASE_URL", "https://upstream.test")

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code,
            json={"error": {"code": status_code, "message": "x", "status": "X"}},
            headers={"retry-after": "7"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        execution = _execution(http)
        execution.circuit = circuit = _circuit()
        with pytest.raises(ProviderCallError) as raised:
            await execution.execute(
                invocation=_invocation(),
                prepared=_prepared(_HELLO),
                provider_start_callback=AsyncMock(),
            )

    assert raised.value.status_code == status_code
    assert raised.value.retry_after == "7"
    circuit.record_success.assert_not_awaited()
    if status_code == 429:
        assert raised.value.error_code == "PROVIDER_RATE_LIMITED"
        circuit.release_probe.assert_awaited_once()
        circuit.record_failure.assert_not_awaited()
    else:
        assert raised.value.error_code == "PROVIDER_UNAVAILABLE"
        circuit.record_failure.assert_awaited_once()
        circuit.release_probe.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error", [httpx.ConnectError("refused"), httpx.ReadTimeout("slow")]
)
async def test_connection_and_timeout_errors_count_as_provider_failures(
    monkeypatch: pytest.MonkeyPatch,
    error: httpx.TransportError,
) -> None:
    monkeypatch.setattr(settings, "GOOGLE_BASE_URL", "https://upstream.test")

    async def handler(_request: httpx.Request) -> httpx.Response:
        raise error

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        execution = _execution(http)
        execution.circuit = circuit = _circuit()
        with pytest.raises(ProviderCallError):
            await execution.execute(
                invocation=_invocation(),
                prepared=_prepared(_HELLO),
                provider_start_callback=AsyncMock(),
            )

    # google-genai does not wrap httpx errors, so only this arm opens the circuit.
    circuit.record_failure.assert_awaited_once()
    circuit.release_probe.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["sdk_refusal", "unserializable_answer"])
async def test_local_exceptions_release_the_probe_without_counting(
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    async def generate_content(**_kwargs):
        if failure == "sdk_refusal":
            raise ValueError("refused before any request")
        return SimpleNamespace(model_dump=lambda **_kwargs: [])

    monkeypatch.setattr(
        google_execution.genai,
        "Client",
        lambda **_kwargs: SimpleNamespace(
            aio=SimpleNamespace(
                models=SimpleNamespace(generate_content=generate_content),
                aclose=AsyncMock(),
            ),
            close=lambda: None,
        ),
    )
    async with httpx.AsyncClient() as http:
        execution = _execution(http)
        execution.circuit = circuit = _circuit()
        with pytest.raises(ProviderCallError):
            await execution.execute(
                invocation=_invocation(),
                prepared=_prepared(_HELLO),
                provider_start_callback=AsyncMock(),
            )

    circuit.release_probe.assert_awaited_once()
    circuit.record_failure.assert_not_awaited()
    circuit.record_success.assert_not_awaited()


@pytest.mark.asyncio
async def test_requests_share_one_tls_context_but_never_a_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "GOOGLE_BASE_URL", "https://upstream.test")
    upstream_keys: list[str | None] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        upstream_keys.append(request.headers.get("x-goog-api-key"))
        return httpx.Response(
            200,
            json={
                "candidates": [
                    {
                        "content": {"role": "model", "parts": [{"text": "ok"}]},
                        "finishReason": "STOP",
                    }
                ]
            },
        )

    real_client = google_execution.genai.Client
    clients: list[tuple[google_execution.types.HttpOptions, object]] = []

    def recording_client(**kwargs):
        client = real_client(**kwargs)
        client.close = Mock(wraps=client.close)
        client.aio.aclose = AsyncMock(wraps=client.aio.aclose)
        clients.append((kwargs["http_options"], client))
        return client

    monkeypatch.setattr(google_execution.genai, "Client", recording_client)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        execution = _execution(http)
        for key in ("google-key-one", "google-key-two"):
            await execution.execute(
                invocation=_invocation(key),
                prepared=_prepared(_HELLO),
                provider_start_callback=AsyncMock(),
            )

    assert upstream_keys == ["google-key-one", "google-key-two"]
    assert isinstance(execution.ssl_context, ssl.SSLContext)
    for options, client in clients:
        assert options.client_args == {"verify": execution.ssl_context}
        assert options.async_client_args == {
            "verify": execution.ssl_context,
            "ssl": execution.ssl_context,
        }
        assert options.httpx_client is execution.sync_http_client
        assert options.httpx_async_client is http
        client.close.assert_called_once()
        client.aio.aclose.assert_awaited_once()
    assert clients[0][1] is not clients[1][1]


@pytest.mark.asyncio
async def test_circuit_for_is_asked_once_and_serves_the_whole_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "GOOGLE_BASE_URL", "https://upstream.test")
    chunk = {
        "candidates": [
            {
                "content": {"role": "model", "parts": [{"text": "ok"}]},
                "finishReason": "STOP",
            }
        ]
    }

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text=f"data: {json.dumps(chunk)}\n\n",
            headers={"content-type": "text/event-stream"},
        )

    circuit = _circuit()
    circuit_for = Mock(return_value=circuit)
    prepared = _prepared(_HELLO, stream=True)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        result = await GoogleExecution(
            credential_resolver=EnvironmentProviderCredentialResolver("google", {}),
            circuit_for=circuit_for,
            settings=settings,
            http_client=http,
            sync_http_client=httpx.Client(),
        ).execute(
            invocation=_invocation(),
            prepared=prepared,
            provider_start_callback=AsyncMock(),
        )
        assert isinstance(result, ProviderStream)
        [event async for event in result.events]

    circuit_for.assert_called_once_with(prepared)
    circuit.acquire_call.assert_awaited_once()
    circuit.record_success.assert_awaited_once()


@pytest.mark.parametrize(
    "circuits", [{}, {"circuit": InMemoryCircuitBreaker(), "circuit_for": Mock()}]
)
def test_an_execution_takes_exactly_one_circuit_source(circuits: dict) -> None:
    with pytest.raises(ValueError, match="exactly one of circuit and circuit_for"):
        GoogleExecution(
            credential_resolver=EnvironmentProviderCredentialResolver("google", {}),
            settings=settings,
            http_client=SimpleNamespace(),  # type: ignore[arg-type]
            sync_http_client=httpx.Client(),
            **circuits,
        )
