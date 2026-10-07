from __future__ import annotations

import asyncio
from io import StringIO
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import UUID

import httpx
import pytest
from openai.types.responses import ResponseErrorEvent

import shim.gateway.pipeline.anthropic_execution as anthropic_execution
import shim.gateway.pipeline.google_execution as google_execution
import shim.gateway.pipeline.openai_execution as openai_execution
from shim.application import create_community_app
from shim.core.circuit_breaker import InMemoryCircuitBreaker
from shim.core.community_config import CommunitySettings
from shim.gateway.contracts.ids import TenantId
from shim.gateway.kernel.result import InferenceTiming, ProviderTarget
from shim.gateway.pipeline.openai_execution import OpenAIExecution
from shim.gateway.pipeline.provider_execution import (
    ProviderCallError,
    ProviderNonStream,
    ProviderStream,
)
from shim.privacy.pii_scrubber import PIIScrubberService
from shim.privacy.policies import PrivacyAction, PrivacyOutcome
from shim.secrets.credentials import (
    EnvironmentProviderCredentialResolver,
    EphemeralProviderCredential,
)


settings = CommunitySettings(_env_file=None)


def _response(response_id: str, *, status: str = "completed") -> dict:
    return {
        "id": response_id,
        "object": "response",
        "created_at": 1.0,
        "status": status,
        "model": "gpt-5.6-luna",
        "output": [],
        "parallel_tool_calls": True,
        "tool_choice": "auto",
        "tools": [],
        "usage": {
            "input_tokens": 1,
            "input_tokens_details": {
                "cached_tokens": 0,
                "cache_write_tokens": 0,
            },
            "output_tokens": 2,
            "output_tokens_details": {"reasoning_tokens": 0},
            "total_tokens": 3,
        },
    }


def _prepared(
    payload: dict,
    *,
    tenant: str,
    protocol: str = "responses",
    mapping: dict[str, str] | None = None,
):
    privacy = PrivacyOutcome(
        action=PrivacyAction.SCRUBBED if mapping else PrivacyAction.DISABLED,
        pii_detected=bool(mapping),
        verification_map=mapping or {},
    )
    return SimpleNamespace(
        payload=payload,
        timing=InferenceTiming(),
        target=None,
        tenant_id=TenantId(UUID(tenant)),
        protocol=protocol,
        stream=bool(payload.get("stream")),
        privacy=privacy,
    )


def _execution(http_client: httpx.AsyncClient, chain_store) -> OpenAIExecution:
    return OpenAIExecution(
        credential_resolver=EnvironmentProviderCredentialResolver("openai", {}),
        circuit=InMemoryCircuitBreaker(),
        settings=settings,
        http_client=http_client,
        chain_store=chain_store,
    )


@pytest.mark.asyncio
async def test_responses_nonstream_uses_sdk_key_and_restores_native_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "OPENAI_BASE_URL", "https://upstream.test/v1")
    scrubber = PIIScrubberService()
    placeholder, mapping = scrubber.scrub("alice@example.com")
    seen: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        seen["authorization"] = request.headers["authorization"]
        seen["body"] = json.loads(request.content)
        response = _response("resp_native")
        response["output"] = [
            {
                "id": "msg_1",
                "type": "message",
                "status": "completed",
                "role": "assistant",
                "content": [
                    {
                        "type": "output_text",
                        "text": f"hello {placeholder}",
                        "annotations": [],
                        "logprobs": [],
                    }
                ],
            }
        ]
        return httpx.Response(
            200, json=response, headers={"x-request-id": "upstream_req_1"}
        )

    chain_store = SimpleNamespace(save=AsyncMock())
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        credential = EphemeralProviderCredential("openai", "sk-tenant-a")
        result = await _execution(http, chain_store).execute(
            invocation=SimpleNamespace(db=object(), provider_credential=credential),
            prepared=_prepared(
                {
                    "model": "gpt-5.6-luna",
                    "input": placeholder,
                    "tools": [
                        {
                            "type": "function",
                            "name": "lookup",
                            "parameters": {"type": "object"},
                        },
                        {"type": "custom", "name": "exec"},
                        {"type": "local_shell"},
                        {"type": "apply_patch"},
                    ],
                },
                tenant="11111111-1111-1111-1111-111111111111",
                mapping=mapping,
            ),
            provider_start_callback=AsyncMock(),
        )

        assert isinstance(result, ProviderNonStream)
        assert result.request_id == "upstream_req_1"
        assert result.payload["output"][0]["content"][0]["text"] == (
            "hello alice@example.com"
        )
        assert seen == {
            "authorization": "Bearer sk-tenant-a",
            "body": {
                "input": placeholder,
                "model": "gpt-5.6-luna",
                "tools": [
                    {
                        "type": "function",
                        "name": "lookup",
                        "parameters": {"type": "object"},
                    },
                    {"type": "custom", "name": "exec"},
                    {"type": "local_shell"},
                    {"type": "apply_patch"},
                ],
            },
        }
        assert credential.available() is False
        assert http.is_closed is False
    chain_store.save.assert_awaited_once()


@pytest.mark.asyncio
async def test_sdk_forwards_future_body_fields_and_only_feature_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "OPENAI_BASE_URL", "https://upstream.test/v1")
    seen: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        seen["headers"] = dict(request.headers)
        return httpx.Response(200, json=_response("resp_forwarded"))

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        await _execution(http, SimpleNamespace(save=AsyncMock())).execute(
            invocation=SimpleNamespace(
                db=object(),
                provider_credential=EphemeralProviderCredential("openai", "sk-real"),
                headers={
                    "Authorization": "Bearer attacker",
                    "Cookie": "session=secret",
                    "Host": "attacker.test",
                    "Content-Length": "999",
                    "OpenAI-Organization": "org_forwarded",
                    "OpenAI-Project": "proj_forwarded",
                    "OpenAI-Beta": "feature=v1",
                    "X-Client-Request-Id": "client_req_1",
                    "Idempotency-Key": "idem_1",
                    "X-Shim-Key": "shim-secret",
                    "X-Arbitrary": "drop-me",
                },
            ),
            prepared=_prepared(
                {
                    "model": "gpt-5.6-luna",
                    "input": "hello",
                    "future_field": {"enabled": True},
                    "timeout": 0,
                    "extra_headers": {"x-unsafe": "body-only"},
                    "extra_query": {"unsafe": "body-only"},
                    "extra_body": {"nested": "body-only"},
                },
                tenant="11111111-1111-1111-1111-111111111111",
            ),
            provider_start_callback=AsyncMock(),
        )

    assert seen["body"] == {
        "model": "gpt-5.6-luna",
        "input": "hello",
        "future_field": {"enabled": True},
        "timeout": 0,
        "extra_headers": {"x-unsafe": "body-only"},
        "extra_query": {"unsafe": "body-only"},
        "extra_body": {"nested": "body-only"},
    }
    headers = seen["headers"]
    assert isinstance(headers, dict)
    assert headers["authorization"] == "Bearer sk-real"
    assert headers["openai-organization"] == "org_forwarded"
    assert headers["openai-project"] == "proj_forwarded"
    assert headers["openai-beta"] == "feature=v1"
    assert headers["x-client-request-id"] == "client_req_1"
    assert headers["idempotency-key"] == "idem_1"
    assert headers["host"] == "upstream.test"
    assert headers["content-length"] != "999"
    assert "cookie" not in headers
    assert "x-shim-key" not in headers
    assert "x-arbitrary" not in headers


@pytest.mark.asyncio
async def test_concurrent_tenant_keys_never_cross_invocations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "OPENAI_BASE_URL", "https://upstream.test/v1")
    seen: dict[str, str] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen[body["input"]] = request.headers["authorization"]
        await asyncio.sleep(0)
        return httpx.Response(200, json=_response(f"resp_{body['input']}"))

    chain_store = SimpleNamespace(save=AsyncMock())
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        execution = _execution(http, chain_store)

        async def call(input_text: str, key: str, tenant: str):
            return await execution.execute(
                invocation=SimpleNamespace(
                    db=object(),
                    provider_credential=EphemeralProviderCredential("openai", key),
                ),
                prepared=_prepared(
                    {"model": "gpt-5.6-luna", "input": input_text},
                    tenant=tenant,
                ),
                provider_start_callback=AsyncMock(),
            )

        await asyncio.gather(
            call("tenant-a", "sk-a", "11111111-1111-1111-1111-111111111111"),
            call("tenant-b", "sk-b", "22222222-2222-2222-2222-222222222222"),
        )

        assert seen == {"tenant-a": "Bearer sk-a", "tenant-b": "Bearer sk-b"}
        assert http.is_closed is False


@pytest.mark.asyncio
async def test_sdk_retries_are_disabled_and_error_is_sanitized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "OPENAI_BASE_URL", "https://upstream.test/v1")
    attempts = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(
            500,
            json={"error": {"message": "secret upstream body", "type": "server_error"}},
            headers={"x-request-id": "upstream_req_failure"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        with pytest.raises(ProviderCallError) as error:
            await _execution(http, SimpleNamespace(save=AsyncMock())).execute(
                invocation=SimpleNamespace(
                    db=object(),
                    provider_credential=EphemeralProviderCredential(
                        "openai", "sk-never-log"
                    ),
                ),
                prepared=_prepared(
                    {"model": "gpt-5.6-luna", "input": "hello"},
                    tenant="11111111-1111-1111-1111-111111111111",
                ),
                provider_start_callback=AsyncMock(),
            )

    assert attempts == 1
    assert error.value.request_id == "upstream_req_failure"
    assert str(error.value) == "PROVIDER_UNAVAILABLE"
    assert "secret upstream body" not in repr(error.value)
    assert "sk-never-log" not in repr(error.value)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status_code", "outcome"),
    [
        (400, "success"),
        (401, "success"),
        (403, "success"),
        (404, "success"),
        (408, "failure"),
        (409, "failure"),
        (413, "success"),
        (422, "success"),
        (429, "release"),
        (500, "failure"),
        (504, "failure"),
        (529, "failure"),
    ],
)
async def test_http_statuses_update_circuit_without_exposing_bodies(
    monkeypatch: pytest.MonkeyPatch,
    status_code: int,
    outcome: str,
) -> None:
    monkeypatch.setattr(settings, "OPENAI_BASE_URL", "https://upstream.test/v1")
    attempts = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(
            status_code,
            json={"error": {"message": "alice@example.com", "type": "bad"}},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        execution = _execution(http, SimpleNamespace(save=AsyncMock()))
        execution.circuit = SimpleNamespace(
            acquire_call=AsyncMock(return_value=True),
            record_success=AsyncMock(),
            record_failure=AsyncMock(),
            release_probe=AsyncMock(),
        )
        with pytest.raises(ProviderCallError) as error:
            await execution.execute(
                invocation=SimpleNamespace(
                    db=object(),
                    provider_credential=EphemeralProviderCredential("openai", "sk-key"),
                ),
                prepared=_prepared(
                    {"model": "gpt-5.6-luna", "input": "hello"},
                    tenant="11111111-1111-1111-1111-111111111111",
                ),
                provider_start_callback=AsyncMock(),
            )

    assert attempts == 1
    assert error.value.status_code == status_code
    assert str(error.value) == {
        408: "PROVIDER_TIMEOUT",
        429: "PROVIDER_RATE_LIMITED",
    }.get(status_code, "PROVIDER_UNAVAILABLE")
    assert "alice@example.com" not in repr(error.value)
    calls = {
        "success": execution.circuit.record_success.await_count,
        "failure": execution.circuit.record_failure.await_count,
        "release": execution.circuit.release_probe.await_count,
    }
    assert calls == {name: int(name == outcome) for name in calls}


@pytest.mark.asyncio
async def test_start_marker_failure_releases_probe_without_calling_openai(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "OPENAI_BASE_URL", "https://upstream.test/v1")
    attempts = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(200, json=_response("unexpected"))

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        execution = _execution(http, SimpleNamespace(save=AsyncMock()))
        execution.circuit = SimpleNamespace(
            acquire_call=AsyncMock(return_value=True),
            record_success=AsyncMock(),
            record_failure=AsyncMock(),
            release_probe=AsyncMock(),
        )
        failure = RuntimeError("start marker failed")
        with pytest.raises(RuntimeError) as error:
            await execution.execute(
                invocation=SimpleNamespace(
                    db=object(),
                    provider_credential=EphemeralProviderCredential("openai", "sk-key"),
                ),
                prepared=_prepared(
                    {"model": "gpt-5.6-luna", "input": "hello"},
                    tenant="11111111-1111-1111-1111-111111111111",
                ),
                provider_start_callback=AsyncMock(side_effect=failure),
            )

    assert error.value is failure
    assert attempts == 0
    execution.circuit.release_probe.assert_awaited_once()
    execution.circuit.record_failure.assert_not_awaited()
    execution.circuit.record_success.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("transport_error", "public_code"),
    [
        (httpx.ConnectError("raw connection detail"), "PROVIDER_UNAVAILABLE"),
        (httpx.ReadTimeout("raw timeout detail"), "PROVIDER_TIMEOUT"),
    ],
)
async def test_connection_and_timeout_errors_are_sanitized(
    monkeypatch: pytest.MonkeyPatch,
    transport_error: httpx.TransportError,
    public_code: str,
) -> None:
    monkeypatch.setattr(settings, "OPENAI_BASE_URL", "https://upstream.test/v1")

    async def handler(request: httpx.Request) -> httpx.Response:
        transport_error.request = request
        raise transport_error

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        with pytest.raises(ProviderCallError) as error:
            await _execution(http, SimpleNamespace(save=AsyncMock())).execute(
                invocation=SimpleNamespace(
                    db=object(),
                    provider_credential=EphemeralProviderCredential("openai", "sk-key"),
                ),
                prepared=_prepared(
                    {"model": "gpt-5.6-luna", "input": "hello"},
                    tenant="11111111-1111-1111-1111-111111111111",
                ),
                provider_start_callback=AsyncMock(),
            )

    assert str(error.value) == public_code
    assert "raw" not in repr(error.value)


@pytest.mark.asyncio
async def test_responses_stream_preserves_sdk_event_identity_and_request_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "OPENAI_BASE_URL", "https://upstream.test/v1")
    response = _response("resp_stream")
    events = [
        {
            "type": "response.created",
            "response": {**response, "status": "in_progress"},
            "sequence_number": 0,
        },
        {
            "type": "response.output_text.delta",
            "item_id": "msg_1",
            "output_index": 0,
            "content_index": 0,
            "delta": "hello",
            "sequence_number": 1,
            "logprobs": [],
        },
        {
            "type": "response.completed",
            "response": response,
            "sequence_number": 2,
        },
    ]
    sse = "".join(
        f"event: {event['type']}\ndata: {json.dumps(event, separators=(',', ':'))}\n\n"
        for event in events
    )

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=sse,
            headers={
                "content-type": "text/event-stream",
                "x-request-id": "upstream_req_stream",
            },
        )

    chain_store = SimpleNamespace(save=AsyncMock())
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        result = await _execution(http, chain_store).execute(
            invocation=SimpleNamespace(
                db=object(),
                provider_credential=EphemeralProviderCredential("openai", "sk-stream"),
            ),
            prepared=_prepared(
                {"model": "gpt-5.6-luna", "input": "hello", "stream": True},
                tenant="11111111-1111-1111-1111-111111111111",
            ),
            provider_start_callback=AsyncMock(),
        )
        assert isinstance(result, ProviderStream)
        wire = b"".join([chunk async for chunk in result.events])

        assert result.request_id == "upstream_req_stream"
        assert [
            line.removeprefix(b"event: ")
            for line in wire.splitlines()
            if line.startswith(b"event: ")
        ] == [
            b"response.created",
            b"response.output_text.delta",
            b"response.completed",
        ]
        assert b'"item_id":"msg_1"' in wire
        assert b'"sequence_number":1' in wire
        assert http.is_closed is False
    chain_store.save.assert_awaited_once()


@pytest.mark.asyncio
async def test_stream_failure_emits_sanitized_error_and_closes_sdk_resource(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "OPENAI_BASE_URL", "https://upstream.test/v1")
    created = {
        "type": "response.created",
        "response": {**_response("resp_broken"), "status": "in_progress"},
        "sequence_number": 0,
    }

    class BrokenStream(httpx.AsyncByteStream):
        closed = False

        async def __aiter__(self):
            yield (
                f"event: response.created\ndata: "
                f"{json.dumps(created, separators=(',', ':'))}\n\n"
            ).encode()
            raise RuntimeError("alice@example.com upstream stream detail")

        async def aclose(self) -> None:
            self.closed = True

    source = BrokenStream()

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            stream=source,
            headers={"content-type": "text/event-stream"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        execution = _execution(http, SimpleNamespace(save=AsyncMock()))
        execution.circuit = SimpleNamespace(
            acquire_call=AsyncMock(return_value=True),
            record_success=AsyncMock(),
            record_failure=AsyncMock(),
            release_probe=AsyncMock(),
        )
        result = await execution.execute(
            invocation=SimpleNamespace(
                db=object(),
                provider_credential=EphemeralProviderCredential("openai", "sk-key"),
            ),
            prepared=_prepared(
                {"model": "gpt-5.6-luna", "input": "hello", "stream": True},
                tenant="11111111-1111-1111-1111-111111111111",
            ),
            provider_start_callback=AsyncMock(),
        )
        wire = b"".join([chunk async for chunk in result.events])

    assert b"response.created" in wire
    assert b'"code":"PROVIDER_UNAVAILABLE"' in wire
    assert b"alice@example.com" not in wire
    assert source.closed is True
    error_payload = next(
        json.loads(line.removeprefix(b"data: "))
        for line in wire.splitlines()
        if line.startswith(b"data: ") and b'"type":"error"' in line
    )
    error_event = ResponseErrorEvent.model_validate(error_payload)
    assert error_event.sequence_number == 1
    assert error_event.code == "PROVIDER_UNAVAILABLE"
    execution.circuit.release_probe.assert_awaited_once()
    execution.circuit.record_failure.assert_not_awaited()


@pytest.mark.asyncio
async def test_responses_failed_payloads_hide_provider_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "OPENAI_BASE_URL", "https://upstream.test/v1")
    raw_message = "alice@example.com upstream failure detail"

    async def handler(request: httpx.Request) -> httpx.Response:
        failed = {
            **_response("resp_failed", status="failed"),
            "error": {"code": "server_error", "message": raw_message},
            "extra_future": {"error_detail": raw_message},
            "metadata": {"detail": raw_message},
            "output": [
                {
                    "id": "msg_failed",
                    "type": "message",
                    "status": "completed",
                    "role": "assistant",
                    "content": [
                        {
                            "type": "output_text",
                            "text": raw_message,
                            "annotations": [],
                            "logprobs": [],
                        }
                    ],
                }
            ],
        }
        if json.loads(request.content).get("stream"):
            event = {
                "type": "response.failed",
                "response": failed,
                "sequence_number": 0,
            }
            return httpx.Response(
                200,
                content=(
                    "event: response.failed\ndata: "
                    f"{json.dumps(event, separators=(',', ':'))}\n\n"
                ),
                headers={"content-type": "text/event-stream"},
            )
        return httpx.Response(200, json=failed)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        execution = _execution(http, SimpleNamespace(save=AsyncMock()))
        execution.circuit = SimpleNamespace(
            acquire_call=AsyncMock(return_value=True),
            record_success=AsyncMock(),
            record_failure=AsyncMock(),
            release_probe=AsyncMock(),
        )
        nonstream = await execution.execute(
            invocation=SimpleNamespace(
                db=object(),
                provider_credential=EphemeralProviderCredential("openai", "sk-key"),
            ),
            prepared=_prepared(
                {"model": "gpt-5.6-luna", "input": "hello"},
                tenant="11111111-1111-1111-1111-111111111111",
            ),
            provider_start_callback=AsyncMock(),
        )
        streamed = await execution.execute(
            invocation=SimpleNamespace(
                db=object(),
                provider_credential=EphemeralProviderCredential("openai", "sk-key"),
            ),
            prepared=_prepared(
                {"model": "gpt-5.6-luna", "input": "hello", "stream": True},
                tenant="11111111-1111-1111-1111-111111111111",
            ),
            provider_start_callback=AsyncMock(),
        )
        assert isinstance(nonstream, ProviderNonStream)
        assert isinstance(streamed, ProviderStream)
        wire = b"".join([chunk async for chunk in streamed.events])

    assert nonstream.payload["error"] == {
        "code": "server_error",
        "message": "The OpenAI response failed.",
    }
    assert raw_message not in json.dumps(nonstream.payload)
    assert "extra_future" not in nonstream.payload
    assert "metadata" not in nonstream.payload
    assert nonstream.payload["output"] == []
    assert b"response.failed" in wire
    assert raw_message.encode() not in wire
    assert b"The OpenAI response failed." in wire
    assert execution.circuit.record_failure.await_count == 2
    execution.circuit.record_success.assert_not_awaited()


@pytest.mark.asyncio
async def test_responses_completed_payload_with_an_error_field_is_not_forwarded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "OPENAI_BASE_URL", "https://upstream.test/v1")
    raw_message = "alice@example.com upstream detail"

    async def handler(request: httpx.Request) -> httpx.Response:
        response = {
            **_response("resp_malformed"),
            "error": {"code": "server_error", "message": raw_message},
        }
        if json.loads(request.content).get("stream"):
            event = {
                "type": "response.completed",
                "response": response,
                "sequence_number": 0,
            }
            return httpx.Response(
                200,
                content=(
                    "event: response.completed\ndata: "
                    f"{json.dumps(event, separators=(',', ':'))}\n\n"
                ),
                headers={
                    "content-type": "text/event-stream",
                    "x-request-id": "req_malformed",
                },
            )
        return httpx.Response(
            200,
            json=response,
            headers={"x-request-id": "req_malformed"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        execution = _execution(http, SimpleNamespace(save=AsyncMock()))
        execution.circuit = SimpleNamespace(
            acquire_call=AsyncMock(return_value=True),
            record_success=AsyncMock(),
            record_failure=AsyncMock(),
            release_probe=AsyncMock(),
        )
        with pytest.raises(ProviderCallError) as error:
            await execution.execute(
                invocation=SimpleNamespace(
                    db=object(),
                    provider_credential=EphemeralProviderCredential(
                        "openai",
                        "sk-key",
                    ),
                ),
                prepared=_prepared(
                    {"model": "gpt-5.6-luna", "input": "hello"},
                    tenant="11111111-1111-1111-1111-111111111111",
                ),
                provider_start_callback=AsyncMock(),
            )
        streamed = await execution.execute(
            invocation=SimpleNamespace(
                db=object(),
                provider_credential=EphemeralProviderCredential("openai", "sk-key"),
            ),
            prepared=_prepared(
                {"model": "gpt-5.6-luna", "input": "hello", "stream": True},
                tenant="11111111-1111-1111-1111-111111111111",
            ),
            provider_start_callback=AsyncMock(),
        )
        assert isinstance(streamed, ProviderStream)
        wire = b"".join([chunk async for chunk in streamed.events])

    assert error.value.request_id == "req_malformed"
    assert raw_message not in repr(error.value)
    assert raw_message.encode() not in wire
    assert b'"type":"error"' in wire
    assert execution.circuit.record_failure.await_count == 2
    execution.circuit.record_success.assert_not_awaited()


@pytest.mark.asyncio
async def test_chat_nonstream_and_stream_use_native_sdk_shapes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "OPENAI_BASE_URL", "https://upstream.test/v1")
    requests: list[dict] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        requests.append(body)
        if body.get("stream"):
            chunks = [
                {
                    "id": "chatcmpl_stream",
                    "object": "chat.completion.chunk",
                    "created": 1,
                    "model": "gpt-5.6-luna",
                    "choices": [
                        {
                            "index": 0,
                            "delta": {"content": "hello"},
                            "finish_reason": None,
                            "logprobs": None,
                        }
                    ],
                },
                {
                    "id": "chatcmpl_stream",
                    "object": "chat.completion.chunk",
                    "created": 1,
                    "model": "gpt-5.6-luna",
                    "choices": [
                        {
                            "index": 0,
                            "delta": {},
                            "finish_reason": "stop",
                            "logprobs": None,
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 1,
                        "completion_tokens": 1,
                        "total_tokens": 2,
                    },
                },
            ]
            content = (
                "".join(
                    f"data: {json.dumps(chunk, separators=(',', ':'))}\n\n"
                    for chunk in chunks
                )
                + "data: [DONE]\n\n"
            )
            return httpx.Response(
                200,
                content=content,
                headers={"content-type": "text/event-stream"},
            )
        return httpx.Response(
            200,
            json={
                "id": "chatcmpl_1",
                "object": "chat.completion",
                "created": 1,
                "model": "gpt-5.6-luna",
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "logprobs": None,
                        "message": {"role": "assistant", "content": "hello"},
                    }
                ],
                "usage": {
                    "prompt_tokens": 1,
                    "completion_tokens": 1,
                    "total_tokens": 2,
                },
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        execution = _execution(http, SimpleNamespace(save=AsyncMock()))
        nonstream = await execution.execute(
            invocation=SimpleNamespace(
                db=object(),
                provider_credential=EphemeralProviderCredential("openai", "sk-chat"),
            ),
            prepared=_prepared(
                {
                    "model": "gpt-5.6-luna",
                    "messages": [{"role": "user", "content": "hello"}],
                },
                protocol="chat",
                tenant="11111111-1111-1111-1111-111111111111",
            ),
            provider_start_callback=AsyncMock(),
        )
        stream = await execution.execute(
            invocation=SimpleNamespace(
                db=object(),
                provider_credential=EphemeralProviderCredential("openai", "sk-chat"),
            ),
            prepared=_prepared(
                {
                    "model": "gpt-5.6-luna",
                    "messages": [{"role": "user", "content": "hello"}],
                    "stream": True,
                },
                protocol="chat",
                tenant="11111111-1111-1111-1111-111111111111",
            ),
            provider_start_callback=AsyncMock(),
        )

        assert isinstance(nonstream, ProviderNonStream)
        assert nonstream.payload["choices"][0]["message"]["content"] == "hello"
        assert isinstance(stream, ProviderStream)
        wire = b"".join([chunk async for chunk in stream.events])
        assert b'"id":"chatcmpl_stream"' in wire
        assert wire.endswith(b"data: [DONE]\n\n")
        assert requests[0].get("stream") is None
    assert requests[1]["stream"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "provider_error",
    [
        "alice@example.com upstream detail",
        {"type": "server_error", "message": "alice@example.com upstream detail"},
    ],
)
async def test_chat_success_status_with_an_error_field_is_not_forwarded(
    monkeypatch: pytest.MonkeyPatch,
    provider_error: object,
) -> None:
    monkeypatch.setattr(settings, "OPENAI_BASE_URL", "https://upstream.test/v1")
    raw_message = "alice@example.com upstream detail"

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "id": "chatcmpl_malformed",
                "object": "chat.completion",
                "created": 1,
                "model": "gpt-5.6-luna",
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": "ignored"},
                    }
                ],
                "error": provider_error,
            },
            headers={"x-request-id": "req_malformed"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        execution = _execution(http, SimpleNamespace(save=AsyncMock()))
        execution.circuit = SimpleNamespace(
            acquire_call=AsyncMock(return_value=True),
            record_success=AsyncMock(),
            record_failure=AsyncMock(),
            release_probe=AsyncMock(),
        )
        with pytest.raises(ProviderCallError) as error:
            await execution.execute(
                invocation=SimpleNamespace(
                    db=object(),
                    provider_credential=EphemeralProviderCredential(
                        "openai",
                        "sk-chat",
                    ),
                ),
                prepared=_prepared(
                    {
                        "model": "gpt-5.6-luna",
                        "messages": [{"role": "user", "content": "hello"}],
                    },
                    protocol="chat",
                    tenant="11111111-1111-1111-1111-111111111111",
                ),
                provider_start_callback=AsyncMock(),
            )

    assert error.value.request_id == "req_malformed"
    assert raw_message not in repr(error.value)
    execution.circuit.record_failure.assert_awaited_once()
    execution.circuit.record_success.assert_not_awaited()


@pytest.mark.asyncio
async def test_chat_stream_rejects_eof_before_every_choice_finishes() -> None:
    async def chunks():
        yield SimpleNamespace(
            model_dump=lambda **_kwargs: {
                "choices": [
                    {
                        "index": 0,
                        "delta": {"content": "partial"},
                        "finish_reason": "stop",
                    }
                ]
            }
        )

    async with httpx.AsyncClient() as http:
        execution = _execution(http, SimpleNamespace(save=AsyncMock()))
        execution.circuit = SimpleNamespace(
            record_success=AsyncMock(),
            record_failure=AsyncMock(),
            release_probe=AsyncMock(),
        )
        state = {"closed": False, "recorded": False}
        close_stream = AsyncMock()
        wire = b"".join(
            [
                event
                async for event in execution._chat_stream(
                    chunks(),
                    _prepared(
                        {
                            "model": "gpt-5.6-luna",
                            "messages": [{"role": "user", "content": "hello"}],
                            "stream": True,
                            "n": 2,
                        },
                        protocol="chat",
                        tenant="11111111-1111-1111-1111-111111111111",
                    ),
                    state,
                    close_stream,
                    execution.circuit,
                    False,
                )
            ]
        )

    assert b"PROVIDER_UNAVAILABLE" in wire
    assert b"[DONE]" not in wire
    execution.circuit.record_failure.assert_awaited_once()
    execution.circuit.record_success.assert_not_awaited()
    close_stream.assert_awaited_once()


def test_explicit_timeout_policy_is_mapped_to_httpx() -> None:
    execution = _execution(
        httpx.AsyncClient(),
        SimpleNamespace(save=AsyncMock()),
    )
    try:
        assert execution.timeout.connect == settings.OPENAI_CONNECT_TIMEOUT_SECONDS
        assert execution.timeout.read == settings.OPENAI_READ_TIMEOUT_SECONDS
        assert execution.timeout.write == settings.OPENAI_WRITE_TIMEOUT_SECONDS
        assert execution.timeout.pool == settings.OPENAI_POOL_TIMEOUT_SECONDS
    finally:
        asyncio.run(execution.http_client.aclose())


def test_provider_boundary_defaults_match_sdk_limits() -> None:
    defaults = CommunitySettings.model_fields

    assert defaults["MAX_REQUEST_BODY_SIZE"].default == 32_000_000
    for provider in ("OPENAI", "ANTHROPIC"):
        assert defaults[f"{provider}_CONNECT_TIMEOUT_SECONDS"].default == 5
        assert defaults[f"{provider}_READ_TIMEOUT_SECONDS"].default == 600
        assert defaults[f"{provider}_WRITE_TIMEOUT_SECONDS"].default == 600
        assert defaults[f"{provider}_POOL_TIMEOUT_SECONDS"].default == 600


@pytest.mark.asyncio
async def test_chat_placeholder_overflow_on_finished_choice_is_a_terminal_error():
    async def chunks():
        yield SimpleNamespace(
            model_dump=lambda **kwargs: {
                "choices": [
                    {
                        "index": 0,
                        "delta": {"content": "<" + " " * 256},
                        "finish_reason": "stop",
                    }
                ]
            }
        )

    async with httpx.AsyncClient() as http:
        execution = _execution(http, SimpleNamespace(save=AsyncMock()))
        wire = b"".join(
            [
                event
                async for event in execution._chat_stream(
                    chunks(),
                    _prepared(
                        {"stream": True},
                        protocol="chat",
                        tenant="11111111-1111-1111-1111-111111111111",
                        mapping={"<EMAIL_ADDRESS_a1>": "alice@example.com"},
                    ),
                    {"closed": False, "recorded": False},
                    AsyncMock(),
                    execution.circuit,
                    False,
                )
            ]
        )
    assert b"PROVIDER_UNAVAILABLE" in wire
    assert b"[DONE]" not in wire
    assert b"alice@example.com" not in wire


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "provider,protocol,stream",
    [
        ("openai", "chat", False),
        ("openai", "chat", True),
        ("openai", "responses", False),
        ("openai", "responses", True),
        ("anthropic", "messages", False),
        ("anthropic", "messages", True),
        ("anthropic", "count_tokens", False),
        ("google", "generate_content", False),
        ("google", "generate_content", True),
    ],
)
@pytest.mark.parametrize("failed", [False, True])
async def test_provider_wait_is_excluded_but_restoration_is_counted(
    monkeypatch: pytest.MonkeyPatch,
    provider: str,
    protocol: str,
    stream: bool,
    failed: bool,
) -> None:
    clock = [0.0]
    monkeypatch.setattr("shim.gateway.kernel.result.perf_counter", lambda: clock[0])
    timing = InferenceTiming(started_at=0.0)
    module = {
        "openai": openai_execution,
        "anthropic": anthropic_execution,
        "google": google_execution,
    }[provider]
    class_prefix = {"openai": "OpenAI", "anthropic": "Anthropic", "google": "Google"}[
        provider
    ]
    restore_calls = []
    if stream:
        restorer = getattr(module, f"{class_prefix}StreamRestorer")
        method = {
            "chat": "restore_chat_chunk",
            "responses": "restore_response_event",
            "messages": "restore_events",
            "generate_content": "restore_chunk",
        }[protocol]
        original_restore = getattr(restorer, method)

        def restore(self, payload):
            clock[0] += 7
            restore_calls.append(payload)
            return original_restore(self, payload)

        monkeypatch.setattr(restorer, method, restore)
    else:
        name = f"restore_{provider}_payload"
        original_restore = getattr(module, name)

        def restore(*args):
            clock[0] += 7
            restore_calls.append(args[0])
            return original_restore(*args)

        monkeypatch.setattr(module, name, restore)

    placeholder = "<EMAIL_ADDRESS_deadbeef>"
    if protocol == "responses":
        payload = {"model": "gpt-5.6-luna", "input": "hello"}
        response = _response("resp_timing")
        response["output"] = [
            {
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": placeholder}],
            }
        ]
        chunks = [{"type": "response.completed", "response": response}]
    elif protocol == "chat":
        payload = {"model": "gpt-5.6-luna", "messages": []}
        response = {
            "id": "chat_timing",
            "object": "chat.completion",
            "created": 1,
            "model": "gpt-5.6-luna",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": placeholder},
                    "finish_reason": "stop",
                }
            ],
        }
        chunks = [
            {
                **response,
                "object": "chat.completion.chunk",
                "choices": [
                    {
                        "index": 0,
                        "delta": {"content": placeholder},
                        "finish_reason": "stop",
                    }
                ],
            }
        ]
    elif provider == "anthropic":
        payload = {"model": "claude-sonnet-4-5", "max_tokens": 32, "messages": []}
        response = {
            "id": "msg_timing",
            "type": "message",
            "role": "assistant",
            "model": "claude-sonnet-4-5",
            "content": [{"type": "text", "text": placeholder}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 1, "output_tokens": 1},
        }
        chunks = [
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": placeholder},
            },
            {"type": "content_block_stop", "index": 0},
            {"type": "message_stop"},
        ]
        if protocol == "count_tokens":
            payload.pop("max_tokens")
            response = {"input_tokens": 1}
    else:
        payload = {"contents": [{"role": "user", "parts": [{"text": "hello"}]}]}
        response = {
            "candidates": [
                {"content": {"parts": [{"text": placeholder}]}, "finishReason": "STOP"}
            ]
        }
        chunks = [
            {"candidates": [{"content": {"parts": [{"text": placeholder}]}}]},
            {"candidates": [{"finishReason": "STOP"}]},
        ]
    if stream and provider != "google":
        payload["stream"] = True

    class DelayedStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            for chunk in chunks:
                clock[0] += 100
                event = f"event: {chunk['type']}\n" if provider == "anthropic" else ""
                yield f"{event}data: {json.dumps(chunk)}\n\n".encode()
            if protocol == "chat":
                clock[0] += 100
                yield b"data: [DONE]\n\n"

        async def aclose(self):
            clock[0] += 100

    async def handler(_request):
        clock[0] += 100
        if failed:
            return httpx.Response(
                500, json={"error": {"code": 500, "message": "failed"}}
            )
        if stream:
            return httpx.Response(
                200,
                stream=DelayedStream(),
                headers={"content-type": "text/event-stream"},
            )
        return httpx.Response(200, json=response)

    async def started():
        clock[0] += 3

    async def recorded():
        clock[0] += 5

    async def saved(*_args):
        clock[0] += 11

    prepared = _prepared(
        payload,
        tenant="11111111-1111-1111-1111-111111111111",
        protocol=protocol,
        mapping={placeholder: "alice@example.com"},
    )
    prepared.timing = timing
    prepared.stream = stream
    prepared.model = payload.get("model", "gemini-3.5-flash")
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        execution = getattr(module, f"{class_prefix}Execution")(
            credential_resolver=EnvironmentProviderCredentialResolver(provider, {}),
            circuit=SimpleNamespace(
                acquire_call=AsyncMock(return_value=True),
                record_success=recorded,
                record_failure=recorded,
                release_probe=AsyncMock(),
            ),
            settings=settings,
            http_client=http,
            **{
                "openai": {"chain_store": SimpleNamespace(save=saved)},
                "google": {"sync_http_client": httpx.Client()},
            }.get(provider, {}),
        )
        original_resolve = execution.credential_resolver.resolve

        async def resolve(*args, **kwargs):
            clock[0] += 2
            return await original_resolve(*args, **kwargs)

        execution.credential_resolver = SimpleNamespace(resolve=resolve)
        invocation = SimpleNamespace(
            provider_credential=EphemeralProviderCredential(provider, "secret")
        )
        if failed:
            with pytest.raises(ProviderCallError):
                await execution.execute(
                    invocation=invocation,
                    prepared=prepared,
                    provider_start_callback=started,
                )
            assert not restore_calls
        else:
            result = await execution.execute(
                invocation=invocation,
                prepared=prepared,
                provider_start_callback=started,
            )
            if stream:
                wire = b"".join([event async for event in result.events])
                assert b"alice@example.com" in wire
                assert b"PROVIDER_UNAVAILABLE" not in wire
            elif protocol != "count_tokens":
                assert "alice@example.com" in json.dumps(result.payload)
            assert restore_calls

    continuation_seconds = 11 if protocol == "responses" and not failed else 0
    assert (
        timing.shim_latency_ms
        == (10 + 7 * len(restore_calls) + continuation_seconds) * 1_000
    )
    assert timing.excluded_seconds >= 100


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure", "raised_type"),
    [("sdk_refusal", ProviderCallError), ("unserializable_answer", TypeError)],
)
async def test_local_exceptions_release_the_probe_without_counting(
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
    raised_type: type[Exception],
) -> None:
    async def create(**_kwargs):
        if failure == "sdk_refusal":
            raise ValueError("refused before any request")
        return SimpleNamespace(_request_id=None, model_dump=lambda **_kwargs: [])

    monkeypatch.setattr(
        openai_execution,
        "AsyncOpenAI",
        lambda **_kwargs: SimpleNamespace(responses=SimpleNamespace(create=create)),
    )
    async with httpx.AsyncClient() as http:
        execution = _execution(http, SimpleNamespace(save=AsyncMock()))
        execution.circuit = circuit = SimpleNamespace(
            acquire_call=AsyncMock(return_value=True),
            record_success=AsyncMock(),
            record_failure=AsyncMock(),
            release_probe=AsyncMock(),
        )
        with pytest.raises(raised_type):
            await execution.execute(
                invocation=SimpleNamespace(
                    db=object(),
                    provider_credential=EphemeralProviderCredential("openai", "sk-key"),
                ),
                prepared=_prepared(
                    {"model": "gpt-5.6-luna", "input": "hello"},
                    tenant="11111111-1111-1111-1111-111111111111",
                ),
                provider_start_callback=AsyncMock(),
            )

    circuit.release_probe.assert_awaited_once()
    circuit.record_failure.assert_not_awaited()
    circuit.record_success.assert_not_awaited()


def _usage_aware_upstream(seen: list[dict]):
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append(body)
        base = {
            "id": "chat_usage",
            "object": "chat.completion.chunk",
            "created": 1,
            "model": "gpt-5.6-luna",
        }
        events = [
            {
                **base,
                "choices": [
                    {"index": 0, "delta": {"content": "ok"}, "finish_reason": "stop"}
                ],
            },
        ]
        if (body.get("stream_options") or {}).get("include_usage") is True:
            events.append(
                {
                    **base,
                    "choices": [],
                    "usage": {
                        "prompt_tokens": 61,
                        "completion_tokens": 9,
                        "total_tokens": 70,
                    },
                }
            )
        content = (
            "".join(f"data: {json.dumps(event)}\n\n" for event in events)
            + "data: [DONE]\n\n"
        )
        return httpx.Response(
            200, text=content, headers={"content-type": "text/event-stream"}
        )

    return handler


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("client_options", "upstream_options", "client_asked"),
    [
        (None, {"include_usage": True}, False),
        ({"include_usage": True}, {"include_usage": True}, True),
        ({"include_usage": False}, {"include_usage": True}, False),
        (
            {"include_obfuscation": False},
            {"include_obfuscation": False, "include_usage": True},
            False,
        ),
    ],
)
async def test_chat_streams_are_metered_from_provider_usage(
    client_options: dict | None, upstream_options: dict, client_asked: bool
) -> None:
    seen: list[dict] = []
    events = StringIO()
    upstream = httpx.AsyncClient(
        transport=httpx.MockTransport(_usage_aware_upstream(seen))
    )
    application = create_community_app(
        CommunitySettings(
            OPENAI_BASE_URL="https://upstream.test/v1",
            BACKEND_CORS_ORIGINS=[],
            _env_file=None,
        ),
        http_client=upstream,
        event_stream=events,
    )
    body = {
        "model": "gpt-5.6-luna",
        "stream": True,
        "messages": [{"role": "user", "content": "hello"}],
        **({"stream_options": client_options} if client_options is not None else {}),
    }
    async with (
        application.router.lifespan_context(application),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application),
            base_url="http://127.0.0.1",
        ) as client,
    ):
        response = await client.post(
            "/v1/chat/completions",
            headers={"x-openai-api-key": "sk-provider"},
            json=body,
        )
    await upstream.aclose()

    usage_chunks = [
        line for line in response.text.splitlines() if '"choices":[]' in line
    ]
    event = json.loads(events.getvalue().splitlines()[-1])
    assert seen[0]["stream_options"] == upstream_options
    assert len(usage_chunks) == (1 if client_asked else 0)
    assert (event["prompt_tokens"], event["completion_tokens"]) == (61, 9)
    assert event["estimated"] is False


@pytest.mark.asyncio
async def test_registry_targets_are_not_asked_for_stream_usage() -> None:
    seen: list[dict] = []
    prepared = _prepared(
        {"model": "gpt-5.6-luna", "messages": [], "stream": True},
        tenant="11111111-1111-1111-1111-111111111111",
        protocol="chat",
    )
    prepared.target = ProviderTarget(
        deployment_id="deployment",
        base_url="https://registry.test/v1",
        upstream_model="gpt-5.6-luna",
        credential_reference="managed-reference",
        timeout_seconds=30.0,
        declared_version="1",
    )
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(_usage_aware_upstream(seen))
    ) as http:
        execution = OpenAIExecution(
            credential_resolver=SimpleNamespace(
                resolve=AsyncMock(return_value="sk-registry")
            ),
            circuit=InMemoryCircuitBreaker(),
            settings=settings,
            http_client=http,
            chain_store=SimpleNamespace(save=AsyncMock()),
        )
        result = await execution.execute(
            invocation=SimpleNamespace(db=object(), provider_credential=None),
            prepared=prepared,
            provider_start_callback=AsyncMock(),
        )
        assert isinstance(result, ProviderStream)
        [chunk async for chunk in result.events]

    assert "stream_options" not in seen[0]


def _recording_circuit() -> SimpleNamespace:
    return SimpleNamespace(
        acquire_call=AsyncMock(return_value=True),
        record_success=AsyncMock(),
        record_failure=AsyncMock(),
        release_probe=AsyncMock(),
    )


@pytest.mark.asyncio
async def test_circuit_for_is_asked_once_and_serves_the_whole_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "OPENAI_BASE_URL", "https://upstream.test/v1")
    chunk = {
        "id": "chat_circuit",
        "object": "chat.completion.chunk",
        "created": 1,
        "model": "gpt-5.6-luna",
        "choices": [{"index": 0, "delta": {"content": "ok"}, "finish_reason": "stop"}],
    }

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text=f"data: {json.dumps(chunk)}\n\ndata: [DONE]\n\n",
            headers={"content-type": "text/event-stream"},
        )

    circuit = _recording_circuit()
    circuit_for = Mock(return_value=circuit)
    prepared = _prepared(
        {"model": "gpt-5.6-luna", "messages": [], "stream": True},
        tenant="11111111-1111-1111-1111-111111111111",
        protocol="chat",
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        result = await OpenAIExecution(
            credential_resolver=EnvironmentProviderCredentialResolver("openai", {}),
            circuit_for=circuit_for,
            settings=settings,
            http_client=http,
            chain_store=SimpleNamespace(save=AsyncMock()),
        ).execute(
            invocation=SimpleNamespace(
                db=object(),
                provider_credential=EphemeralProviderCredential("openai", "sk-key"),
            ),
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
        OpenAIExecution(
            credential_resolver=EnvironmentProviderCredentialResolver("openai", {}),
            settings=settings,
            http_client=SimpleNamespace(),  # type: ignore[arg-type]
            chain_store=SimpleNamespace(save=AsyncMock()),
            **circuits,
        )
