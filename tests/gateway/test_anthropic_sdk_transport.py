from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID

import httpx
import pytest
from pydantic import ValidationError

import shim.gateway.pipeline.anthropic_execution as anthropic_execution
from shim.api.v1.messages import MessagesRequest
from shim.core.circuit_breaker import InMemoryCircuitBreaker
from shim.core.community_config import CommunitySettings
from shim.gateway.contracts.ids import TenantId
from shim.gateway.pipeline.anthropic_execution import AnthropicExecution
from shim.gateway.pipeline.privacy import scrub_payload
from shim.gateway.pipeline.provider_execution import (
    ProviderCallError,
    ProviderNonStream,
    ProviderStream,
)
from shim.privacy.deanonymizer import AnthropicStreamRestorer, restore_anthropic_payload
from shim.privacy.pii_scrubber import PIIScrubberService
from shim.privacy.policies import PrivacyAction, PrivacyOutcome
from shim.secrets.credentials import (
    EnvironmentProviderCredentialResolver,
    EphemeralProviderCredential,
)


settings = CommunitySettings(_env_file=None)


def _prepared(payload: dict, mapping: dict[str, str] | None = None):
    return SimpleNamespace(
        payload=payload,
        tenant_id=TenantId(UUID("11111111-1111-1111-1111-111111111111")),
        stream=bool(payload.get("stream")),
        privacy=PrivacyOutcome(
            action=PrivacyAction.SCRUBBED if mapping else PrivacyAction.DISABLED,
            pii_detected=bool(mapping),
            verification_map=mapping or {},
        ),
    )


def _execution(http_client: httpx.AsyncClient) -> AnthropicExecution:
    return AnthropicExecution(
        credential_resolver=EnvironmentProviderCredentialResolver("anthropic", {}),
        circuit=InMemoryCircuitBreaker(),
        settings=settings,
        http_client=http_client,
    )


def _invocation(key: str = "sk-ant-tenant") -> SimpleNamespace:
    return SimpleNamespace(
        db=object(),
        provider_credential=EphemeralProviderCredential("anthropic", key),
    )


def _message(text: str) -> dict:
    return {
        "id": "msg_native",
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": text}],
        "model": "claude-sonnet-4-5",
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 1, "output_tokens": 2},
    }


def test_messages_request_preserves_provider_fields_and_validates_routing() -> None:
    request = MessagesRequest.model_validate(
        {
            "model": "claude-sonnet-4-5",
            "max_tokens": 32,
            "messages": [{"role": "user", "content": "hello"}],
            "user_profile_id": "profile_1",
            "future_field": {"enabled": True},
        }
    )
    assert request.provider_payload()["user_profile_id"] == "profile_1"
    assert request.provider_payload()["future_field"] == {"enabled": True}

    with pytest.raises(ValidationError):
        MessagesRequest.model_validate(
            {
                "model": "claude-sonnet-4-5",
                "max_tokens": -1,
                "messages": [{"role": "user", "content": "hello"}],
            }
        )


def test_restoration_never_changes_anthropic_protocol_metadata() -> None:
    scrubber = PIIScrubberService()
    placeholder, mapping = scrubber.scrub("alice@example.com")
    restored = restore_anthropic_payload(
        {
            "type": placeholder,
            "id": placeholder,
            "name": placeholder,
            "metadata": {"value": placeholder},
            "content": [
                {
                    "type": "text",
                    "text": placeholder,
                    "input": {"email": placeholder, "id": placeholder},
                }
            ],
        },
        mapping,
        scrubber,
    )

    assert restored["type"] == placeholder
    assert restored["id"] == placeholder
    assert restored["name"] == placeholder
    assert restored["metadata"] == {"value": placeholder}
    assert restored["content"][0]["text"] == "alice@example.com"
    assert restored["content"][0]["input"] == {
        "email": "alice@example.com",
        "id": "alice@example.com",
    }


def test_anthropic_scrubbing_preserves_valid_protocol_fields_and_covers_native_tools() -> (
    None
):
    scrubber = PIIScrubberService()
    email = "alice@example.com"
    safe, mapping = scrub_payload(
        {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_1",
                            "name": "lookup",
                            "input": {"id": email},
                        },
                        {
                            "type": "tool_result",
                            "tool_use_id": "toolu_1",
                            "content": email,
                        },
                    ],
                }
            ],
            "stop_sequences": [email],
            "tools": [
                {
                    "type": "web_search_20250305",
                    "name": "web_search",
                    "user_location": {"city": email},
                },
                {
                    "name": "lookup",
                    "input_schema": {"default": email},
                },
            ],
        },
        None,
        scrubber,
    )

    blocks = safe["messages"][0]["content"]
    assert blocks[0]["id"] == "toolu_1"
    assert blocks[0]["name"] == "lookup"
    assert blocks[1]["tool_use_id"] == "toolu_1"
    assert blocks[0]["input"]["id"] != email
    assert blocks[1]["content"] != email
    assert safe["tools"][0]["user_location"]["city"] != email
    assert safe["tools"][1]["input_schema"]["default"] != email
    assert (
        restore_anthropic_payload(
            {"stop_sequence": safe["stop_sequences"][0]}, mapping, scrubber
        )["stop_sequence"]
        == email
    )


def test_stream_restoration_flushes_a_literal_placeholder_prefix() -> None:
    scrubber = PIIScrubberService()
    placeholder, mapping = scrubber.scrub("alice@example.com")
    prefix = placeholder[:8]
    restorer = AnthropicStreamRestorer(mapping, scrubber)

    delta = restorer.restore_events(
        {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": prefix},
        }
    )
    stopped = restorer.restore_events({"type": "content_block_stop", "index": 0})

    assert delta[0]["delta"]["text"] == ""
    assert stopped[0]["delta"]["text"] == prefix
    assert stopped[1] == {"type": "content_block_stop", "index": 0}


@pytest.mark.asyncio
async def test_nonstream_uses_native_sdk_and_restores_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "ANTHROPIC_BASE_URL", "https://upstream.test")
    scrubber = PIIScrubberService()
    placeholder, mapping = scrubber.scrub("alice@example.com")
    seen: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.update(
            {
                "url": str(request.url),
                "key": request.headers["x-api-key"],
                "version": request.headers["anthropic-version"],
                "profile": request.headers["anthropic-user-profile-id"],
                "headers": dict(request.headers),
                "body": json.loads(request.content),
            }
        )
        return httpx.Response(
            200,
            json=_message(f"hello {placeholder}"),
            headers={"request-id": "req_upstream"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        credential = EphemeralProviderCredential("anthropic", "sk-ant-tenant")
        result = await _execution(http).execute(
            invocation=SimpleNamespace(
                db=object(),
                provider_credential=credential,
                headers={
                    "Authorization": "Bearer attacker",
                    "Cookie": "session=secret",
                    "Host": "attacker.test",
                    "Content-Length": "999",
                    "Anthropic-Version": "2025-01-01",
                    "Anthropic-User-Profile-Id": "attacker-profile",
                    "X-Shim-Key": "shim-secret",
                    "X-Arbitrary": "drop-me",
                },
            ),
            prepared=_prepared(
                {
                    "model": "claude-sonnet-4-5",
                    "max_tokens": 32,
                    "messages": [{"role": "user", "content": placeholder}],
                    "user_profile_id": "profile_1",
                    "future_field": {"enabled": True},
                    "timeout": 0,
                    "extra_headers": {"x-unsafe": "body-only"},
                    "extra_query": {"unsafe": "body-only"},
                    "extra_body": {"nested": "body-only"},
                },
                mapping,
            ),
            provider_start_callback=AsyncMock(),
        )

        assert isinstance(result, ProviderNonStream)
        assert result.request_id == "req_upstream"
        assert result.payload["content"][0]["text"] == "hello alice@example.com"
        assert seen["url"] == "https://upstream.test/v1/messages"
        assert seen["key"] == "sk-ant-tenant"
        assert seen["version"] == "2025-01-01"
        assert seen["profile"] == "profile_1"
        assert seen["body"] == {
            "model": "claude-sonnet-4-5",
            "max_tokens": 32,
            "messages": [{"role": "user", "content": placeholder}],
            "future_field": {"enabled": True},
            "timeout": 0,
            "extra_headers": {"x-unsafe": "body-only"},
            "extra_query": {"unsafe": "body-only"},
            "extra_body": {"nested": "body-only"},
        }
        headers = seen["headers"]
        assert isinstance(headers, dict)
        assert headers["host"] == "upstream.test"
        assert headers["content-length"] != "999"
        assert "authorization" not in headers
        assert "cookie" not in headers
        assert "x-shim-key" not in headers
        assert "x-arbitrary" not in headers
        assert credential.available() is False
        assert http.is_closed is False


@pytest.mark.asyncio
async def test_beta_header_selects_beta_sdk_and_parses_betas(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}

    async def beta_create(
        *,
        model,
        max_tokens,
        messages,
        betas=None,
        extra_headers=None,
        extra_body=None,
    ):
        seen.update(
            model=model,
            max_tokens=max_tokens,
            messages=messages,
            betas=betas,
            extra_headers=extra_headers,
            extra_body=extra_body,
        )
        return SimpleNamespace(
            _request_id="req_beta",
            model_dump=lambda **_kwargs: _message("beta response"),
        )

    regular_create = AsyncMock(side_effect=AssertionError("regular SDK path used"))
    monkeypatch.setattr(
        anthropic_execution,
        "AsyncAnthropic",
        lambda **_kwargs: SimpleNamespace(
            messages=SimpleNamespace(create=regular_create),
            beta=SimpleNamespace(messages=SimpleNamespace(create=beta_create)),
        ),
    )

    async with httpx.AsyncClient() as http:
        result = await _execution(http).execute(
            invocation=SimpleNamespace(
                db=object(),
                provider_credential=EphemeralProviderCredential(
                    "anthropic", "sk-ant-beta"
                ),
                headers={
                    "Anthropic-Beta": "feature-a, feature-b ,feature-c",
                    "Authorization": "Bearer attacker",
                },
                metadata=SimpleNamespace(query_params=()),
            ),
            prepared=_prepared(
                {
                    "model": "claude-sonnet-4-5",
                    "max_tokens": 32,
                    "messages": [{"role": "user", "content": "hello"}],
                    "betas": ["body-only"],
                    "future_beta_field": True,
                }
            ),
            provider_start_callback=AsyncMock(),
        )

    assert isinstance(result, ProviderNonStream)
    assert result.payload["content"][0]["text"] == "beta response"
    assert seen["betas"] == ["feature-a", "feature-b", "feature-c"]
    assert seen["extra_headers"] == {
        "anthropic-beta": "feature-a, feature-b ,feature-c"
    }
    assert seen["extra_body"] == {
        "betas": ["body-only"],
        "future_beta_field": True,
    }
    regular_create.assert_not_awaited()


@pytest.mark.asyncio
async def test_beta_query_stream_preserves_beta_models_and_future_body_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "ANTHROPIC_BASE_URL", "https://upstream.test")
    events = [
        {
            "type": "message_start",
            "message": {
                **_message(""),
                "content": [],
                "container": {
                    "id": "container_1",
                    "expires_at": "2026-08-11T12:00:00Z",
                },
                "usage": {"input_tokens": 1, "output_tokens": 0},
            },
        },
        {"type": "message_stop"},
    ]
    seen: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            content="".join(
                f"event: {event['type']}\ndata: {json.dumps(event)}\n\n"
                for event in events
            ),
            headers={"content-type": "text/event-stream"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        result = await _execution(http).execute(
            invocation=SimpleNamespace(
                db=object(),
                provider_credential=EphemeralProviderCredential(
                    "anthropic", "sk-ant-beta"
                ),
                headers={},
                metadata=SimpleNamespace(query_params=(("beta", "true"),)),
            ),
            prepared=_prepared(
                {
                    "model": "claude-sonnet-4-5",
                    "max_tokens": 32,
                    "messages": [{"role": "user", "content": "hello"}],
                    "stream": True,
                    "speed": "fast",
                    "future_beta_field": {"enabled": True},
                    "timeout": 0,
                }
            ),
            provider_start_callback=AsyncMock(),
        )
        assert isinstance(result, ProviderStream)
        wire = b"".join([chunk async for chunk in result.events])

    assert seen["url"] == "https://upstream.test/v1/messages?beta=true"
    assert seen["body"] == {
        "model": "claude-sonnet-4-5",
        "max_tokens": 32,
        "messages": [{"role": "user", "content": "hello"}],
        "stream": True,
        "speed": "fast",
        "future_beta_field": {"enabled": True},
        "timeout": 0,
    }
    assert b'"container":{"id":"container_1"' in wire
    assert b'event: message_stop\ndata: {"type":"message_stop"}\n\n' in wire


@pytest.mark.asyncio
async def test_stream_preserves_native_sse_and_split_privacy_placeholders(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "ANTHROPIC_BASE_URL", "https://upstream.test")
    scrubber = PIIScrubberService()
    placeholder, mapping = scrubber.scrub("alice@example.com")
    split = len(placeholder) // 2
    events = [
        {
            "type": "message_start",
            "message": {
                **_message(""),
                "content": [],
                "stop_reason": None,
                "usage": {"input_tokens": 1, "output_tokens": 0},
            },
        },
        {
            "type": "content_block_start",
            "index": 0,
            "content_block": {"type": "text", "text": ""},
        },
        {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": placeholder[:split]},
        },
        {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": placeholder[split:]},
        },
        {"type": "content_block_stop", "index": 0},
        {
            "type": "message_delta",
            "delta": {"stop_reason": "end_turn", "stop_sequence": None},
            "usage": {"output_tokens": 2},
        },
        {"type": "message_stop"},
    ]
    sse = "".join(
        f"event: {event['type']}\ndata: {json.dumps(event, separators=(',', ':'))}\n\n"
        for event in events
    ).encode()

    class TrackingStream(httpx.AsyncByteStream):
        closed = False

        async def __aiter__(self):
            yield sse

        async def aclose(self) -> None:
            self.closed = True

    source = TrackingStream()

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            stream=source,
            headers={
                "content-type": "text/event-stream",
                "request-id": "req_stream",
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
                {
                    "model": "claude-sonnet-4-5",
                    "max_tokens": 32,
                    "messages": [{"role": "user", "content": "hello"}],
                    "stream": True,
                },
                mapping,
            ),
            provider_start_callback=AsyncMock(),
        )
        assert isinstance(result, ProviderStream)
        wire = b"".join([chunk async for chunk in result.events])

        assert result.request_id == "req_stream"
        assert b"alice@example.com" in wire
        assert placeholder.encode() not in wire
        assert wire.count(b"event: content_block_delta\n") == 2
        assert wire.endswith(b'event: message_stop\ndata: {"type":"message_stop"}\n\n')
        assert b"[DONE]" not in wire
        assert source.closed is True
        assert http.is_closed is False
    execution.circuit.record_success.assert_awaited_once()
    execution.circuit.record_failure.assert_not_awaited()


@pytest.mark.asyncio
async def test_sdk_does_not_retry_or_expose_anthropic_error_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "ANTHROPIC_BASE_URL", "https://upstream.test")
    attempts = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(
            500,
            json={
                "type": "error",
                "error": {
                    "type": "api_error",
                    "message": "alice@example.com upstream detail",
                },
            },
            headers={"request-id": "req_failure"},
        )

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
                invocation=_invocation("sk-ant-secret"),
                prepared=_prepared(
                    {
                        "model": "claude-sonnet-4-5",
                        "max_tokens": 32,
                        "messages": [{"role": "user", "content": "hello"}],
                    }
                ),
                provider_start_callback=AsyncMock(),
            )

    assert attempts == 1
    assert error.value.provider == "anthropic"
    assert error.value.request_id == "req_failure"
    assert str(error.value) == "PROVIDER_UNAVAILABLE"
    assert "alice@example.com" not in repr(error.value)
    assert "sk-ant-secret" not in repr(error.value)
    execution.circuit.record_failure.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "provider_error",
    [
        "alice@example.com upstream detail",
        {"type": "api_error", "message": "alice@example.com upstream detail"},
    ],
)
async def test_success_status_with_an_error_field_is_not_forwarded(
    monkeypatch: pytest.MonkeyPatch,
    provider_error: object,
) -> None:
    monkeypatch.setattr(settings, "ANTHROPIC_BASE_URL", "https://upstream.test")
    raw_message = "alice@example.com upstream detail"

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                **_message("ignored"),
                "error": provider_error,
            },
            headers={"request-id": "req_malformed"},
        )

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
                    {
                        "model": "claude-sonnet-4-5",
                        "max_tokens": 32,
                        "messages": [{"role": "user", "content": "hello"}],
                    }
                ),
                provider_start_callback=AsyncMock(),
            )

    assert error.value.request_id == "req_malformed"
    assert raw_message not in repr(error.value)
    execution.circuit.record_failure.assert_awaited_once()
    execution.circuit.record_success.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status_code",
    [400, 401, 403, 404, 408, 409, 413, 422, 429, 500, 504, 529],
)
async def test_upstream_status_request_id_and_retry_after_are_preserved(
    monkeypatch: pytest.MonkeyPatch,
    status_code: int,
) -> None:
    monkeypatch.setattr(settings, "ANTHROPIC_BASE_URL", "https://upstream.test")
    attempts = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(
            status_code,
            json={
                "type": "error",
                "error": {"type": "api_error", "message": "private detail"},
            },
            headers={"request-id": "req_matrix", "retry-after": "11"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        with pytest.raises(ProviderCallError) as raised:
            await _execution(http).execute(
                invocation=_invocation(),
                prepared=_prepared(
                    {
                        "model": "claude-sonnet-4-5",
                        "max_tokens": 32,
                        "messages": [{"role": "user", "content": "hello"}],
                    }
                ),
                provider_start_callback=AsyncMock(),
            )

    assert attempts == 1
    assert raised.value.status_code == status_code
    assert raised.value.request_id == "req_matrix"
    assert raised.value.retry_after == "11"
    assert "private detail" not in repr(raised.value)
