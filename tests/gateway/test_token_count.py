"""Anthropic token counting shares auth/privacy but never the inference ledger."""

import io
import json
from unittest.mock import AsyncMock

import httpx
import pytest
from anthropic import AsyncAnthropic, AuthenticationError

from shim.application import create_community_app
from shim.core.community_config import CommunitySettings


@pytest.mark.asyncio
@pytest.mark.parametrize("beta", [False, True])
async def test_native_token_count_scrubs_and_does_not_execute_or_settle(beta):
    calls = []

    def upstream(request):
        calls.append(request)
        assert request.url.path == "/v1/messages/count_tokens"
        assert request.headers["x-api-key"] == "provider-secret"
        assert "alice@example.com" not in request.content.decode()
        assert json.loads(request.content)["messages"][0]["role"] == "user"
        return httpx.Response(
            200, json={"input_tokens": 17}, headers={"request-id": "count-1"}
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(upstream)) as outbound:
        app = create_community_app(
            CommunitySettings(_env_file=None, SHIM_API_KEY="gateway-secret-12345"),
            http_client=outbound,
            event_stream=io.StringIO(),
        )
        async with app.router.lifespan_context(app):
            usage = AsyncMock()
            app.state.gateway_service.kernel.usage = usage
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app)) as inbound:
                sdk = AsyncAnthropic(
                    api_key="gateway-secret-12345",
                    base_url="http://shim.test",
                    http_client=inbound,
                    max_retries=0,
                    default_headers={"x-provider-key": "provider-secret"},
                )
                messages = sdk.beta.messages if beta else sdk.messages
                result = await messages.count_tokens(
                    model="claude-sonnet-4-6",
                    messages=[{"role": "user", "content": "Contact alice@example.com"}],
                )
                assert result.input_tokens == 17
                assert result._request_id == "count-1"
                sdk.api_key = "invalid"
                with pytest.raises(AuthenticationError):
                    await sdk.messages.count_tokens(
                        model="claude-sonnet-4-6", messages=[]
                    )
    assert len(calls) == 1
    assert [call.args[1] for call in usage.record_token_count.await_args_list] == [
        None,
        17,
    ]
    for name in (
        "admit",
        "record_privacy",
        "reserve_provider_spend",
        "mark_provider_started",
        "finalize",
        "fail",
    ):
        getattr(usage, name).assert_not_awaited()


@pytest.mark.asyncio
async def test_token_count_errors_are_native_sanitized_and_never_retried():
    calls = []

    def upstream(request):
        calls.append(request)
        return httpx.Response(
            500,
            json={
                "type": "error",
                "error": {
                    "type": "api_error",
                    "message": "provider-secret alice@example.com",
                },
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(upstream)) as outbound:
        app = create_community_app(
            CommunitySettings(_env_file=None, SHIM_API_KEY="gateway-secret-12345"),
            http_client=outbound,
            event_stream=io.StringIO(),
        )
        async with app.router.lifespan_context(app):
            usage = AsyncMock()
            app.state.gateway_service.kernel.usage = usage
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app), base_url="http://shim.test"
            ) as inbound:
                headers = {
                    "x-api-key": "gateway-secret-12345",
                    "x-provider-key": "provider-secret",
                }
                payload = {"model": "claude-sonnet-4-6", "messages": []}
                failed = await inbound.post(
                    "/v1/messages/count_tokens", headers=headers, json=payload
                )
                invalid = await inbound.post(
                    "/v1/messages/count_tokens",
                    headers=headers,
                    json={**payload, "stream": True},
                )
    assert len(calls) == 1
    assert failed.status_code == 500
    assert failed.json()["type"] == "error"
    assert (
        "provider-secret" not in failed.text and "alice@example.com" not in failed.text
    )
    assert invalid.status_code == 422 and invalid.json()["type"] == "error"
    usage.admit.assert_not_awaited()
    usage.finalize.assert_not_awaited()


@pytest.mark.asyncio
async def test_token_count_does_not_consume_message_repeat_allowance():
    def upstream(request):
        if request.url.path.endswith("/count_tokens"):
            return httpx.Response(200, json={"input_tokens": 2})
        return httpx.Response(
            200,
            json={
                "id": "msg_test",
                "type": "message",
                "role": "assistant",
                "model": "claude-sonnet-4-6",
                "content": [],
                "stop_reason": "end_turn",
                "stop_sequence": None,
                "usage": {"input_tokens": 2, "output_tokens": 0},
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(upstream)) as outbound:
        app = create_community_app(
            CommunitySettings(
                _env_file=None, SHIM_API_KEY="gateway-secret-12345", LOOP_REPEAT_LIMIT=2
            ),
            http_client=outbound,
            event_stream=io.StringIO(),
        )
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app),
                base_url="http://shim.test",
                headers={
                    "x-api-key": "gateway-secret-12345",
                    "x-provider-key": "provider-secret",
                },
            ) as inbound:
                payload = {
                    "model": "claude-sonnet-4-6",
                    "messages": [{"role": "user", "content": "hello"}],
                }
                counted = await inbound.post("/v1/messages/count_tokens", json=payload)
                generated = await inbound.post(
                    "/v1/messages", json={**payload, "max_tokens": 10}
                )
                repeated = await inbound.post(
                    "/v1/messages", json={**payload, "max_tokens": 10}
                )
    assert counted.status_code == generated.status_code == 200
    assert repeated.status_code == 429
