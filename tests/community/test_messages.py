from __future__ import annotations

from io import StringIO
import json

from anthropic import AsyncAnthropic
import httpx
import pytest

from shim.application import create_community_app
from shim.core.community_config import CommunitySettings


MODEL = "claude-sonnet-4-6"
GATEWAY_KEY = "shim-gateway-key-123"
PROVIDER_KEY = "sk-ant-provider-secret-123"
EMAIL = "alice@example.com"


def _settings() -> CommunitySettings:
    return CommunitySettings(
        ANTHROPIC_BASE_URL="https://upstream.test",
        BACKEND_CORS_ORIGINS=[],
        SHIM_API_KEY=GATEWAY_KEY,
        _env_file=None,
    )


def _message(message_id: str, text: str) -> dict[str, object]:
    return {
        "id": message_id,
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": text}],
        "model": MODEL,
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 1, "output_tokens": 2},
    }


@pytest.mark.asyncio
async def test_messages_json_uses_gateway_key_only_for_gateway_auth() -> None:
    attempts: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(request)
        payload = json.loads(request.content)
        safe_content = payload["messages"][0]["content"]
        assert isinstance(safe_content, str)
        assert EMAIL not in safe_content
        return httpx.Response(
            200,
            json=_message("msg_json", f"Received {safe_content}"),
            headers={"request-id": "req_json"},
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
            client = AsyncAnthropic(
                api_key=GATEWAY_KEY,
                base_url="http://shim.test",
                http_client=gateway_http,
                max_retries=0,
            )
            message = await client.messages.create(
                model=MODEL,
                max_tokens=32,
                messages=[{"role": "user", "content": f"Contact {EMAIL}"}],
                extra_headers={"x-provider-key": PROVIDER_KEY},
            )

    assert message.id == "msg_json"
    content = message.content[0]
    assert content.type == "text"
    assert content.text == f"Received Contact {EMAIL}"
    assert len(attempts) == 1
    assert attempts[0].headers["x-api-key"] == PROVIDER_KEY
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

    async def __aiter__(self):
        for index in range(0, len(self.content), 11):
            yield self.content[index : index + 11]

    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_messages_beta_stream_preserves_native_events_and_finalizes_once() -> (
    None
):
    attempts: list[httpx.Request] = []
    provider_stream: _SplitStream | None = None
    placeholder = ""

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal placeholder, provider_stream
        attempts.append(request)
        payload = json.loads(request.content)
        placeholder = payload["messages"][0]["content"]
        assert isinstance(placeholder, str)
        assert EMAIL not in placeholder
        split = len(placeholder) // 2
        events = [
            {
                "type": "message_start",
                "message": {
                    **_message("msg_stream", ""),
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
        wire = "".join(
            f"event: {event['type']}\ndata: {json.dumps(event)}\n\n" for event in events
        ).encode()
        provider_stream = _SplitStream(wire)
        return httpx.Response(
            200,
            stream=provider_stream,
            headers={
                "content-type": "text/event-stream",
                "request-id": "req_stream",
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
            client = AsyncAnthropic(
                api_key=GATEWAY_KEY,
                base_url="http://shim.test",
                http_client=gateway_http,
                max_retries=0,
            )
            stream = await client.beta.messages.create(
                model=MODEL,
                max_tokens=32,
                messages=[{"role": "user", "content": EMAIL}],
                stream=True,
                betas=["feature-a"],
                extra_headers={"x-provider-key": PROVIDER_KEY},
            )
            events = [
                event.model_dump(mode="json", exclude_unset=True)
                async for event in stream
            ]

    assert [event["type"] for event in events] == [
        "message_start",
        "content_block_start",
        "content_block_delta",
        "content_block_delta",
        "content_block_stop",
        "message_delta",
        "message_stop",
    ]
    text = "".join(
        event["delta"]["text"]
        for event in events
        if event["type"] == "content_block_delta"
    )
    assert text == EMAIL
    assert len(attempts) == 1
    assert attempts[0].url.query == b"beta=true"
    assert attempts[0].headers["anthropic-beta"] == "feature-a"
    assert attempts[0].headers["x-api-key"] == PROVIDER_KEY
    assert "x-provider-key" not in attempts[0].headers
    assert GATEWAY_KEY not in str(dict(attempts[0].headers))
    assert provider_stream is not None and provider_stream.closed is True
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
