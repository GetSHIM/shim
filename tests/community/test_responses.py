from __future__ import annotations

from io import StringIO
import json

import httpx
from openai import APIStatusError, AsyncOpenAI
import pytest

import shim.application as community_module
from shim.application import create_community_app
from shim.core.community_config import CommunitySettings


MODEL = "gpt-5.6-luna"
GATEWAY_KEY = "shim-gateway-key-123"
PROVIDER_KEY = "sk-provider-secret-123"
EMAIL = "alice@example.com"


def _settings() -> CommunitySettings:
    return CommunitySettings(
        OPENAI_BASE_URL="https://upstream.test/v1",
        BACKEND_CORS_ORIGINS=[],
        SHIM_API_KEY=GATEWAY_KEY,
        _env_file=None,
    )


def _response(response_id: str, text: str = "") -> dict[str, object]:
    output: list[dict[str, object]] = []
    if text:
        output.append(
            {
                "id": f"msg_{response_id}",
                "type": "message",
                "status": "completed",
                "role": "assistant",
                "content": [
                    {
                        "type": "output_text",
                        "text": text,
                        "annotations": [],
                        "logprobs": [],
                    }
                ],
            }
        )
    return {
        "id": response_id,
        "object": "response",
        "created_at": 1.0,
        "status": "completed",
        "model": MODEL,
        "output": output,
        "parallel_tool_calls": True,
        "tool_choice": "auto",
        "tools": [],
        "usage": {
            "input_tokens": 1,
            "input_tokens_details": {
                "cached_tokens": 0,
                "cache_write_tokens": 0,
            },
            "output_tokens": 1,
            "output_tokens_details": {"reasoning_tokens": 0},
            "total_tokens": 2,
        },
    }


@pytest.mark.asyncio
async def test_responses_json_uses_one_sanitized_provider_request() -> None:
    attempts: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(request)
        payload = json.loads(request.content)
        safe_input = payload["input"]
        assert isinstance(safe_input, str)
        assert EMAIL not in safe_input
        return httpx.Response(
            200,
            json=_response("resp_json", f"Received {safe_input}"),
        )

    upstream = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    application = create_community_app(
        _settings(),
        http_client=upstream,
        event_stream=StringIO(),
    )
    async with application.router.lifespan_context(application):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application),
            base_url="http://shim.test",
        ) as gateway_http:
            client = AsyncOpenAI(
                api_key=GATEWAY_KEY,
                base_url="http://shim.test/v1",
                http_client=gateway_http,
                max_retries=0,
            )
            response = await client.responses.create(
                model=MODEL,
                input=f"Contact {EMAIL}",
                extra_headers={"x-provider-key": PROVIDER_KEY},
            )

    assert response.id == "resp_json"
    assert response.output_text == f"Received Contact {EMAIL}"
    assert len(attempts) == 1
    assert attempts[0].headers["authorization"] == f"Bearer {PROVIDER_KEY}"
    assert "x-provider-key" not in attempts[0].headers
    assert GATEWAY_KEY not in str(dict(attempts[0].headers))
    assert upstream.is_closed is False
    await upstream.aclose()


@pytest.mark.asyncio
async def test_responses_stream_preserves_named_events_and_finalizes_once() -> None:
    attempts = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        assert json.loads(request.content)["stream"] is True
        response = _response("resp_stream")
        events = [
            {
                "type": "response.created",
                "response": {**response, "status": "in_progress"},
                "sequence_number": 0,
            },
            {
                "type": "response.output_text.delta",
                "item_id": "msg_stream",
                "output_index": 0,
                "content_index": 0,
                "delta": "ok",
                "sequence_number": 1,
                "logprobs": [],
            },
            {
                "type": "response.completed",
                "response": response,
                "sequence_number": 2,
            },
        ]
        wire = "".join(
            f"event: {event['type']}\ndata: {json.dumps(event)}\n\n" for event in events
        )
        return httpx.Response(
            200,
            content=wire,
            headers={"content-type": "text/event-stream"},
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
                "/v1/responses",
                headers={
                    "authorization": f"Bearer {GATEWAY_KEY}",
                    "x-provider-key": PROVIDER_KEY,
                },
                json={"model": MODEL, "input": "hello", "stream": True},
            )

    event_names = [
        line.removeprefix("event: ")
        for line in response.text.splitlines()
        if line.startswith("event: ")
    ]
    sequence_numbers = [
        json.loads(line.removeprefix("data: "))["sequence_number"]
        for line in response.text.splitlines()
        if line.startswith("data: ")
    ]
    assert event_names == [
        "response.created",
        "response.output_text.delta",
        "response.completed",
    ]
    assert sequence_numbers == [0, 1, 2]
    assert "[DONE]" not in response.text
    assert attempts == 1
    lines = terminal_events.getvalue().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["outcome"] == "completed"
    await upstream.aclose()


@pytest.mark.asyncio
async def test_responses_continuation_is_restored_and_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(community_module, "_LOCAL_STATE_CAPACITY", 1)
    upstream_payloads: list[dict[str, object]] = []
    placeholder = ""

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal placeholder
        payload = json.loads(request.content)
        upstream_payloads.append(payload)
        safe_input = payload["input"]
        assert isinstance(safe_input, str)
        assert EMAIL not in safe_input
        if len(upstream_payloads) == 1:
            placeholder = safe_input
            return httpx.Response(200, json=_response("resp_parent", safe_input))
        assert payload["previous_response_id"] == "resp_parent"
        assert safe_input == placeholder
        return httpx.Response(200, json=_response("resp_child", safe_input))

    upstream = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    application = create_community_app(
        _settings(),
        http_client=upstream,
        event_stream=StringIO(),
    )
    async with application.router.lifespan_context(application):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application),
            base_url="http://shim.test",
        ) as gateway_http:
            client = AsyncOpenAI(
                api_key=GATEWAY_KEY,
                base_url="http://shim.test/v1",
                http_client=gateway_http,
                max_retries=0,
            )
            parent = await client.responses.create(
                model=MODEL,
                input=EMAIL,
                extra_headers={"x-provider-key": PROVIDER_KEY},
            )
            child = await client.responses.create(
                model=MODEL,
                input=EMAIL,
                previous_response_id=parent.id,
                extra_headers={"x-provider-key": PROVIDER_KEY},
            )
            with pytest.raises(APIStatusError) as failure:
                await client.responses.create(
                    model=MODEL,
                    input="must not reach the provider",
                    previous_response_id=parent.id,
                    extra_headers={"x-provider-key": PROVIDER_KEY},
                )

    assert parent.output_text == EMAIL
    assert child.output_text == EMAIL
    assert failure.value.status_code == 503
    assert len(upstream_payloads) == 2
    await upstream.aclose()
