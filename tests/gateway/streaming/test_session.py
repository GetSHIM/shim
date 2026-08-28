from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from shim.gateway.streaming import StreamMeter, StreamSession
from shim.gateway.pipeline.postprocess import _ManagedStreamingResponse


def _session(finalizer: AsyncMock, *, provider: str = "openai") -> StreamSession:
    return StreamSession(
        meter=StreamMeter(
            provider=provider,
            requested_model="gpt-5.6-luna",
            prompt_tokens_estimated=1,
        ),
        finalizer=finalizer,
        stream_start_recorder=AsyncMock(),
    )


@pytest.mark.asyncio
async def test_native_bytes_finalize_completed_exactly_once() -> None:
    finalizer = AsyncMock(return_value=SimpleNamespace())
    session = _session(finalizer)

    async def events():
        yield b'event: response.output_text.delta\ndata: {"type":"response.output_text.delta","delta":"hi"}\n\n'
        yield b'event: response.completed\ndata: {"type":"response.completed","response":{"usage":{"input_tokens":1,"output_tokens":1}}}\n\n'

    session.bind(events())
    wire = b"".join([chunk async for chunk in session])
    await session.finalize("completed")

    assert b"response.output_text.delta" in wire
    assert session.terminal_status == "completed"
    finalizer.assert_awaited_once()


@pytest.mark.asyncio
async def test_active_stream_refreshes_its_durable_deadline() -> None:
    finalizer = AsyncMock(return_value=SimpleNamespace())
    heartbeat = AsyncMock()
    ticks = iter((0.0, 0.0, 31.0, 31.0))
    session = StreamSession(
        meter=StreamMeter(
            provider="openai",
            requested_model="gpt-5.6-luna",
            prompt_tokens_estimated=1,
        ),
        finalizer=finalizer,
        stream_start_recorder=AsyncMock(),
        stream_heartbeat_recorder=heartbeat,
        heartbeat_interval_seconds=30,
        monotonic_clock=lambda: next(ticks),
    )

    async def events():
        yield b'data: {"choices":[{"delta":{"content":"hi"}}]}\n\n'
        yield b'data: {"choices":[{"finish_reason":"stop"}]}\n\n'
        yield b"data: [DONE]\n\n"

    session.bind(events())
    _ = [chunk async for chunk in session]

    heartbeat.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("provider", "event"),
    [
        (
            "anthropic",
            b'event: message_stop\ndata: {"type":"message_stop"}\n\n',
        ),
        (
            "google",
            b'data: {"candidates":[{"content":{"parts":[{"text":"hi"}]},'
            b'"finishReason":"STOP"}]}\n\n',
        ),
    ],
)
async def test_native_provider_bytes_are_unchanged_and_finalize_completed(
    provider: str,
    event: bytes,
) -> None:
    finalizer = AsyncMock(return_value=SimpleNamespace())
    session = _session(finalizer, provider=provider)

    async def events():
        yield event

    session.bind(events())
    wire = b"".join([chunk async for chunk in session])

    assert wire == event
    assert session.terminal_status == "completed"
    finalizer.assert_awaited_once()


@pytest.mark.asyncio
async def test_google_eof_without_terminal_event_is_provider_error() -> None:
    finalizer = AsyncMock(return_value=SimpleNamespace())
    session = _session(finalizer, provider="google")

    async def events():
        yield b'data: {"candidates":[{"content":{"parts":[{"text":"hi"}]}}]}\n\n'

    session.bind(events())
    _ = [chunk async for chunk in session]

    assert session.terminal_status == "provider_error"


@pytest.mark.asyncio
async def test_sanitized_stream_error_finalizes_as_provider_error() -> None:
    finalizer = AsyncMock(return_value=SimpleNamespace())
    session = _session(finalizer)

    async def events():
        yield b'event: error\ndata: {"type":"error","error":{"code":"PROVIDER_UNAVAILABLE"}}\n\n'

    session.bind(events())
    _ = [chunk async for chunk in session]

    terminal = finalizer.await_args.args[0]
    assert terminal.terminal_status == "provider_error"
    assert terminal.error_code == "PROVIDER_STREAM_ERROR"


@pytest.mark.asyncio
async def test_unconsumed_stream_is_closed_and_finalized_as_disconnect() -> None:
    finalizer = AsyncMock(return_value=SimpleNamespace())
    provider_stream = SimpleNamespace(aclose=AsyncMock())
    session = _session(finalizer)
    session.bind(provider_stream)

    await session.aclose()

    provider_stream.aclose.assert_awaited_once()
    assert finalizer.await_args.args[0].terminal_status == "client_disconnected"


@pytest.mark.asyncio
async def test_unconsumed_prefetched_usage_uses_explicit_provider_closer() -> None:
    finalizer = AsyncMock(return_value=SimpleNamespace())
    closer = AsyncMock()
    event = (
        b'data: {"candidates":[{"finishReason":"STOP"}],"usageMetadata":'
        b'{"promptTokenCount":2,"candidatesTokenCount":3,"totalTokenCount":5}}\n\n'
    )
    session = _session(finalizer, provider="google")

    async def events():
        yield event

    session.bind(events(), close=closer, prefetched_events=(event,))
    await session.aclose()

    closer.assert_awaited_once()
    terminal = finalizer.await_args.args[0]
    assert (terminal.usage.prompt_tokens, terminal.usage.completion_tokens) == (2, 3)


@pytest.mark.asyncio
async def test_provider_stream_close_method_is_awaited() -> None:
    finalizer = AsyncMock(return_value=SimpleNamespace())
    provider_stream = SimpleNamespace(close=AsyncMock())
    session = _session(finalizer, provider="anthropic")
    session.bind(provider_stream)

    await session.aclose()

    provider_stream.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_response_send_failure_always_closes_and_finalizes_session() -> None:
    finalizer = AsyncMock(return_value=SimpleNamespace())
    closer = AsyncMock()
    session = _session(finalizer)

    async def events():
        yield b'data: {"choices":[{"delta":{"content":"hello"}}]}\n\n'

    async def send(message: dict) -> None:
        if message["type"] == "http.response.body":
            raise OSError("client disconnected")

    session.bind(events(), close=closer)
    response = _ManagedStreamingResponse(session, media_type="text/event-stream")

    with pytest.raises(OSError):
        await response.stream_response(send)

    closer.assert_awaited_once()
    assert finalizer.await_args.args[0].terminal_status == "client_disconnected"


@pytest.mark.asyncio
async def test_concurrent_finalization_is_idempotent() -> None:
    finalizer = AsyncMock(return_value=SimpleNamespace())
    session = _session(finalizer)

    first, second = await asyncio.gather(
        session.finalize("completed"),
        session.finalize("provider_error"),
    )

    assert first == second
    finalizer.assert_awaited_once()


@pytest.mark.asyncio
async def test_failed_finalization_retries_the_same_terminal_record() -> None:
    finalizer = AsyncMock(
        side_effect=[RuntimeError("temporary failure"), SimpleNamespace()]
    )
    session = _session(finalizer)

    with pytest.raises(RuntimeError, match="temporary failure"):
        await session.finalize("completed")
    terminal, _ = await session.finalize("provider_error")

    assert terminal.terminal_status == "completed"
    assert finalizer.await_count == 2
    assert finalizer.await_args_list[0].args == finalizer.await_args_list[1].args
