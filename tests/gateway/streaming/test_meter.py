from __future__ import annotations

from decimal import Decimal

import pytest

from shim.billing.pricing import UNSPECIFIED_PROVIDER_MODEL
from shim.gateway.streaming import StreamMeter


def meter(
    provider: str = "openai",
    model: str = "gpt-5.6-luna",
) -> StreamMeter:
    return StreamMeter(
        provider=provider,
        requested_model=model,
        prompt_tokens_estimated=5,
    )


def test_fragmented_chat_sse_captures_usage_and_completion() -> None:
    stream_meter = meter()
    stream_meter.observe_sse(b'data: {"choices":[{"delta":{"content":"hello"}}]')
    stream_meter.observe_sse(
        b',"usage":{"prompt_tokens":7,"completion_tokens":3}}\n\ndata: [DONE]\n\n'
    )

    snapshot = stream_meter.snapshot()

    assert (snapshot.prompt_tokens, snapshot.completion_tokens) == (7, 3)
    assert snapshot.estimated is False
    assert stream_meter.terminal_hint == "completed"


def test_native_responses_usage_and_terminal_state_are_observed() -> None:
    stream_meter = meter()
    stream_meter.observe_sse(
        b'event: response.output_text.delta\ndata: {"type":"response.output_text.delta",'
        b'"delta":"123456789"}\n\n'
        b'event: response.completed\ndata: {"type":"response.completed","response":'
        b'{"usage":{"input_tokens":8,"output_tokens":4}}}\n\n'
    )

    snapshot = stream_meter.snapshot()

    assert (snapshot.prompt_tokens, snapshot.completion_tokens) == (8, 4)
    assert stream_meter.terminal_hint == "completed"


def test_responses_without_a_requested_model_use_the_completed_response_model() -> None:
    stream_meter = StreamMeter(
        provider="openai",
        requested_model=UNSPECIFIED_PROVIDER_MODEL,
        prompt_tokens_estimated=20,
    )
    stream_meter.observe_sse(
        b'event: response.completed\ndata: {"type":"response.completed","response":'
        b'{"model":"gpt-5.6-luna","usage":{"input_tokens":20,'
        b'"output_tokens":30}}}\n\n'
    )

    snapshot = stream_meter.snapshot()
    assert snapshot.settlement_cost_usd == Decimal("0.000041")
    assert snapshot.provider_model == "gpt-5.6-luna"


def test_current_text_deltas_exclude_opaque_audio_from_estimates() -> None:
    stream_meter = meter()
    stream_meter.observe_sse(
        b'event: response.code_interpreter_call_code.delta\ndata: {"type":'
        b'"response.code_interpreter_call_code.delta","delta":"1234"}\n\n'
        b'event: response.audio.transcript.delta\ndata: {"type":'
        b'"response.audio.transcript.delta","delta":"5678"}\n\n'
        b'event: response.audio.delta\ndata: {"type":"response.audio.delta",'
        b'"delta":"12345678901234567890"}\n\n'
    )

    snapshot = stream_meter.snapshot()

    assert snapshot.completion_tokens == 2
    assert snapshot.estimated is True


def test_openai_cache_breakdowns_do_not_double_count_inclusive_totals() -> None:
    stream_meter = meter()
    stream_meter.observe_sse(
        b'event: response.completed\ndata: {"type":"response.completed","response":'
        b'{"usage":{"input_tokens":8,"input_tokens_details":{"cached_tokens":6,'
        b'"cache_write_tokens":2},"output_tokens":4,"output_tokens_details":'
        b'{"reasoning_tokens":3},"total_tokens":12}}}\n\n'
    )

    snapshot = stream_meter.snapshot()

    assert (snapshot.prompt_tokens, snapshot.completion_tokens) == (8, 4)
    assert snapshot.estimated is False


def test_anthropic_usage_and_terminal_state_are_observed() -> None:
    stream_meter = meter("anthropic", "claude-sonnet-4-5")
    stream_meter.observe_sse(
        b'event: message_start\ndata: {"type":"message_start","message":{"usage":'
        b'{"input_tokens":7,"output_tokens":0}}}\n\n'
        b'event: content_block_delta\ndata: {"type":"content_block_delta","delta":'
        b'{"type":"text_delta","text":"hello"}}\n\n'
        b'event: message_delta\ndata: {"type":"message_delta","delta":'
        b'{"stop_reason":"end_turn"},"usage":{"output_tokens":3}}\n\n'
        b'event: message_stop\ndata: {"type":"message_stop"}\n\n'
    )

    snapshot = stream_meter.snapshot()

    assert (snapshot.prompt_tokens, snapshot.completion_tokens) == (7, 3)
    assert snapshot.estimated is False
    assert stream_meter.terminal_hint == "completed"


def test_anthropic_cache_usage_and_partial_output_are_not_undercounted() -> None:
    stream_meter = meter("anthropic", "claude-sonnet-4-5")
    stream_meter.observe_sse(
        b'event: message_start\ndata: {"type":"message_start","message":{"usage":'
        b'{"input_tokens":7,"output_tokens":0,"cache_creation_input_tokens":2,'
        b'"cache_read_input_tokens":3}}}\n\n'
        b'event: content_block_delta\ndata: {"type":"content_block_delta","delta":'
        b'{"type":"text_delta","text":"12345678"}}\n\n'
    )

    snapshot = stream_meter.snapshot()

    assert (snapshot.prompt_tokens, snapshot.completion_tokens) == (12, 2)
    assert snapshot.estimated is True


def test_anthropic_beta_cache_details_and_compaction_are_not_double_counted() -> None:
    stream_meter = meter("anthropic", "claude-sonnet-4-5")
    stream_meter.observe_sse(
        b'event: message_start\ndata: {"type":"message_start","message":{"usage":'
        b'{"input_tokens":7,"output_tokens":0,"cache_creation_input_tokens":2,'
        b'"cache_read_input_tokens":3,"cache_creation":{"ephemeral_5m_input_tokens":2,'
        b'"ephemeral_1h_input_tokens":0},"iterations":[{"input_tokens":7,'
        b'"output_tokens":1}]}}}\n\n'
        b'event: content_block_delta\ndata: {"type":"content_block_delta","delta":'
        b'{"type":"compaction_delta","content":"12345678",'
        b'"encrypted_content":"opaque"}}\n\n'
        b'event: message_delta\ndata: {"type":"message_delta","delta":{},"usage":'
        b'{"input_tokens":7,"cache_creation_input_tokens":2,'
        b'"cache_read_input_tokens":3,"output_tokens":4,"output_tokens_details":'
        b'{"reasoning_tokens":2}}}\n\n'
    )

    snapshot = stream_meter.snapshot()

    assert (snapshot.prompt_tokens, snapshot.completion_tokens) == (12, 4)
    assert snapshot.estimated is False


@pytest.mark.parametrize(
    "usage",
    [
        b'"promptTokenCount":6,"candidatesTokenCount":4,"totalTokenCount":10',
        b'"promptTokenCount":6,"totalTokenCount":10',
    ],
)
def test_google_usage_and_terminal_state_are_observed(usage: bytes) -> None:
    stream_meter = meter("google", "gemini-2.5-flash")
    stream_meter.observe_sse(
        b'data: {"candidates":[{"content":{"parts":[{"text":"hello"}]},'
        b'"finishReason":"STOP"}],"usageMetadata":{' + usage + b"}}\n\n"
    )

    snapshot = stream_meter.snapshot()

    assert (snapshot.prompt_tokens, snapshot.completion_tokens) == (6, 4)
    assert snapshot.estimated is False
    assert stream_meter.terminal_hint == "completed"


def test_google_tool_and_thinking_usage_and_all_candidates_are_observed() -> None:
    stream_meter = StreamMeter(
        provider="google",
        requested_model="gemini-3.5-flash",
        prompt_tokens_estimated=5,
        expected_candidates=2,
    )
    stream_meter.observe_sse(
        b'data: {"candidates":[{"index":0,"finishReason":"STOP"}],'
        b'"usageMetadata":{"promptTokenCount":6,"toolUsePromptTokenCount":2,'
        b'"candidatesTokenCount":4,"thoughtsTokenCount":3,"totalTokenCount":15}}\n\n'
    )
    assert stream_meter.terminal_hint is None
    stream_meter.observe_sse(
        b'data: {"candidates":[{"index":1,"finishReason":"STOP"}]}\n\n'
    )

    snapshot = stream_meter.snapshot()

    assert (snapshot.prompt_tokens, snapshot.completion_tokens) == (8, 7)
    assert stream_meter.terminal_hint == "completed"


def test_missing_usage_uses_emitted_character_estimate() -> None:
    stream_meter = meter()
    stream_meter.observe_sse(
        b'data: {"choices":[{"delta":{"content":"123456789"}}]}\n\ndata: [DONE]\n\n'
    )

    snapshot = stream_meter.snapshot()

    assert snapshot.prompt_tokens == 5
    assert snapshot.completion_tokens == 3
    assert snapshot.estimated is True


def test_first_terminal_event_is_sticky() -> None:
    stream_meter = meter()
    stream_meter.observe_sse(
        b'event: error\ndata: {"type":"error","error":{"message":"safe"}}\n\n'
        b"data: [DONE]\n\n"
    )

    assert stream_meter.terminal_hint == "provider_error"


def test_error_overrides_an_earlier_completion_hint() -> None:
    stream_meter = meter()
    stream_meter.observe_sse(
        b'event: response.completed\ndata: {"type":"response.completed"}\n\n'
        b'event: error\ndata: {"type":"error","error":{"message":"safe"}}\n\n'
    )

    assert stream_meter.terminal_hint == "provider_error"


def test_gateway_privacy_failure_is_internal_not_provider_error() -> None:
    stream_meter = meter()
    stream_meter.observe_sse(
        b'event: error\ndata: {"type":"error","code":"PRIVACY_STATE_UNAVAILABLE"}\n\n'
    )

    assert stream_meter.terminal_hint == "internal_error"


@pytest.mark.parametrize(
    ("event_type", "expected"),
    [
        ("response.incomplete", "completed"),
        ("response.failed", "provider_error"),
        ("response.cancelled", "cancelled"),
    ],
)
def test_responses_terminal_events_are_classified(
    event_type: str, expected: str
) -> None:
    stream_meter = meter()
    stream_meter.observe_sse(
        f'event: {event_type}\ndata: {{"type":"{event_type}"}}\n\n'.encode()
    )

    assert stream_meter.terminal_hint == expected
