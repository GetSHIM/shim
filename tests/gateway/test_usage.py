from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from io import StringIO
import json
from types import MethodType, SimpleNamespace

import pytest

from shim.gateway.streaming import StreamFinalization
from shim.gateway.kernel.result import InferenceTiming, PreparedInference
from shim.gateway.streaming.meter import StreamUsageSnapshot
from shim.gateway.usage import LocalUsageLifecycle
from shim.privacy.policies import PrivacyAction, PrivacyOutcome


def _prepared(*, model: str = "gpt-5.6-luna") -> SimpleNamespace:
    started_at = datetime.now(timezone.utc) - timedelta(milliseconds=12)
    prepared = SimpleNamespace(
        policy_verdicts=[],
        warnings=[],
        timing=InferenceTiming(),
        request_id="req_local",
        provider="openai",
        model=model,
        pricing_model=model,
        target=None,
        unpriced=False,
        deployment_price=None,
        tenant_id="tenant-private",
        api_key_id="key-private",
        headers={"authorization": "credential-private"},
        context=SimpleNamespace(started_at=started_at),
        admission=SimpleNamespace(
            estimated_input_tokens=11,
            repeat_chain_length=1,
            cost_center="risk",
            tags=("risk", "batch"),
        ),
        deployment_kind="unknown",
        response_scan="off",
        payload={"messages": [{"content": "secret-body"}]},
        privacy=PrivacyOutcome(
            action=PrivacyAction.SCRUBBED,
            pii_detected=True,
            verification_map={"<EMAIL_ADDRESS_a1>": "private@example.com"},
        ),
    )
    prepared.warn = MethodType(PreparedInference.warn, prepared)
    return prepared


def _terminal(*, model: str = "gpt-5.6-luna") -> StreamFinalization:
    return StreamFinalization(
        terminal_status="completed",
        usage=StreamUsageSnapshot(
            prompt_tokens=11,
            completion_tokens=7,
            settlement_cost_usd=Decimal("0.0000106"),
            provider_model=model,
            pricing_metadata={},
            estimated=False,
            output_hash=None,
            completion_outcome="complete",
        ),
        completed_at=datetime.now(timezone.utc),
        error_code=None,
        error_message=None,
        shim_latency_ms=12,
    )


@pytest.mark.asyncio
async def test_local_usage_writes_one_exact_redacted_terminal_event() -> None:
    stream = StringIO()
    prepared = _prepared()
    lifecycle = LocalUsageLifecycle(stream)

    await lifecycle.admit(prepared, prepared.admission)
    await lifecycle.record_privacy(prepared)
    await lifecycle.reserve_provider_spend(prepared, ephemeral_byok=True)
    await lifecycle.mark_provider_started(prepared)
    await lifecycle.mark_stream_started(prepared)
    await lifecycle.heartbeat_stream(prepared)
    await lifecycle.finalize(prepared, _terminal())

    await lifecycle.aclose()
    lines = stream.getvalue().splitlines()
    assert len(lines) == 1
    assert "secret-body" not in lines[0]
    assert "private@example.com" not in lines[0]
    assert "tenant-private" not in lines[0]
    assert "key-private" not in lines[0]
    assert "credential-private" not in lines[0]
    event = json.loads(lines[0])
    assert set(event) == {
        "version",
        "event",
        "request_id",
        "provider",
        "model",
        "outcome",
        "shim_latency_ms",
        "prompt_tokens",
        "completion_tokens",
        "estimated_cost_usd",
        "estimated",
        "cache_read_tokens",
        "cache_write_tokens",
        "privacy_counts",
        "monitored_entities",
        "blocked_entities",
        "bulk_disclosure",
        "provider_finish_reasons",
        "completion_outcome",
        "ttft_ms",
        "repeat_chain_length",
        "cost_center",
        "tags",
        "system_prompt_hash",
        "deployment_kind",
        "warnings",
        "policy_verdicts",
    }
    latency_ms = event.pop("shim_latency_ms")
    assert event == {
        "version": 4,
        "event": "request",
        "request_id": "req_local",
        "provider": "openai",
        "model": "gpt-5.6-luna",
        "outcome": "completed",
        "prompt_tokens": 11,
        "completion_tokens": 7,
        "estimated_cost_usd": "0.0000106",
        "estimated": False,
        "cache_read_tokens": None,
        "cache_write_tokens": None,
        "privacy_counts": {"EMAIL_ADDRESS": 1},
        "monitored_entities": {},
        "blocked_entities": {},
        "bulk_disclosure": None,
        "provider_finish_reasons": None,
        "completion_outcome": "complete",
        "ttft_ms": None,
        "repeat_chain_length": 1,
        "cost_center": "risk",
        "tags": ["risk", "batch"],
        "system_prompt_hash": None,
        "deployment_kind": "unknown",
        "warnings": [],
        "policy_verdicts": [],
    }
    assert latency_ms >= 0


@pytest.mark.asyncio
async def test_a_rejection_before_admission_has_no_attribution() -> None:
    stream = StringIO()
    prepared = _prepared()
    prepared.admission = None
    lifecycle = LocalUsageLifecycle(stream)

    await lifecycle.reject(prepared)

    await lifecycle.aclose()
    event = json.loads(stream.getvalue())
    assert event["version"] == 4
    assert event["outcome"] == "rejected"
    assert (event["cost_center"], event["tags"]) == (None, [])
    assert event["completion_outcome"] is None


@pytest.mark.asyncio
async def test_a_privacy_block_is_a_rejection_with_its_counts() -> None:
    stream = StringIO()
    prepared = _prepared()
    prepared.privacy = PrivacyOutcome(
        action=PrivacyAction.SCRUBBED,
        pii_detected=True,
        monitored_entities={"EMAIL_ADDRESS": 1},
        blocked_entities={"SECRET": 2},
    )
    prepared.policy_verdicts = [SimpleNamespace(outcome="deny", model_dump=dict)]
    lifecycle = LocalUsageLifecycle(stream)

    await lifecycle.fail(prepared, reason="request_aborted")

    await lifecycle.aclose()
    event = json.loads(stream.getvalue())
    assert event["outcome"] == "rejected"
    assert (event["estimated_cost_usd"], event["estimated"]) == ("0", False)
    assert event["privacy_counts"] == {}
    assert event["monitored_entities"] == {"EMAIL_ADDRESS": 1}
    assert event["blocked_entities"] == {"SECRET": 2}


@pytest.mark.asyncio
async def test_local_usage_uses_null_cost_for_unsupported_model() -> None:
    stream = StringIO()
    prepared = _prepared(model="private-model")

    lifecycle = LocalUsageLifecycle(stream)
    await lifecycle.finalize(
        prepared,
        _terminal(model="private-model"),
    )

    await lifecycle.aclose()
    assert json.loads(stream.getvalue())["estimated_cost_usd"] is None


@pytest.mark.asyncio
async def test_local_failure_writes_one_terminal_event() -> None:
    stream = StringIO()

    lifecycle = LocalUsageLifecycle(stream)
    await lifecycle.fail(
        _prepared(),
        reason="provider_rejected_without_usage",
    )

    await lifecycle.aclose()
    event = json.loads(stream.getvalue())
    assert event["outcome"] == "provider_rejected_without_usage"
    assert event["completion_tokens"] == 0
    assert event["provider_finish_reasons"] is None
    assert event["ttft_ms"] is None
    assert len(stream.getvalue().splitlines()) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["write", "flush"])
async def test_local_sink_failure_does_not_fail_settlement(failure):
    class BrokenSink(StringIO):
        def write(self, value):
            if failure == "write":
                raise OSError("private sink detail")
            return super().write(value)

        def flush(self):
            if failure == "flush":
                raise OSError("private sink detail")

    lifecycle = LocalUsageLifecycle(BrokenSink())
    await lifecycle.finalize(_prepared(), _terminal())
    await lifecycle.aclose()
    assert lifecycle.write_failures == 1


@pytest.mark.asyncio
async def test_blocked_sink_keeps_event_loop_and_buffer_bounded():
    import asyncio
    from threading import Event

    entered = Event()
    release = Event()

    class BlockedSink(StringIO):
        def write(self, value):
            entered.set()
            release.wait(2)
            return super().write(value)

    lifecycle = LocalUsageLifecycle(BlockedSink(), capacity=2)
    try:
        await lifecycle.finalize(_prepared(), _terminal())
        assert await asyncio.to_thread(entered.wait, 1)
        for _ in range(10):
            await lifecycle.finalize(_prepared(), _terminal())
        assert lifecycle._queue.qsize() == 2
        assert lifecycle.dropped_events == 8
        await asyncio.wait_for(asyncio.sleep(0), 0.1)
        await lifecycle.aclose(timeout_seconds=0.01)
    finally:
        release.set()
        await lifecycle.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("salt", [None, "hash-salt"])
async def test_nonstream_hash_is_optional_without_changing_response(monkeypatch, salt):
    from unittest.mock import AsyncMock, Mock
    from fastapi.responses import JSONResponse
    import shim.gateway.pipeline.postprocess as module
    from shim.gateway.pipeline.provider_execution import ProviderNonStream
    from shim.privacy.classification import content_ref

    payload = {
        "nested": {"content": "İstanbul 🌍"},
        "usage": {"prompt_tokens": 2, "completion_tokens": 3},
    }
    expected = JSONResponse(payload)
    prepared = _prepared()
    prepared.protocol = "chat"
    prepared.admission.maximum_output_tokens = 10
    usage = SimpleNamespace(finalize=AsyncMock())
    dumps = Mock(wraps=json.dumps)
    monkeypatch.setattr(json, "dumps", dumps)
    response = await module.ResponsePostprocessor(
        usage, heartbeat_interval_seconds=30, output_hash_salt=salt
    ).finalize(prepared, ProviderNonStream(payload, "upstream-id"), stream_session=None)
    assert response.body == expected.body
    assert response.headers["x-request-id"] == "upstream-id"
    usage.finalize.assert_awaited_once()
    terminal = usage.finalize.await_args.args[1]
    assert response.headers["x-shim-latency-ms"] == str(terminal.shim_latency_ms)
    assert dumps.call_count == 1
    assert terminal.usage.output_hash == (
        content_ref(
            salt, json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        )
        if salt is not None
        else None
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("provider", "payload", "outcome"),
    [
        (
            "openai",
            {
                "status": "completed",
                "output": [
                    {
                        "type": "message",
                        "content": [{"type": "output_text", "text": "ok"}],
                    }
                ],
            },
            "complete",
        ),
        ("openai", {"status": "failed", "output": []}, None),
        ("google", {"promptFeedback": {"blockReason": "SAFETY"}}, "filtered"),
    ],
)
async def test_a_json_outcome_is_settled_only_for_an_answer(provider, payload, outcome):
    from unittest.mock import AsyncMock
    from prometheus_client import REGISTRY
    import shim.gateway.pipeline.postprocess as module
    from shim.gateway.pipeline.provider_execution import ProviderNonStream

    def counted(label: str | None) -> float:
        return (
            REGISTRY.get_sample_value(
                "shim_completion_outcomes_total",
                {"provider": provider, "outcome": label or "other"},
            )
            or 0
        )

    prepared = _prepared()
    prepared.provider = provider
    prepared.protocol = "responses" if provider == "openai" else "gemini"
    prepared.admission.maximum_output_tokens = 10
    usage = SimpleNamespace(finalize=AsyncMock())
    before = counted(outcome)

    await module.ResponsePostprocessor(
        usage, heartbeat_interval_seconds=30, output_hash_salt=None
    ).finalize(prepared, ProviderNonStream(payload, None), stream_session=None)

    assert usage.finalize.await_args.args[1].usage.completion_outcome == outcome
    # A failure is not counted, not even as "other".
    assert counted(outcome) == before + (outcome is not None)


def _scan_processor(monkeypatch, scan):
    from unittest.mock import AsyncMock
    import shim.gateway.pipeline.postprocess as module

    monkeypatch.setattr(module, "scan_response", scan)
    usage = SimpleNamespace(
        finalize=AsyncMock(),
        record_response_privacy=AsyncMock(),
        mark_stream_started=AsyncMock(),
        heartbeat_stream=AsyncMock(),
    )
    prepared = _prepared()
    prepared.protocol = "chat"
    prepared.stream = False
    prepared.admission.maximum_output_tokens = 10
    processor = module.ResponsePostprocessor(
        usage, heartbeat_interval_seconds=30, output_hash_salt=None
    )
    return processor, prepared, usage


@pytest.mark.asyncio
@pytest.mark.parametrize("fails", [False, True])
async def test_a_json_answer_is_sent_before_its_response_scan_runs(monkeypatch, fails):
    from fastapi.responses import JSONResponse
    from shim.gateway.pipeline.provider_execution import ProviderNonStream

    order: list[str] = []

    def scan(text, _prepared, _scrubber):
        order.append(f"scan:{text}")
        if fails:
            raise RuntimeError("analyzer down")
        return {"response_entities": {"TR_NATIONAL_ID": 1}, "truncated": False}

    processor, prepared, usage = _scan_processor(monkeypatch, scan)
    prepared.response_scan = "count"
    payload = {
        "choices": [
            {
                "message": {
                    "content": "TCKN 10000000146",
                    "tool_calls": [
                        {"function": {"arguments": '{"to": "x@example.com"}'}}
                    ],
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 2, "completion_tokens": 3},
    }

    response = await processor.finalize(
        prepared, ProviderNonStream(payload, None), stream_session=None
    )

    async def send(message):
        order.append(message["type"])

    async def receive():
        return {"type": "http.disconnect"}

    assert order == [] and "x-shim-latency-ms" in response.headers
    usage.finalize.assert_awaited_once()
    await response({"type": "http", "method": "POST"}, receive, send)
    assert response.body == JSONResponse(payload).body
    assert order == [
        "http.response.start",
        "http.response.body",
        'scan:TCKN 10000000146\n{"to": "x@example.com"}',
    ]
    usage.record_response_privacy.assert_awaited_once_with(
        prepared,
        {"response_entities": None, "error": True}
        if fails
        else {"response_entities": {"TR_NATIONAL_ID": 1}, "truncated": False},
    )
    assert not processor._finalization_tasks


@pytest.mark.asyncio
async def test_a_json_answer_has_no_response_scan_when_it_is_off(monkeypatch):
    from shim.gateway.pipeline.provider_execution import ProviderNonStream

    processor, prepared, usage = _scan_processor(monkeypatch, None)

    response = await processor.finalize(
        prepared,
        ProviderNonStream({"choices": [], "usage": {}}, None),
        stream_session=None,
    )

    assert response.background is None


@pytest.mark.asyncio
async def test_a_stream_is_neither_held_nor_changed_by_its_response_scan(monkeypatch):
    import threading
    from unittest.mock import AsyncMock
    from shim.gateway.pipeline.provider_execution import ProviderStream

    started, release = threading.Event(), threading.Event()
    scanned: list[str] = []

    def scan(text, _prepared, _scrubber):
        started.set()
        release.wait(5)
        scanned.append(text)
        return {"response_entities": {"TR_NATIONAL_ID": 1}, "truncated": False}

    processor, prepared, usage = _scan_processor(monkeypatch, scan)
    prepared.stream = True
    chunks = [
        b'data: {"choices":[{"index":0,"delta":{"content":"TCKN 1000"}}]}\n\n',
        b'data: {"choices":[{"index":0,"delta":{"content":"0000146"},'
        b'"finish_reason":"stop"}]}\n\n',
        b"data: [DONE]\n\n",
    ]

    async def events():
        for chunk in chunks:
            yield chunk

    received: dict[str, list[bytes]] = {}
    for setting in ("off", "count"):
        prepared.response_scan = setting
        session = processor.create_stream_session(prepared)
        await processor.finalize(
            prepared,
            ProviderStream(events(), None, AsyncMock()),
            stream_session=session,
        )
        received[setting] = []
        async for chunk in session:
            if not received[setting]:
                assert not started.is_set()
            received[setting].append(chunk)
        if setting == "off":
            assert session.meter.answer_text == []
            assert not processor._finalization_tasks

    assert received["off"] == received["count"] == chunks
    assert processor._finalization_tasks and not scanned
    release.set()
    await processor.drain()
    assert scanned == ["TCKN 10000000146"]
    usage.record_response_privacy.assert_awaited_once_with(
        prepared, {"response_entities": {"TR_NATIONAL_ID": 1}, "truncated": False}
    )


@pytest.mark.asyncio
async def test_a_response_scan_writes_a_second_jsonl_line() -> None:
    stream = StringIO()
    usage = LocalUsageLifecycle(stream)

    await usage.finalize(_prepared(), _terminal())
    await usage.record_response_privacy(
        _prepared(), {"response_entities": {"TR_NATIONAL_ID": 1}, "truncated": False}
    )
    await usage.aclose()

    request, response = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert (request["version"], request["event"]) == (4, "request")
    assert response == {
        "version": 4,
        "event": "response_privacy",
        "request_id": "req_local",
        "response_entities": {"TR_NATIONAL_ID": 1},
        "truncated": False,
    }


@pytest.mark.parametrize(
    ("provider", "usage", "split"),
    [
        (
            "anthropic",
            {
                "input_tokens": 100,
                "cache_creation_input_tokens": 4_000,
                "cache_read_input_tokens": 6_000,
            },
            (6_000, 4_000, 0),
        ),
        (
            "anthropic",
            {
                "input_tokens": 100,
                "cache_creation_input_tokens": 4_000,
                "cache_read_input_tokens": 0,
                "cache_creation": {
                    "ephemeral_5m_input_tokens": 1_000,
                    "ephemeral_1h_input_tokens": 3_000,
                },
            },
            (0, 1_000, 3_000),
        ),
        ("anthropic", {"input_tokens": 100}, None),
        (
            "openai",
            {"prompt_tokens": 5_000, "prompt_tokens_details": {"cached_tokens": 4_096}},
            (4_096, 0, 0),
        ),
        (
            "openai",
            {"input_tokens": 5_000, "input_tokens_details": {"cached_tokens": 1_024}},
            (1_024, 0, 0),
        ),
        ("openai", {"prompt_tokens": 5_000}, None),
        (
            "google",
            {"promptTokenCount": 5_000, "cachedContentTokenCount": 2_048},
            (2_048, 0, 0),
        ),
        ("google", {"promptTokenCount": 5_000}, None),
        ("openai", {"prompt_tokens_details": {"cached_tokens": -1}}, None),
    ],
)
def test_the_cache_split_is_read_from_each_providers_usage(provider, usage, split):
    from shim.gateway.streaming.meter import cache_split

    assert cache_split(usage, provider) == split


@pytest.mark.asyncio
@pytest.mark.parametrize("stream", [False, True])
async def test_reported_cache_tokens_settle_at_cache_prices(monkeypatch, stream):
    from unittest.mock import AsyncMock
    import shim.gateway.pipeline.postprocess as module
    from shim.gateway.pipeline.provider_execution import ProviderNonStream
    from shim.gateway.streaming import StreamMeter

    usage = {
        "input_tokens": 100,
        "output_tokens": 20,
        "cache_creation_input_tokens": 4_000,
        "cache_read_input_tokens": 6_000,
    }
    if stream:
        meter = StreamMeter(
            provider="anthropic",
            requested_model="claude-haiku-4-5",
            prompt_tokens_estimated=1,
        )
        meter.observe_sse(
            b'event: message_start\ndata: {"type":"message_start","message":{"usage":'
            + json.dumps({**usage, "output_tokens": 1}).encode()
            + b"}}\n\n"
        )
        meter.observe_sse(
            b'event: message_delta\ndata: {"type":"message_delta","usage":{"output_tokens":20}}\n\n'
        )
        snapshot = meter.snapshot()
    else:
        prepared = _prepared(model="claude-haiku-4-5")
        prepared.provider = "anthropic"
        prepared.protocol = "messages"
        prepared.admission.maximum_output_tokens = 10
        recorder = SimpleNamespace(finalize=AsyncMock())
        await module.ResponsePostprocessor(
            recorder, heartbeat_interval_seconds=30, output_hash_salt=None
        ).finalize(
            prepared,
            ProviderNonStream(
                {"content": [], "stop_reason": "end_turn", "usage": usage}, None
            ),
            stream_session=None,
        )
        snapshot = recorder.finalize.await_args.args[1].usage

    # 100 uncached at $1, 6,000 read at $0.10, 4,000 written at $1.25, 20 out at $5.
    assert snapshot.prompt_tokens == 10_100
    assert snapshot.cache_split == (6_000, 4_000, 0)
    assert snapshot.settlement_cost_usd == Decimal("0.0058")
    assert snapshot.pricing_metadata["cache_read_tokens"] == 6_000


def test_a_priced_deployment_is_priced_on_its_span(monkeypatch):
    from unittest.mock import Mock
    import shim.gateway.pipeline.postprocess as module
    from shim.billing.pricing import ModelPrice

    span = Mock()
    span.is_recording.return_value = True
    monkeypatch.setattr(module.trace, "get_current_span", lambda: span)
    # custom-model-v1 is not in the catalog; the operator's price makes it priced.
    prepared = _prepared(model="internal-a")
    prepared.deployment_price = ModelPrice(Decimal("0.5"), Decimal("1.5"))
    terminal = _terminal(model="custom-model-v1")

    module.record_settled_usage(prepared, terminal.usage)

    attributes = span.set_attributes.call_args.args[0]
    assert attributes["gen_ai.request.model"] == "custom-model-v1"
    assert attributes["shim.cost_usd"] == str(terminal.usage.settlement_cost_usd)


@pytest.mark.asyncio
async def test_an_estimated_input_never_claims_the_large_context_price():
    from unittest.mock import AsyncMock
    import shim.gateway.pipeline.postprocess as module
    from shim.gateway.pipeline.provider_execution import ProviderNonStream

    # gpt-5.4's tier starts above 272,000 input tokens; the byte estimate is not usage.
    prepared = _prepared(model="gpt-5.4")
    prepared.protocol = "chat"
    prepared.admission.estimated_input_tokens = 300_000
    prepared.admission.maximum_output_tokens = 10
    prepared.payload = {}

    await module.ResponsePostprocessor(
        SimpleNamespace(finalize=AsyncMock()),
        heartbeat_interval_seconds=30,
        output_hash_salt=None,
    ).finalize(
        prepared,
        ProviderNonStream(
            {"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]},
            None,
        ),
        stream_session=None,
    )

    assert prepared.warnings == []


@pytest.mark.parametrize(
    ("model", "prompt_tokens", "split", "payload", "warnings"),
    [
        ("gpt-5.4", 272_001, None, {}, ["LARGE_CONTEXT_PRICE"]),
        ("gpt-5.4", 272_000, None, {}, []),
        (
            "claude-haiku-4-5",
            900,
            (0, 0, 0),
            {"cache_control": {"type": "ephemeral"}},
            ["CACHE_NOT_APPLIED"],
        ),
        (
            "claude-haiku-4-5",
            900,
            (0, 0, 0),
            {
                "system": [
                    {
                        "type": "text",
                        "text": "x",
                        "cache_control": {"type": "ephemeral"},
                    }
                ]
            },
            ["CACHE_NOT_APPLIED"],
        ),
        (
            "claude-haiku-4-5",
            900,
            (0, 1_024, 0),
            {"cache_control": {"type": "ephemeral"}},
            [],
        ),
        ("claude-haiku-4-5", 900, None, {"cache_control": {"type": "ephemeral"}}, []),
        ("claude-haiku-4-5", 900, (0, 0, 0), {"messages": []}, []),
        (
            "claude-haiku-4-5",
            900,
            (0, 0, 0),
            {"tools": [{"name": "t", "cache_control": {"type": "ephemeral"}}]},
            ["CACHE_NOT_APPLIED"],
        ),
        (
            "claude-haiku-4-5",
            900,
            (0, 0, 0),
            {
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": "x",
                                "cache_control": {"type": "ephemeral"},
                            }
                        ],
                    }
                ]
            },
            ["CACHE_NOT_APPLIED"],
        ),
        # A tool's schema may name a property cache_control; that is not caching.
        (
            "claude-haiku-4-5",
            900,
            (0, 0, 0),
            {
                "tools": [
                    {
                        "name": "t",
                        "input_schema": {
                            "properties": {"cache_control": {"type": "string"}}
                        },
                    }
                ]
            },
            [],
        ),
    ],
)
def test_warnings_known_only_after_the_answer(
    model, prompt_tokens, split, payload, warnings
):
    from shim.gateway.pipeline.postprocess import warn_after_answer

    prepared = _prepared(model=model)
    prepared.provider = "anthropic" if model.startswith("claude") else "openai"
    prepared.payload = payload

    warn_after_answer(prepared, prompt_tokens, split)

    assert prepared.warnings == warnings


@pytest.mark.asyncio
@pytest.mark.parametrize("stream", [False, True])
async def test_the_warnings_header_carries_what_is_known_when_headers_are_sent(stream):
    from unittest.mock import AsyncMock
    import shim.gateway.pipeline.postprocess as module
    from shim.gateway.pipeline.provider_execution import (
        ProviderNonStream,
        ProviderStream,
    )

    prepared = _prepared(model="claude-haiku-4-5")
    prepared.provider = "anthropic"
    prepared.protocol = "messages"
    prepared.stream = stream
    prepared.admission.maximum_output_tokens = 10
    prepared.payload = {
        "system": [
            {"type": "text", "text": "x", "cache_control": {"type": "ephemeral"}}
        ]
    }
    prepared.warn("MODEL_DEPRECATED")
    usage = {
        "input_tokens": 900,
        "output_tokens": 2,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
    }
    recorder = SimpleNamespace(
        finalize=AsyncMock(),
        mark_stream_started=AsyncMock(),
        heartbeat_stream=AsyncMock(),
    )
    processor = module.ResponsePostprocessor(
        recorder, heartbeat_interval_seconds=30, output_hash_salt=None
    )

    if not stream:
        response = await processor.finalize(
            prepared,
            ProviderNonStream(
                {"content": [], "stop_reason": "end_turn", "usage": usage}, None
            ),
            stream_session=None,
        )
        assert (
            response.headers["x-shim-warnings"] == "MODEL_DEPRECATED,CACHE_NOT_APPLIED"
        )
        return

    async def events():
        yield (
            b'event: message_start\ndata: {"type":"message_start","message":{"usage":'
            + json.dumps(usage).encode()
            + b"}}\n\n"
        )
        yield (
            b'event: message_delta\ndata: {"type":"message_delta",'
            b'"delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":2}}\n\n'
        )
        yield b'event: message_stop\ndata: {"type":"message_stop"}\n\n'

    session = processor.create_stream_session(prepared)
    response = await processor.finalize(
        prepared, ProviderStream(events(), None, AsyncMock()), stream_session=session
    )
    assert response.headers["x-shim-warnings"] == "MODEL_DEPRECATED"
    [chunk async for chunk in session]
    assert prepared.warnings == ["MODEL_DEPRECATED", "CACHE_NOT_APPLIED"]


@pytest.mark.asyncio
async def test_the_jsonl_event_lists_the_requests_warnings() -> None:
    stream = StringIO()
    usage = LocalUsageLifecycle(stream)
    prepared = _prepared()
    prepared.warn("MODEL_DEPRECATED")

    await usage.finalize(prepared, _terminal())
    await usage.aclose()

    assert json.loads(stream.getvalue())["warnings"] == ["MODEL_DEPRECATED"]


_PINNED_PROMPTS = {
    "chat": {
        "messages": [
            {"role": "system", "content": "Be brief."},
            {"role": "developer", "content": "Use Turkish."},
            {"role": "user", "content": "hi"},
        ]
    },
    "responses": {
        "instructions": "Be brief.",
        "input": [
            {"role": "developer", "content": "Use Turkish."},
            {"role": "user", "content": "hi"},
        ],
    },
    "messages": {
        "system": [{"type": "text", "text": "Be brief. Ünlü"}],
        "messages": [{"role": "user", "content": "hi"}],
    },
    "count_tokens": {"system": "Be brief.", "messages": []},
    "generate_content": {
        "systemInstruction": {"parts": [{"text": "Be brief."}]},
        "contents": [],
    },
}


@pytest.mark.parametrize(
    ("protocol", "deployment", "digest"),
    [
        # Computed by the enterprise implementation before it moved to the core.
        (
            "chat",
            False,
            "8445b0326d15e8bf73be73411086f2537c9c1d2876ad7b3e34a1d8188be01952",
        ),
        (
            "chat",
            True,
            "1181818d789660ae2fdd82f2d6203436cf441fcabced1b2aff827e1af5b21ce5",
        ),
        (
            "responses",
            False,
            "8013098bd02771debde101e17ad0f3b51d9f637ec5ab3149662b9250645ca767",
        ),
        (
            "responses",
            True,
            "8d175fda2c62907b50568e7c055303079a196fa0a3aa9d825e664dcd9b675b9c",
        ),
        (
            "messages",
            False,
            "e1efded75e69ae58e5785ab8a00d8384b2b07651f8539d97113e2a1a65f3ab08",
        ),
        (
            "messages",
            True,
            "6b9b9e4df9573baacf5ab8cf6fb210b262ed443bd361f69159b90a68c9649f15",
        ),
        (
            "count_tokens",
            False,
            "879c5cb9d35e05717764ca76d9752dcc9921e7d7854c33135dca45d5e318265f",
        ),
        (
            "count_tokens",
            True,
            "e5e296d337da3f4b4ca8406c93cf93a9c25fd55c823bc94ebe7443a8c92ef9ed",
        ),
        (
            "generate_content",
            False,
            "0b38bdbcc05a35d72b2585db2c47267607a197e099a75660b8ccebc4281513bd",
        ),
        (
            "generate_content",
            True,
            "762c05a75629fcf3dbd0ecc5bf8502293922d51ae23a8766b48da8d75540c791",
        ),
    ],
)
def test_the_system_prompt_hash_keeps_its_pinned_digests(protocol, deployment, digest):
    from shim.gateway.usage import system_prompt_hash

    prepared = SimpleNamespace(
        payload=_PINNED_PROMPTS[protocol],
        protocol=protocol,
        tenant_id="11111111-1111-1111-1111-111111111111",
        target=SimpleNamespace(deployment_id="dep-1") if deployment else None,
        deployment_kind="internal" if deployment else "unknown",
    )

    assert system_prompt_hash(prepared, b"pinned-system-prompt-hash-key-0000") == (
        f"hmac-sha256:v1:{digest}"
    )
