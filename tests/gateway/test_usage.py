from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from io import StringIO
import json
from types import SimpleNamespace

import pytest

from shim.gateway.streaming import StreamFinalization
from shim.gateway.kernel.result import InferenceTiming
from shim.gateway.streaming.meter import StreamUsageSnapshot
from shim.gateway.usage import LocalUsageLifecycle
from shim.privacy.policies import PrivacyAction, PrivacyOutcome


def _prepared(*, model: str = "gpt-5.6-luna") -> SimpleNamespace:
    started_at = datetime.now(timezone.utc) - timedelta(milliseconds=12)
    return SimpleNamespace(
        policy_verdicts=[],
        timing=InferenceTiming(),
        request_id="req_local",
        provider="openai",
        model=model,
        pricing_model=model,
        target=None,
        unpriced=False,
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
