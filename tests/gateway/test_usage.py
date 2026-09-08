from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from io import StringIO
import json
from types import SimpleNamespace

import pytest

from shim.gateway.streaming import StreamFinalization
from shim.gateway.streaming.meter import StreamUsageSnapshot
from shim.gateway.usage import LocalUsageLifecycle
from shim.privacy.policies import PrivacyAction, PrivacyOutcome


def _prepared(*, model: str = "gpt-5.6-luna") -> SimpleNamespace:
    started_at = datetime.now(timezone.utc) - timedelta(milliseconds=12)
    return SimpleNamespace(
        policy_verdicts=[],
        request_id="req_local",
        provider="openai",
        model=model,
        tenant_id="tenant-private",
        api_key_id="key-private",
        headers={"authorization": "credential-private"},
        context=SimpleNamespace(started_at=started_at),
        admission=SimpleNamespace(estimated_input_tokens=11, repeat_chain_length=1),
        deployment_kind="unknown",
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
        ),
        completed_at=datetime.now(timezone.utc),
        error_code=None,
        error_message=None,
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
        "request_id",
        "provider",
        "model",
        "outcome",
        "latency_ms",
        "prompt_tokens",
        "completion_tokens",
        "estimated_cost_usd",
        "estimated",
        "privacy_counts",
        "provider_finish_reasons",
        "ttft_ms",
        "repeat_chain_length",
        "system_prompt_hash",
        "deployment_kind",
        "policy_verdicts",
    }
    latency_ms = event.pop("latency_ms")
    assert event == {
        "version": 1,
        "request_id": "req_local",
        "provider": "openai",
        "model": "gpt-5.6-luna",
        "outcome": "completed",
        "prompt_tokens": 11,
        "completion_tokens": 7,
        "estimated_cost_usd": "0.0000106",
        "estimated": False,
        "privacy_counts": {"EMAIL_ADDRESS": 1},
        "provider_finish_reasons": None,
        "ttft_ms": None,
        "repeat_chain_length": 1,
        "system_prompt_hash": None,
        "deployment_kind": "unknown",
        "policy_verdicts": [],
    }
    assert latency_ms >= 0


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
    assert dumps.call_count == 1
    assert terminal.usage.output_hash == (
        content_ref(
            salt, json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        )
        if salt is not None
        else None
    )
