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
        request_id="req_local",
        provider="openai",
        model=model,
        tenant_id="tenant-private",
        api_key_id="key-private",
        headers={"authorization": "credential-private"},
        context=SimpleNamespace(started_at=started_at),
        admission=SimpleNamespace(estimated_input_tokens=11),
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
    }
    assert latency_ms >= 0


@pytest.mark.asyncio
async def test_local_usage_uses_null_cost_for_unsupported_model() -> None:
    stream = StringIO()
    prepared = _prepared(model="private-model")

    await LocalUsageLifecycle(stream).finalize(
        prepared,
        _terminal(model="private-model"),
    )

    assert json.loads(stream.getvalue())["estimated_cost_usd"] is None


@pytest.mark.asyncio
async def test_local_failure_writes_one_terminal_event() -> None:
    stream = StringIO()

    await LocalUsageLifecycle(stream).fail(
        _prepared(),
        reason="provider_rejected_without_usage",
    )

    event = json.loads(stream.getvalue())
    assert event["outcome"] == "provider_rejected_without_usage"
    assert event["completion_tokens"] == 0
    assert len(stream.getvalue().splitlines()) == 1
