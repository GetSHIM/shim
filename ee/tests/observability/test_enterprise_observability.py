from __future__ import annotations

import json
import re
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from sqlalchemy.dialects import postgresql

from shim_enterprise.gateway.contracts.audit import validate_audit_intent
from shim_enterprise.observability.lifecycle import (
    PersistenceConflictError,
    RequestLifecycleRepository,
)


def _registered_metric_names(module: str) -> set[str]:
    code = (
        f"import {module}\n"
        "import json\n"
        "from prometheus_client import REGISTRY\n"
        "print(json.dumps(sorted(metric.name for metric in REGISTRY.collect())))"
    )
    output = subprocess.check_output([sys.executable, "-c", code], text=True)
    return set(json.loads(output.splitlines()[-1]))


def _result(value: object) -> SimpleNamespace:
    return SimpleNamespace(scalar_one_or_none=lambda: value)


def _replay_session(existing: object) -> SimpleNamespace:
    return SimpleNamespace(
        execute=AsyncMock(side_effect=[_result(None), _result(existing)])
    )


def test_enterprise_metric_registration_includes_both_profiles() -> None:
    public = {
        "privacy_detection",
        "provider_latency_ms",
        "provider_requests",
        "requests",
        "stream_terminal_state",
    }
    enterprise_only = {
        "audit_worker_lag_seconds",
        "outbox_dead_letter",
        "outbox_lag_seconds",
        "quota_reservation",
        "usage_settlement",
    }

    enterprise_metrics = _registered_metric_names("shim_enterprise.application")
    assert public | enterprise_only <= enterprise_metrics


@pytest.mark.asyncio
async def test_lifecycle_create_rejects_conflicting_immutable_replay() -> None:
    organization_id = uuid4()
    request_id = "req_lifecycle_replay"
    existing = SimpleNamespace(
        organization_id=organization_id,
        request_id=request_id,
        requested_model="gpt-5",
    )

    with pytest.raises(
        PersistenceConflictError,
        match="^request lifecycle identity conflict$",
    ):
        await RequestLifecycleRepository.create(
            _replay_session(existing),
            organization_id=organization_id,
            values={
                "request_id": request_id,
                "requested_model": "gpt-5-mini",
                "status": "accepted",
            },
        )


@pytest.mark.asyncio
async def test_lifecycle_create_allows_replay_after_mutable_state_progresses() -> None:
    organization_id = uuid4()
    request_id = "req_lifecycle_progressed"
    existing = SimpleNamespace(
        organization_id=organization_id,
        request_id=request_id,
        requested_model="gpt-5",
        status="completed",
    )

    replayed = await RequestLifecycleRepository.create(
        _replay_session(existing),
        organization_id=organization_id,
        values={
            "request_id": request_id,
            "requested_model": "gpt-5",
            "status": "accepted",
        },
    )

    assert replayed is existing


@pytest.mark.asyncio
async def test_spend_denial_audit_matches_every_audit_reader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from shim_enterprise.api.v1.management import _request_summary_statement
    from shim_enterprise.billing import ledger
    from shim_enterprise.observability.overview import _spend_denied

    captured: dict[str, object] = {}

    async def create(session, *, organization_id, values):
        captured.update(values)

    monkeypatch.setattr(ledger.AuditIntentRepository, "create", create)
    monkeypatch.setattr(
        ledger.RequestLifecycleRepository,
        "get",
        AsyncMock(
            return_value=SimpleNamespace(
                lifecycle_metadata={},
                actor_type="api_key",
                api_key_id=uuid4(),
                user_id=None,
            )
        ),
    )

    command = SimpleNamespace(
        tenant_id=uuid4(),
        request_id="req_spend_denied",
        policy_verdicts=(),
        audit_policy_mode="strict",
        input_hash="a" * 64,
        pii_entities=None,
        provider="openai",
        provider_model="gpt-5",
    )
    repository = ledger.DurableAccountingRepository()
    await repository.write_spend_denial_preflight(AsyncMock(), command)

    validate_audit_intent(uuid4(), {**captured, "tenant_id": uuid4()})

    summary = captured["usage_summary"]
    assert captured["lifecycle_status"] == "spend_denied"
    assert summary["spend_denied"] == 1

    for statement in (
        _spend_denied(uuid4()),
        _request_summary_statement(uuid4(), []),
    ):
        compiled = statement.compile(dialect=postgresql.dialect())
        match = re.search(
            r"usage_summary ->> %\((\w+)\)s\) AS INTEGER\) = %\((\w+)\)s",
            str(compiled),
        )
        assert match is not None, "reader no longer compares a usage_summary value"
        key_param, value_param = match.groups()
        assert (compiled.params[key_param], compiled.params[value_param]) == (
            "spend_denied",
            1,
        )


@pytest.mark.parametrize("shim_latency_ms", [None, 0, 17])
def test_analytics_projection_preserves_nullable_shim_measurement(shim_latency_ms):
    from datetime import datetime, timezone
    from shim_enterprise.observability.analytics_projection import _projection_values
    from shim_enterprise.outbox.publisher import OutboxMessage

    tenant_id = uuid4()
    now = datetime.now(timezone.utc)
    payload = {
        "organization_id": str(tenant_id),
        "request_id": "request",
        "api_key_id": str(uuid4()),
        "timestamp": now.isoformat(),
        "latency_ms": 20000,
    }
    if shim_latency_ms is not None:
        payload["shim_latency_ms"] = shim_latency_ms
    message = OutboxMessage(
        id=uuid4(),
        organization_id=tenant_id,
        event_type="analytics.request_completed",
        aggregate_type="request",
        aggregate_id="request",
        idempotency_key="request",
        payload=payload,
        attempt_count=0,
        created_at=now,
    )
    values = _projection_values(message)
    assert values["latency_ms"] == 20000
    assert values["details"]["shim_latency_ms"] == shim_latency_ms
