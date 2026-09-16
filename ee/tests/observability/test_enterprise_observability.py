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

    # The payload must satisfy the audit contract the repository enforces.
    validate_audit_intent(uuid4(), {**captured, "tenant_id": uuid4()})

    summary = captured["usage_summary"]
    assert captured["lifecycle_status"] == "spend_denied"
    assert summary["spend_denied"] == 1

    # A reader that misses this key or value counts the denial as a technical failure.
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
