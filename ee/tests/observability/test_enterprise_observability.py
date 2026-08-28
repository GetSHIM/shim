from __future__ import annotations

import json
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

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
