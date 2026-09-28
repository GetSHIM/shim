import asyncio
import json
from pathlib import Path
import subprocess
import sys

import pytest

from shim_enterprise.workers import (
    ai_act,
    compliance,
    outbox,
    readiness,
    reconciliation,
)


def test_heartbeat_file_and_cli(tmp_path, monkeypatch, caplog):
    path = tmp_path / "heartbeat.json"
    monkeypatch.setattr(readiness.time, "monotonic", lambda: 100.0)
    assert not readiness.is_ready(path, "outbox", 10)
    readiness.write_heartbeat(None, "outbox")
    readiness.write_heartbeat(path, "outbox")
    assert readiness.is_ready(path, "outbox", 10)
    assert not readiness.is_ready(path, "compliance", 10)
    for timestamp in [float("nan"), float("inf"), 101, 89, True, None, "100", 10**1000]:
        path.write_text(
            json.dumps({"worker": "outbox", "monotonic_success": timestamp})
        )
        assert not readiness.is_ready(path, "outbox", 10)
    for payload in ["{", "[]", "null", "{}"]:
        path.write_text(payload)
        assert not readiness.is_ready(path, "outbox", 10)
    for age in [0, -1, float("nan"), float("inf")]:
        assert not readiness.is_ready(path, "outbox", age)
    assert not readiness.is_ready(Path("relative"), "outbox", 10)
    readiness.write_heartbeat(tmp_path / "missing" / "secret-path", "outbox")
    assert "Worker heartbeat write failed" in caplog.text
    assert "secret-path" not in caplog.text
    monkeypatch.undo()
    readiness.write_heartbeat(path, "outbox")
    command = [
        sys.executable,
        "-m",
        "shim_enterprise.workers.readiness",
        "--path",
        str(path),
        "--worker",
        "outbox",
        "--max-age-seconds",
        "10",
    ]
    assert subprocess.run(command, capture_output=True).returncode == 0
    path.write_text("invalid")
    assert subprocess.run(command, capture_output=True).returncode == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "module,worker_class,summary",
    [
        (outbox, outbox.OutboxWorker, outbox.WorkerPass(0, 0, 0, 0, 0)),
        (outbox, outbox.OutboxWorker, outbox.WorkerPass(1, 0, 1, 0, 0)),
        (outbox, outbox.OutboxWorker, outbox.WorkerPass(1, 0, 0, 1, 0)),
        (outbox, outbox.OutboxWorker, outbox.WorkerPass(1, 0, 0, 0, 1)),
        (compliance, compliance.ComplianceSweepWorker, compliance.SweepSummary()),
        (
            compliance,
            compliance.ComplianceSweepWorker,
            compliance.SweepSummary(errors=1),
        ),
        (ai_act, ai_act.AuditMaintenanceWorker, ai_act.MaintenanceSummary()),
        (ai_act, ai_act.AuditMaintenanceWorker, ai_act.MaintenanceSummary(errors=1)),
        (reconciliation, reconciliation.ReconciliationWorker, 0),
    ],
)
async def test_only_successful_pass_refreshes_heartbeat(
    tmp_path, monkeypatch, module, worker_class, summary
):
    path = tmp_path / "heartbeat.json"
    monkeypatch.setattr(module.settings, "WORKER_HEARTBEAT_PATH", path)
    worker = object.__new__(worker_class)
    worker.interval_seconds = 1
    worker.worker_id = "test"
    stop = asyncio.Event()

    async def run_once():
        stop.set()
        return summary

    worker.run_once = run_once
    await worker.run(stop)
    failures = sum(
        getattr(summary, key, 0)
        for key in ("failed", "dead_lettered", "lease_lost", "errors")
    )
    assert path.exists() == (failures == 0)
    stop.clear()

    async def fail():
        stop.set()
        raise RuntimeError("unavailable")

    worker.run_once = fail
    previous = path.read_bytes() if path.exists() else None
    await worker.run(stop)
    assert (path.read_bytes() if path.exists() else None) == previous


@pytest.mark.asyncio
async def test_anchor_failure_is_reported(monkeypatch):
    from contextlib import asynccontextmanager
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    @asynccontextmanager
    async def transaction():
        yield

    session = SimpleNamespace(
        execute=AsyncMock(return_value=SimpleNamespace(scalars=lambda: ["tenant"])),
        begin_nested=transaction,
    )
    monkeypatch.setattr(
        ai_act, "write_anchor", AsyncMock(side_effect=OSError("secret"))
    )
    worker = object.__new__(ai_act.AuditMaintenanceWorker)
    assert await worker._anchor_tenants(session, None) == (0, 1)
