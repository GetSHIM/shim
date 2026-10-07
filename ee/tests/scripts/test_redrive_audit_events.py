from datetime import datetime, timezone
from pathlib import Path
import runpy
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select

from shim_enterprise.ai_act.audit_writer import write_audit_row
from shim_enterprise.ai_act.models import AIActAuditLog
from shim_enterprise.outbox.handlers import (
    AUDIT_CHAIN_APPEND,
    BUDGET_THRESHOLD,
    append_audit_chain,
)
from shim_enterprise.outbox.models import OutboxEvent
from shim_enterprise.outbox.publisher import OutboxMessage
from shim_enterprise.tenants.models import Organization


redrive = runpy.run_path(
    str(Path(__file__).parents[2] / "scripts" / "redrive_audit_events.py")
)["redrive"]


def _event(
    organization_id: UUID,
    *,
    event_type: str = AUDIT_CHAIN_APPEND,
    status: str = "dead_letter",
) -> OutboxEvent:
    request_id = f"req_redrive_{uuid4().hex}"
    return OutboxEvent(
        organization_id=organization_id,
        event_type=event_type,
        aggregate_type="request",
        aggregate_id=request_id,
        idempotency_key=f"redrive:{request_id}",
        payload={"organization_id": str(organization_id), "request_id": request_id},
        status=status,
        attempt_count=8,
        next_attempt_at=datetime(2026, 10, 1, tzinfo=timezone.utc),
    )


@pytest.mark.asyncio
async def test_redrive_resets_only_dead_audit_events(db, test_org) -> None:
    other = Organization(id=uuid4(), name="Re-drive", slug=f"redrive-{uuid4().hex}")
    db.add(other)
    await db.flush()
    dead = [_event(test_org.id), _event(test_org.id)]
    untouched = [
        _event(test_org.id, event_type=BUDGET_THRESHOLD),
        _event(test_org.id, status="failed"),
    ]
    other_dead = _event(other.id)
    db.add_all([*dead, *untouched, other_dead])
    await db.flush()

    async def states() -> dict[UUID, tuple[str, int]]:
        rows = await db.execute(
            select(OutboxEvent.id, OutboxEvent.status, OutboxEvent.attempt_count).where(
                OutboxEvent.organization_id.in_((test_org.id, other.id))
            )
        )
        return {row.id: (row.status, row.attempt_count) for row in rows}

    before = await states()
    assert await redrive(db, test_org.id, dry_run=True) == 2
    assert await states() == before

    assert await redrive(db, test_org.id, dry_run=False) == 2
    after = await states()
    assert {after[event.id] for event in dead} == {("pending", 0)}
    assert all(after[event.id] == before[event.id] for event in untouched)
    assert after[other_dead.id] == ("dead_letter", 8)

    assert await redrive(db, None, dry_run=False) == 1
    assert (await states())[other_dead.id] == ("pending", 0)
    assert await redrive(db, None, dry_run=True) == 0


@pytest.mark.asyncio
async def test_redriven_event_already_appended_adds_no_second_row(
    db, test_org, monkeypatch
) -> None:
    event = _event(test_org.id)
    db.add(event)
    await db.flush()
    await write_audit_row(dict(event.payload), db, deduplicate=True)

    async def append(context):
        return await write_audit_row(context, db, deduplicate=True)

    monkeypatch.setattr(
        "shim_enterprise.ai_act.audit_writer.append_audit_row_deduplicated", append
    )
    assert await redrive(db, test_org.id, dry_run=False) == 1
    await db.refresh(event)
    await append_audit_chain(OutboxMessage.from_event(event))

    rows = await db.scalar(
        select(func.count()).where(
            AIActAuditLog.organization_id == test_org.id,
            AIActAuditLog.request_id == event.aggregate_id,
        )
    )
    assert rows == 1
