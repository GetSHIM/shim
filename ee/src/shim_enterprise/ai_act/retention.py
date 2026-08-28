"""Export-only retention selection for immutable AI Act evidence."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.ai_act.models import AIActAuditLog
from shim_enterprise.core.config import settings


RETENTION_FLOOR_DAYS = 180
ArchiveSink = Callable[[dict[str, Any]], Awaitable[None]]


def effective_retention_days() -> int:
    return max(RETENTION_FLOOR_DAYS, settings.AI_ACT_AUDIT_RETENTION_DAYS)


def _archive_record(row: AIActAuditLog) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "organization_id": str(row.organization_id),
        "seq": row.seq,
        "event_type": row.event_type,
        "request_id": row.request_id,
        "created_at": row.created_at.isoformat(),
        "prev_hash": row.prev_hash,
        "row_hash": row.row_hash,
    }


async def archive_expired(
    session: AsyncSession,
    *,
    sink: ArchiveSink | None = None,
    org_id: UUID | None = None,
    now: datetime | None = None,
    retention_days: int | None = None,
) -> dict[str, Any]:
    """Export eligible hashes and counts without deleting authoritative evidence."""

    window = max(
        RETENTION_FLOOR_DAYS,
        retention_days if retention_days is not None else effective_retention_days(),
    )
    current = now or datetime.now(timezone.utc)
    cutoff = current - timedelta(days=window)
    filters = [AIActAuditLog.created_at < cutoff]
    if org_id is not None:
        filters.append(AIActAuditLog.organization_id == org_id)
    if sink is None:
        eligible = int(
            await session.scalar(select(func.count(AIActAuditLog.id)).where(*filters))
            or 0
        )
        return {
            "cutoff": cutoff.isoformat(),
            "retention_days": window,
            "eligible": eligible,
            "exported": 0,
            "deleted": 0,
        }

    statement = select(AIActAuditLog).where(*filters)
    rows = (
        await session.execute(
            statement.order_by(AIActAuditLog.organization_id, AIActAuditLog.seq)
        )
    ).scalars()

    exported = 0
    for row in rows:
        await sink(_archive_record(row))
        exported += 1
    return {
        "cutoff": cutoff.isoformat(),
        "retention_days": window,
        "eligible": exported,
        "exported": exported,
        "deleted": 0,
    }
