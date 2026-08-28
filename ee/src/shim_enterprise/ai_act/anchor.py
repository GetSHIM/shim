"""Deterministic daily anchoring for the tenant audit chain."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
import hashlib
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.ai_act.models import AIActAuditAnchor, AIActAuditLog


@dataclass(frozen=True, slots=True)
class DailyAnchor:
    organization_id: UUID
    anchor_date: date
    root_hash: str | None
    tip_hash: str | None
    row_count: int
    from_seq: int | None
    to_seq: int | None


class DailyAnchorLimitExceeded(ValueError):
    """Raised before daily anchor computation exceeds a requested row cap."""


def merkle_root(leaves: list[str]) -> str:
    """Return an order-sensitive SHA-256 Merkle root for hexadecimal leaves."""

    if not leaves:
        raise ValueError("at least one leaf is required")
    level = leaves.copy()
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            hashlib.sha256(f"{left}{right}".encode()).hexdigest()
            for left, right in zip(level[::2], level[1::2], strict=True)
        ]
    return level[0]


async def compute_daily_anchor(
    session: AsyncSession,
    org_id: UUID,
    anchor_date: date,
    *,
    max_rows: int | None = None,
) -> DailyAnchor:
    """Compute a tenant/day anchor without mutating persistence."""

    start = datetime.combine(anchor_date, datetime.min.time(), tzinfo=timezone.utc)
    statement = (
        select(AIActAuditLog.seq, AIActAuditLog.row_hash)
        .where(
            AIActAuditLog.organization_id == org_id,
            AIActAuditLog.created_at >= start,
            AIActAuditLog.created_at < start + timedelta(days=1),
        )
        .order_by(AIActAuditLog.seq)
    )
    if max_rows is not None:
        if max_rows < 1:
            raise ValueError("daily anchor max_rows must be positive")
        statement = statement.limit(max_rows + 1)
    rows = (await session.execute(statement)).all()
    if max_rows is not None and len(rows) > max_rows:
        raise DailyAnchorLimitExceeded(
            f"daily anchor computation is limited to {max_rows} rows"
        )
    if not rows:
        return DailyAnchor(org_id, anchor_date, None, None, 0, None, None)
    hashes = [row.row_hash for row in rows]
    return DailyAnchor(
        organization_id=org_id,
        anchor_date=anchor_date,
        root_hash=merkle_root(hashes),
        tip_hash=hashes[-1],
        row_count=len(rows),
        from_seq=rows[0].seq,
        to_seq=rows[-1].seq,
    )


async def write_anchor(
    session: AsyncSession,
    org_id: UUID,
    anchor_date: date,
    *,
    external_ref: str | None = None,
) -> AIActAuditAnchor | None:
    """Idempotently persist a local anchor; external delivery is not implemented."""

    anchor = await compute_daily_anchor(session, org_id, anchor_date)
    if anchor.row_count == 0:
        return None
    values = {
        "organization_id": anchor.organization_id,
        "anchor_date": anchor.anchor_date,
        "root_hash": anchor.root_hash,
        "tip_hash": anchor.tip_hash,
        "row_count": anchor.row_count,
        "from_seq": anchor.from_seq,
        "to_seq": anchor.to_seq,
        "external_ref": external_ref,
    }
    statement = (
        insert(AIActAuditAnchor)
        .values(**values)
        .on_conflict_do_nothing(
            constraint="uq_ai_anchor_tenant_date",
        )
        .returning(AIActAuditAnchor)
    )
    persisted = (await session.execute(statement)).scalar_one_or_none()
    if persisted is not None:
        return persisted
    return (
        await session.execute(
            select(AIActAuditAnchor).where(
                AIActAuditAnchor.organization_id == org_id,
                AIActAuditAnchor.anchor_date == anchor_date,
            )
        )
    ).scalar_one()
