"""Read-only audit-chain and daily-anchor integrity verification."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.ai_act import audit_writer
from shim_enterprise.ai_act.audit_writer import (
    canonical_fields_from_values,
    row_to_values,
)
from shim_enterprise.ai_act.hashing import compute_row_hash, genesis_hash
from shim_enterprise.ai_act.models import AIActAuditAnchor, AIActAuditLog
from shim_enterprise.ai_act.anchor import DailyAnchorLimitExceeded, compute_daily_anchor


MAX_SYNC_AUDIT_ROWS = 10_000
MAX_SYNC_AUDIT_ANCHORS = 366


class AuditVerificationLimitExceeded(ValueError):
    """Raised before interactive verification exceeds its resource budget."""


def _break(sequence: int, row_id: UUID, reason: str) -> dict[str, object]:
    return {"seq": sequence, "id": str(row_id), "reason": reason}


async def verify_chain(
    session: AsyncSession,
    org_id: UUID,
    *,
    salt: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
) -> dict[str, object]:
    """Verify the full chain prefix through ``end`` and report the first break."""

    organization_id = UUID(str(org_id))
    statement = (
        select(AIActAuditLog)
        .where(AIActAuditLog.organization_id == organization_id)
        .order_by(AIActAuditLog.seq)
        .limit(MAX_SYNC_AUDIT_ROWS + 1)
    )
    if end is not None:
        statement = statement.where(AIActAuditLog.created_at <= end)
    rows = list((await session.execute(statement)).scalars())
    if len(rows) > MAX_SYNC_AUDIT_ROWS:
        raise AuditVerificationLimitExceeded(
            f"synchronous verification is limited to {MAX_SYNC_AUDIT_ROWS} rows"
        )
    selected = [
        row
        for row in rows
        if (start is None or row.created_at >= start)
        and (end is None or row.created_at <= end)
    ]
    if not rows:
        return {
            "ok": True,
            "rows_checked": 0,
            "rows_selected": 0,
            "first_break": None,
            "last_verified_seq": None,
        }

    chain_salt = salt if salt is not None else audit_writer.audit_salt()
    expected_sequence = 1
    expected_previous = genesis_hash(chain_salt, str(organization_id))
    last_verified: int | None = None
    for row in rows:
        if row.seq != expected_sequence:
            return _failure(rows, selected, row, "seq_gap", last_verified)
        if row.prev_hash != expected_previous:
            reason = "genesis_mismatch" if row.seq == 1 else "prev_hash_mismatch"
            return _failure(rows, selected, row, reason, last_verified)
        recomputed = compute_row_hash(
            row.prev_hash,
            canonical_fields_from_values(row_to_values(row)),
        )
        if recomputed != row.row_hash:
            return _failure(rows, selected, row, "row_hash_mismatch", last_verified)
        expected_sequence += 1
        expected_previous = row.row_hash
        last_verified = row.seq
    return {
        "ok": True,
        "rows_checked": len(rows),
        "rows_selected": len(selected),
        "first_break": None,
        "last_verified_seq": last_verified,
    }


def _failure(
    rows: list[AIActAuditLog],
    selected: list[AIActAuditLog],
    row: AIActAuditLog,
    reason: str,
    last_verified: int | None,
) -> dict[str, object]:
    return {
        "ok": False,
        "rows_checked": len(rows),
        "rows_selected": len(selected),
        "first_break": _break(row.seq, row.id, reason),
        "last_verified_seq": last_verified,
    }


async def verify_anchors(
    session: AsyncSession,
    org_id: UUID,
    *,
    start: datetime | None = None,
    end: datetime | None = None,
) -> dict[str, object]:
    organization_id = UUID(str(org_id))
    statement = (
        select(AIActAuditAnchor)
        .where(AIActAuditAnchor.organization_id == organization_id)
        .order_by(AIActAuditAnchor.anchor_date)
    )
    if start is not None:
        statement = statement.where(
            AIActAuditAnchor.anchor_date >= start.astimezone(timezone.utc).date()
        )
    if end is not None:
        statement = statement.where(
            AIActAuditAnchor.anchor_date <= end.astimezone(timezone.utc).date()
        )
    anchors = list(
        (await session.execute(statement.limit(MAX_SYNC_AUDIT_ANCHORS + 1))).scalars()
    )
    if len(anchors) > MAX_SYNC_AUDIT_ANCHORS:
        raise AuditVerificationLimitExceeded(
            f"synchronous verification is limited to {MAX_SYNC_AUDIT_ANCHORS} anchors"
        )
    mismatches: list[dict[str, object]] = []
    remaining_rows = MAX_SYNC_AUDIT_ROWS
    for anchor in anchors:
        if remaining_rows < 1 or anchor.row_count > remaining_rows:
            raise AuditVerificationLimitExceeded(
                "synchronous verification is limited to "
                f"{MAX_SYNC_AUDIT_ROWS} anchor rows"
            )
        try:
            computed = await compute_daily_anchor(
                session,
                organization_id,
                anchor.anchor_date,
                max_rows=remaining_rows,
            )
        except DailyAnchorLimitExceeded as exc:
            raise AuditVerificationLimitExceeded(str(exc)) from None
        remaining_rows -= computed.row_count
        if (
            computed.root_hash != anchor.root_hash
            or computed.tip_hash != anchor.tip_hash
            or computed.row_count != anchor.row_count
            or computed.from_seq != anchor.from_seq
            or computed.to_seq != anchor.to_seq
        ):
            mismatches.append(
                {
                    "anchor_date": anchor.anchor_date.isoformat(),
                    "stored_root": anchor.root_hash,
                    "recomputed_root": computed.root_hash,
                    "stored_row_count": anchor.row_count,
                    "live_row_count": computed.row_count,
                }
            )
    return {
        "ok": not mismatches,
        "anchors_checked": len(anchors),
        "mismatches": mismatches,
    }
