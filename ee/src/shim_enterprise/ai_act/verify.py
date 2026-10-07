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
_PAGE_ROWS = 2_000


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
    """Verify the chain through ``end`` and report the first break.

    With ``start``, the check starts after the latest daily anchor dated before
    it, linked to that anchor's stored tip; without one it starts at genesis.
    """

    organization_id = UUID(str(org_id))
    expected_sequence = 1
    expected_previous = genesis_hash(
        salt if salt is not None else audit_writer.audit_salt(), str(organization_id)
    )
    chain_start: dict[str, object] = {"from_seq": 1, "anchor_date": None}
    rows_checked = rows_selected = 0
    last_verified: int | None = None

    def result(first_break: dict[str, object] | None) -> dict[str, object]:
        return {
            "ok": first_break is None,
            "rows_checked": rows_checked,
            "rows_selected": rows_selected,
            "first_break": first_break,
            "last_verified_seq": last_verified,
            "chain_start": chain_start,
        }

    if start is not None:
        anchor = (
            await session.execute(
                select(AIActAuditAnchor)
                .where(
                    AIActAuditAnchor.organization_id == organization_id,
                    AIActAuditAnchor.anchor_date
                    < start.astimezone(timezone.utc).date(),
                    AIActAuditAnchor.to_seq.is_not(None),
                )
                .order_by(AIActAuditAnchor.anchor_date.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        if anchor is not None and anchor.to_seq is not None:
            chain_start = {
                "from_seq": anchor.to_seq + 1,
                "anchor_date": anchor.anchor_date.isoformat(),
            }
            link = (
                await session.execute(
                    select(AIActAuditLog).where(
                        AIActAuditLog.organization_id == organization_id,
                        AIActAuditLog.seq == anchor.to_seq,
                    )
                )
            ).scalar_one_or_none()
            if link is None or link.row_hash != anchor.tip_hash:
                row_id = link.id if link is not None else anchor.id
                return result(_break(anchor.to_seq, row_id, "anchor_link_mismatch"))
            expected_sequence = anchor.to_seq + 1
            expected_previous = link.row_hash

    statement = (
        select(AIActAuditLog)
        .where(AIActAuditLog.organization_id == organization_id)
        .order_by(AIActAuditLog.seq)
    )
    if end is not None:
        statement = statement.where(AIActAuditLog.created_at <= end)
    while True:
        # Keyset pages keep memory flat; the budget counts only rows read.
        limit = min(_PAGE_ROWS, MAX_SYNC_AUDIT_ROWS + 1 - rows_checked)
        page = list(
            (
                await session.execute(
                    statement.where(AIActAuditLog.seq >= expected_sequence).limit(limit)
                )
            ).scalars()
        )
        rows_checked += len(page)
        if rows_checked > MAX_SYNC_AUDIT_ROWS:
            raise AuditVerificationLimitExceeded(
                f"synchronous verification is limited to {MAX_SYNC_AUDIT_ROWS} rows"
            )
        for row in page:
            if (start is None or row.created_at >= start) and (
                end is None or row.created_at <= end
            ):
                rows_selected += 1
            if row.seq != expected_sequence:
                return result(_break(row.seq, row.id, "seq_gap"))
            if row.prev_hash != expected_previous:
                reason = "genesis_mismatch" if row.seq == 1 else "prev_hash_mismatch"
                return result(_break(row.seq, row.id, reason))
            recomputed = compute_row_hash(
                row.prev_hash,
                canonical_fields_from_values(row_to_values(row)),
            )
            if recomputed != row.row_hash:
                return result(_break(row.seq, row.id, "row_hash_mismatch"))
            expected_sequence += 1
            expected_previous = row.row_hash
            last_verified = row.seq
        if len(page) < limit:
            return result(None)


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
