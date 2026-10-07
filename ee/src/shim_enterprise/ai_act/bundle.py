"""`shim.audit.bundle` v1 export; the format document is FORMAT.md in shim-audit-verify."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.ai_act.audit_writer import (
    audit_salt,
    canonical_fields_from_values,
    gateway_version,
    row_to_values,
)
from shim_enterprise.ai_act.hashing import canonical_row, genesis_hash
from shim_enterprise.ai_act.models import AIActAuditAnchor, AIActAuditLog
from shim_enterprise.ai_act.verify import (
    MAX_SYNC_AUDIT_ANCHORS,
    MAX_SYNC_AUDIT_ROWS,
    AuditVerificationLimitExceeded,
)


def _exported_rows(
    rows: list[tuple[dict[str, Any], str, str, str]],
) -> list[dict[str, Any]]:
    return [
        {
            **json.loads(canonical_row(canonical_fields_from_values(values))),
            "prev_hash": prev_hash,
            "row_hash": row_hash,
            "id": row_id,
        }
        for values, prev_hash, row_hash, row_id in rows
    ]


async def build_audit_bundle(
    session: AsyncSession,
    organization_id: UUID,
    *,
    start: datetime | None,
    end: datetime | None,
    now: datetime,
) -> dict[str, Any] | None:
    statement = (
        select(AIActAuditLog)
        .where(AIActAuditLog.organization_id == organization_id)
        .order_by(AIActAuditLog.seq)
        .limit(MAX_SYNC_AUDIT_ROWS + 1)
    )
    if start is not None:
        statement = statement.where(AIActAuditLog.created_at >= start)
    if end is not None:
        statement = statement.where(AIActAuditLog.created_at <= end)
    rows = list((await session.execute(statement)).scalars())
    if len(rows) > MAX_SYNC_AUDIT_ROWS:
        raise AuditVerificationLimitExceeded(
            f"bundle export is limited to {MAX_SYNC_AUDIT_ROWS} rows"
        )
    if not rows:
        return None
    period_start = (start or rows[0].created_at).astimezone(timezone.utc)
    period_end = (end or now).astimezone(timezone.utc)
    anchors = list(
        (
            await session.execute(
                select(AIActAuditAnchor)
                .where(
                    AIActAuditAnchor.organization_id == organization_id,
                    AIActAuditAnchor.anchor_date >= period_start.date(),
                    AIActAuditAnchor.anchor_date <= period_end.date(),
                )
                .order_by(AIActAuditAnchor.anchor_date)
                .limit(MAX_SYNC_AUDIT_ANCHORS + 1)
            )
        ).scalars()
    )
    if len(anchors) > MAX_SYNC_AUDIT_ANCHORS:
        raise AuditVerificationLimitExceeded(
            f"bundle export is limited to {MAX_SYNC_AUDIT_ANCHORS} anchors"
        )
    # Up to 10,000 rows of canonical JSON: keep the CPU work off the event loop.
    exported = await asyncio.to_thread(
        _exported_rows,
        [
            (row_to_values(row), row.prev_hash, row.row_hash, str(row.id))
            for row in rows
        ],
    )
    genesis = genesis_hash(audit_salt(), str(organization_id))
    first = rows[0]
    return {
        "format": "shim.audit.bundle",
        "format_version": 1,
        "generated_at": now.astimezone(timezone.utc).isoformat(),
        "gateway_version": gateway_version(),
        "organization_id": str(organization_id),
        "genesis_hash": genesis,
        "chain_start": {
            "from_seq": first.seq,
            "prev_hash": genesis if first.seq == 1 else first.prev_hash,
        },
        "period": {"start": period_start.isoformat(), "end": period_end.isoformat()},
        "row_count": len(exported),
        "rows": exported,
        "anchors": [
            {
                "anchor_date": anchor.anchor_date.isoformat(),
                "root_hash": anchor.root_hash,
                "tip_hash": anchor.tip_hash,
                "row_count": anchor.row_count,
                "from_seq": anchor.from_seq,
                "to_seq": anchor.to_seq,
            }
            for anchor in anchors
        ],
        "notes": "Metadata only. No prompt or response bodies are recorded.",
    }
