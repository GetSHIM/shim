"""Transactional audit intent shared by management and identity synchronization."""

from datetime import datetime, timezone
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from shim.gateway.contracts.ids import TenantId
from shim_enterprise.outbox.publisher import OutboxWriter
from shim_enterprise.tenants.models import User


async def record_management_action(
    session: AsyncSession,
    user: User,
    action: str,
    subject_id: str,
    *,
    details: dict[str, object] | None = None,
) -> str:
    """Append non-secret change facts to the caller's transaction; never commit."""
    event_id = f"management:{uuid4()}"
    await OutboxWriter().append(
        session,
        organization_id=TenantId(user.organization_id),
        values={
            "event_type": "audit.chain_append_requested",
            "aggregate_type": "management",
            "aggregate_id": event_id,
            "idempotency_key": f"{event_id}:audit",
            "payload": {
                "organization_id": str(user.organization_id),
                "request_id": event_id,
                "event_type": "management_action",
                "actor": str(user.id),
                "endpoint": action,
                "extra": {
                    "subject_id": subject_id,
                    "actor_type": "service" if user.kind == "service" else "user_jwt",
                    **(details or {}),
                },
            },
            "status": "pending",
            "next_attempt_at": datetime.now(timezone.utc),
        },
    )
    return event_id


def change_details(
    before: dict[str, Any] | None, after: dict[str, Any] | None
) -> dict[str, object]:
    """Before/after of the fields that differ; one side only for create or delete."""
    changed = [
        field
        for field in after or before or {}
        if before is None or after is None or before[field] != after[field]
    ]
    return {
        label: {
            field: str(facts[field])
            if isinstance(facts[field], (Decimal, UUID))
            else facts[field]
            for field in changed
        }
        for label, facts in (("before", before), ("after", after))
        if facts is not None
    }


def export_details(
    start: datetime | None, end: datetime | None, **facts: object
) -> dict[str, object]:
    """The window and size of an evidence export, for its read audit event."""
    return {
        "start": start.isoformat() if start is not None else None,
        "end": end.isoformat() if end is not None else None,
        **facts,
    }
