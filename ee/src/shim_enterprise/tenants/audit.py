"""Transactional audit intent shared by management and identity synchronization."""

from datetime import datetime, timezone
from uuid import uuid4

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
) -> None:
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
                "extra": {"subject_id": subject_id, **(details or {})},
            },
            "status": "pending",
            "next_attempt_at": datetime.now(timezone.utc),
        },
    )
