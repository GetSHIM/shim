"""Persistence model for the tenant-scoped durable outbox."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID as UUIDValue, uuid4

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from shim_enterprise.core.database import Base
from shim_enterprise.tenants.models import Organization


class OutboxEvent(Base):
    __tablename__ = "outbox_event"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "id",
            name="uq_outbox_event_org_id",
        ),
        UniqueConstraint(
            "organization_id",
            "idempotency_key",
            name="uq_outbox_event_org_idempotency",
        ),
        CheckConstraint(
            "status IN ('pending', 'processing', 'processed', 'failed', 'dead_letter')",
            name="ck_outbox_event_status",
        ),
        CheckConstraint("attempt_count >= 0", name="ck_outbox_event_attempt_count"),
        CheckConstraint(
            "(status = 'processing' AND locked_by IS NOT NULL "
            "AND lease_expires_at IS NOT NULL) OR "
            "(status <> 'processing' AND locked_by IS NULL "
            "AND lease_expires_at IS NULL)",
            name="ck_outbox_event_lease_shape",
        ),
        Index(
            "ix_outbox_event_claimable",
            "status",
            "next_attempt_at",
            postgresql_where=text("status IN ('pending', 'failed')"),
        ),
        Index(
            "ix_outbox_event_expired_lease",
            "lease_expires_at",
            postgresql_where=text("status = 'processing'"),
        ),
    )

    id: Mapped[UUIDValue] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    organization_id: Mapped[UUIDValue] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(Organization.id),
        nullable=False,
    )
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    aggregate_type: Mapped[str] = mapped_column(Text, nullable=False)
    aggregate_id: Mapped[str] = mapped_column(Text, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="pending",
        server_default=text("'pending'"),
    )
    attempt_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default=text("0"),
    )
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    locked_by: Mapped[str | None] = mapped_column(Text, nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )
    processed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    def cancel(self, *, now: datetime) -> None:
        # ponytail: already-running handlers may finish; add cooperative
        # cancellation only if strict revocation becomes a requirement.
        self.status = "processed"
        self.processed_at = now
        self.locked_by = None
        self.lease_expires_at = None
        self.last_error = None
