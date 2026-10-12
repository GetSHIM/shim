"""A held request: who sent it, what matched and how big it was; never its content.

Its keyed digest lives only while the row can still be used.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, get_args
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    func,
    text,
)
from sqlalchemy import UUID as SqlUUID
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from shim_enterprise.core.database import Base

ApprovalStatus = Literal["pending", "approved", "rejected", "expired", "used"]
STATUSES: tuple[str, ...] = get_args(ApprovalStatus)


class RequestApproval(Base):
    __tablename__ = "request_approvals"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'approved', 'rejected', 'expired', 'used')",
            name="ck_request_approvals_status",
        ),
        Index(
            "uq_request_approvals_pending_digest",
            "organization_id",
            "request_digest",
            unique=True,
            postgresql_where=text("status = 'pending'"),
        ),
        Index(
            "ix_request_approvals_tenant_status_created",
            "organization_id",
            "status",
            "created_at",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey(
            "organizations.id",
            name="fk_request_approvals_organization",
            ondelete="CASCADE",
        ),
        nullable=False,
    )
    api_key_id: Mapped[UUID] = mapped_column(
        ForeignKey(
            "api_keys.id", name="fk_request_approvals_api_key", ondelete="CASCADE"
        ),
        nullable=False,
    )
    requested_by: Mapped[UUID | None] = mapped_column(SqlUUID(as_uuid=True))
    team_id: Mapped[UUID | None] = mapped_column(SqlUUID(as_uuid=True))
    # Cleared once the row can no longer be used: used, expired or rejected.
    request_digest: Mapped[str | None] = mapped_column(String(64))
    request_id: Mapped[str] = mapped_column(String(64), nullable=False)
    protocol: Mapped[str] = mapped_column(String(24), nullable=False)
    provider: Mapped[str] = mapped_column(String(16), nullable=False)
    model: Mapped[str] = mapped_column(String(255), nullable=False)
    stream: Mapped[bool] = mapped_column(Boolean, nullable=False)
    rule_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    detected: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    input_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    estimated_input_tokens: Mapped[int | None] = mapped_column(Integer)
    status: Mapped[ApprovalStatus] = mapped_column(
        String(16), nullable=False, default="pending", server_default="pending"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    decided_by: Mapped[UUID | None] = mapped_column(SqlUUID(as_uuid=True))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    use_by: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    used_request_id: Mapped[str | None] = mapped_column(String(64))
