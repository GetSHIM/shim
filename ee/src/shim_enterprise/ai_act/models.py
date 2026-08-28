"""Tenant-scoped AI Act audit-chain and human-oversight persistence."""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    UUID as SqlUUID,
    event,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Mapped, Mapper, mapped_column

from shim_enterprise.core.database import Base, TimestampMixin


class AuditLogImmutableError(RuntimeError):
    """Raised when application code attempts to mutate an append-only audit row."""


class AIActAuditLog(Base):
    """Append-only, tenant-serialized hash-chain entry with no raw content."""

    __tablename__ = "ai_act_audit_log"
    __table_args__ = (
        UniqueConstraint("organization_id", "id", name="uq_ai_audit_tenant_id"),
        UniqueConstraint("organization_id", "seq", name="uq_ai_audit_tenant_seq"),
        ForeignKeyConstraint(
            ["organization_id", "api_key_id"],
            ["api_keys.organization_id", "api_keys.id"],
            name="fk_ai_audit_tenant_api_key",
        ),
        CheckConstraint("seq > 0", name="ck_ai_audit_seq_positive"),
        CheckConstraint(
            "prompt_tokens >= 0 AND completion_tokens >= 0",
            name="ck_ai_audit_tokens_nonnegative",
        ),
        CheckConstraint("latency_ms >= 0", name="ck_ai_audit_latency_nonnegative"),
        CheckConstraint("cost_usd >= 0", name="ck_ai_audit_cost_nonnegative"),
        Index("ix_ai_audit_tenant_created", "organization_id", "created_at"),
        Index("ix_ai_audit_tenant_request", "organization_id", "request_id"),
    )

    id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False
    )
    seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(255))
    api_key_id: Mapped[UUID | None] = mapped_column(SqlUUID(as_uuid=True))
    actor: Mapped[str | None] = mapped_column(String(320))
    model: Mapped[str | None] = mapped_column(String(255))
    provider: Mapped[str | None] = mapped_column(String(64))
    gateway_version: Mapped[str | None] = mapped_column(String(64))
    endpoint: Mapped[str | None] = mapped_column(String(255))
    input_hash: Mapped[str | None] = mapped_column(String(128))
    output_hash: Mapped[str | None] = mapped_column(String(128))
    prompt_tokens: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    completion_tokens: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    pii_detected: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    pii_entities: Mapped[dict[str, int]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )
    policy_verdicts: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list, server_default="[]"
    )
    is_cache_hit: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    latency_ms: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    cost_usd: Mapped[Decimal] = mapped_column(
        Numeric(18, 8), nullable=False, default=Decimal("0"), server_default="0"
    )
    prev_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    row_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    extra: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )


class AIActAuditAnchor(Base):
    """Daily tenant audit-chain root suitable for external anchoring."""

    __tablename__ = "ai_act_audit_anchor"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "anchor_date", name="uq_ai_anchor_tenant_date"
        ),
        CheckConstraint("row_count >= 0", name="ck_ai_anchor_row_count"),
        CheckConstraint(
            "(from_seq IS NULL AND to_seq IS NULL) OR "
            "(from_seq > 0 AND to_seq >= from_seq)",
            name="ck_ai_anchor_sequence_range",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    anchor_date: Mapped[date] = mapped_column(Date, nullable=False)
    root_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    tip_hash: Mapped[str | None] = mapped_column(String(128))
    row_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    from_seq: Mapped[int | None] = mapped_column(BigInteger)
    to_seq: Mapped[int | None] = mapped_column(BigInteger)
    external_ref: Mapped[str | None] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class OversightPolicy(Base, TimestampMixin):
    """Tenant-owned asynchronous human-oversight trigger policy."""

    __tablename__ = "oversight_policy"
    __table_args__ = (
        UniqueConstraint("organization_id", "id", name="uq_oversight_policy_tenant_id"),
        CheckConstraint("mode IN ('flag')", name="ck_oversight_policy_mode"),
        CheckConstraint("ttl_seconds > 0", name="ck_oversight_policy_ttl"),
        CheckConstraint(
            "default_on_timeout IN ('allow', 'deny')",
            name="ck_oversight_policy_timeout",
        ),
        Index("ix_oversight_policy_tenant_enabled", "organization_id", "enabled"),
    )

    id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    mode: Mapped[str] = mapped_column(
        String(16), nullable=False, default="flag", server_default="flag"
    )
    trigger: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )
    ttl_seconds: Mapped[int] = mapped_column(
        Integer, nullable=False, default=3600, server_default="3600"
    )
    default_on_timeout: Mapped[str] = mapped_column(
        String(16), nullable=False, default="allow", server_default="allow"
    )


class OversightRequest(Base, TimestampMixin):
    """Metadata-only oversight decision associated with a tenant audit entry."""

    __tablename__ = "oversight_request"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "audit_log_id",
            name="uq_oversight_request_tenant_audit",
        ),
        ForeignKeyConstraint(
            ["organization_id", "policy_id"],
            ["oversight_policy.organization_id", "oversight_policy.id"],
            name="fk_oversight_request_tenant_policy",
        ),
        ForeignKeyConstraint(
            ["organization_id", "audit_log_id"],
            ["ai_act_audit_log.organization_id", "ai_act_audit_log.id"],
            name="fk_oversight_request_tenant_audit",
        ),
        CheckConstraint(
            "status IN ('pending', 'approved', 'rejected', 'expired')",
            name="ck_oversight_request_status",
        ),
        Index("ix_oversight_request_tenant_status", "organization_id", "status"),
    )

    id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    policy_id: Mapped[UUID | None] = mapped_column(SqlUUID(as_uuid=True))
    request_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    audit_log_id: Mapped[UUID | None] = mapped_column(SqlUUID(as_uuid=True))
    reason: Mapped[str | None] = mapped_column(Text)
    trigger_detail: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="pending", server_default="pending"
    )
    approver: Mapped[str | None] = mapped_column(String(320))
    decision_note: Mapped[str | None] = mapped_column(Text)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


@event.listens_for(AIActAuditLog, "before_update", propagate=True)
def _block_audit_update(
    _mapper: Mapper[AIActAuditLog],
    _connection: Connection,
    _target: AIActAuditLog,
) -> None:
    raise AuditLogImmutableError("ai_act_audit_log is append-only")


@event.listens_for(AIActAuditLog, "before_delete", propagate=True)
def _block_audit_delete(
    _mapper: Mapper[AIActAuditLog],
    _connection: Connection,
    _target: AIActAuditLog,
) -> None:
    raise AuditLogImmutableError("ai_act_audit_log is append-only")
