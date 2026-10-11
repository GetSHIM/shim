"""Tenant findings: one open row per rule and subject."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from decimal import Decimal

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    Numeric,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    UUID as SqlUUID,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from shim_enterprise.core.database import Base, TimestampMixin


class Finding(Base, TimestampMixin):
    """A rule's conclusion about one subject, with evidence, impact and the fix."""

    __tablename__ = "findings"
    __table_args__ = (
        CheckConstraint("severity_id BETWEEN 1 AND 5", name="ck_findings_severity_id"),
        CheckConstraint("status_id BETWEEN 1 AND 4", name="ck_findings_status_id"),
        CheckConstraint("occurrences >= 1", name="ck_findings_occurrences"),
        ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_findings_organization_id_organizations",
        ),
        Index(
            "uq_findings_open_subject",
            "organization_id",
            "rule_id",
            "subject_key",
            unique=True,
            postgresql_where=text("status_id <> 4"),
        ),
        Index("ix_findings_org_last_seen", "organization_id", "last_seen_at"),
    )

    id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    organization_id: Mapped[UUID] = mapped_column(SqlUUID(as_uuid=True), nullable=False)
    source: Mapped[str] = mapped_column(
        String(32), nullable=False, default="gateway", server_default="gateway"
    )
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_version: Mapped[int] = mapped_column(Integer, nullable=False)
    subject_key: Mapped[str] = mapped_column(Text, nullable=False)
    subject: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    severity_id: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    status_id: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, default=1, server_default="1"
    )
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    occurrences: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default="1"
    )
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    impact: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    remediation: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_by: Mapped[str | None] = mapped_column(String(64))


class ExternalUsageRecord(Base):
    """One call another gateway logged, as that gateway reported it; never content.

    Kept apart from request_lifecycle and usage_ledger: the source's claim, read by
    the findings it raises and nothing else.
    """

    __tablename__ = "external_usage_records"
    __table_args__ = (
        CheckConstraint("source IN ('litellm')", name="ck_external_usage_source"),
        UniqueConstraint(
            "organization_id",
            "source",
            "source_request_id",
            name="uq_external_usage_source_request",
        ),
        Index(
            "ix_external_usage_tenant_source_started",
            "organization_id",
            "source",
            "started_at",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey(
            "organizations.id",
            name="fk_external_usage_organization",
            ondelete="CASCADE",
        ),
        nullable=False,
    )
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    source_request_id: Mapped[str] = mapped_column(String(255), nullable=False)
    import_id: Mapped[UUID] = mapped_column(SqlUUID(as_uuid=True), nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ttft_ms: Mapped[int | None] = mapped_column(Integer)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    status: Mapped[str | None] = mapped_column(String(32))
    call_type: Mapped[str | None] = mapped_column(String(64))
    model: Mapped[str | None] = mapped_column(String(255))
    model_group: Mapped[str | None] = mapped_column(String(255))
    provider: Mapped[str | None] = mapped_column(String(64))
    api_base_origin: Mapped[str | None] = mapped_column(String(512))
    source_key_hash: Mapped[str | None] = mapped_column(String(128))
    source_team: Mapped[str | None] = mapped_column(String(255))
    source_user: Mapped[str | None] = mapped_column(String(255))
    prompt_tokens: Mapped[int | None] = mapped_column(Integer)
    completion_tokens: Mapped[int | None] = mapped_column(Integer)
    cost_usd: Mapped[Decimal | None] = mapped_column(Numeric(18, 8))
    cache_hit: Mapped[bool | None] = mapped_column(Boolean)
    tags: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    imported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
