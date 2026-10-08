"""Tenant findings: one open row per rule and subject."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    UUID as SqlUUID,
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
