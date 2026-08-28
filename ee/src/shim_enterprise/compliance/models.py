"""Tenant-owned compliance connector metadata and derived findings."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    UUID as SqlUUID,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from shim_enterprise.core.database import Base, TimestampMixin


class ComplianceConnector(Base, TimestampMixin):
    """Tenant connector with an opaque SecretStore credential reference."""

    __tablename__ = "compliance_connector"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "provider", name="uq_compliance_connector_provider"
        ),
        CheckConstraint(
            "status IN ('active', 'paused', 'error')",
            name="ck_compliance_connector_status",
        ),
        CheckConstraint(
            "consecutive_errors >= 0", name="ck_compliance_connector_errors"
        ),
        CheckConstraint(
            "retention_days IS NULL OR retention_days > 0",
            name="ck_compliance_connector_retention",
        ),
        CheckConstraint(
            "length(masked_key) > 0",
            name="ck_compliance_connector_masked_key",
        ),
        Index("ix_compliance_connector_tenant", "organization_id"),
    )

    id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="active", server_default="active"
    )
    secret_ref: Mapped[str] = mapped_column(Text, nullable=False)
    secret_backend: Mapped[str] = mapped_column(String(32), nullable=False)
    secret_version: Mapped[str] = mapped_column(String(128), nullable=False)
    masked_key: Mapped[str] = mapped_column(String(64), nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cursor: Mapped[str | None] = mapped_column(Text)
    scope_type: Mapped[str | None] = mapped_column(String(32))
    scope_id: Mapped[str | None] = mapped_column(String(255))
    retention_days: Mapped[int | None] = mapped_column(Integer)
    backfill_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    backfill_completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    consecutive_errors: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    config: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )

    activities: Mapped[list[ComplianceActivity]] = relationship(
        back_populates="connector", cascade="all, delete-orphan"
    )
    findings: Mapped[list[ComplianceFinding]] = relationship(
        back_populates="connector", cascade="all, delete-orphan"
    )
    forward_targets: Mapped[list[ComplianceForwardTarget]] = relationship(
        back_populates="connector", cascade="all, delete-orphan"
    )
    ingest_cursors: Mapped[list[ComplianceIngestCursor]] = relationship(
        back_populates="connector", cascade="all, delete-orphan"
    )
    log_files: Mapped[list[ComplianceLogFile]] = relationship(
        back_populates="connector", cascade="all, delete-orphan"
    )


class ComplianceActivity(Base, TimestampMixin):
    """Metadata-only provider activity; raw provider content is never stored."""

    __tablename__ = "compliance_activity"
    __table_args__ = (
        UniqueConstraint(
            "connector_id", "provider_event_id", name="uq_compliance_activity_event"
        ),
        Index("ix_compliance_activity_event_type", "event_type"),
        Index("ix_compliance_activity_occurred", "occurred_at"),
    )

    id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    connector_id: Mapped[UUID] = mapped_column(
        ForeignKey("compliance_connector.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provider_event_id: Mapped[str] = mapped_column(String(255), nullable=False)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_email: Mapped[str | None] = mapped_column(String(320))
    actor_user_id: Mapped[str | None] = mapped_column(String(255))
    actor_ip: Mapped[str | None] = mapped_column(String(64))
    occurred_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    extras: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )

    connector: Mapped[ComplianceConnector] = relationship(back_populates="activities")
    findings: Mapped[list[ComplianceFinding]] = relationship(back_populates="activity")


class ComplianceFinding(Base, TimestampMixin):
    """Classification and salted match hash without the matched PII value."""

    __tablename__ = "compliance_finding"
    __table_args__ = (
        UniqueConstraint(
            "connector_id",
            "content_id",
            "value_hash",
            "match_offset",
            name="uq_compliance_finding_dedup",
        ),
        CheckConstraint("match_offset >= 0", name="ck_compliance_finding_offset"),
        CheckConstraint("match_length > 0", name="ck_compliance_finding_length"),
        CheckConstraint(
            "severity IN ('low', 'medium', 'high', 'critical')",
            name="ck_compliance_finding_severity",
        ),
        Index("ix_compliance_finding_severity", "severity"),
        Index("ix_compliance_finding_entity", "entity_type"),
        Index("ix_compliance_finding_occurred", "occurred_at"),
    )

    id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    connector_id: Mapped[UUID] = mapped_column(
        ForeignKey("compliance_connector.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    activity_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("compliance_activity.id", ondelete="SET NULL")
    )
    content_id: Mapped[str] = mapped_column(String(255), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    kvkk_category: Mapped[str | None] = mapped_column(String(128))
    gdpr_category: Mapped[str | None] = mapped_column(String(128))
    match_offset: Mapped[int] = mapped_column(Integer, nullable=False)
    match_length: Mapped[int] = mapped_column(Integer, nullable=False)
    value_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_email: Mapped[str | None] = mapped_column(String(320))
    model: Mapped[str | None] = mapped_column(String(255))
    occurred_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source_log_file_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("compliance_log_file.id", ondelete="SET NULL")
    )

    connector: Mapped[ComplianceConnector] = relationship(back_populates="findings")
    activity: Mapped[ComplianceActivity | None] = relationship(
        back_populates="findings"
    )


class ComplianceForwardTarget(Base, TimestampMixin):
    """Outbound SIEM destination represented by a SecretStore endpoint bundle."""

    __tablename__ = "compliance_forward_target"
    __table_args__ = (
        CheckConstraint(
            "kind IN ('siem_webhook', 'slack', 'email')",
            name="ck_compliance_forward_target_kind",
        ),
        CheckConstraint(
            "min_severity IN ('low', 'medium', 'high', 'critical')",
            name="ck_compliance_forward_target_severity",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    connector_id: Mapped[UUID] = mapped_column(
        ForeignKey("compliance_connector.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    kind: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="siem_webhook",
        server_default="siem_webhook",
    )
    endpoint_origin: Mapped[str] = mapped_column(Text, nullable=False)
    secret_ref: Mapped[str] = mapped_column(Text, nullable=False)
    secret_backend: Mapped[str] = mapped_column(String(32), nullable=False)
    secret_version: Mapped[str] = mapped_column(String(128), nullable=False)
    signed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    min_severity: Mapped[str] = mapped_column(
        String(16), nullable=False, default="high", server_default="high"
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )

    connector: Mapped[ComplianceConnector] = relationship(
        back_populates="forward_targets"
    )


class ComplianceIngestCursor(Base, TimestampMixin):
    """Durable high-water mark for one provider event stream."""

    __tablename__ = "compliance_ingest_cursor"
    __table_args__ = (
        UniqueConstraint(
            "connector_id", "event_type", name="uq_compliance_ingest_cursor_stream"
        ),
        CheckConstraint(
            "lag_seconds IS NULL OR lag_seconds >= 0",
            name="ck_compliance_ingest_cursor_lag",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    connector_id: Mapped[UUID] = mapped_column(
        ForeignKey("compliance_connector.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    last_end_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_file_id: Mapped[str | None] = mapped_column(String(255))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lag_seconds: Mapped[int | None] = mapped_column(Integer)

    connector: Mapped[ComplianceConnector] = relationship(
        back_populates="ingest_cursors"
    )


class ComplianceLogFile(Base, TimestampMixin):
    """File-level ingestion deduplication without persisted file contents."""

    __tablename__ = "compliance_log_file"
    __table_args__ = (
        UniqueConstraint(
            "connector_id", "provider_file_id", name="uq_compliance_log_file_dedup"
        ),
        CheckConstraint(
            "status IN ('pending', 'downloaded', 'processed', 'error')",
            name="ck_compliance_log_file_status",
        ),
        CheckConstraint(
            "record_count IS NULL OR record_count >= 0",
            name="ck_compliance_log_file_count",
        ),
        CheckConstraint(
            "window_start IS NULL OR window_end IS NULL OR window_end >= window_start",
            name="ck_compliance_log_file_window",
        ),
        Index("ix_compliance_log_file_event", "event_type"),
    )

    id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    connector_id: Mapped[UUID] = mapped_column(
        ForeignKey("compliance_connector.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    provider_file_id: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="pending", server_default="pending"
    )
    record_count: Mapped[int | None] = mapped_column(Integer)
    window_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    window_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    connector: Mapped[ComplianceConnector] = relationship(back_populates="log_files")
