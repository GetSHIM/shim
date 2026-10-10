"""Incidents: opened by a person, tracked to closure, tied to notification deadlines."""

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
    SmallInteger,
    String,
    UniqueConstraint,
    UUID as SqlUUID,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from shim_enterprise.core.database import Base, TimestampMixin

IncidentStatus = Literal["new", "in_progress", "on_hold", "resolved", "closed"]
STATUSES: tuple[str, ...] = get_args(IncidentStatus)
Regime = Literal["kvkk_board", "kvkk_data_subjects", "gdpr_authority"]
REGIMES: tuple[str, ...] = get_args(Regime)


class Incident(Base, TimestampMixin):
    """What went wrong, who owns it, and references to the evidence; never content."""

    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint("severity_id BETWEEN 1 AND 5", name="ck_incidents_severity_id"),
        CheckConstraint(
            "status IN ('new', 'in_progress', 'on_hold', 'resolved', 'closed')",
            name="ck_incidents_status",
        ),
        Index(
            "ix_incidents_tenant_status_updated",
            "organization_id",
            "status",
            "updated_at",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey(
            "organizations.id", name="fk_incidents_organization_id", ondelete="CASCADE"
        ),
        nullable=False,
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(
        String(2000), nullable=False, default="", server_default=""
    )
    severity_id: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="new", server_default="new"
    )
    owner_user_id: Mapped[UUID | None] = mapped_column(SqlUUID(as_uuid=True))
    opened_by: Mapped[str] = mapped_column(String(64), nullable=False)
    occurred_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    aware_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    is_suspected_breach: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    breach: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    links: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class IncidentNotification(Base, TimestampMixin):
    """One notification duty of an incident; its state is derived, never stored."""

    __tablename__ = "incident_notifications"
    __table_args__ = (
        UniqueConstraint(
            "incident_id", "regime", name="uq_incident_notifications_incident_regime"
        ),
        CheckConstraint(
            "regime IN ('kvkk_board', 'kvkk_data_subjects', 'gdpr_authority')",
            name="ck_incident_notifications_regime",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey(
            "organizations.id",
            name="fk_incident_notifications_organization_id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )
    incident_id: Mapped[UUID] = mapped_column(
        ForeignKey(
            "incidents.id",
            name="fk_incident_notifications_incident_id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )
    regime: Mapped[str] = mapped_column(String(32), nullable=False)
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    required: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    not_required_reason: Mapped[str | None] = mapped_column(String(1000))
    submissions: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    reminded: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
