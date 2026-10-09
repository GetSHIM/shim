"""Policy versions and plans: every managed write is versioned, every plan is a change set."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, get_args
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    UUID as SqlUUID,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from shim_enterprise.core.database import Base

SOURCES = ("api", "mcp", "plan", "restore", "file", "auto", "import", "proposal")
RISKS = ("tightening", "relaxing", "neutral")
PlanStatus = Literal[
    "draft", "pending_approval", "applied", "rejected", "expired", "rolled_back"
]
PLAN_STATUSES = get_args(PlanStatus)


def _one_of(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(value) for value in values)})"


class PolicyVersion(Base):
    """The before and after state of the managed items one write changed."""

    __tablename__ = "policy_versions"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "version", name="uq_policy_versions_tenant_version"
        ),
        CheckConstraint(_one_of("source", SOURCES), name="ck_policy_versions_source"),
        CheckConstraint(_one_of("risk", RISKS), name="ck_policy_versions_risk"),
        CheckConstraint(
            _one_of("actor_type", ("user_jwt", "service", "system")),
            name="ck_policy_versions_actor_type",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey(
            "organizations.id",
            name="fk_policy_versions_organization_id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    previous: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    plan_id: Mapped[UUID | None] = mapped_column(SqlUUID(as_uuid=True))
    risk: Mapped[str] = mapped_column(String(16), nullable=False)
    created_by: Mapped[str | None] = mapped_column(String(64))
    actor_type: Mapped[str] = mapped_column(String(16), nullable=False)
    reason: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class PolicyPlan(Base):
    """A change set with its effect, applied in one step or not at all."""

    __tablename__ = "policy_plans"
    __table_args__ = (
        CheckConstraint(_one_of("source", SOURCES), name="ck_policy_plans_source"),
        CheckConstraint(_one_of("risk", RISKS), name="ck_policy_plans_risk"),
        CheckConstraint(
            _one_of("status", PLAN_STATUSES), name="ck_policy_plans_status"
        ),
        CheckConstraint(
            _one_of("created_by_actor_type", ("user_jwt", "service", "system")),
            name="ck_policy_plans_actor_type",
        ),
        Index(
            "ix_policy_plans_tenant_status", "organization_id", "status", "created_at"
        ),
    )

    id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey(
            "organizations.id",
            name="fk_policy_plans_organization_id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )
    base_version: Mapped[int] = mapped_column(Integer, nullable=False)
    changes: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False)
    risk: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    reason: Mapped[str | None] = mapped_column(String(500))
    context: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    created_by: Mapped[str | None] = mapped_column(String(64))
    created_by_actor_type: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    submitted_by: Mapped[str | None] = mapped_column(String(64))
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    approved_by: Mapped[str | None] = mapped_column(String(64))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    applied_by: Mapped[str | None] = mapped_column(String(64))
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    applied_version: Mapped[int | None] = mapped_column(Integer)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
