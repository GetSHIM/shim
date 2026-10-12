"""The tenant's rule set: one row per organization, replaced whole on every change."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    PrimaryKeyConstraint,
    SmallInteger,
    String,
    func,
    text,
)
from sqlalchemy import UUID as SqlUUID
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from shim_enterprise.core.database import Base


class OrganizationRuleSet(Base):
    __tablename__ = "organization_rule_sets"
    __table_args__ = (
        CheckConstraint("revision >= 0", name="ck_organization_rule_sets_revision"),
    )

    organization_id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True),
        ForeignKey(
            "organizations.id",
            name="fk_organization_rule_sets_organization",
            ondelete="CASCADE",
        ),
        primary_key=True,
    )
    revision: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    rules: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    updated_by: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class RuleDefinition(Base):
    """When a rule's kind, scope or match last changed: where its monitor history starts."""

    __tablename__ = "rule_definitions"
    __table_args__ = (
        PrimaryKeyConstraint("organization_id", "rule_id", name="pk_rule_definitions"),
    )

    organization_id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True),
        ForeignKey(
            "organizations.id",
            name="fk_rule_definitions_organization",
            ondelete="CASCADE",
        ),
    )
    rule_id: Mapped[str] = mapped_column(String(48))
    definition_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    defined_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class RulePreview(Base):
    """A preview that lets this exact rule be created enforced, for 24 hours."""

    __tablename__ = "rule_previews"
    __table_args__ = (
        CheckConstraint(
            "basis IN ('metadata', 'monitor_history')", name="ck_rule_previews_basis"
        ),
        Index(
            "ix_rule_previews_tenant_rule", "organization_id", "rule_id", "expires_at"
        ),
    )

    id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    organization_id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True),
        ForeignKey(
            "organizations.id",
            name="fk_rule_previews_organization",
            ondelete="CASCADE",
        ),
        nullable=False,
    )
    rule_id: Mapped[str] = mapped_column(String(48), nullable=False)
    preview_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    basis: Mapped[str] = mapped_column(String(24), nullable=False)
    requests: Mapped[int] = mapped_column(Integer, nullable=False)
    window_days: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    window_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    window_end: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    created_by: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
