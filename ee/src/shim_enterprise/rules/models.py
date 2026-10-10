"""The tenant's rule set: one row per organization, replaced whole on every change."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
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
