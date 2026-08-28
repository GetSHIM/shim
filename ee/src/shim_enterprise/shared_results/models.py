"""Persistent privacy-scrubbed Playground results."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UUID as SqlUUID,
)
from sqlalchemy.orm import Mapped, mapped_column

from shim_enterprise.core.database import Base, TimestampMixin


class SharedResult(Base, TimestampMixin):
    """A bounded public view containing no raw access token or unscrubbed text."""

    __tablename__ = "shared_results"
    __table_args__ = (
        CheckConstraint(
            "view_count >= 0 AND view_count <= max_views",
            name="ck_shared_results_view_count",
        ),
        CheckConstraint(
            "max_views >= 1 AND max_views <= 25",
            name="ck_shared_results_max_views",
        ),
        CheckConstraint(
            "char_length(token_hash) = 64",
            name="ck_shared_results_token_hash",
        ),
        Index("ix_shared_results_token_hash", "token_hash", unique=True),
        Index("ix_shared_results_organization_id", "organization_id"),
    )

    id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    prompt: Mapped[str] = mapped_column(Text, nullable=False)
    response: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    view_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    max_views: Mapped[int] = mapped_column(
        Integer, nullable=False, default=25, server_default="25"
    )
