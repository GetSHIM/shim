"""The tenant's semantic questions and the reviews of archived requests."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    UniqueConstraint,
    UUID as SqlUUID,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from shim_enterprise.core.database import Base, TimestampMixin


class OrganizationSemanticQuestions(Base, TimestampMixin):
    """One row per tenant; the questions are the tenant's own confidential text."""

    __tablename__ = "organization_semantic_questions"
    __table_args__ = (
        CheckConstraint(
            "revision >= 0", name="ck_organization_semantic_questions_revision"
        ),
    )

    organization_id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True),
        ForeignKey(
            "organizations.id",
            name="fk_organization_semantic_questions_organization_id",
            ondelete="CASCADE",
        ),
        primary_key=True,
    )
    revision: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    questions: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    updated_by: Mapped[UUID | None] = mapped_column(
        SqlUUID(as_uuid=True),
        ForeignKey(
            "users.id",
            name="fk_organization_semantic_questions_updated_by",
            ondelete="SET NULL",
        ),
    )


class SemanticReview(Base):
    """One archived item read against one revision of the questions."""

    __tablename__ = "semantic_reviews"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'matched', 'clear', 'invalid_answer', 'failed', "
            "'skipped_guard', 'skipped_empty')",
            name="ck_semantic_reviews_status",
        ),
        UniqueConstraint(
            "archive_id", "questions_revision", name="uq_semantic_reviews_item_revision"
        ),
        Index("ix_semantic_reviews_org_created_at", "organization_id", "created_at"),
        Index(
            "ix_semantic_reviews_org_status_claimed_at",
            "organization_id",
            "status",
            "claimed_at",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    organization_id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True),
        ForeignKey(
            "organizations.id",
            name="fk_semantic_reviews_organization_id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )
    archive_id: Mapped[UUID] = mapped_column(
        SqlUUID(as_uuid=True),
        ForeignKey(
            "request_archive.id",
            name="fk_semantic_reviews_archive_id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )
    request_id: Mapped[str] = mapped_column(String(255), nullable=False)
    api_key_id: Mapped[UUID | None] = mapped_column(SqlUUID(as_uuid=True))
    questions_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    matched_question_ids: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    review_request_id: Mapped[str | None] = mapped_column(String(255))
    cost_usd: Mapped[Decimal | None] = mapped_column(Numeric(18, 8))
    error_code: Mapped[str | None] = mapped_column(String(64))
    claimed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
