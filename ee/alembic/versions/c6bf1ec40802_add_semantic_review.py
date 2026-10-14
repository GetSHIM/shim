"""Add the semantic review: a tenant's questions and one review per archived item.

Neither table holds request content; the questions are the tenant's own text. A review
disappears with its archive item.

Revision: c6bf1ec40802
Parent: 9d8bdbc80b0e
Created: 2026-10-14 18:40:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "c6bf1ec40802"
down_revision: str | Sequence[str] | None = "9d8bdbc80b0e"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "organization_semantic_questions",
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("revision", sa.Integer(), server_default="0", nullable=False),
        sa.Column(
            "questions",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("updated_by", sa.UUID(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "revision >= 0", name="ck_organization_semantic_questions_revision"
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_organization_semantic_questions_organization_id",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["updated_by"],
            ["users.id"],
            name="fk_organization_semantic_questions_updated_by",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint(
            "organization_id", name="pk_organization_semantic_questions"
        ),
    )
    op.create_table(
        "semantic_reviews",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("archive_id", sa.UUID(), nullable=False),
        sa.Column("request_id", sa.String(length=255), nullable=False),
        sa.Column("api_key_id", sa.UUID(), nullable=True),
        sa.Column("questions_revision", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column(
            "matched_question_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("review_request_id", sa.String(length=255), nullable=True),
        sa.Column("cost_usd", sa.Numeric(precision=18, scale=8), nullable=True),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'matched', 'clear', 'invalid_answer', 'failed', "
            "'skipped_guard', 'skipped_empty')",
            name="ck_semantic_reviews_status",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_semantic_reviews_organization_id",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["archive_id"],
            ["request_archive.id"],
            name="fk_semantic_reviews_archive_id",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_semantic_reviews"),
        sa.UniqueConstraint(
            "archive_id",
            "questions_revision",
            name="uq_semantic_reviews_item_revision",
        ),
    )
    op.create_index(
        "ix_semantic_reviews_org_created_at",
        "semantic_reviews",
        ["organization_id", "created_at"],
    )
    op.create_index(
        "ix_semantic_reviews_org_status_claimed_at",
        "semantic_reviews",
        ["organization_id", "status", "claimed_at"],
    )


def downgrade() -> None:
    op.drop_table("semantic_reviews")
    op.drop_table("organization_semantic_questions")
