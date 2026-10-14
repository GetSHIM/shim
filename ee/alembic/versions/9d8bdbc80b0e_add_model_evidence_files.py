"""Add model evidence documents.

One generated PDF per row with the facts it was built from and both digests; the
file's SHA-256 is also in the audit chain entry the row names. Rows are never updated.

Revision: 9d8bdbc80b0e
Parent: ea548dcbea1b
Created: 2026-10-14 17:30:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "9d8bdbc80b0e"
down_revision: str | Sequence[str] | None = "ea548dcbea1b"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "model_evidence_files",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("title", sa.String(length=120), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("sources", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("facts", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("facts_sha256", sa.String(length=64), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("content", sa.LargeBinary(), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("generated_by", sa.UUID(), nullable=True),
        sa.Column("generator_version", sa.String(length=64), nullable=False),
        sa.Column("audit_event_id", sa.String(length=64), nullable=False),
        sa.CheckConstraint(
            "kind IN ('model_selection', 'routing')",
            name="ck_model_evidence_files_kind",
        ),
        sa.CheckConstraint(
            "window_start < window_end", name="ck_model_evidence_files_window"
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_model_evidence_files_organization_id",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["generated_by"],
            ["users.id"],
            name="fk_model_evidence_files_generated_by",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_model_evidence_files"),
    )
    op.create_index(
        "ix_model_evidence_files_org_generated_at",
        "model_evidence_files",
        ["organization_id", "generated_at"],
    )


def downgrade() -> None:
    op.drop_table("model_evidence_files")
