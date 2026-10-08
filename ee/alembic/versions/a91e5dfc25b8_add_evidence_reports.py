"""Store generated monthly evidence files.

Revision: a91e5dfc25b8
Parent: 5050a43c2a46
Created: 2026-10-08
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "a91e5dfc25b8"
down_revision: str | Sequence[str] | None = "5050a43c2a46"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "evidence_reports",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("period", sa.String(length=7), nullable=False),
        sa.Column("format", sa.String(length=8), server_default="pdf", nullable=False),
        sa.Column("content", sa.LargeBinary(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("generator_version", sa.String(length=64), nullable=False),
        sa.CheckConstraint(
            "kind IN ('monthly', 'monthly_partial')", name="ck_evidence_reports_kind"
        ),
        sa.CheckConstraint("format = 'pdf'", name="ck_evidence_reports_format"),
        sa.CheckConstraint(
            "period ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'", name="ck_evidence_reports_period"
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_evidence_reports_organization_id",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id", "kind", "period", name="uq_evidence_reports_period"
        ),
    )


def downgrade() -> None:
    # Downgrades are disposable-only; stored evidence files are lost.
    op.drop_table("evidence_reports")
