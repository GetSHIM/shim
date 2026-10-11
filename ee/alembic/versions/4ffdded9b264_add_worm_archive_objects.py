"""Add write-once archive bookkeeping.

One row per object copied to the operator's Object Lock bucket (audit row chunks,
anchors, monthly evidence files), or its last failure. References and checksums
only; the objects themselves live in the bucket.

Revision: 4ffdded9b264
Parent: 79a194bca40f
Created: 2026-10-12
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "4ffdded9b264"
down_revision: str | Sequence[str] | None = "79a194bca40f"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "worm_archive_objects",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("period_key", sa.String(length=64), nullable=False),
        sa.Column("from_seq", sa.BigInteger(), nullable=True),
        sa.Column("to_seq", sa.BigInteger(), nullable=True),
        sa.Column("object_key", sa.String(length=1024), nullable=False),
        sa.Column("version_id", sa.String(length=255), nullable=True),
        sa.Column("sha256", sa.String(length=64), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("lock_mode", sa.String(length=16), nullable=True),
        sa.Column("retain_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("error_type", sa.String(length=64), nullable=True),
        sa.Column("attempts", sa.Integer(), server_default="1", nullable=False),
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
            "kind IN ('audit_rows', 'audit_anchor', 'evidence_monthly')",
            name="ck_worm_archive_objects_kind",
        ),
        sa.CheckConstraint(
            "status IN ('stored', 'failed')", name="ck_worm_archive_objects_status"
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_worm_archive_objects_organization",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "kind",
            "period_key",
            name="uq_worm_archive_objects_period",
        ),
    )


def downgrade() -> None:
    op.drop_table("worm_archive_objects")
