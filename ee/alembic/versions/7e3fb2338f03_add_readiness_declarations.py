"""Add readiness declarations and the paid readiness report feature.

Revision: 7e3fb2338f03
Parent: a91e5dfc25b8
Created: 2026-10-08
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "7e3fb2338f03"
down_revision: str | Sequence[str] | None = "a91e5dfc25b8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "readiness_declarations",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("framework", sa.String(length=32), nullable=False),
        sa.Column("control_id", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("declared_by", sa.UUID(), nullable=False),
        sa.Column(
            "declared_at",
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
            "status IN ('implemented', 'partial', 'not_implemented', 'not_applicable')",
            name="ck_readiness_declarations_status",
        ),
        sa.CheckConstraint(
            "char_length(note) <= 2000", name="ck_readiness_declarations_note"
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_readiness_declarations_organization_id",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "framework",
            "control_id",
            name="uq_readiness_declarations_control",
        ),
    )
    op.execute(
        "UPDATE tier_definitions SET features = features || "
        "'{\"readiness_report\": true}'::jsonb WHERE slug = 'enterprise'"
    )


def downgrade() -> None:
    # Downgrades are disposable-only; declarations are lost.
    op.execute("UPDATE tier_definitions SET features = features - 'readiness_report'")
    op.drop_table("readiness_declarations")
