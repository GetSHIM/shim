"""Add organization rule sets.

One row per tenant holds its whole rule set and a revision that every change
increments; no row means no rule.

Revision: b6102c005b0c
Parent: 24b8466be324
Created: 2026-10-10
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "b6102c005b0c"
down_revision: str | Sequence[str] | None = "24b8466be324"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "organization_rule_sets",
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column(
            "revision", sa.Integer(), server_default=sa.text("0"), nullable=False
        ),
        sa.Column(
            "rules",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("updated_by", sa.String(length=64), nullable=True),
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
        sa.CheckConstraint("revision >= 0", name="ck_organization_rule_sets_revision"),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_organization_rule_sets_organization",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("organization_id"),
    )


def downgrade() -> None:
    # Downgrades are disposable-only; every tenant's rules are lost.
    op.drop_table("organization_rule_sets")
