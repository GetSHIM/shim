"""Add organization gateway settings.

One row per tenant holds its gateway switches as validated JSON; no row means
every switch at its off default.

Revision: 24b8466be324
Parent: 7e3fb2338f03
Created: 2026-10-09
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "24b8466be324"
down_revision: str | Sequence[str] | None = "7e3fb2338f03"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "organization_gateway_settings",
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column(
            "settings",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "revision", sa.Integer(), server_default=sa.text("0"), nullable=False
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
            "revision >= 0", name="ck_organization_gateway_settings_revision"
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_organization_gateway_settings_organization_id",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["updated_by"],
            ["users.id"],
            name="fk_organization_gateway_settings_updated_by",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("organization_id"),
    )


def downgrade() -> None:
    # Downgrades are disposable-only; every tenant's gateway settings are lost.
    op.drop_table("organization_gateway_settings")
