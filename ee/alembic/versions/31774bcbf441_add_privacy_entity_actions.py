"""Add per-entity privacy actions and the privacy settings later PRs read.

Revision: 31774bcbf441
Parent: 195c95f5e798
Created: 2026-10-08
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "31774bcbf441"
down_revision: str | Sequence[str] | None = "195c95f5e798"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Existing tenants keep today's behaviour: no overrides, random placeholders,
    # a bulk threshold of 50 and no response scan.
    op.add_column(
        "organization_pii_configs",
        sa.Column(
            "entity_actions",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
    )
    op.add_column(
        "organization_pii_configs",
        sa.Column(
            "placeholder_mode",
            sa.String(length=16),
            server_default=sa.text("'random'"),
            nullable=False,
        ),
    )
    op.add_column(
        "organization_pii_configs",
        sa.Column(
            "bulk_threshold",
            sa.Integer(),
            server_default=sa.text("50"),
            nullable=True,
        ),
    )
    op.add_column(
        "organization_pii_configs",
        sa.Column(
            "response_scan",
            sa.String(length=16),
            server_default=sa.text("'off'"),
            nullable=False,
        ),
    )
    op.create_check_constraint(
        "ck_organization_pii_configs_placeholder_mode",
        "organization_pii_configs",
        "placeholder_mode IN ('random', 'stable')",
    )
    op.create_check_constraint(
        "ck_organization_pii_configs_bulk_threshold",
        "organization_pii_configs",
        "bulk_threshold IS NULL OR bulk_threshold >= 2",
    )
    op.create_check_constraint(
        "ck_organization_pii_configs_response_scan",
        "organization_pii_configs",
        "response_scan IN ('off', 'count')",
    )


def downgrade() -> None:
    # Downgrades are disposable-only; the tenants' privacy choices are lost.
    op.drop_constraint(
        "ck_organization_pii_configs_response_scan",
        "organization_pii_configs",
        type_="check",
    )
    op.drop_constraint(
        "ck_organization_pii_configs_bulk_threshold",
        "organization_pii_configs",
        type_="check",
    )
    op.drop_constraint(
        "ck_organization_pii_configs_placeholder_mode",
        "organization_pii_configs",
        type_="check",
    )
    op.drop_column("organization_pii_configs", "response_scan")
    op.drop_column("organization_pii_configs", "bulk_threshold")
    op.drop_column("organization_pii_configs", "placeholder_mode")
    op.drop_column("organization_pii_configs", "entity_actions")
