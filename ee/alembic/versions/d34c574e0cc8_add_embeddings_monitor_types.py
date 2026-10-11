"""Add the entity types an embeddings request only counts.

Revision: d34c574e0cc8
Parent: a61706150d6c
Created: 2026-10-11
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "d34c574e0cc8"
down_revision: str | Sequence[str] | None = "a61706150d6c"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Existing tenants keep their chat actions for embeddings: nothing is relaxed.
    op.add_column(
        "organization_pii_configs",
        sa.Column(
            "embeddings_monitor_types",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
    )


def downgrade() -> None:
    # Downgrades are disposable-only; the relaxation is lost and chat actions apply.
    op.drop_column("organization_pii_configs", "embeddings_monitor_types")
