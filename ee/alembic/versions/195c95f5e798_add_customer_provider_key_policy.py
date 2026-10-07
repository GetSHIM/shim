"""Add the tenant switch for customer provider keys.

Revision: 195c95f5e798
Parent: ea4e658a2648
Created: 2026-10-07
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "195c95f5e798"
down_revision: str | Sequence[str] | None = "ea4e658a2648"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Existing tenants keep today's behaviour: a request's x-provider-key is used.
    op.add_column(
        "organizations",
        sa.Column(
            "allow_customer_provider_keys",
            sa.Boolean(),
            server_default=sa.text("true"),
            nullable=False,
        ),
    )


def downgrade() -> None:
    # Downgrades are disposable-only; the tenant's refusal is lost.
    op.drop_column("organizations", "allow_customer_provider_keys")
