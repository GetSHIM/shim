"""Mark a personal workspace archived when its user joins an organization.

Revision: 41f1a2ff58a9
Parent: 195c95f5e798
Created: 2026-10-08
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "41f1a2ff58a9"
down_revision: str | Sequence[str] | None = "195c95f5e798"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "organizations",
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "organizations",
        sa.Column("archived_reason", sa.String(length=32), nullable=True),
    )
    op.create_check_constraint(
        "ck_organizations_archive_pair",
        "organizations",
        "(archived_at IS NULL) = (archived_reason IS NULL)",
    )


def downgrade() -> None:
    # Downgrades are disposable-only; archived workspaces read as active again.
    op.drop_constraint("ck_organizations_archive_pair", "organizations", type_="check")
    op.drop_column("organizations", "archived_reason")
    op.drop_column("organizations", "archived_at")
