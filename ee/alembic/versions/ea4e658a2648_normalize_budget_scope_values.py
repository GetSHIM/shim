"""Normalize tag and team budget scopes the way ingest normalizes labels.

Revision: ea4e658a2648
Parent: de7150dd2f7a
"""

from collections.abc import Sequence

from alembic import op


revision: str = "ea4e658a2648"
down_revision: str | Sequence[str] | None = "de7150dd2f7a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # cost_budget has no uniqueness on scope, so equal lowercased values cannot collide.
    op.execute(
        "UPDATE cost_budget SET scope_value = lower(btrim(scope_value)) "
        "WHERE scope_type IN ('tag', 'team') "
        "AND lower(btrim(scope_value)) ~ '^[a-z0-9_.:-]+$' "
        "AND scope_value <> lower(btrim(scope_value))"
    )


def downgrade() -> None:
    # The original spelling is not kept; lowercased scopes stay lowercased.
    pass
