"""Let a budget match requests by the key's team id.

Revision: 1ad1ca2101a5
Parent: d94f7f0ba8a2
Created: 2026-10-08
"""

from collections.abc import Sequence

from alembic import op


revision: str = "1ad1ca2101a5"
down_revision: str | Sequence[str] | None = "d94f7f0ba8a2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint("ck_cost_budget_scope_type", "cost_budget", type_="check")
    op.create_check_constraint(
        "ck_cost_budget_scope_type",
        "cost_budget",
        "scope_type IN ('org', 'tag', 'team', 'team_id')",
    )


def downgrade() -> None:
    # Downgrades are disposable-only; team id budgets and their alert state are lost.
    op.execute("DELETE FROM cost_budget WHERE scope_type = 'team_id'")
    op.drop_constraint("ck_cost_budget_scope_type", "cost_budget", type_="check")
    op.create_check_constraint(
        "ck_cost_budget_scope_type",
        "cost_budget",
        "scope_type IN ('org', 'tag', 'team')",
    )
