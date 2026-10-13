"""Allow the recommender role, for service accounts only.

An agent's service account may now hold `recommender`: it reads, proposes plans
and applies only allowlisted ones. The two CHECK constraints of `users` keep
their names and get new bodies; a human can never hold the role.

Revision: 5bcf3c3e89cb
Parent: 26a1f479a9ce
Created: 2026-10-13
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "5bcf3c3e89cb"
down_revision: str | Sequence[str] | None = "26a1f479a9ce"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint("ck_users_role", "users", type_="check")
    op.create_check_constraint(
        "ck_users_role",
        "users",
        "role IN ('owner', 'admin', 'member', 'auditor', 'recommender')",
    )
    op.drop_constraint("ck_users_service_role", "users", type_="check")
    op.create_check_constraint(
        "ck_users_service_role",
        "users",
        "(kind = 'human' AND role <> 'recommender') OR "
        "(kind = 'service' AND role IN ('admin', 'auditor', 'recommender'))",
    )


def downgrade() -> None:
    # Disposable data only: a recommender account has no role to go back to.
    if (
        op.get_bind()
        .execute(sa.text("SELECT 1 FROM users WHERE role = 'recommender' LIMIT 1"))
        .first()
    ):
        raise RuntimeError("Remove recommender service accounts before downgrading.")
    op.drop_constraint("ck_users_service_role", "users", type_="check")
    op.create_check_constraint(
        "ck_users_service_role",
        "users",
        "kind = 'human' OR role IN ('admin', 'auditor')",
    )
    op.drop_constraint("ck_users_role", "users", type_="check")
    op.create_check_constraint(
        "ck_users_role", "users", "role IN ('owner', 'admin', 'member', 'auditor')"
    )
