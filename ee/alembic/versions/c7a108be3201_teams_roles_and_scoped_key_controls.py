"""teams roles and scoped key controls

Revision: c7a108be3201
Parent: f10e4ac92d17
Created: 2026-09-08 02:49:20.778421
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "c7a108be3201"
down_revision: str | Sequence[str] | None = "f10e4ac92d17"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    for table, constraint in (
        ("users", "ck_users_role"),
        ("organization_invites", "ck_invites_role"),
    ):
        op.drop_constraint(constraint, table, type_="check")
        op.create_check_constraint(
            constraint, table, "role IN ('owner', 'admin', 'member', 'auditor')"
        )
    op.create_table(
        "teams",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("daily_request_limit", sa.Integer(), nullable=True),
        sa.Column("monthly_request_limit", sa.Integer(), nullable=True),
        sa.Column("monthly_token_limit", sa.Integer(), nullable=True),
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
            "daily_request_limit IS NULL OR daily_request_limit >= 0",
            name="ck_teams_daily_requests",
        ),
        sa.CheckConstraint(
            "monthly_request_limit IS NULL OR monthly_request_limit >= 0",
            name="ck_teams_monthly_requests",
        ),
        sa.CheckConstraint(
            "monthly_token_limit IS NULL OR monthly_token_limit >= 0",
            name="ck_teams_monthly_tokens",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "id", name="uq_teams_tenant_id"),
        sa.UniqueConstraint("organization_id", "name", name="uq_teams_tenant_name"),
    )
    op.create_table(
        "team_memberships",
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("team_id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column(
            "role", sa.String(length=16), server_default="member", nullable=False
        ),
        sa.Column(
            "source", sa.String(length=16), server_default="local", nullable=False
        ),
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
            "role IN ('member', 'team_admin')", name="ck_team_memberships_role"
        ),
        sa.CheckConstraint(
            "source IN ('local', 'oidc')", name="ck_team_memberships_source"
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "team_id"],
            ["teams.organization_id", "teams.id"],
            name="fk_team_memberships_tenant_team",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "user_id"],
            ["users.organization_id", "users.id"],
            name="fk_team_memberships_tenant_user",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("organization_id", "team_id", "user_id"),
    )
    op.add_column("api_keys", sa.Column("team_id", sa.UUID(), nullable=True))
    op.add_column(
        "api_keys",
        sa.Column(
            "allowed_models", postgresql.JSONB(astext_type=sa.Text()), nullable=True
        ),
    )
    op.create_foreign_key(
        "fk_api_keys_tenant_team",
        "api_keys",
        "teams",
        ["organization_id", "team_id"],
        ["organization_id", "id"],
    )
    # Billing labels retain their exact spelling and never grant membership.
    op.execute(
        "INSERT INTO teams (id, organization_id, name) SELECT gen_random_uuid(), organization_id, team FROM api_keys WHERE team IS NOT NULL GROUP BY organization_id, team"
    )
    op.add_column("quota_period_usage", sa.Column("team_id", sa.UUID(), nullable=True))
    op.alter_column(
        "quota_period_usage", "api_key_id", existing_type=sa.UUID(), nullable=True
    )
    op.create_index(
        "uq_quota_period_usage_team_scope",
        "quota_period_usage",
        ["organization_id", "team_id", "period_type", "period_start"],
        unique=True,
        postgresql_where=sa.text("team_id IS NOT NULL"),
    )
    op.create_foreign_key(
        "fk_quota_period_usage_org_team",
        "quota_period_usage",
        "teams",
        ["organization_id", "team_id"],
        ["organization_id", "id"],
    )
    op.create_check_constraint(
        "ck_quota_period_usage_single_scope",
        "quota_period_usage",
        "(api_key_id IS NULL) <> (team_id IS NULL)",
    )


def downgrade() -> None:
    # Downgrades are for disposable data only; team allocations need the new schema.
    op.execute("DELETE FROM quota_period_usage WHERE team_id IS NOT NULL")
    for table, constraint in (
        ("users", "ck_users_role"),
        ("organization_invites", "ck_invites_role"),
    ):
        op.execute(f"UPDATE {table} SET role = 'member' WHERE role = 'auditor'")
        op.drop_constraint(constraint, table, type_="check")
        op.create_check_constraint(
            constraint, table, "role IN ('owner', 'admin', 'member')"
        )
    op.drop_constraint(
        "ck_quota_period_usage_single_scope", "quota_period_usage", type_="check"
    )
    op.drop_constraint(
        "fk_quota_period_usage_org_team", "quota_period_usage", type_="foreignkey"
    )
    op.drop_index(
        "uq_quota_period_usage_team_scope",
        table_name="quota_period_usage",
        postgresql_where=sa.text("team_id IS NOT NULL"),
    )
    op.alter_column(
        "quota_period_usage", "api_key_id", existing_type=sa.UUID(), nullable=False
    )
    op.drop_column("quota_period_usage", "team_id")
    op.drop_constraint("fk_api_keys_tenant_team", "api_keys", type_="foreignkey")
    op.drop_column("api_keys", "allowed_models")
    op.drop_column("api_keys", "team_id")
    op.drop_table("team_memberships")
    op.drop_table("teams")
