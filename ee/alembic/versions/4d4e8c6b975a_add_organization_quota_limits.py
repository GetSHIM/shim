"""Add organization quota limits.

Revision: 4d4e8c6b975a
Parent: fcc02bbe6443
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "4d4e8c6b975a"
down_revision: str | Sequence[str] | None = "fcc02bbe6443"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "organizations",
        sa.Column("quota_monthly_request_limit", sa.Integer(), nullable=True),
    )
    op.add_column(
        "organizations",
        sa.Column("quota_monthly_token_limit", sa.Integer(), nullable=True),
    )
    op.add_column(
        "organizations",
        sa.Column(
            "billing_revision",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
    )
    op.create_check_constraint(
        "ck_organizations_quota_monthly_requests",
        "organizations",
        "quota_monthly_request_limit IS NULL OR quota_monthly_request_limit >= 0",
    )
    op.create_check_constraint(
        "ck_organizations_quota_monthly_tokens",
        "organizations",
        "quota_monthly_token_limit IS NULL OR quota_monthly_token_limit >= 0",
    )
    op.drop_constraint(
        "ck_quota_period_usage_single_scope", "quota_period_usage", type_="check"
    )
    op.create_check_constraint(
        "ck_quota_period_usage_single_scope",
        "quota_period_usage",
        "NOT (api_key_id IS NOT NULL AND team_id IS NOT NULL)",
    )
    op.create_index(
        "uq_quota_period_usage_organization_scope",
        "quota_period_usage",
        ["organization_id", "period_type", "period_start"],
        unique=True,
        postgresql_where=sa.text("api_key_id IS NULL AND team_id IS NULL"),
    )


def downgrade() -> None:
    # Downgrades are disposable-only; organization allocations need this schema.
    op.execute(
        "DELETE FROM quota_period_usage WHERE api_key_id IS NULL AND team_id IS NULL"
    )
    op.drop_index(
        "uq_quota_period_usage_organization_scope",
        table_name="quota_period_usage",
        postgresql_where=sa.text("api_key_id IS NULL AND team_id IS NULL"),
    )
    op.drop_constraint(
        "ck_quota_period_usage_single_scope", "quota_period_usage", type_="check"
    )
    op.create_check_constraint(
        "ck_quota_period_usage_single_scope",
        "quota_period_usage",
        "(api_key_id IS NULL) <> (team_id IS NULL)",
    )
    op.drop_constraint(
        "ck_organizations_quota_monthly_tokens", "organizations", type_="check"
    )
    op.drop_constraint(
        "ck_organizations_quota_monthly_requests", "organizations", type_="check"
    )
    op.drop_column("organizations", "billing_revision")
    op.drop_column("organizations", "quota_monthly_token_limit")
    op.drop_column("organizations", "quota_monthly_request_limit")
