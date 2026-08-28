"""architecture baseline

Revision ID: aa8b038bc50c
Revises:
Create Date: 2026-07-12 13:32:07.716917

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "aa8b038bc50c"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create the standalone trust-boundary gateway schema."""
    op.create_table(
        "organizations",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("slug", sa.String(length=200), nullable=False),
        sa.Column("tier", sa.String(length=64), server_default="free", nullable=False),
        sa.Column(
            "billing_status",
            sa.String(length=32),
            server_default="free",
            nullable=False,
        ),
        sa.Column("billing_source", sa.String(length=32), nullable=True),
        sa.Column("external_customer_id", sa.String(length=128), nullable=True),
        sa.Column("external_subscription_id", sa.String(length=128), nullable=True),
        sa.Column("billing_variant_id", sa.String(length=128), nullable=True),
        sa.Column("current_period_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "cancel_at_period_end",
            sa.Boolean(),
            server_default="false",
            nullable=False,
        ),
        sa.Column("billing_event_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("customer_portal_url", sa.Text(), nullable=True),
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
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("external_customer_id"),
        sa.UniqueConstraint("external_subscription_id"),
        sa.UniqueConstraint("slug"),
    )
    op.create_table(
        "tier_definitions",
        sa.Column("slug", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("rate_limit_rpm", sa.Integer(), nullable=False),
        sa.Column("rate_limit_tpm", sa.Integer(), nullable=False),
        sa.Column("monthly_request_limit", sa.Integer(), nullable=False),
        sa.Column("monthly_token_limit", sa.Integer(), nullable=False),
        sa.Column("daily_request_limit", sa.Integer(), nullable=True),
        sa.Column(
            "features",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
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
            "daily_request_limit IS NULL OR daily_request_limit >= 0",
            name="ck_tier_daily_requests",
        ),
        sa.CheckConstraint(
            "monthly_request_limit >= 0", name="ck_tier_monthly_requests"
        ),
        sa.CheckConstraint("monthly_token_limit >= 0", name="ck_tier_monthly_tokens"),
        sa.CheckConstraint("rate_limit_rpm > 0", name="ck_tier_rate_limit_rpm"),
        sa.CheckConstraint("rate_limit_tpm > 0", name="ck_tier_rate_limit_tpm"),
        sa.PrimaryKeyConstraint("slug"),
    )
    op.bulk_insert(
        sa.table(
            "tier_definitions",
            sa.column("slug", sa.String()),
            sa.column("name", sa.String()),
            sa.column("rate_limit_rpm", sa.Integer()),
            sa.column("rate_limit_tpm", sa.Integer()),
            sa.column("monthly_request_limit", sa.Integer()),
            sa.column("monthly_token_limit", sa.Integer()),
            sa.column("daily_request_limit", sa.Integer()),
            sa.column("features", postgresql.JSONB()),
        ),
        [
            {
                "slug": "free",
                "name": "Developer",
                "rate_limit_rpm": 60,
                "rate_limit_tpm": 15_000,
                "monthly_request_limit": 1_000,
                "monthly_token_limit": 1_000_000,
                "daily_request_limit": None,
                "features": {"pii_shield": True},
            },
            {
                "slug": "managed",
                "name": "Solo Pro",
                "rate_limit_rpm": 300,
                "rate_limit_tpm": 150_000,
                "monthly_request_limit": 100_000,
                "monthly_token_limit": 10_000_000,
                "daily_request_limit": None,
                "features": {
                    "pii_shield": True,
                    "budgets": True,
                    "compliance": True,
                    "priority_support": True,
                },
            },
            {
                "slug": "agency",
                "name": "Agency",
                "rate_limit_rpm": 600,
                "rate_limit_tpm": 500_000,
                "monthly_request_limit": 1_000_000,
                "monthly_token_limit": 100_000_000,
                "daily_request_limit": None,
                "features": {
                    "pii_shield": True,
                    "team_rbac": True,
                    "budgets": True,
                    "compliance": True,
                    "priority_support": True,
                    "onboarding": True,
                },
            },
            {
                "slug": "enterprise",
                "name": "Enterprise",
                "rate_limit_rpm": 1_200,
                "rate_limit_tpm": 1_000_000,
                "monthly_request_limit": 1_000_000,
                "monthly_token_limit": 1_000_000_000,
                "daily_request_limit": None,
                "features": {
                    "team_rbac": True,
                    "budgets": True,
                    "compliance": True,
                    "oversight": True,
                },
            },
        ],
    )
    op.create_foreign_key(
        "fk_organizations_tier",
        "organizations",
        "tier_definitions",
        ["tier"],
        ["slug"],
    )
    op.create_table(
        "ai_act_audit_anchor",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("anchor_date", sa.Date(), nullable=False),
        sa.Column("root_hash", sa.String(length=128), nullable=False),
        sa.Column("tip_hash", sa.String(length=128), nullable=True),
        sa.Column("row_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("from_seq", sa.BigInteger(), nullable=True),
        sa.Column("to_seq", sa.BigInteger(), nullable=True),
        sa.Column("external_ref", sa.String(length=512), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "(from_seq IS NULL AND to_seq IS NULL) OR (from_seq > 0 AND to_seq >= from_seq)",
            name="ck_ai_anchor_sequence_range",
        ),
        sa.CheckConstraint("row_count >= 0", name="ck_ai_anchor_row_count"),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id", "anchor_date", name="uq_ai_anchor_tenant_date"
        ),
    )
    op.create_index(
        op.f("ix_ai_act_audit_anchor_organization_id"),
        "ai_act_audit_anchor",
        ["organization_id"],
        unique=False,
    )
    op.create_table(
        "compliance_connector",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column(
            "status", sa.String(length=16), server_default="active", nullable=False
        ),
        sa.Column("secret_ref", sa.Text(), nullable=False),
        sa.Column("secret_backend", sa.String(length=32), nullable=False),
        sa.Column("secret_version", sa.String(length=128), nullable=False),
        sa.Column("masked_key", sa.String(length=64), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cursor", sa.Text(), nullable=True),
        sa.Column("scope_type", sa.String(length=32), nullable=True),
        sa.Column("scope_id", sa.String(length=255), nullable=True),
        sa.Column("retention_days", sa.Integer(), nullable=True),
        sa.Column("backfill_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("backfill_completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column(
            "consecutive_errors", sa.Integer(), server_default="0", nullable=False
        ),
        sa.Column(
            "config",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
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
            "status IN ('active', 'paused', 'error')",
            name="ck_compliance_connector_status",
        ),
        sa.CheckConstraint(
            "consecutive_errors >= 0", name="ck_compliance_connector_errors"
        ),
        sa.CheckConstraint(
            "retention_days IS NULL OR retention_days > 0",
            name="ck_compliance_connector_retention",
        ),
        sa.CheckConstraint(
            "length(masked_key) > 0",
            name="ck_compliance_connector_masked_key",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id", "provider", name="uq_compliance_connector_provider"
        ),
    )
    op.create_index(
        "ix_compliance_connector_tenant",
        "compliance_connector",
        ["organization_id"],
        unique=False,
    )
    op.create_table(
        "cost_budget",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("scope_type", sa.Text(), nullable=False),
        sa.Column("scope_value", sa.Text(), nullable=True),
        sa.Column("period", sa.Text(), server_default="monthly", nullable=False),
        sa.Column("limit_usd", sa.Numeric(precision=18, scale=8), nullable=True),
        sa.Column("limit_tokens", sa.BigInteger(), nullable=True),
        sa.Column(
            "alert_thresholds",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[0.8, 1.0]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "notify_targets",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False
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
            "(scope_type = 'org' AND scope_value IS NULL) OR (scope_type <> 'org' AND scope_value IS NOT NULL)",
            name="ck_cost_budget_scope_value",
        ),
        sa.CheckConstraint("period = 'monthly'", name="ck_cost_budget_period"),
        sa.CheckConstraint(
            "scope_type IN ('org', 'tag', 'team')", name="ck_cost_budget_scope_type"
        ),
        sa.CheckConstraint(
            "limit_tokens IS NULL OR limit_tokens >= 0",
            name="ck_cost_budget_limit_tokens",
        ),
        sa.CheckConstraint(
            "limit_usd IS NOT NULL OR limit_tokens IS NOT NULL",
            name="ck_cost_budget_has_limit",
        ),
        sa.CheckConstraint(
            "limit_usd IS NULL OR limit_usd >= 0", name="ck_cost_budget_limit_usd"
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_cost_budget_org", "cost_budget", ["organization_id"], unique=False
    )
    op.create_table(
        "organization_pii_configs",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("block_email", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("block_phone", sa.Boolean(), server_default="true", nullable=False),
        sa.Column(
            "block_credit_card", sa.Boolean(), server_default="true", nullable=False
        ),
        sa.Column("block_secrets", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("block_pii_tr", sa.Boolean(), server_default="true", nullable=False),
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
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id"),
    )
    op.create_table(
        "outbox_event",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("aggregate_type", sa.Text(), nullable=False),
        sa.Column("aggregate_id", sa.Text(), nullable=False),
        sa.Column("idempotency_key", sa.Text(), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "status", sa.Text(), server_default=sa.text("'pending'"), nullable=False
        ),
        sa.Column(
            "attempt_count", sa.Integer(), server_default=sa.text("0"), nullable=False
        ),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("locked_by", sa.Text(), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
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
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "(status = 'processing' AND locked_by IS NOT NULL AND lease_expires_at IS NOT NULL) OR (status <> 'processing' AND locked_by IS NULL AND lease_expires_at IS NULL)",
            name="ck_outbox_event_lease_shape",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'processing', 'processed', 'failed', 'dead_letter')",
            name="ck_outbox_event_status",
        ),
        sa.CheckConstraint("attempt_count >= 0", name="ck_outbox_event_attempt_count"),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "id", name="uq_outbox_event_org_id"),
        sa.UniqueConstraint(
            "organization_id", "idempotency_key", name="uq_outbox_event_org_idempotency"
        ),
    )
    op.create_index(
        "ix_outbox_event_claimable",
        "outbox_event",
        ["status", "next_attempt_at"],
        unique=False,
        postgresql_where=sa.text("status IN ('pending', 'failed')"),
    )
    op.create_index(
        "ix_outbox_event_expired_lease",
        "outbox_event",
        ["lease_expires_at"],
        unique=False,
        postgresql_where=sa.text("status = 'processing'"),
    )
    op.create_table(
        "oversight_policy",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("mode", sa.String(length=16), server_default="flag", nullable=False),
        sa.Column(
            "trigger",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
        ),
        sa.Column("ttl_seconds", sa.Integer(), server_default="3600", nullable=False),
        sa.Column(
            "default_on_timeout",
            sa.String(length=16),
            server_default="allow",
            nullable=False,
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
            "default_on_timeout IN ('allow', 'deny')",
            name="ck_oversight_policy_timeout",
        ),
        sa.CheckConstraint("mode IN ('flag')", name="ck_oversight_policy_mode"),
        sa.CheckConstraint("ttl_seconds > 0", name="ck_oversight_policy_ttl"),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id", "id", name="uq_oversight_policy_tenant_id"
        ),
    )
    op.create_index(
        "ix_oversight_policy_tenant_enabled",
        "oversight_policy",
        ["organization_id", "enabled"],
        unique=False,
    )
    op.create_table(
        "provider_secrets",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=True),
        sa.Column("secret_ref", sa.Text(), nullable=False),
        sa.Column("secret_backend", sa.String(length=32), nullable=False),
        sa.Column("secret_version", sa.String(length=128), nullable=False),
        sa.Column("masked_key", sa.String(length=64), nullable=False),
        sa.Column(
            "monthly_limit_usd", sa.Numeric(precision=18, scale=8), nullable=True
        ),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
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
            "monthly_limit_usd IS NULL OR monthly_limit_usd >= 0",
            name="ck_provider_secret_monthly_limit",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_provider_secrets_tenant_provider",
        "provider_secrets",
        ["organization_id", "provider"],
        unique=False,
    )
    op.create_table(
        "spend_period_usage",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("provider", sa.Text(), nullable=False),
        sa.Column("period_start", sa.Date(), nullable=False),
        sa.Column("period_end", sa.Date(), nullable=False),
        sa.Column(
            "reserved_usd",
            sa.Numeric(precision=18, scale=8),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "settled_usd",
            sa.Numeric(precision=18, scale=8),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column("limit_usd", sa.Numeric(precision=18, scale=8), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "reserved_usd >= 0", name="ck_spend_period_usage_reserved_usd"
        ),
        sa.CheckConstraint(
            "settled_usd >= 0", name="ck_spend_period_usage_settled_usd"
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "provider",
            "period_start",
            name="uq_spend_period_usage_scope",
        ),
    )
    op.create_table(
        "users",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("full_name", sa.String(length=200), nullable=True),
        sa.Column("is_active", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("is_verified", sa.Boolean(), server_default="false", nullable=False),
        sa.Column(
            "role", sa.String(length=16), server_default="member", nullable=False
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
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.CheckConstraint(
            "role IN ('owner', 'admin', 'member')", name="ck_users_role"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
        sa.UniqueConstraint("organization_id", "id", name="uq_users_tenant_id"),
    )
    op.create_index(
        "ix_users_organization_id", "users", ["organization_id"], unique=False
    )
    op.create_table(
        "billing_webhook_receipts",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("payload_digest", sa.String(length=64), nullable=False),
        sa.Column("event_name", sa.String(length=64), nullable=False),
        sa.Column("external_subscription_id", sa.String(length=128), nullable=True),
        sa.Column("event_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_billing_receipts_digest",
        "billing_webhook_receipts",
        ["payload_digest"],
        unique=True,
    )
    op.create_index(
        "ix_billing_receipts_organization_id",
        "billing_webhook_receipts",
        ["organization_id"],
        unique=False,
    )
    op.create_table(
        "organization_invites",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("invited_by_user_id", sa.UUID(), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
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
            "role IN ('owner', 'admin', 'member')", name="ck_invites_role"
        ),
        sa.ForeignKeyConstraint(
            ["invited_by_user_id"], ["users.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_invites_organization_id",
        "organization_invites",
        ["organization_id"],
        unique=False,
    )
    op.create_index(
        "ix_invites_token_hash",
        "organization_invites",
        ["token_hash"],
        unique=True,
    )
    op.create_table(
        "api_keys",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column("prefix", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=True),
        sa.Column("is_active", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cost_center", sa.String(length=128), nullable=True),
        sa.Column("team", sa.String(length=128), nullable=True),
        sa.Column("tier", sa.String(length=64), nullable=False),
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
        sa.ForeignKeyConstraint(
            ["organization_id", "user_id"],
            ["users.organization_id", "users.id"],
            name="fk_api_keys_tenant_user",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["tier"],
            ["tier_definitions.slug"],
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "id", name="uq_api_keys_tenant_id"),
    )
    op.create_index("ix_api_keys_key_hash", "api_keys", ["key_hash"], unique=True)
    op.create_index(
        "ix_api_keys_organization_id", "api_keys", ["organization_id"], unique=False
    )
    op.create_table(
        "compliance_activity",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("connector_id", sa.UUID(), nullable=False),
        sa.Column("provider_event_id", sa.String(length=255), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("actor_email", sa.String(length=320), nullable=True),
        sa.Column("actor_user_id", sa.String(length=255), nullable=True),
        sa.Column("actor_ip", sa.String(length=64), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "extras",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
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
        sa.ForeignKeyConstraint(
            ["connector_id"], ["compliance_connector.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "connector_id", "provider_event_id", name="uq_compliance_activity_event"
        ),
    )
    op.create_index(
        op.f("ix_compliance_activity_connector_id"),
        "compliance_activity",
        ["connector_id"],
        unique=False,
    )
    op.create_index(
        "ix_compliance_activity_event_type",
        "compliance_activity",
        ["event_type"],
        unique=False,
    )
    op.create_index(
        "ix_compliance_activity_occurred",
        "compliance_activity",
        ["occurred_at"],
        unique=False,
    )
    op.create_table(
        "compliance_forward_target",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("connector_id", sa.UUID(), nullable=False),
        sa.Column(
            "kind", sa.String(length=32), server_default="siem_webhook", nullable=False
        ),
        sa.Column("endpoint_origin", sa.Text(), nullable=False),
        sa.Column("secret_ref", sa.Text(), nullable=False),
        sa.Column("secret_backend", sa.String(length=32), nullable=False),
        sa.Column("secret_version", sa.String(length=128), nullable=False),
        sa.Column("signed", sa.Boolean(), server_default="false", nullable=False),
        sa.Column(
            "min_severity", sa.String(length=16), server_default="high", nullable=False
        ),
        sa.Column("enabled", sa.Boolean(), server_default="true", nullable=False),
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
            "kind IN ('siem_webhook', 'slack', 'email')",
            name="ck_compliance_forward_target_kind",
        ),
        sa.CheckConstraint(
            "min_severity IN ('low', 'medium', 'high', 'critical')",
            name="ck_compliance_forward_target_severity",
        ),
        sa.ForeignKeyConstraint(
            ["connector_id"], ["compliance_connector.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_compliance_forward_target_connector_id"),
        "compliance_forward_target",
        ["connector_id"],
        unique=False,
    )
    op.create_table(
        "compliance_ingest_cursor",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("connector_id", sa.UUID(), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("last_end_time", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_file_id", sa.String(length=255), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lag_seconds", sa.Integer(), nullable=True),
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
            "lag_seconds IS NULL OR lag_seconds >= 0",
            name="ck_compliance_ingest_cursor_lag",
        ),
        sa.ForeignKeyConstraint(
            ["connector_id"], ["compliance_connector.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "connector_id", "event_type", name="uq_compliance_ingest_cursor_stream"
        ),
    )
    op.create_index(
        op.f("ix_compliance_ingest_cursor_connector_id"),
        "compliance_ingest_cursor",
        ["connector_id"],
        unique=False,
    )
    op.create_table(
        "compliance_log_file",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("connector_id", sa.UUID(), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("provider_file_id", sa.String(length=255), nullable=False),
        sa.Column(
            "status", sa.String(length=16), server_default="pending", nullable=False
        ),
        sa.Column("record_count", sa.Integer(), nullable=True),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
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
            "status IN ('pending', 'downloaded', 'processed', 'error')",
            name="ck_compliance_log_file_status",
        ),
        sa.CheckConstraint(
            "record_count IS NULL OR record_count >= 0",
            name="ck_compliance_log_file_count",
        ),
        sa.CheckConstraint(
            "window_start IS NULL OR window_end IS NULL OR window_end >= window_start",
            name="ck_compliance_log_file_window",
        ),
        sa.ForeignKeyConstraint(
            ["connector_id"], ["compliance_connector.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "connector_id", "provider_file_id", name="uq_compliance_log_file_dedup"
        ),
    )
    op.create_index(
        op.f("ix_compliance_log_file_connector_id"),
        "compliance_log_file",
        ["connector_id"],
        unique=False,
    )
    op.create_index(
        "ix_compliance_log_file_event",
        "compliance_log_file",
        ["event_type"],
        unique=False,
    )
    op.create_table(
        "cost_budget_alert_state",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("budget_id", sa.UUID(), nullable=False),
        sa.Column("period_key", sa.Text(), nullable=False),
        sa.Column("threshold", sa.Numeric(precision=8, scale=6), nullable=False),
        sa.Column("fired_at", sa.DateTime(timezone=True), nullable=False),
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
        sa.CheckConstraint("threshold > 0", name="ck_budget_alert_threshold"),
        sa.ForeignKeyConstraint(["budget_id"], ["cost_budget.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "budget_id", "period_key", "threshold", name="uq_budget_period_threshold"
        ),
    )
    op.create_index(
        op.f("ix_cost_budget_alert_state_budget_id"),
        "cost_budget_alert_state",
        ["budget_id"],
        unique=False,
    )
    op.create_table(
        "ai_act_audit_log",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("seq", sa.BigInteger(), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("request_id", sa.String(length=255), nullable=True),
        sa.Column("api_key_id", sa.UUID(), nullable=True),
        sa.Column("actor", sa.String(length=320), nullable=True),
        sa.Column("model", sa.String(length=255), nullable=True),
        sa.Column("provider", sa.String(length=64), nullable=True),
        sa.Column("gateway_version", sa.String(length=64), nullable=True),
        sa.Column("endpoint", sa.String(length=255), nullable=True),
        sa.Column("input_hash", sa.String(length=128), nullable=True),
        sa.Column("output_hash", sa.String(length=128), nullable=True),
        sa.Column("prompt_tokens", sa.Integer(), server_default="0", nullable=False),
        sa.Column(
            "completion_tokens", sa.Integer(), server_default="0", nullable=False
        ),
        sa.Column("pii_detected", sa.Boolean(), server_default="false", nullable=False),
        sa.Column(
            "pii_entities",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
        ),
        sa.Column(
            "policy_verdicts",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="[]",
            nullable=False,
        ),
        sa.Column("is_cache_hit", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("latency_ms", sa.Integer(), server_default="0", nullable=False),
        sa.Column(
            "cost_usd",
            sa.Numeric(precision=18, scale=8),
            server_default="0",
            nullable=False,
        ),
        sa.Column("prev_hash", sa.String(length=128), nullable=False),
        sa.Column("row_hash", sa.String(length=128), nullable=False),
        sa.Column(
            "extra",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("cost_usd >= 0", name="ck_ai_audit_cost_nonnegative"),
        sa.CheckConstraint("latency_ms >= 0", name="ck_ai_audit_latency_nonnegative"),
        sa.CheckConstraint(
            "prompt_tokens >= 0 AND completion_tokens >= 0",
            name="ck_ai_audit_tokens_nonnegative",
        ),
        sa.CheckConstraint("seq > 0", name="ck_ai_audit_seq_positive"),
        sa.ForeignKeyConstraint(
            ["organization_id", "api_key_id"],
            ["api_keys.organization_id", "api_keys.id"],
            name="fk_ai_audit_tenant_api_key",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "id", name="uq_ai_audit_tenant_id"),
        sa.UniqueConstraint("organization_id", "seq", name="uq_ai_audit_tenant_seq"),
        sa.UniqueConstraint("row_hash"),
    )
    op.create_index(
        op.f("ix_ai_act_audit_log_created_at"),
        "ai_act_audit_log",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        "ix_ai_audit_tenant_created",
        "ai_act_audit_log",
        ["organization_id", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_ai_audit_tenant_request",
        "ai_act_audit_log",
        ["organization_id", "request_id"],
        unique=False,
    )
    op.execute(
        """
        CREATE FUNCTION reject_ai_act_audit_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $function$
        BEGIN
            RAISE EXCEPTION 'AI Act audit evidence is append-only';
        END;
        $function$
        """
    )
    op.execute(
        """
        CREATE TRIGGER ai_act_audit_log_append_only
        BEFORE UPDATE OR DELETE ON ai_act_audit_log
        FOR EACH ROW EXECUTE FUNCTION reject_ai_act_audit_mutation()
        """
    )
    op.execute(
        """
        CREATE TRIGGER ai_act_audit_log_reject_truncate
        BEFORE TRUNCATE ON ai_act_audit_log
        FOR EACH STATEMENT EXECUTE FUNCTION reject_ai_act_audit_mutation()
        """
    )
    op.execute(
        """
        CREATE TRIGGER ai_act_audit_anchor_append_only
        BEFORE UPDATE OR DELETE ON ai_act_audit_anchor
        FOR EACH ROW EXECUTE FUNCTION reject_ai_act_audit_mutation()
        """
    )
    op.execute(
        """
        CREATE TRIGGER ai_act_audit_anchor_reject_truncate
        BEFORE TRUNCATE ON ai_act_audit_anchor
        FOR EACH STATEMENT EXECUTE FUNCTION reject_ai_act_audit_mutation()
        """
    )
    op.execute(
        """
        REVOKE UPDATE, DELETE, TRUNCATE ON TABLE
            ai_act_audit_log, ai_act_audit_anchor
        FROM PUBLIC
        """
    )
    op.execute(
        """
        DO $block$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM pg_roles WHERE rolname = 'shim_audit_append'
            ) THEN
                EXECUTE 'REVOKE ALL ON TABLE '
                    'ai_act_audit_log, ai_act_audit_anchor '
                    'FROM shim_audit_append';
                EXECUTE 'GRANT SELECT, INSERT ON TABLE '
                    'ai_act_audit_log, ai_act_audit_anchor '
                    'TO shim_audit_append';
            END IF;
        END;
        $block$
        """
    )
    op.create_table(
        "audit_intent",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("request_id", sa.Text(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("actor_type", sa.Text(), nullable=False),
        sa.Column("api_key_id", sa.UUID(), nullable=True),
        sa.Column("user_id", sa.UUID(), nullable=True),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("audit_policy_mode", sa.Text(), nullable=False),
        sa.Column("input_hash", sa.Text(), nullable=True),
        sa.Column("output_hash", sa.Text(), nullable=True),
        sa.Column(
            "pii_entities",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("provider", sa.Text(), nullable=True),
        sa.Column("model", sa.Text(), nullable=True),
        sa.Column(
            "usage_summary",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("lifecycle_status", sa.Text(), nullable=False),
        sa.Column("outbox_event_id", sa.UUID(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "(actor_type = 'api_key' AND api_key_id IS NOT NULL) OR (actor_type = 'user_jwt' AND user_id IS NOT NULL AND api_key_id IS NULL) OR (actor_type = 'internal' AND api_key_id IS NULL AND user_id IS NULL)",
            name="ck_audit_intent_actor_identity",
        ),
        sa.CheckConstraint(
            "actor_type IN ('api_key', 'user_jwt', 'internal')",
            name="ck_audit_intent_actor_type",
        ),
        sa.CheckConstraint(
            "audit_policy_mode IN ('off', 'best_effort', 'strict')",
            name="ck_audit_intent_policy_mode",
        ),
        sa.CheckConstraint(
            "event_type IN ('preflight', 'completion')",
            name="ck_audit_intent_event_type",
        ),
        sa.ForeignKeyConstraint(
            ["api_key_id"],
            ["api_keys.id"],
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "api_key_id"],
            ["api_keys.organization_id", "api_keys.id"],
            name="fk_audit_intent_org_api_key",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "user_id"],
            ["users.organization_id", "users.id"],
            name="fk_audit_intent_org_user",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "outbox_event_id"],
            ["outbox_event.organization_id", "outbox_event.id"],
            name="fk_audit_intent_org_outbox_event",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "request_id",
            "event_type",
            name="uq_audit_intent_org_request_event",
        ),
    )
    op.create_table(
        "compliance_finding",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("connector_id", sa.UUID(), nullable=False),
        sa.Column("activity_id", sa.UUID(), nullable=True),
        sa.Column("content_id", sa.String(length=255), nullable=False),
        sa.Column("entity_type", sa.String(length=128), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("kvkk_category", sa.String(length=128), nullable=True),
        sa.Column("gdpr_category", sa.String(length=128), nullable=True),
        sa.Column("match_offset", sa.Integer(), nullable=False),
        sa.Column("match_length", sa.Integer(), nullable=False),
        sa.Column("value_hash", sa.String(length=128), nullable=False),
        sa.Column("actor_email", sa.String(length=320), nullable=True),
        sa.Column("model", sa.String(length=255), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source_log_file_id", sa.UUID(), nullable=True),
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
            "severity IN ('low', 'medium', 'high', 'critical')",
            name="ck_compliance_finding_severity",
        ),
        sa.CheckConstraint("match_length > 0", name="ck_compliance_finding_length"),
        sa.CheckConstraint("match_offset >= 0", name="ck_compliance_finding_offset"),
        sa.ForeignKeyConstraint(
            ["activity_id"], ["compliance_activity.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["connector_id"], ["compliance_connector.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["source_log_file_id"], ["compliance_log_file.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "connector_id",
            "content_id",
            "value_hash",
            "match_offset",
            name="uq_compliance_finding_dedup",
        ),
    )
    op.create_index(
        op.f("ix_compliance_finding_connector_id"),
        "compliance_finding",
        ["connector_id"],
        unique=False,
    )
    op.create_index(
        "ix_compliance_finding_entity",
        "compliance_finding",
        ["entity_type"],
        unique=False,
    )
    op.create_index(
        "ix_compliance_finding_occurred",
        "compliance_finding",
        ["occurred_at"],
        unique=False,
    )
    op.create_index(
        "ix_compliance_finding_severity",
        "compliance_finding",
        ["severity"],
        unique=False,
    )
    op.execute(
        """
        CREATE FUNCTION validate_compliance_finding_connector()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $function$
        BEGIN
            IF NEW.activity_id IS NOT NULL AND NOT EXISTS (
                SELECT 1
                FROM compliance_activity
                WHERE id = NEW.activity_id
                  AND connector_id = NEW.connector_id
            ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23503',
                    MESSAGE = 'compliance finding activity belongs to another connector',
                    CONSTRAINT = 'fk_compliance_finding_activity_connector',
                    TABLE = 'compliance_finding';
            END IF;

            IF NEW.source_log_file_id IS NOT NULL AND NOT EXISTS (
                SELECT 1
                FROM compliance_log_file
                WHERE id = NEW.source_log_file_id
                  AND connector_id = NEW.connector_id
            ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23503',
                    MESSAGE = 'compliance finding log file belongs to another connector',
                    CONSTRAINT = 'fk_compliance_finding_log_file_connector',
                    TABLE = 'compliance_finding';
            END IF;

            RETURN NEW;
        END;
        $function$
        """
    )
    op.execute(
        """
        CREATE TRIGGER compliance_finding_connector_guard
        BEFORE INSERT OR UPDATE ON compliance_finding
        FOR EACH ROW EXECUTE FUNCTION validate_compliance_finding_connector()
        """
    )
    op.create_table(
        "quota_period_usage",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("api_key_id", sa.UUID(), nullable=False),
        sa.Column("period_type", sa.Text(), nullable=False),
        sa.Column("period_start", sa.Date(), nullable=False),
        sa.Column("period_end", sa.Date(), nullable=False),
        sa.Column(
            "reserved_requests",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "settled_requests",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "reserved_tokens", sa.Integer(), server_default=sa.text("0"), nullable=False
        ),
        sa.Column(
            "settled_tokens", sa.Integer(), server_default=sa.text("0"), nullable=False
        ),
        sa.Column("limit_requests", sa.Integer(), nullable=True),
        sa.Column("limit_tokens", sa.Integer(), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "period_type IN ('daily', 'monthly')",
            name="ck_quota_period_usage_period_type",
        ),
        sa.CheckConstraint(
            "reserved_requests >= 0", name="ck_quota_period_usage_reserved_requests"
        ),
        sa.CheckConstraint(
            "reserved_tokens >= 0", name="ck_quota_period_usage_reserved_tokens"
        ),
        sa.CheckConstraint(
            "settled_requests >= 0", name="ck_quota_period_usage_settled_requests"
        ),
        sa.CheckConstraint(
            "settled_tokens >= 0", name="ck_quota_period_usage_settled_tokens"
        ),
        sa.ForeignKeyConstraint(
            ["api_key_id"],
            ["api_keys.id"],
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "api_key_id"],
            ["api_keys.organization_id", "api_keys.id"],
            name="fk_quota_period_usage_org_api_key",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "api_key_id",
            "period_type",
            "period_start",
            name="uq_quota_period_usage_scope",
        ),
    )
    op.create_table(
        "request_lifecycle",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("request_id", sa.Text(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("actor_type", sa.Text(), nullable=False),
        sa.Column("api_key_id", sa.UUID(), nullable=True),
        sa.Column("user_id", sa.UUID(), nullable=True),
        sa.Column("source_endpoint", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("provider", sa.Text(), nullable=True),
        sa.Column("provider_model", sa.Text(), nullable=True),
        sa.Column("requested_model", sa.Text(), nullable=True),
        sa.Column(
            "route_decision", postgresql.JSONB(astext_type=sa.Text()), nullable=True
        ),
        sa.Column(
            "stream", sa.Boolean(), server_default=sa.text("false"), nullable=False
        ),
        sa.Column(
            "cache_status", sa.Text(), server_default="not_checked", nullable=False
        ),
        sa.Column(
            "privacy_status", sa.Text(), server_default="not_checked", nullable=False
        ),
        sa.Column(
            "pii_detected",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("provider_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("stream_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("client_disconnected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reconciled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reconciliation_due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("terminal_error_code", sa.Text(), nullable=True),
        sa.Column("terminal_error_message", sa.Text(), nullable=True),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
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
            "(actor_type = 'api_key' AND api_key_id IS NOT NULL) OR (actor_type = 'user_jwt' AND user_id IS NOT NULL AND api_key_id IS NULL) OR (actor_type = 'internal' AND api_key_id IS NULL AND user_id IS NULL)",
            name="ck_request_lifecycle_actor_identity",
        ),
        sa.CheckConstraint(
            "actor_type IN ('api_key', 'user_jwt', 'internal')",
            name="ck_request_lifecycle_actor_type",
        ),
        sa.CheckConstraint(
            "status IN ('accepted', 'routing_pending', 'routing_rejected', 'provider_pending', 'provider_started', 'streaming', 'completed', 'provider_error', 'client_disconnected', 'timeout', 'cancelled', 'internal_error', 'rejected', 'failed')",
            name="ck_request_lifecycle_status",
        ),
        sa.ForeignKeyConstraint(
            ["api_key_id"],
            ["api_keys.id"],
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "api_key_id"],
            ["api_keys.organization_id", "api_keys.id"],
            name="fk_request_lifecycle_org_api_key",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "user_id"],
            ["users.organization_id", "users.id"],
            name="fk_request_lifecycle_org_user",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("request_id", name="uq_request_lifecycle_request_id"),
    )
    op.create_index(
        "ix_request_lifecycle_api_key_started_at",
        "request_lifecycle",
        ["api_key_id", "started_at"],
        unique=False,
    )
    op.create_index(
        "ix_request_lifecycle_org_started_at",
        "request_lifecycle",
        ["organization_id", "started_at"],
        unique=False,
    )
    op.create_index(
        "ix_request_lifecycle_org_reconciled_at",
        "request_lifecycle",
        ["organization_id", "reconciled_at"],
        unique=False,
        postgresql_where=sa.text("reconciled_at IS NOT NULL"),
    )
    op.create_index(
        "ix_request_lifecycle_org_status_started_at",
        "request_lifecycle",
        ["organization_id", "status", "started_at"],
        unique=False,
    )
    op.create_index(
        "ix_request_lifecycle_reconciliation_due",
        "request_lifecycle",
        ["reconciliation_due_at", "id"],
        unique=False,
        postgresql_where=sa.text(
            "reconciliation_due_at IS NOT NULL AND reconciled_at IS NULL"
        ),
    )
    op.create_index(
        "ix_request_lifecycle_user_started_at",
        "request_lifecycle",
        ["user_id", "started_at"],
        unique=False,
    )
    op.create_table(
        "request_logs",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("request_id", sa.String(), nullable=False),
        sa.Column("api_key_id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("prompt_tokens", sa.Integer(), nullable=False),
        sa.Column("completion_tokens", sa.Integer(), nullable=False),
        sa.Column("cost_saved", sa.Float(), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=False),
        sa.Column("is_cache_hit", sa.Boolean(), nullable=False),
        sa.Column("pii_detected", sa.Boolean(), nullable=False),
        sa.Column("path", sa.String(), nullable=True),
        sa.Column("method", sa.String(), nullable=True),
        sa.Column("model", sa.String(), nullable=True),
        sa.Column("tokens_saved", sa.Integer(), nullable=False),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("flags", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("cost_usd", sa.Float(), server_default="0", nullable=False),
        sa.Column("cost_center", sa.String(), nullable=True),
        sa.Column("team", sa.String(), nullable=True),
        sa.Column("tags", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.ForeignKeyConstraint(
            ["organization_id", "api_key_id"],
            ["api_keys.organization_id", "api_keys.id"],
            name="fk_request_logs_org_api_key",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_request_logs_organization_id",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id", "request_id", name="uq_request_logs_org_request_id"
        ),
    )
    op.create_index(
        op.f("ix_request_logs_api_key_id"), "request_logs", ["api_key_id"], unique=False
    )
    op.create_index(
        op.f("ix_request_logs_cost_center"),
        "request_logs",
        ["cost_center"],
        unique=False,
    )
    op.create_index(
        "ix_request_logs_org_timestamp",
        "request_logs",
        ["organization_id", "timestamp"],
        unique=False,
    )
    op.create_index(
        op.f("ix_request_logs_organization_id"),
        "request_logs",
        ["organization_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_request_logs_timestamp"), "request_logs", ["timestamp"], unique=False
    )
    op.create_table(
        "usage_ledger",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("request_id", sa.Text(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("api_key_id", sa.UUID(), nullable=False),
        sa.Column("requested_model", sa.Text(), nullable=False),
        sa.Column("provider", sa.Text(), nullable=True),
        sa.Column("provider_model", sa.Text(), nullable=True),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("idempotency_key", sa.Text(), nullable=False),
        sa.Column("reservation_event_id", sa.UUID(), nullable=True),
        sa.Column(
            "request_count", sa.Integer(), server_default=sa.text("0"), nullable=False
        ),
        sa.Column(
            "prompt_tokens", sa.Integer(), server_default=sa.text("0"), nullable=False
        ),
        sa.Column(
            "completion_tokens",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "total_tokens", sa.Integer(), server_default=sa.text("0"), nullable=False
        ),
        sa.Column(
            "estimated", sa.Boolean(), server_default=sa.text("true"), nullable=False
        ),
        sa.Column(
            "cost_usd",
            sa.Numeric(precision=18, scale=8),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column("currency", sa.Text(), server_default="USD", nullable=False),
        sa.Column(
            "period_allocations",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "((event_type IN ('quota_reservation', 'quota_settlement', 'quota_refund') AND provider IS NULL AND provider_model IS NULL) OR (event_type IN ('spend_reservation', 'spend_settlement', 'spend_refund', 'provider_error') AND provider IS NOT NULL AND provider_model IS NOT NULL) OR event_type IN ('cache_hit', 'adjustment_debit', 'adjustment_credit'))",
            name="ck_usage_ledger_provider_shape",
        ),
        sa.CheckConstraint(
            "((event_type IN ('quota_settlement', 'quota_refund', 'spend_settlement', 'spend_refund') AND reservation_event_id IS NOT NULL) OR (event_type NOT IN ('quota_settlement', 'quota_refund', 'spend_settlement', 'spend_refund') AND reservation_event_id IS NULL))",
            name="ck_usage_ledger_reservation_reference",
        ),
        sa.CheckConstraint(
            "event_type IN ('quota_reservation', 'quota_settlement', 'quota_refund', 'spend_reservation', 'spend_settlement', 'spend_refund', 'adjustment_debit', 'adjustment_credit', 'cache_hit', 'provider_error')",
            name="ck_usage_ledger_event_type",
        ),
        sa.CheckConstraint(
            "(provider IS NULL AND provider_model IS NULL) OR (provider IS NOT NULL AND provider_model IS NOT NULL)",
            name="ck_usage_ledger_provider_pair",
        ),
        sa.CheckConstraint(
            "completion_tokens >= 0", name="ck_usage_ledger_completion_tokens"
        ),
        sa.CheckConstraint("cost_usd >= 0", name="ck_usage_ledger_cost_usd"),
        sa.CheckConstraint("prompt_tokens >= 0", name="ck_usage_ledger_prompt_tokens"),
        sa.CheckConstraint("request_count >= 0", name="ck_usage_ledger_request_count"),
        sa.CheckConstraint(
            "total_tokens = prompt_tokens + completion_tokens",
            name="ck_usage_ledger_total_tokens",
        ),
        sa.ForeignKeyConstraint(
            ["api_key_id"],
            ["api_keys.id"],
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "api_key_id"],
            ["api_keys.organization_id", "api_keys.id"],
            name="fk_usage_ledger_org_api_key",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "reservation_event_id"],
            ["usage_ledger.organization_id", "usage_ledger.id"],
            name="fk_usage_ledger_org_reservation_event",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "id", name="uq_usage_ledger_org_id"),
        sa.UniqueConstraint(
            "organization_id", "idempotency_key", name="uq_usage_ledger_org_idempotency"
        ),
    )
    op.create_index(
        "ix_usage_ledger_org_request_event",
        "usage_ledger",
        ["organization_id", "request_id", "event_type"],
        unique=False,
    )
    op.create_index(
        "ix_usage_ledger_org_created_event",
        "usage_ledger",
        ["organization_id", "created_at", "event_type"],
        unique=False,
    )
    op.create_index(
        "ux_usage_ledger_reservation_event_id",
        "usage_ledger",
        ["reservation_event_id"],
        unique=True,
        postgresql_where=sa.text("reservation_event_id IS NOT NULL"),
    )
    op.execute(
        """
        CREATE FUNCTION enforce_usage_ledger_immutability()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $function$
        BEGIN
            IF OLD.event_type IN ('quota_reservation', 'spend_reservation')
               AND OLD.period_allocations = '[]'::jsonb
               AND jsonb_typeof(NEW.period_allocations) = 'array'
               AND jsonb_array_length(NEW.period_allocations) > 0
               AND (to_jsonb(NEW) - 'period_allocations')
                   = (to_jsonb(OLD) - 'period_allocations')
               AND OLD.xmin = (pg_current_xact_id()::text::xid)
            THEN
                RETURN NEW;
            END IF;

            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'usage_ledger is immutable';
        END;
        $function$
        """
    )
    op.execute(
        """
        CREATE TRIGGER usage_ledger_immutable
        BEFORE UPDATE ON usage_ledger
        FOR EACH ROW EXECUTE FUNCTION enforce_usage_ledger_immutability()
        """
    )
    op.create_table(
        "oversight_request",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("policy_id", sa.UUID(), nullable=True),
        sa.Column("request_ref", sa.String(length=255), nullable=False),
        sa.Column("audit_log_id", sa.UUID(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column(
            "trigger_detail",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
        ),
        sa.Column(
            "status", sa.String(length=16), server_default="pending", nullable=False
        ),
        sa.Column("approver", sa.String(length=320), nullable=True),
        sa.Column("decision_note", sa.Text(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
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
            "status IN ('pending', 'approved', 'rejected', 'expired')",
            name="ck_oversight_request_status",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "audit_log_id"],
            ["ai_act_audit_log.organization_id", "ai_act_audit_log.id"],
            name="fk_oversight_request_tenant_audit",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "policy_id"],
            ["oversight_policy.organization_id", "oversight_policy.id"],
            name="fk_oversight_request_tenant_policy",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "audit_log_id",
            name="uq_oversight_request_tenant_audit",
        ),
    )
    op.create_index(
        "ix_oversight_request_tenant_status",
        "oversight_request",
        ["organization_id", "status"],
        unique=False,
    )
    op.create_table(
        "shared_results",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("prompt", sa.Text(), nullable=False),
        sa.Column("response", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("view_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("max_views", sa.Integer(), server_default="25", nullable=False),
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
            "view_count >= 0 AND view_count <= max_views",
            name="ck_shared_results_view_count",
        ),
        sa.CheckConstraint(
            "max_views >= 1 AND max_views <= 25",
            name="ck_shared_results_max_views",
        ),
        sa.CheckConstraint(
            "char_length(token_hash) = 64",
            name="ck_shared_results_token_hash",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_shared_results_token_hash",
        "shared_results",
        ["token_hash"],
        unique=True,
    )
    op.create_index(
        "ix_shared_results_organization_id",
        "shared_results",
        ["organization_id"],
        unique=False,
    )


def downgrade() -> None:
    """Remove the standalone trust-boundary gateway schema."""
    op.drop_index("ix_shared_results_organization_id", table_name="shared_results")
    op.drop_index("ix_shared_results_token_hash", table_name="shared_results")
    op.drop_table("shared_results")
    op.drop_index("ix_oversight_request_tenant_status", table_name="oversight_request")
    op.drop_table("oversight_request")
    op.execute("DROP TRIGGER usage_ledger_immutable ON usage_ledger")
    op.execute("DROP FUNCTION enforce_usage_ledger_immutability()")
    op.drop_index(
        "ux_usage_ledger_reservation_event_id",
        table_name="usage_ledger",
        postgresql_where=sa.text("reservation_event_id IS NOT NULL"),
    )
    op.drop_index("ix_usage_ledger_org_created_event", table_name="usage_ledger")
    op.drop_index("ix_usage_ledger_org_request_event", table_name="usage_ledger")
    op.drop_table("usage_ledger")
    op.drop_index(op.f("ix_request_logs_timestamp"), table_name="request_logs")
    op.drop_index(op.f("ix_request_logs_organization_id"), table_name="request_logs")
    op.drop_index("ix_request_logs_org_timestamp", table_name="request_logs")
    op.drop_index(op.f("ix_request_logs_cost_center"), table_name="request_logs")
    op.drop_index(op.f("ix_request_logs_api_key_id"), table_name="request_logs")
    op.drop_table("request_logs")
    op.drop_index(
        "ix_request_lifecycle_user_started_at", table_name="request_lifecycle"
    )
    op.drop_index(
        "ix_request_lifecycle_reconciliation_due",
        table_name="request_lifecycle",
        postgresql_where=sa.text(
            "reconciliation_due_at IS NOT NULL AND reconciled_at IS NULL"
        ),
    )
    op.drop_index(
        "ix_request_lifecycle_org_status_started_at", table_name="request_lifecycle"
    )
    op.drop_index(
        "ix_request_lifecycle_org_reconciled_at",
        table_name="request_lifecycle",
        postgresql_where=sa.text("reconciled_at IS NOT NULL"),
    )
    op.drop_index("ix_request_lifecycle_org_started_at", table_name="request_lifecycle")
    op.drop_index(
        "ix_request_lifecycle_api_key_started_at", table_name="request_lifecycle"
    )
    op.drop_table("request_lifecycle")
    op.drop_table("quota_period_usage")
    op.execute("DROP TRIGGER compliance_finding_connector_guard ON compliance_finding")
    op.execute("DROP FUNCTION validate_compliance_finding_connector()")
    op.drop_index("ix_compliance_finding_severity", table_name="compliance_finding")
    op.drop_index("ix_compliance_finding_occurred", table_name="compliance_finding")
    op.drop_index("ix_compliance_finding_entity", table_name="compliance_finding")
    op.drop_index(
        op.f("ix_compliance_finding_connector_id"), table_name="compliance_finding"
    )
    op.drop_table("compliance_finding")
    op.drop_table("audit_intent")
    op.execute(
        "DROP TRIGGER IF EXISTS ai_act_audit_anchor_reject_truncate "
        "ON ai_act_audit_anchor"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS ai_act_audit_anchor_append_only ON ai_act_audit_anchor"
    )
    op.drop_index("ix_ai_audit_tenant_request", table_name="ai_act_audit_log")
    op.drop_index("ix_ai_audit_tenant_created", table_name="ai_act_audit_log")
    op.drop_index(op.f("ix_ai_act_audit_log_created_at"), table_name="ai_act_audit_log")
    op.drop_table("ai_act_audit_log")
    op.execute("DROP FUNCTION reject_ai_act_audit_mutation()")
    op.drop_index(
        op.f("ix_cost_budget_alert_state_budget_id"),
        table_name="cost_budget_alert_state",
    )
    op.drop_table("cost_budget_alert_state")
    op.drop_index("ix_compliance_log_file_event", table_name="compliance_log_file")
    op.drop_index(
        op.f("ix_compliance_log_file_connector_id"), table_name="compliance_log_file"
    )
    op.drop_table("compliance_log_file")
    op.drop_index(
        op.f("ix_compliance_ingest_cursor_connector_id"),
        table_name="compliance_ingest_cursor",
    )
    op.drop_table("compliance_ingest_cursor")
    op.drop_index(
        op.f("ix_compliance_forward_target_connector_id"),
        table_name="compliance_forward_target",
    )
    op.drop_table("compliance_forward_target")
    op.drop_index("ix_compliance_activity_occurred", table_name="compliance_activity")
    op.drop_index("ix_compliance_activity_event_type", table_name="compliance_activity")
    op.drop_index(
        op.f("ix_compliance_activity_connector_id"), table_name="compliance_activity"
    )
    op.drop_table("compliance_activity")
    op.drop_index("ix_api_keys_organization_id", table_name="api_keys")
    op.drop_index("ix_api_keys_key_hash", table_name="api_keys")
    op.drop_table("api_keys")
    op.drop_index("ix_invites_token_hash", table_name="organization_invites")
    op.drop_index("ix_invites_organization_id", table_name="organization_invites")
    op.drop_table("organization_invites")
    op.drop_index(
        "ix_billing_receipts_organization_id", table_name="billing_webhook_receipts"
    )
    op.drop_index("ix_billing_receipts_digest", table_name="billing_webhook_receipts")
    op.drop_table("billing_webhook_receipts")
    op.drop_index("ix_users_organization_id", table_name="users")
    op.drop_table("users")
    op.drop_table("spend_period_usage")
    op.drop_index("ix_provider_secrets_tenant_provider", table_name="provider_secrets")
    op.drop_table("provider_secrets")
    op.drop_index("ix_oversight_policy_tenant_enabled", table_name="oversight_policy")
    op.drop_table("oversight_policy")
    op.drop_index(
        "ix_outbox_event_expired_lease",
        table_name="outbox_event",
        postgresql_where=sa.text("status = 'processing'"),
    )
    op.drop_index(
        "ix_outbox_event_claimable",
        table_name="outbox_event",
        postgresql_where=sa.text("status IN ('pending', 'failed')"),
    )
    op.drop_table("outbox_event")
    op.drop_table("organization_pii_configs")
    op.drop_index("ix_cost_budget_org", table_name="cost_budget")
    op.drop_table("cost_budget")
    op.drop_index("ix_compliance_connector_tenant", table_name="compliance_connector")
    op.drop_table("compliance_connector")
    op.drop_index(
        op.f("ix_ai_act_audit_anchor_organization_id"), table_name="ai_act_audit_anchor"
    )
    op.drop_table("ai_act_audit_anchor")
    op.drop_table("organizations")
    op.drop_table("tier_definitions")
