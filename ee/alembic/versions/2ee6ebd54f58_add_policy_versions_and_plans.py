"""Add policy versions and plans.

A version records the before and after state of every managed write; a plan is a
change set shown with its effect before it is applied.

Revision: 2ee6ebd54f58
Parent: 1f036bd115c8
Created: 2026-10-09
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "2ee6ebd54f58"
down_revision: str | Sequence[str] | None = "1f036bd115c8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "policy_plans",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("base_version", sa.Integer(), nullable=False),
        sa.Column("changes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("risk", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("reason", sa.String(length=500), nullable=True),
        sa.Column(
            "context",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("created_by", sa.String(length=64), nullable=True),
        sa.Column("created_by_actor_type", sa.String(length=16), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("submitted_by", sa.String(length=64), nullable=True),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("approved_by", sa.String(length=64), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("applied_by", sa.String(length=64), nullable=True),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("applied_version", sa.Integer(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "created_by_actor_type IN ('user_jwt', 'service', 'system')",
            name="ck_policy_plans_actor_type",
        ),
        sa.CheckConstraint(
            "risk IN ('tightening', 'relaxing', 'neutral')", name="ck_policy_plans_risk"
        ),
        sa.CheckConstraint(
            "source IN ('api', 'mcp', 'plan', 'restore', 'file', 'auto', 'import', 'proposal')",
            name="ck_policy_plans_source",
        ),
        sa.CheckConstraint(
            "status IN ('draft', 'pending_approval', 'applied', 'rejected', 'expired', 'rolled_back')",
            name="ck_policy_plans_status",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_policy_plans_organization_id",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_policy_plans_tenant_status",
        "policy_plans",
        ["organization_id", "status", "created_at"],
        unique=False,
    )
    op.create_table(
        "policy_versions",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("snapshot", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("previous", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("plan_id", sa.UUID(), nullable=True),
        sa.Column("risk", sa.String(length=16), nullable=False),
        sa.Column("created_by", sa.String(length=64), nullable=True),
        sa.Column("actor_type", sa.String(length=16), nullable=False),
        sa.Column("reason", sa.String(length=500), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "actor_type IN ('user_jwt', 'service', 'system')",
            name="ck_policy_versions_actor_type",
        ),
        sa.CheckConstraint(
            "risk IN ('tightening', 'relaxing', 'neutral')",
            name="ck_policy_versions_risk",
        ),
        sa.CheckConstraint(
            "source IN ('api', 'mcp', 'plan', 'restore', 'file', 'auto', 'import', 'proposal')",
            name="ck_policy_versions_source",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_policy_versions_organization_id",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id", "version", name="uq_policy_versions_tenant_version"
        ),
    )


def downgrade() -> None:
    # Downgrades are disposable-only; versions and plans are lost.
    op.drop_table("policy_versions")
    op.drop_index("ix_policy_plans_tenant_status", table_name="policy_plans")
    op.drop_table("policy_plans")
