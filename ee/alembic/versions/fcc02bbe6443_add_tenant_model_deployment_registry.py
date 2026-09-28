"""Add tenant model deployment registry

Revision: fcc02bbe6443
Parent: c31b7a91d602
Created: 2026-09-08 02:51:52.112876
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "fcc02bbe6443"
down_revision: str | Sequence[str] | None = "c31b7a91d602"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_unique_constraint(
        "uq_provider_secrets_tenant_id", "provider_secrets", ["organization_id", "id"]
    )
    op.create_table(
        "model_deployments",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("alias", sa.String(length=200), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("upstream_model", sa.String(length=200), nullable=False),
        sa.Column("base_url", sa.String(length=2048), nullable=False),
        sa.Column("provider_secret_id", sa.UUID(), nullable=False),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False),
        sa.Column("deployment_kind", sa.String(length=16), nullable=False),
        sa.Column("declared_version", sa.String(length=200), nullable=False),
        sa.Column("owner", sa.String(length=200), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default="true", nullable=False),
        sa.Column(
            "health", sa.String(length=16), server_default="unknown", nullable=False
        ),
        sa.Column("health_checked_at", sa.DateTime(timezone=True), nullable=True),
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
            "deployment_kind IN ('internal', 'external')",
            name="ck_model_deployments_kind",
        ),
        sa.CheckConstraint(
            "health IN ('unknown', 'healthy', 'unhealthy')",
            name="ck_model_deployments_health",
        ),
        sa.CheckConstraint(
            "provider IN ('openai', 'anthropic')", name="ck_model_deployments_provider"
        ),
        sa.CheckConstraint(
            "timeout_seconds BETWEEN 1 AND 300", name="ck_model_deployments_timeout"
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "provider_secret_id"],
            ["provider_secrets.organization_id", "provider_secrets.id"],
            name="fk_model_deployments_tenant_secret",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id", "alias", name="uq_model_deployments_tenant_alias"
        ),
    )


def downgrade() -> None:
    op.drop_table("model_deployments")
    op.drop_constraint(
        "uq_provider_secrets_tenant_id", "provider_secrets", type_="unique"
    )
