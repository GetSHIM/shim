"""Add external usage records.

One row per call another gateway (LiteLLM first) logged, imported by an operator
script. The source's numbers the findings read, kept apart from shim's
accounting; never content, a user, a team, a tag or an endpoint.

Revision: 099f6ff61feb
Parent: b93eaf9b1386
Created: 2026-10-12
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "099f6ff61feb"
down_revision: str | Sequence[str] | None = "b93eaf9b1386"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "external_usage_records",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("source_request_id", sa.String(length=255), nullable=False),
        sa.Column("import_id", sa.UUID(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ttft_ms", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=True),
        sa.Column("model", sa.String(length=255), nullable=True),
        sa.Column("model_group", sa.String(length=255), nullable=True),
        sa.Column("source_key_hash", sa.String(length=128), nullable=True),
        sa.Column("prompt_tokens", sa.Integer(), nullable=True),
        sa.Column("completion_tokens", sa.Integer(), nullable=True),
        sa.Column("cost_usd", sa.Numeric(precision=18, scale=8), nullable=True),
        sa.Column(
            "imported_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("source IN ('litellm')", name="ck_external_usage_source"),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_external_usage_organization",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "source",
            "source_request_id",
            name="uq_external_usage_source_request",
        ),
    )
    op.create_index(
        "ix_external_usage_tenant_source_started",
        "external_usage_records",
        ["organization_id", "source", "started_at"],
    )


def downgrade() -> None:
    op.drop_table("external_usage_records")
