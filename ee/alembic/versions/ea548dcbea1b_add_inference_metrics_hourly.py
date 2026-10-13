"""Add hourly aggregates of model servers' own load metrics.

Counts, sums and maxima per internal deployment and UTC hour, kept 90 days; no raw
series, no model names, no text from a metrics page.

Revision: ea548dcbea1b
Parent: a0b7b834770b
Created: 2026-10-13 10:42:43.625185
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "ea548dcbea1b"
down_revision: str | Sequence[str] | None = "a0b7b834770b"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "inference_metrics_hourly",
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("deployment_id", sa.UUID(), nullable=False),
        sa.Column("hour", sa.DateTime(timezone=True), nullable=False),
        sa.Column("server", sa.String(length=16), nullable=False),
        sa.Column("samples", sa.Integer(), server_default="0", nullable=False),
        sa.Column("busy_samples", sa.Integer(), server_default="0", nullable=False),
        sa.Column("queued_samples", sa.Integer(), server_default="0", nullable=False),
        sa.Column("loaded_samples", sa.Integer(), server_default="0", nullable=False),
        sa.Column("errors", sa.Integer(), server_default="0", nullable=False),
        sa.Column("running_sum", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("waiting_sum", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("running_max", sa.Integer(), nullable=True),
        sa.Column("waiting_max", sa.Integer(), nullable=True),
        sa.Column("cache_usage_sum", sa.Float(), server_default="0", nullable=False),
        sa.Column("cache_usage_max", sa.Float(), nullable=True),
        sa.Column("vram_bytes_max", sa.BigInteger(), nullable=True),
        sa.Column("last_error", sa.String(length=32), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "server IN ('vllm', 'tgi', 'ollama')",
            name="ck_inference_metrics_hourly_server",
        ),
        sa.CheckConstraint(
            "cache_usage_max IS NULL OR cache_usage_max BETWEEN 0 AND 1",
            name="ck_inference_metrics_hourly_cache",
        ),
        sa.CheckConstraint(
            "samples >= 0 AND busy_samples >= 0 AND queued_samples >= 0 AND loaded_samples >= 0 AND errors >= 0",
            name="ck_inference_metrics_hourly_counts",
        ),
        sa.ForeignKeyConstraint(
            ["deployment_id"],
            ["model_deployments.id"],
            name="fk_inference_metrics_hourly_deployment",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_inference_metrics_hourly_organization",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "organization_id",
            "deployment_id",
            "hour",
            name="pk_inference_metrics_hourly",
        ),
    )
    # Every scrape pass deletes hours past retention; the key leads with the tenant.
    op.create_index(
        "ix_inference_metrics_hourly_hour", "inference_metrics_hourly", ["hour"]
    )


def downgrade() -> None:
    op.drop_table("inference_metrics_hourly")
