"""Add Azure OpenAI deployments: upstream, price model and cache prices.

Revision: c9ed4e82b922
Parent: 73669c9be04c
Created: 2026-10-11
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "c9ed4e82b922"
down_revision: str | Sequence[str] | None = "73669c9be04c"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # The server default keeps every existing row generic. An Entra secret is a
    # provider_secrets row with provider azure_entra: no column of its own.
    op.add_column("model_deployments", sa.Column("price_model", sa.String(length=200)))
    op.add_column(
        "model_deployments",
        sa.Column("cache_read_price_per_million", sa.Numeric(18, 8)),
    )
    op.add_column(
        "model_deployments",
        sa.Column("cache_write_price_per_million", sa.Numeric(18, 8)),
    )
    op.add_column(
        "model_deployments",
        sa.Column(
            "upstream", sa.String(length=32), server_default="generic", nullable=False
        ),
    )
    op.create_check_constraint(
        "ck_model_deployments_cache_prices",
        "model_deployments",
        "(cache_read_price_per_million IS NULL OR (input_price_per_million "
        "IS NOT NULL AND cache_read_price_per_million >= 0)) AND "
        "(cache_write_price_per_million IS NULL OR (input_price_per_million "
        "IS NOT NULL AND cache_write_price_per_million >= 0))",
    )
    op.create_check_constraint(
        "ck_model_deployments_upstream",
        "model_deployments",
        "upstream IN ('generic', 'azure_openai')",
    )


def downgrade() -> None:
    # Downgrades are disposable-only; Azure rows lose their meaning.
    op.drop_constraint(
        "ck_model_deployments_upstream", "model_deployments", type_="check"
    )
    op.drop_constraint(
        "ck_model_deployments_cache_prices", "model_deployments", type_="check"
    )
    for column in (
        "upstream",
        "cache_write_price_per_million",
        "cache_read_price_per_million",
        "price_model",
    ):
        op.drop_column("model_deployments", column)
