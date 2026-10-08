"""Add an optional price and context window to model deployments.

Revision: 73260da93588
Parent: 31774bcbf441
Created: 2026-10-08
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "73260da93588"
down_revision: str | Sequence[str] | None = "31774bcbf441"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Existing deployments stay unpriced and unchecked, as before.
    op.add_column(
        "model_deployments",
        sa.Column("input_price_per_million", sa.Numeric(18, 8), nullable=True),
    )
    op.add_column(
        "model_deployments",
        sa.Column("output_price_per_million", sa.Numeric(18, 8), nullable=True),
    )
    op.add_column(
        "model_deployments", sa.Column("context_window", sa.Integer(), nullable=True)
    )
    op.create_check_constraint(
        "ck_model_deployments_price_pair",
        "model_deployments",
        "(input_price_per_million IS NULL AND output_price_per_million IS NULL) "
        "OR (input_price_per_million IS NOT NULL AND output_price_per_million "
        "IS NOT NULL AND input_price_per_million >= 0 AND output_price_per_million >= 0)",
    )
    op.create_check_constraint(
        "ck_model_deployments_context_window",
        "model_deployments",
        "context_window IS NULL OR context_window > 0",
    )


def downgrade() -> None:
    # Downgrades are disposable-only; deployment prices and windows are lost.
    op.drop_constraint(
        "ck_model_deployments_context_window", "model_deployments", type_="check"
    )
    op.drop_constraint(
        "ck_model_deployments_price_pair", "model_deployments", type_="check"
    )
    op.drop_column("model_deployments", "context_window")
    op.drop_column("model_deployments", "output_price_per_million")
    op.drop_column("model_deployments", "input_price_per_million")
