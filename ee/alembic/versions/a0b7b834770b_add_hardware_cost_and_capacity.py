"""Add monthly hardware cost per internal deployment and its entered capacity.

A cost is entered per month and deployment in its own currency; capacity is the
concurrent requests the admin says the hardware holds. Neither changes a request.

Revision: a0b7b834770b
Parent: a7d3e5f1c2b4
Created: 2026-10-13
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "a0b7b834770b"
down_revision: str | Sequence[str] | None = "a7d3e5f1c2b4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "deployment_hardware_costs",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("deployment_id", sa.UUID(), nullable=False),
        sa.Column("period", sa.String(length=7), nullable=False),
        sa.Column("amount", sa.Numeric(precision=18, scale=2), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False),
        sa.Column("note", sa.String(length=200), nullable=True),
        sa.Column("entered_by", sa.String(length=64), nullable=True),
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
            "currency ~ '^[A-Z]{3}$'", name="ck_deployment_hardware_costs_currency"
        ),
        sa.CheckConstraint(
            "period ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'",
            name="ck_deployment_hardware_costs_period",
        ),
        sa.CheckConstraint("amount > 0", name="ck_deployment_hardware_costs_amount"),
        sa.ForeignKeyConstraint(
            ["deployment_id"],
            ["model_deployments.id"],
            name="fk_deployment_hardware_costs_deployment",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "deployment_id",
            "period",
            name="uq_deployment_hardware_costs_period",
        ),
    )
    op.add_column(
        "model_deployments",
        sa.Column("capacity_concurrent_requests", sa.Integer(), nullable=True),
    )
    op.create_check_constraint(
        "ck_model_deployments_capacity",
        "model_deployments",
        "capacity_concurrent_requests BETWEEN 1 AND 100000",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_model_deployments_capacity", "model_deployments", type_="check"
    )
    op.drop_column("model_deployments", "capacity_concurrent_requests")
    op.drop_table("deployment_hardware_costs")
