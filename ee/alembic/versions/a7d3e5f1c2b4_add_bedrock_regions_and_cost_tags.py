"""Add Bedrock destination regions and team AWS cost tags.

A Bedrock deployment keeps where its inference profile can route (null until
known); a team may name the session tag value its Bedrock requests carry.

Revision: a7d3e5f1c2b4
Parent: e248b23a6fe1
Created: 2026-10-13
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "a7d3e5f1c2b4"
down_revision: str | Sequence[str] | None = "e248b23a6fe1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "model_deployments",
        sa.Column("aws_destination_regions", postgresql.JSONB(astext_type=sa.Text())),
    )
    op.add_column(
        "model_deployments",
        sa.Column("aws_destinations_checked_at", sa.DateTime(timezone=True)),
    )
    op.add_column("teams", sa.Column("aws_cost_tag", sa.String(length=256)))
    op.create_check_constraint(
        "ck_teams_aws_cost_tag",
        "teams",
        "aws_cost_tag ~ '^[A-Za-z0-9 _.:/=+@-]+$'",
    )


def downgrade() -> None:
    op.drop_constraint("ck_teams_aws_cost_tag", "teams", type_="check")
    op.drop_column("teams", "aws_cost_tag")
    op.drop_column("model_deployments", "aws_destinations_checked_at")
    op.drop_column("model_deployments", "aws_destination_regions")
