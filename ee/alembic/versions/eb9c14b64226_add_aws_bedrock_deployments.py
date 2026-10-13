"""Add Amazon Bedrock deployments.

A Bedrock deployment names its AWS region. Its credential is a provider secret of
its own provider value (aws_access_key, aws_bedrock_api_key), which a build that
predates Bedrock never selects. Every existing deployment keeps its upstream and
no region.

Revision: eb9c14b64226
Parent: 6cf65cda411e
Created: 2026-10-13
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "eb9c14b64226"
down_revision: str | Sequence[str] | None = "6cf65cda411e"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("model_deployments", sa.Column("aws_region", sa.String(length=32)))
    op.drop_constraint(
        "ck_model_deployments_upstream", "model_deployments", type_="check"
    )
    op.create_check_constraint(
        "ck_model_deployments_upstream",
        "model_deployments",
        "upstream IN ('generic', 'azure_openai', 'aws_bedrock')",
    )
    op.create_check_constraint(
        "ck_model_deployments_aws_region",
        "model_deployments",
        "((upstream = 'aws_bedrock') = (aws_region IS NOT NULL)) AND "
        "(aws_region IS NULL OR aws_region ~ '^[a-z]{2}(-[a-z]+)+-[0-9]$')",
    )


def downgrade() -> None:
    # Disposable data only: the older upstream check cannot hold a Bedrock deployment.
    if (
        op.get_bind()
        .execute(
            sa.text(
                "SELECT 1 FROM model_deployments WHERE upstream = 'aws_bedrock' LIMIT 1"
            )
        )
        .first()
    ):
        raise RuntimeError("Remove Amazon Bedrock deployments before downgrading.")
    op.drop_constraint(
        "ck_model_deployments_aws_region", "model_deployments", type_="check"
    )
    op.drop_constraint(
        "ck_model_deployments_upstream", "model_deployments", type_="check"
    )
    op.create_check_constraint(
        "ck_model_deployments_upstream",
        "model_deployments",
        "upstream IN ('generic', 'azure_openai')",
    )
    op.drop_column("model_deployments", "aws_region")
