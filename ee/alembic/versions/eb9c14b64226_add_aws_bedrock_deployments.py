"""Add Amazon Bedrock deployments and the AWS credential kinds.

A Bedrock deployment names its AWS region; a provider secret says which kind of
credential it holds. Every existing secret is an `api_key` and every existing
deployment keeps its upstream and no region.

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
    op.add_column(
        "provider_secrets",
        sa.Column(
            "credential_kind",
            sa.String(length=32),
            server_default="api_key",
            nullable=False,
        ),
    )
    op.create_check_constraint(
        "ck_provider_secrets_credential_kind",
        "provider_secrets",
        "credential_kind IN ('api_key', 'aws_access_key', 'aws_bedrock_api_key')",
    )


def downgrade() -> None:
    # Downgrades are disposable-only; Bedrock rows and AWS secrets lose their meaning.
    op.drop_constraint(
        "ck_provider_secrets_credential_kind", "provider_secrets", type_="check"
    )
    op.drop_column("provider_secrets", "credential_kind")
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
