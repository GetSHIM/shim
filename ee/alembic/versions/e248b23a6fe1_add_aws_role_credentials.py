"""Add AWS role credentials: nothing secret stored, and a per-tenant external id.

A role secret keeps its ARN instead of a secret-store reference, so the reference
columns become nullable for it alone. Every existing row keeps its reference.

Revision: e248b23a6fe1
Parent: eb9c14b64226
Created: 2026-10-13
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "e248b23a6fe1"
down_revision: str | Sequence[str] | None = "eb9c14b64226"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ROLE_SHAPE = (
    "((credential_kind = 'aws_role') = (aws_role_arn IS NOT NULL)) AND "
    "((credential_kind = 'aws_role') = (secret_ref IS NULL)) AND "
    "((secret_ref IS NULL) = (secret_backend IS NULL)) AND "
    "((secret_ref IS NULL) = (secret_version IS NULL))"
)


def upgrade() -> None:
    op.create_table(
        "organization_aws_identities",
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("external_id", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_organization_aws_identities_organization_id",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("organization_id"),
        sa.UniqueConstraint(
            "external_id", name="uq_organization_aws_identities_external_id"
        ),
    )
    op.add_column("provider_secrets", sa.Column("aws_role_arn", sa.String(length=2048)))
    for column in ("secret_ref", "secret_backend", "secret_version"):
        op.alter_column("provider_secrets", column, nullable=True)
    op.drop_constraint(
        "ck_provider_secrets_credential_kind", "provider_secrets", type_="check"
    )
    op.create_check_constraint(
        "ck_provider_secrets_credential_kind",
        "provider_secrets",
        "credential_kind IN "
        "('api_key', 'aws_access_key', 'aws_bedrock_api_key', 'aws_role')",
    )
    op.create_check_constraint(
        "ck_provider_secrets_role_shape", "provider_secrets", _ROLE_SHAPE
    )


def downgrade() -> None:
    # Downgrades are disposable-only: role secrets have no reference to keep.
    op.execute("DELETE FROM provider_secrets WHERE credential_kind = 'aws_role'")
    op.drop_constraint(
        "ck_provider_secrets_role_shape", "provider_secrets", type_="check"
    )
    op.drop_constraint(
        "ck_provider_secrets_credential_kind", "provider_secrets", type_="check"
    )
    op.create_check_constraint(
        "ck_provider_secrets_credential_kind",
        "provider_secrets",
        "credential_kind IN ('api_key', 'aws_access_key', 'aws_bedrock_api_key')",
    )
    for column in ("secret_ref", "secret_backend", "secret_version"):
        op.alter_column("provider_secrets", column, nullable=False)
    op.drop_column("provider_secrets", "aws_role_arn")
    op.drop_table("organization_aws_identities")
