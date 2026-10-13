"""Add the configuration-file mode and its signing keys.

`organization_config_modes` says whether a tenant manages privacy, gateway
settings or rules from a signed YAML file (no row: the panel and the API, as
before). `config_signing_keys` holds the Ed25519 public keys of the tenant's
people who may sign that file.

Revision: 26a1f479a9ce
Parent: 4ffdded9b264
Created: 2026-10-13
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "26a1f479a9ce"
down_revision: str | Sequence[str] | None = "4ffdded9b264"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "organization_config_modes",
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column(
            "mode", sa.String(length=8), server_default=sa.text("'api'"), nullable=False
        ),
        sa.Column(
            "resources",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "last_serial", sa.BigInteger(), server_default=sa.text("0"), nullable=False
        ),
        sa.Column("last_file_sha256", sa.String(length=64), nullable=True),
        sa.Column("last_applied_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_by", sa.String(length=64), nullable=True),
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
            "mode IN ('api', 'file')", name="ck_organization_config_modes_mode"
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_organization_config_modes_organization",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("organization_id"),
    )
    op.create_table(
        "config_signing_keys",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("key_id", sa.String(length=32), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("created_by", sa.String(length=64), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_config_signing_keys_organization",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "user_id"],
            ["users.organization_id", "users.id"],
            name="fk_config_signing_keys_tenant_user",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id", "key_id", name="uq_config_signing_keys_tenant_key"
        ),
    )


def downgrade() -> None:
    op.drop_table("config_signing_keys")
    op.drop_table("organization_config_modes")
