"""Add custom organization roles.

A custom role is a tenant-defined permission set held only by human members.

Revision: 1f036bd115c8
Parent: 7e3fb2338f03
Created: 2026-10-09
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "1f036bd115c8"
down_revision: str | Sequence[str] | None = "7e3fb2338f03"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "organization_roles",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("slug", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column(
            "permissions",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("created_by", sa.String(length=64), nullable=True),
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
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_organization_roles_organization_id",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id", "id", name="uq_organization_roles_tenant_id"
        ),
        sa.UniqueConstraint(
            "organization_id", "slug", name="uq_organization_roles_tenant_slug"
        ),
    )
    op.add_column("users", sa.Column("custom_role_id", sa.UUID(), nullable=True))
    op.create_foreign_key(
        "fk_users_tenant_custom_role",
        "users",
        "organization_roles",
        ["organization_id", "custom_role_id"],
        ["organization_id", "id"],
        ondelete="RESTRICT",
    )
    op.create_check_constraint(
        "ck_users_custom_role_member",
        "users",
        "custom_role_id IS NULL OR (role = 'member' AND kind = 'human')",
    )


def downgrade() -> None:
    # Downgrades are disposable-only; custom roles and their assignments are lost.
    op.drop_constraint("ck_users_custom_role_member", "users", type_="check")
    op.drop_constraint("fk_users_tenant_custom_role", "users", type_="foreignkey")
    op.drop_column("users", "custom_role_id")
    op.drop_table("organization_roles")
