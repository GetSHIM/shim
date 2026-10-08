"""Add organization service accounts for the management API.

Revision: d94f7f0ba8a2
Parent: 41f1a2ff58a9
Created: 2026-10-08
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "d94f7f0ba8a2"
down_revision: str | Sequence[str] | None = "41f1a2ff58a9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("kind", sa.String(length=16), server_default="human", nullable=False),
    )
    op.create_check_constraint("ck_users_kind", "users", "kind IN ('human', 'service')")
    op.create_check_constraint(
        "ck_users_service_role",
        "users",
        "kind = 'human' OR role IN ('admin', 'auditor')",
    )
    op.create_table(
        "service_account_credentials",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column("prefix", sa.String(length=32), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "user_id"],
            ["users.organization_id", "users.id"],
            name="fk_service_account_credentials_tenant_user",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("key_hash", name="uq_service_account_credentials_key_hash"),
    )
    op.create_index(
        "ix_service_account_credentials_user_id",
        "service_account_credentials",
        ["user_id"],
    )


def downgrade() -> None:
    # Downgrades are disposable-only; service account keys are lost. Their users
    # stay, inactive, because gateway keys and request history may reference them.
    op.drop_index(
        "ix_service_account_credentials_user_id",
        table_name="service_account_credentials",
    )
    op.drop_table("service_account_credentials")
    op.execute("UPDATE users SET is_active = false WHERE kind = 'service'")
    op.drop_constraint("ck_users_service_role", "users", type_="check")
    op.drop_constraint("ck_users_kind", "users", type_="check")
    op.drop_column("users", "kind")
