"""Cloud-only transient billing operations and explicit activation marker."""

from alembic import op
import sqlalchemy as sa

revision = "cloud_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "billing_activation",
        sa.Column("id", sa.Boolean(), nullable=False),
        sa.Column(
            "activated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint("id", name="ck_billing_activation_singleton"),
        schema="shim_cloud",
    )
    op.create_table(
        "billing_operation",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("request_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("product_id", sa.Text()),
        sa.Column("status", sa.Text(), nullable=False, server_default="pending"),
        sa.Column("result_ciphertext", sa.Text()),
        sa.Column("error", sa.Text()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.UniqueConstraint(
            "organization_id", "request_id", name="uq_billing_operation_request"
        ),
        sa.CheckConstraint(
            "kind IN ('checkout', 'portal')", name="ck_billing_operation_kind"
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'processing', 'complete', 'failed', 'expired')",
            name="ck_billing_operation_status",
        ),
        schema="shim_cloud",
    )
    op.create_index(
        "ix_billing_operation_expiry",
        "billing_operation",
        ["expires_at"],
        schema="shim_cloud",
    )


def downgrade() -> None:
    op.drop_table("billing_operation", schema="shim_cloud")
    op.drop_table("billing_activation", schema="shim_cloud")
    # Retain quota opt-in and all usage history; rollback must not widen allowances.
