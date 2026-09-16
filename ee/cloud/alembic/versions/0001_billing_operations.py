"""Cloud-only transient checkout/portal operations and initial org quota opt-in."""

from alembic import op
import sqlalchemy as sa

revision = "cloud_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
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
        sa.ForeignKeyConstraint(["organization_id"], ["public.organizations.id"]),
        sa.ForeignKeyConstraint(["created_by"], ["public.users.id"]),
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
    op.execute("""
        UPDATE organizations SET
            quota_monthly_request_limit = tier_definitions.monthly_request_limit,
            quota_monthly_token_limit = tier_definitions.monthly_token_limit
        FROM tier_definitions WHERE organizations.tier = tier_definitions.slug
    """)


def downgrade() -> None:
    op.drop_table("billing_operation", schema="shim_cloud")
    # Retain quota opt-in and all usage history; rollback must not widen allowances.
