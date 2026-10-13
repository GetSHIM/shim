"""Add the record of unattended policy changes.

One row per change shim or an agent applied under the allowlist, with its
measurement window and what became of it (kept, restored, undone), or why it was
skipped. Ids, field names, states and counts only.

Revision: 6cf65cda411e
Parent: 5bcf3c3e89cb
Created: 2026-10-13
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "6cf65cda411e"
down_revision: str | Sequence[str] | None = "5bcf3c3e89cb"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "policy_remediations",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("finding_id", sa.UUID(), nullable=True),
        sa.Column("plan_id", sa.UUID(), nullable=True),
        sa.Column("applied_version", sa.Integer(), nullable=True),
        sa.Column("actor_type", sa.String(length=16), nullable=False),
        sa.Column("actor_id", sa.String(length=64), nullable=True),
        sa.Column("items", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "result",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("restore_plan_id", sa.UUID(), nullable=True),
        sa.Column("restored_version", sa.Integer(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "actor_type IN ('system', 'service')",
            name="ck_policy_remediations_actor_type",
        ),
        sa.CheckConstraint(
            "status IN ('watching', 'kept', 'restored', 'restore_skipped', "
            "'skipped', 'undone')",
            name="ck_policy_remediations_status",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_policy_remediations_organization",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name="fk_policy_remediations_finding",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_policy_remediations_tenant_status_window",
        "policy_remediations",
        ["organization_id", "status", "window_end"],
    )
    op.create_index(
        "ix_policy_remediations_tenant_created",
        "policy_remediations",
        ["organization_id", "created_at"],
    )
    op.create_index(
        "uq_policy_remediations_tenant_finding",
        "policy_remediations",
        ["organization_id", "finding_id"],
        unique=True,
        postgresql_where=sa.text("finding_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_table("policy_remediations")
