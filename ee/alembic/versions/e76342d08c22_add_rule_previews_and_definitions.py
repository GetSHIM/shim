"""Add rule previews and rule definition times.

A preview row lets one exact rule be created enforced for 24 hours; a definition
row says since when a rule has matched what it matches now. Neither holds a term,
a pattern or any request content: digests, counts and times only.

Revision: e76342d08c22
Parent: c9ed4e82b922
Created: 2026-10-11
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "e76342d08c22"
down_revision: str | Sequence[str] | None = "c9ed4e82b922"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "rule_previews",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("rule_id", sa.String(length=48), nullable=False),
        sa.Column("preview_digest", sa.String(length=64), nullable=False),
        sa.Column("basis", sa.String(length=24), nullable=False),
        sa.Column("requests", sa.Integer(), nullable=False),
        sa.Column("window_days", sa.SmallInteger(), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(length=64), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "basis IN ('metadata', 'monitor_history')", name="ck_rule_previews_basis"
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_rule_previews_organization",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_rule_previews_tenant_rule",
        "rule_previews",
        ["organization_id", "rule_id", "expires_at"],
    )
    op.create_table(
        "rule_definitions",
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("rule_id", sa.String(length=48), nullable=False),
        sa.Column("definition_digest", sa.String(length=64), nullable=False),
        sa.Column(
            "defined_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_rule_definitions_organization",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "organization_id", "rule_id", name="pk_rule_definitions"
        ),
    )


def downgrade() -> None:
    op.drop_table("rule_definitions")
    op.drop_index("ix_rule_previews_tenant_rule", table_name="rule_previews")
    op.drop_table("rule_previews")
