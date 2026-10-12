"""Add the request archive.

Rule-matched requests a self-hosted tenant chose to keep: the masked payload and
the edit, each Fernet-encrypted with ENCRYPTION_KEY, at most 90 days. Entity types
and rule ids only in the clear; never a value.

Revision: 79a194bca40f
Parent: 099f6ff61feb
Created: 2026-10-12
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "79a194bca40f"
down_revision: str | Sequence[str] | None = "099f6ff61feb"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "request_archive",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("request_id", sa.String(length=255), nullable=False),
        sa.Column("api_key_id", sa.UUID(), nullable=True),
        sa.Column("protocol", sa.String(length=32), nullable=False),
        sa.Column("model", sa.String(length=255), nullable=False),
        sa.Column("matched", postgresql.JSONB(), nullable=False),
        sa.Column("masked_payload", sa.LargeBinary(), nullable=False),
        sa.Column("edit_map", sa.LargeBinary(), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_request_archive_organization",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id", "request_id", name="uq_request_archive_request"
        ),
    )
    op.create_index(
        "ix_request_archive_tenant_created",
        "request_archive",
        ["organization_id", "created_at"],
    )
    op.create_index("ix_request_archive_expires", "request_archive", ["expires_at"])


def downgrade() -> None:
    op.drop_table("request_archive")
