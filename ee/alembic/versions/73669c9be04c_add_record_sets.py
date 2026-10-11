"""Add record sets: hashed customer records and document fingerprints.

Only keyed hashes are stored; the records and documents never reach shim.

Revision: 73669c9be04c
Parent: d34c574e0cc8
Created: 2026-10-11
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "73669c9be04c"
down_revision: str | Sequence[str] | None = "d34c574e0cc8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "record_sets",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column(
            "label", sa.String(length=32), server_default="RECORD", nullable=False
        ),
        sa.Column(
            "fields",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("fingerprint_version", sa.SmallInteger(), nullable=True),
        sa.Column("key_ref", sa.Text(), nullable=False),
        sa.Column(
            "active_revision", sa.Integer(), server_default=sa.text("0"), nullable=False
        ),
        sa.Column(
            "previous_revision",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "entry_count", sa.Integer(), server_default=sa.text("0"), nullable=False
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
        sa.CheckConstraint(
            "kind IN ('records', 'fingerprints')", name="ck_record_sets_kind"
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_record_sets_organization",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "name", name="uq_record_sets_org_name"),
    )
    op.create_table(
        "record_set_chunks",
        sa.Column("record_set_id", sa.UUID(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("chunk_index", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("entry_count", sa.Integer(), nullable=False),
        sa.Column("data", sa.LargeBinary(), nullable=False),
        sa.ForeignKeyConstraint(
            ["record_set_id"],
            ["record_sets.id"],
            name="fk_record_set_chunks_record_set",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("record_set_id", "revision", "chunk_index"),
    )


def downgrade() -> None:
    # Downgrades are disposable-only; the sets are lost and their keys stay orphaned.
    op.drop_table("record_set_chunks")
    op.drop_table("record_sets")
