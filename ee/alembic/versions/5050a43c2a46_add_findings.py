"""Add OCSF-aligned gateway findings.

Revision: 5050a43c2a46
Parent: 1ad1ca2101a5
Created: 2026-10-08
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "5050a43c2a46"
down_revision: str | Sequence[str] | None = "1ad1ca2101a5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column(
            "source", sa.String(length=32), server_default="gateway", nullable=False
        ),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("rule_version", sa.Integer(), nullable=False),
        sa.Column("subject_key", sa.Text(), nullable=False),
        sa.Column("subject", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("severity_id", sa.SmallInteger(), nullable=False),
        sa.Column("status_id", sa.SmallInteger(), server_default="1", nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("occurrences", sa.Integer(), server_default="1", nullable=False),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("impact", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            "remediation", postgresql.JSONB(astext_type=sa.Text()), nullable=False
        ),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_by", sa.String(length=64), nullable=True),
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
            "severity_id BETWEEN 1 AND 5", name="ck_findings_severity_id"
        ),
        sa.CheckConstraint("status_id BETWEEN 1 AND 4", name="ck_findings_status_id"),
        sa.CheckConstraint("occurrences >= 1", name="ck_findings_occurrences"),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_findings_organization_id_organizations",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_findings_open_subject",
        "findings",
        ["organization_id", "rule_id", "subject_key"],
        unique=True,
        postgresql_where=sa.text("status_id <> 4"),
    )
    op.create_index(
        "ix_findings_org_last_seen", "findings", ["organization_id", "last_seen_at"]
    )


def downgrade() -> None:
    # Downgrades are disposable-only; findings are lost.
    op.drop_index("ix_findings_org_last_seen", table_name="findings")
    op.drop_index("uq_findings_open_subject", table_name="findings")
    op.drop_table("findings")
