"""Add incidents and their notification duties.

An incident is opened by a person and holds references and the organization's own
text, never request content; each notification row carries one legal deadline.

Revision: a61706150d6c
Parent: 2ee6ebd54f58
Created: 2026-10-10
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "a61706150d6c"
down_revision: str | Sequence[str] | None = "2ee6ebd54f58"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _timestamps() -> list[sa.Column]:
    return [
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
    ]


def upgrade() -> None:
    op.create_table(
        "incidents",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column(
            "description", sa.String(length=2000), server_default="", nullable=False
        ),
        sa.Column("severity_id", sa.SmallInteger(), nullable=False),
        sa.Column("status", sa.String(length=16), server_default="new", nullable=False),
        sa.Column("owner_user_id", sa.UUID(), nullable=True),
        sa.Column("opened_by", sa.String(length=64), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("aware_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "is_suspected_breach",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column(
            "breach",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "links",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        *_timestamps(),
        sa.CheckConstraint(
            "severity_id BETWEEN 1 AND 5", name="ck_incidents_severity_id"
        ),
        sa.CheckConstraint(
            "status IN ('new', 'in_progress', 'on_hold', 'resolved', 'closed')",
            name="ck_incidents_status",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_incidents_organization_id",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_incidents_tenant_status_updated",
        "incidents",
        ["organization_id", "status", "updated_at"],
        unique=False,
    )
    op.create_table(
        "incident_notifications",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("incident_id", sa.UUID(), nullable=False),
        sa.Column("regime", sa.String(length=32), nullable=False),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "required", sa.Boolean(), server_default=sa.text("true"), nullable=False
        ),
        sa.Column("not_required_reason", sa.String(length=1000), nullable=True),
        sa.Column(
            "submissions",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "reminded",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        *_timestamps(),
        sa.CheckConstraint(
            "regime IN ('kvkk_board', 'kvkk_data_subjects', 'gdpr_authority')",
            name="ck_incident_notifications_regime",
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.id"],
            name="fk_incident_notifications_incident_id",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_incident_notifications_organization_id",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "incident_id", "regime", name="uq_incident_notifications_incident_regime"
        ),
    )


def downgrade() -> None:
    op.drop_table("incident_notifications")
    op.drop_index("ix_incidents_tenant_status_updated", table_name="incidents")
    op.drop_table("incidents")
