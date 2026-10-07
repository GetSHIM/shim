"""Make compliance forward targets tenant-level.

Revision: de7150dd2f7a
Parent: 4d4e8c6b975a
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "de7150dd2f7a"
down_revision: str | Sequence[str] | None = "4d4e8c6b975a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "compliance_forward_target",
        sa.Column("organization_id", sa.UUID(), nullable=True),
    )
    op.execute(
        "UPDATE compliance_forward_target AS target "
        "SET organization_id = connector.organization_id "
        "FROM compliance_connector AS connector "
        "WHERE connector.id = target.connector_id"
    )
    op.alter_column("compliance_forward_target", "organization_id", nullable=False)
    op.create_foreign_key(
        "fk_compliance_forward_target_organization",
        "compliance_forward_target",
        "organizations",
        ["organization_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_index(
        "ix_compliance_forward_target_tenant",
        "compliance_forward_target",
        ["organization_id"],
    )
    op.alter_column(
        "compliance_forward_target",
        "connector_id",
        existing_type=sa.UUID(),
        nullable=True,
    )


def downgrade() -> None:
    # Downgrades are disposable-only; tenant-level targets have no connector.
    op.execute("DELETE FROM compliance_forward_target WHERE connector_id IS NULL")
    op.alter_column(
        "compliance_forward_target",
        "connector_id",
        existing_type=sa.UUID(),
        nullable=False,
    )
    op.drop_index(
        "ix_compliance_forward_target_tenant",
        table_name="compliance_forward_target",
    )
    op.drop_constraint(
        "fk_compliance_forward_target_organization",
        "compliance_forward_target",
        type_="foreignkey",
    )
    op.drop_column("compliance_forward_target", "organization_id")
