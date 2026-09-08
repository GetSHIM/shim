"""Bind customer OIDC issuer and subject without email-based linking."""

from alembic import op
import sqlalchemy as sa

revision = "c31b7a91d602"
down_revision = "f10e4ac92d17"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("oidc_issuer", sa.String(512), nullable=True))
    op.add_column("users", sa.Column("oidc_subject", sa.String(255), nullable=True))
    op.create_unique_constraint(
        "uq_users_oidc_identity", "users", ["oidc_issuer", "oidc_subject"]
    )


def downgrade() -> None:
    op.drop_constraint("uq_users_oidc_identity", "users", type_="unique")
    op.drop_column("users", "oidc_subject")
    op.drop_column("users", "oidc_issuer")
