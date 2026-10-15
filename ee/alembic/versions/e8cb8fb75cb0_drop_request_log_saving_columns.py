"""Drop request_logs.cost_saved and tokens_saved: no code has written or read them.

They held 0 on every row since the semantic cache was removed. Savings are recorded
per request in the lifecycle metadata (S65). The downgrade adds both back at 0, so an
image from before this revision can write request logs again.

Revision: e8cb8fb75cb0
Parent: c6bf1ec40802
Created: 2026-10-15 09:30:00.000000
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "e8cb8fb75cb0"
down_revision: str | Sequence[str] | None = "c6bf1ec40802"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_column("request_logs", "tokens_saved")
    op.drop_column("request_logs", "cost_saved")


def downgrade() -> None:
    op.add_column(
        "request_logs",
        sa.Column("cost_saved", sa.Float(), server_default="0", nullable=False),
    )
    op.add_column(
        "request_logs",
        sa.Column("tokens_saved", sa.Integer(), server_default="0", nullable=False),
    )
    # The baseline shape: the old model writes both columns itself.
    op.alter_column("request_logs", "cost_saved", server_default=None)
    op.alter_column("request_logs", "tokens_saved", server_default=None)
