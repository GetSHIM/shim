"""Harden trigger function search paths.

Revision ID: f10e4ac92d17
Revises: aa8b038bc50c
Create Date: 2026-08-11 16:50:00

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "f10e4ac92d17"
down_revision: Union[str, Sequence[str], None] = "aa8b038bc50c"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_FUNCTIONS = (
    "reject_ai_act_audit_mutation",
    "validate_compliance_finding_connector",
    "enforce_usage_ledger_immutability",
)


def _active_schema() -> str:
    bind = op.get_bind()
    schema = bind.execute(sa.text("SELECT current_schema()")).scalar_one()
    return bind.dialect.identifier_preparer.quote(schema)


def upgrade() -> None:
    """Prevent caller-controlled schemas from changing function resolution."""
    schema = _active_schema()
    for function_name in _FUNCTIONS:
        op.execute(
            f"ALTER FUNCTION {schema}.{function_name}() "
            f"SET search_path = {schema}, pg_catalog"
        )


def downgrade() -> None:
    """Restore the role's search path."""
    schema = _active_schema()
    for function_name in _FUNCTIONS:
        op.execute(f"ALTER FUNCTION {schema}.{function_name}() RESET search_path")
