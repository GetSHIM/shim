from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID

import pytest
from sqlalchemy import text
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import DBAPIError

from shim_enterprise.ai_act.anchor import compute_daily_anchor, write_anchor
from shim_enterprise.ai_act.audit_writer import next_link, write_audit_row
from shim_enterprise.ai_act.hashing import compute_row_hash
import shim_enterprise.ai_act.verify as verify_module
from shim_enterprise.ai_act.verify import (
    AuditVerificationLimitExceeded,
    verify_anchors,
    verify_chain,
)


TENANT_ID = UUID("11111111-1111-1111-1111-111111111111")
NOW = datetime(2026, 7, 12, 12, 0, tzinfo=timezone.utc)


def test_first_link_starts_at_one_and_uses_database_stable_values() -> None:
    link = next_link(
        None,
        {
            "organization_id": str(TENANT_ID).upper(),
            "event_type": "request.completed",
            "cost_usd": "0.10000000",
            "policy_verdicts": ["allowed"],
            "extra": {
                "route": "openai",
                "prompt": "must not cross the boundary",
                "nested": {"api_key": "must not cross the boundary"},
            },
        },
        salt="audit-salt",
        now=NOW,
        gateway_version="shim-gateway/test",
    )

    assert link["seq"] == 1
    assert link["organization_id"] == TENANT_ID
    assert link["cost_usd"] == Decimal("0.10000000")
    assert link["policy_verdicts"] == [{"code": "allowed"}]
    assert link["extra"] == {"route": "openai", "nested": {}}
    assert link["row_hash"] == compute_row_hash(
        link["prev_hash"],
        {
            key: link.get(key)
            for key in (
                "seq",
                "organization_id",
                "created_at",
                "event_type",
                "request_id",
                "api_key_id",
                "actor",
                "model",
                "provider",
                "gateway_version",
                "endpoint",
                "input_hash",
                "output_hash",
                "prompt_tokens",
                "completion_tokens",
                "pii_detected",
                "pii_entities",
                "policy_verdicts",
                "is_cache_hit",
                "latency_ms",
                "cost_usd",
                "extra",
            )
        },
    )


@pytest.mark.asyncio
async def test_database_chain_appends_and_verifies_from_sequence_one(
    db, test_org
) -> None:
    first = await write_audit_row(
        {
            "organization_id": test_org.id,
            "event_type": "request.completed",
            "request_id": "req-audit-one",
            "cost_usd": "0.125",
        },
        db,
    )
    second = await write_audit_row(
        {
            "organization_id": test_org.id,
            "event_type": "request.completed",
            "request_id": "req-audit-two",
            "cost_usd": Decimal("0.25000000"),
        },
        db,
    )

    result = await verify_chain(db, test_org.id)

    assert (first.seq, second.seq) == (1, 2)
    assert second.prev_hash == first.row_hash
    assert result["ok"] is True
    assert result["rows_checked"] == 2
    assert result["last_verified_seq"] == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("operation", "limit_name"),
    [
        (verify_chain, "MAX_SYNC_AUDIT_ROWS"),
        (verify_anchors, "MAX_SYNC_AUDIT_ANCHORS"),
    ],
)
async def test_interactive_verification_rejects_results_over_its_fixed_cap(
    operation,
    limit_name: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(verify_module, limit_name, 1)
    session = SimpleNamespace(
        execute=AsyncMock(
            return_value=SimpleNamespace(scalars=lambda: (object(), object()))
        )
    )

    with pytest.raises(AuditVerificationLimitExceeded, match="limited to 1"):
        await operation(session, TENANT_ID)

    session.execute.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("operation", "ordering", "sentinel"),
    [
        (verify_chain, "ai_act_audit_log.seq", 10_001),
        (verify_anchors, "ai_act_audit_anchor.anchor_date", 367),
    ],
)
async def test_audit_verification_queries_are_stably_ordered_and_bounded(
    operation,
    ordering: str,
    sentinel: int,
) -> None:
    session = SimpleNamespace(
        execute=AsyncMock(return_value=SimpleNamespace(scalars=lambda: ()))
    )

    await operation(session, TENANT_ID)

    statement = session.execute.await_args.args[0]
    compiled = statement.compile(dialect=postgresql.dialect())
    assert f"ORDER BY {ordering}" in str(compiled)
    assert " LIMIT " in str(compiled)
    assert sentinel in compiled.params.values()


@pytest.mark.asyncio
async def test_daily_anchor_recomputation_can_be_bounded() -> None:
    session = SimpleNamespace(
        execute=AsyncMock(return_value=SimpleNamespace(all=lambda: ()))
    )

    await compute_daily_anchor(
        session,
        TENANT_ID,
        NOW.date(),
        max_rows=10_000,
    )

    statement = session.execute.await_args.args[0]
    compiled = statement.compile(dialect=postgresql.dialect())
    assert "ORDER BY ai_act_audit_log.seq" in str(compiled)
    assert " LIMIT " in str(compiled)
    assert 10_001 in compiled.params.values()


@pytest.mark.asyncio
async def test_anchor_verification_converts_the_selected_range_to_utc_dates() -> None:
    session = SimpleNamespace(
        execute=AsyncMock(return_value=SimpleNamespace(scalars=lambda: ()))
    )
    offset = timezone(timedelta(hours=3))
    start = datetime(2026, 7, 5, 1, tzinfo=offset)
    end = datetime(2026, 7, 12, 1, tzinfo=offset)

    await verify_anchors(session, TENANT_ID, start=start, end=end)

    compiled = session.execute.await_args.args[0].compile(dialect=postgresql.dialect())
    sql = str(compiled)
    assert "ai_act_audit_anchor.anchor_date >=" in sql
    assert "ai_act_audit_anchor.anchor_date <=" in sql
    assert start.astimezone(timezone.utc).date() in compiled.params.values()
    assert end.astimezone(timezone.utc).date() in compiled.params.values()


@pytest.mark.asyncio
async def test_anchor_verification_rejects_single_anchor_over_row_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(verify_module, "MAX_SYNC_AUDIT_ROWS", 1)
    anchor = SimpleNamespace(row_count=2)
    session = SimpleNamespace(
        execute=AsyncMock(return_value=SimpleNamespace(scalars=lambda: (anchor,)))
    )

    with pytest.raises(AuditVerificationLimitExceeded, match="1 anchor rows"):
        await verify_anchors(session, TENANT_ID)


@pytest.mark.asyncio
async def test_write_anchor_reuses_the_immutable_daily_row(db, test_org) -> None:
    row = await write_audit_row(
        {
            "organization_id": test_org.id,
            "event_type": "request.completed",
            "request_id": "req-anchor-idempotent",
        },
        db,
    )

    first = await write_anchor(
        db, test_org.id, row.created_at.date(), external_ref="initial"
    )
    second = await write_anchor(
        db, test_org.id, row.created_at.date(), external_ref="replacement"
    )

    assert first is not None
    assert second is not None
    assert second.id == first.id
    assert second.external_ref == "initial"


@pytest.mark.asyncio
async def test_database_rejects_audit_row_anchor_and_truncate_mutations(
    db,
    test_org,
) -> None:
    row = await write_audit_row(
        {
            "organization_id": test_org.id,
            "event_type": "request.completed",
            "request_id": "req-audit-immutable",
        },
        db,
    )
    anchor = await write_anchor(db, test_org.id, row.created_at.date())
    assert anchor is not None

    statements = (
        (
            "UPDATE ai_act_audit_log SET event_type = 'tampered' WHERE id = :id",
            {"id": row.id},
        ),
        ("DELETE FROM ai_act_audit_anchor WHERE id = :id", {"id": anchor.id}),
        # CASCADE lets PostgreSQL reach the table's BEFORE TRUNCATE guard even
        # though oversight_request intentionally holds a tenant-scoped FK.
        ("TRUNCATE TABLE ai_act_audit_log CASCADE", {}),
        ("TRUNCATE TABLE ai_act_audit_anchor", {}),
    )
    for statement, parameters in statements:
        savepoint = await db.begin_nested()
        try:
            with pytest.raises(DBAPIError, match="append-only"):
                await db.execute(text(statement), parameters)
        finally:
            await savepoint.rollback()
