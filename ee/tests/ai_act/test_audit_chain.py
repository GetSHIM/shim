from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy import delete, text
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker

from shim_enterprise.ai_act import audit_writer
from shim_enterprise.ai_act.anchor import compute_daily_anchor, write_anchor
from shim_enterprise.ai_act.bundle import build_audit_bundle
from shim_enterprise.ai_act.audit_writer import (
    append_audit_row_deduplicated,
    next_link,
    write_audit_row,
)
from shim_enterprise.ai_act.hashing import canonical_row, chain_hash, compute_row_hash
from shim_enterprise.ai_act.models import AIActAuditAnchor, AIActAuditLog
import shim_enterprise.ai_act.verify as verify_module
from shim_enterprise.ai_act.verify import (
    MAX_SYNC_AUDIT_ANCHORS,
    AuditVerificationLimitExceeded,
    verify_anchors,
    verify_chain,
)
from shim_enterprise.tenants.models import Organization


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
        (verify_chain, "ai_act_audit_log.seq", 2_000),
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


@pytest.mark.parametrize("shim_latency_ms", [None, 0, 17])
def test_audit_api_preserves_signed_duration_and_nullable_shim_measurement(
    shim_latency_ms,
):
    from shim_enterprise.ai_act.models import AIActAuditLog
    from shim_enterprise.ai_act.schemas import AuditLogRead

    context = {"organization_id": str(TENANT_ID), "latency_ms": 20000, "extra": {}}
    if shim_latency_ms is not None:
        context["extra"]["shim_latency_ms"] = shim_latency_ms
    link = next_link(
        None, context, salt="audit-salt", now=NOW, gateway_version="shim-gateway/test"
    )
    row = AIActAuditLog(id=TENANT_ID, **link)
    view = AuditLogRead.model_validate(row)
    assert view.extra == link["extra"]
    assert row.latency_ms == 20000
    assert "latency_ms" not in view.model_dump()
    assert "request_duration_ms" not in view.model_dump()
    assert view.shim_latency_ms == shim_latency_ms


@pytest_asyncio.fixture
async def committed_tenant(async_engine, monkeypatch):
    factory = async_sessionmaker(async_engine, expire_on_commit=False)
    monkeypatch.setattr("shim_enterprise.core.database.AsyncSessionLocal", factory)
    organization_id = uuid4()
    async with factory.begin() as session:
        session.add(
            Organization(
                id=organization_id,
                name="Audit chain load",
                slug=f"audit-chain-{organization_id}",
            )
        )
    try:
        yield factory, organization_id
    finally:
        async with factory.begin() as cleanup:
            # Audit rows are append-only; the guard is lifted inside this transaction only.
            await cleanup.execute(
                text(
                    "ALTER TABLE ai_act_audit_log "
                    "DISABLE TRIGGER ai_act_audit_log_append_only"
                )
            )
            await cleanup.execute(
                delete(AIActAuditLog).where(
                    AIActAuditLog.organization_id == organization_id
                )
            )
            await cleanup.execute(
                text(
                    "ALTER TABLE ai_act_audit_log "
                    "ENABLE TRIGGER ai_act_audit_log_append_only"
                )
            )
            await cleanup.execute(
                delete(Organization).where(Organization.id == organization_id)
            )


@pytest.mark.asyncio
async def test_concurrent_same_tenant_appends_form_one_gapless_chain(
    committed_tenant,
) -> None:
    factory, organization_id = committed_tenant

    rows = await asyncio.gather(
        *(
            append_audit_row_deduplicated(
                {"organization_id": organization_id, "request_id": f"req-load-{index}"}
            )
            for index in range(30)
        )
    )
    async with factory() as session:
        result = await verify_chain(session, organization_id)

    assert sorted(row.seq for row in rows) == list(range(1, 31))
    assert result["ok"] is True
    assert result["rows_checked"] == 30


@pytest.mark.asyncio
async def test_append_waits_for_a_held_tenant_lock_until_the_timeout(
    committed_tenant, monkeypatch
) -> None:
    factory, organization_id = committed_tenant
    monkeypatch.setattr(audit_writer, "LOCK_MAX_WAIT_SECONDS", 1.0)

    async with factory() as holder:
        await holder.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:tenant, 0))"),
            {"tenant": str(organization_id)},
        )
        started = time.monotonic()
        with pytest.raises(TimeoutError, match="tenant audit lock timed out"):
            await append_audit_row_deduplicated(
                {"organization_id": organization_id, "request_id": "req-held"}
            )
        waited = time.monotonic() - started
        await holder.rollback()

    assert 0.9 <= waited < 3


@pytest.mark.asyncio
async def test_append_restores_the_callers_lock_timeout(db, test_org) -> None:
    await db.execute(text("SET LOCAL lock_timeout = '7s'"))

    await write_audit_row(
        {"organization_id": test_org.id, "request_id": "req-timeout-restored"}, db
    )

    assert await db.scalar(text("SHOW lock_timeout")) == "7s"


BUNDLE_KEYS = {
    "format",
    "format_version",
    "generated_at",
    "gateway_version",
    "organization_id",
    "genesis_hash",
    "chain_start",
    "period",
    "row_count",
    "rows",
    "anchors",
    "notes",
}


async def _bundle_rows(db, organization_id) -> list:
    return [
        await write_audit_row(
            {
                "organization_id": organization_id,
                "event_type": "ai_request",
                "request_id": f"req-bundle-{index}",
                "model": "gpt-5.6-luna",
                "cost_usd": cost,
                "extra": {"score": 0.85, "label": "ölçüm"},
            },
            db,
        )
        for index, cost in enumerate(("0", "0.125", "0.00000012"))
    ]


@pytest.mark.asyncio
async def test_full_chain_bundle_follows_format_v1_and_rehashes(db, test_org) -> None:
    written = await _bundle_rows(db, test_org.id)
    anchor = await write_anchor(db, test_org.id, written[0].created_at.date())

    bundle = await build_audit_bundle(
        db, test_org.id, start=None, end=None, now=datetime.now(timezone.utc)
    )

    assert bundle is not None
    assert set(bundle) == BUNDLE_KEYS
    assert (bundle["format"], bundle["format_version"]) == ("shim.audit.bundle", 1)
    assert bundle["chain_start"] == {"from_seq": 1, "prev_hash": bundle["genesis_hash"]}
    assert bundle["row_count"] == len(bundle["rows"]) == len(written)
    assert bundle["generated_at"].endswith("+00:00")
    assert bundle["period"]["end"].endswith("+00:00")
    previous = bundle["genesis_hash"]
    for row in bundle["rows"]:
        assert set(row) == {*audit_writer.CANONICAL_KEYS, "prev_hash", "row_hash", "id"}
        fields = {key: row[key] for key in audit_writer.CANONICAL_KEYS}
        assert row["prev_hash"] == previous
        assert chain_hash(previous, canonical_row(fields)) == row["row_hash"]
        previous = row["row_hash"]
    assert [row["cost_usd"] for row in bundle["rows"]] == [
        "0E-8",
        "0.12500000",
        "1.2E-7",
    ]
    assert audit_writer.audit_salt() not in json.dumps(bundle)
    assert anchor is not None and anchor.row_count == len(written)
    assert bundle["anchors"] == [
        {
            "anchor_date": anchor.anchor_date.isoformat(),
            "root_hash": anchor.root_hash,
            "tip_hash": anchor.tip_hash,
            "row_count": anchor.row_count,
            "from_seq": anchor.from_seq,
            "to_seq": anchor.to_seq,
        }
    ]


@pytest.mark.asyncio
async def test_partial_bundle_starts_at_the_first_rows_stored_link(
    db, test_org
) -> None:
    written = await _bundle_rows(db, test_org.id)

    bundle = await build_audit_bundle(
        db,
        test_org.id,
        start=written[1].created_at,
        end=None,
        now=datetime.now(timezone.utc),
    )

    assert bundle is not None
    assert bundle["chain_start"] == {
        "from_seq": written[1].seq,
        "prev_hash": written[0].row_hash,
    }
    assert [row["seq"] for row in bundle["rows"]] == [written[1].seq, written[2].seq]


@pytest.mark.asyncio
async def test_a_float_jsonb_cannot_keep_is_hashed_as_its_string(db, test_org) -> None:
    await write_audit_row(
        {
            "organization_id": test_org.id,
            "request_id": "req-big",
            "extra": {"big": 1e16, "small": 1e-07, "nan": float("nan"), "neg": -0.0},
        },
        db,
    )
    # Read the row back from PostgreSQL, not from the identity map.
    db.expunge_all()

    bundle = await build_audit_bundle(
        db, test_org.id, start=None, end=None, now=datetime.now(timezone.utc)
    )

    assert bundle is not None
    (row,) = bundle["rows"]
    assert row["extra"] == {
        "big": "1e+16",
        "small": 1e-07,
        "nan": "nan",
        "neg": "-0.0",
    }
    fields = {key: row[key] for key in audit_writer.CANONICAL_KEYS}
    assert chain_hash(bundle["genesis_hash"], canonical_row(fields)) == row["row_hash"]


@pytest.mark.asyncio
async def test_bundle_refuses_more_anchors_than_the_synchronous_limit(
    db, test_org
) -> None:
    row = await write_audit_row(
        {"organization_id": test_org.id, "request_id": "req-anchors"}, db
    )
    today = row.created_at.date()
    db.add_all(
        AIActAuditAnchor(
            organization_id=test_org.id,
            anchor_date=today - timedelta(days=offset),
            root_hash="0" * 64,
            tip_hash=row.row_hash,
            row_count=1,
            from_seq=row.seq,
            to_seq=row.seq,
        )
        for offset in range(MAX_SYNC_AUDIT_ANCHORS + 1)
    )
    await db.flush()

    with pytest.raises(AuditVerificationLimitExceeded, match="anchors"):
        await build_audit_bundle(
            db,
            test_org.id,
            start=row.created_at - timedelta(days=MAX_SYNC_AUDIT_ANCHORS + 1),
            end=None,
            now=datetime.now(timezone.utc),
        )


DAY_ONE = datetime(2026, 7, 1, 9, 0, tzinfo=timezone.utc)
WINDOW = (
    datetime(2026, 7, 3, tzinfo=timezone.utc),
    datetime(2026, 7, 3, 23, 59, tzinfo=timezone.utc),
)


def _seed_chain(organization_id, times: list[datetime]) -> list:
    """Append linked rows with chosen timestamps, as the writer would have."""
    tip = None
    rows = []
    for index, created_at in enumerate(times):
        values = next_link(
            tip,
            {"organization_id": organization_id, "request_id": f"req-seeded-{index}"},
            salt=audit_writer.audit_salt(),
            now=created_at,
            gateway_version="shim-gateway/test",
        )
        rows.append(AIActAuditLog(**values))
        tip = (values["seq"], values["row_hash"])
    return rows


def _anchored_history_and_window(organization_id, monkeypatch) -> list:
    """Eight anchored rows on day one (over a cap of five), three in the window."""
    monkeypatch.setattr(verify_module, "MAX_SYNC_AUDIT_ROWS", 5)
    monkeypatch.setattr(verify_module, "_PAGE_ROWS", 2)
    history = [DAY_ONE + timedelta(minutes=index) for index in range(8)]
    window = [WINDOW[0] + timedelta(hours=index + 1) for index in range(3)]
    return _seed_chain(organization_id, history + window)


@pytest.mark.asyncio
async def test_window_verification_starts_after_the_last_anchor_before_it(
    db, test_org, monkeypatch
) -> None:
    rows = _anchored_history_and_window(test_org.id, monkeypatch)
    db.add_all(rows)
    await db.flush()
    await write_anchor(db, test_org.id, DAY_ONE.date())

    result = await verify_chain(db, test_org.id, start=WINDOW[0], end=WINDOW[1])

    assert result["ok"] is True
    assert result["chain_start"] == {"from_seq": 9, "anchor_date": "2026-07-01"}
    assert (result["rows_checked"], result["rows_selected"]) == (3, 3)
    assert result["last_verified_seq"] == 11
    with pytest.raises(AuditVerificationLimitExceeded, match="limited to 5 rows"):
        await verify_chain(db, test_org.id, end=WINDOW[1])


@pytest.mark.asyncio
async def test_window_verification_detects_tampering_after_the_anchor(
    db, test_org, monkeypatch
) -> None:
    rows = _anchored_history_and_window(test_org.id, monkeypatch)
    rows[9].request_id = "req-rewritten"
    db.add_all(rows)
    await db.flush()
    await write_anchor(db, test_org.id, DAY_ONE.date())

    result = await verify_chain(db, test_org.id, start=WINDOW[0], end=WINDOW[1])

    assert result["ok"] is False
    assert result["first_break"] == {
        "seq": 10,
        "id": str(rows[9].id),
        "reason": "row_hash_mismatch",
    }
    assert result["last_verified_seq"] == 9


@pytest.mark.asyncio
async def test_window_verification_rejects_an_anchor_tip_the_chain_lacks(
    db, test_org, monkeypatch
) -> None:
    rows = _anchored_history_and_window(test_org.id, monkeypatch)
    db.add_all(rows)
    await db.flush()
    db.add(
        AIActAuditAnchor(
            organization_id=test_org.id,
            anchor_date=DAY_ONE.date(),
            root_hash="0" * 64,
            tip_hash="f" * 64,
            row_count=8,
            from_seq=1,
            to_seq=8,
        )
    )
    await db.flush()

    result = await verify_chain(db, test_org.id, start=WINDOW[0], end=WINDOW[1])

    assert result["ok"] is False
    assert result["first_break"] == {
        "seq": 8,
        "id": str(rows[7].id),
        "reason": "anchor_link_mismatch",
    }
    assert result["rows_checked"] == 0


@pytest.mark.asyncio
async def test_window_verification_without_an_anchor_starts_at_genesis(
    db, test_org
) -> None:
    rows = _seed_chain(test_org.id, [DAY_ONE, WINDOW[0] + timedelta(hours=1)])
    db.add_all(rows)
    await db.flush()

    result = await verify_chain(db, test_org.id, start=WINDOW[0], end=WINDOW[1])

    assert result["ok"] is True
    assert result["chain_start"] == {"from_seq": 1, "anchor_date": None}
    assert (result["rows_checked"], result["rows_selected"]) == (2, 1)


@pytest.mark.asyncio
async def test_audit_report_succeeds_for_a_tenant_past_the_row_cap(
    db, test_user_with_org, monkeypatch
) -> None:
    from shim_enterprise.ai_act import api as api_module
    from shim_enterprise.ai_act.schemas import AuditReportRequest

    organization_id = test_user_with_org.organization_id
    rows = _anchored_history_and_window(organization_id, monkeypatch)
    db.add_all(rows)
    await db.flush()
    await write_anchor(db, organization_id, DAY_ONE.date())

    response = await api_module.generate_audit_report_endpoint(
        AuditReportRequest(start=WINDOW[0], end=WINDOW[1], format="csv"),
        current_user=test_user_with_org,
        session=db,
    )

    assert response.status_code == 200
    assert "chain verified with" in bytes(response.body).decode("utf-8-sig")


@pytest.mark.asyncio
async def test_bundle_window_edges_are_resolved_to_a_sequence_range(
    db, test_org
) -> None:
    # Row 3 came from an instance whose clock ran two minutes behind.
    minute = timedelta(minutes=1)
    rows = _seed_chain(
        test_org.id,
        [DAY_ONE, DAY_ONE + 2 * minute, DAY_ONE, DAY_ONE + 4 * minute],
    )
    db.add_all(rows)
    await db.flush()

    bundle = await build_audit_bundle(
        db,
        test_org.id,
        start=DAY_ONE + minute,
        end=DAY_ONE + 3 * minute,
        now=datetime.now(timezone.utc),
    )

    assert bundle is not None
    assert [row["seq"] for row in bundle["rows"]] == [2, 3]
    assert bundle["chain_start"] == {"from_seq": 2, "prev_hash": rows[0].row_hash}
