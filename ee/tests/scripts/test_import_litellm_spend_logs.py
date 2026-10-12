from __future__ import annotations

import argparse
import hashlib
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
import logging
from pathlib import Path
import runpy
from uuid import uuid4

import asyncpg
import httpx
import pytest
from sqlalchemy import func, select, text

from shim.findings import Finding as FindingV1
from shim_enterprise.billing.models import RequestLifecycle, UsageLedger
from shim_enterprise.core.config import settings
from shim_enterprise.findings import service
from shim_enterprise.findings.models import ExternalUsageRecord, Finding
from shim_enterprise.tenants.models import ModelDeployment, Organization, ProviderSecret

script = runpy.run_path(
    str(Path(__file__).parents[2] / "scripts" / "import_litellm_spend_logs.py")
)
mapped, import_rows, delete_import = (
    script["mapped"],
    script["import_rows"],
    script["delete_import"],
)
url_rows, database_rows, main = (
    script["url_rows"],
    script["database_rows"],
    script["main"],
)
ImportRefused = script["ImportRefused"]

START = datetime(2026, 10, 1, tzinfo=timezone.utc)
SINCE, UNTIL = START, START + timedelta(days=1)
KEY = "ce77089fa9483163dbc642df2890ede7cb7ca99670819aa15c733382fd24f291"
PROMPT = "Müşteri Ayşe Yılmaz'ın kart limitini yükselt"


def _row(index: int, **values) -> dict:
    started = START + timedelta(hours=23, seconds=index)
    return {
        "request_id": f"fixture-{index:04d}",
        "call_type": "acompletion",
        "api_key": KEY,
        "spend": 1.8e-05,
        "prompt_tokens": 120 + index,
        "completion_tokens": 30,
        "startTime": started.replace(tzinfo=None).isoformat(),
        "endTime": (started + timedelta(seconds=1)).replace(tzinfo=None).isoformat(),
        "completionStartTime": None,
        "request_duration_ms": 1000,
        "model": "gpt-5-nano",
        "model_group": "shim-openai",
        "custom_llm_provider": "openai",
        "api_base": "http://localhost:8000/v1",
        "user": "",
        "cache_hit": "",
        "request_tags": ["support"],
        "team_id": "team-alpha",
        "status": "success",
        "metadata": {},
        **values,
    }


async def _source(rows):
    for row in rows:
        yield row


async def _import(db, organization_id, rows) -> dict:
    return await import_rows(
        db, organization_id, _source(rows), since=SINCE, until=UNTIL
    )


async def _tenant(db) -> Organization:
    organization = Organization(
        id=uuid4(), name="LiteLLM", slug=f"litellm-{uuid4().hex}"
    )
    db.add(organization)
    await db.flush()
    return organization


async def _findings(db, organization_id) -> list[Finding]:
    return list(
        await db.scalars(
            select(Finding)
            .where(Finding.organization_id == organization_id)
            .order_by(Finding.rule_id)
        )
    )


def test_a_row_maps_to_the_source_numbers_and_nothing_else() -> None:
    record = mapped(
        _row(
            1,
            spend=0.000123456789012345,
            startTime="2026-10-01T10:00:00",
            endTime="2026-10-01T10:00:03.500000",
            completionStartTime="2026-10-01T10:00:00.750000",
            api_base="https://gw.example:8443/v1/chat?api-key=secret",
            user="ayse.yilmaz@kurum.com.tr",
            team_id="team-alpha",
            request_tags=["Ayşe'nin işi"],
            messages=[{"role": "user", "content": PROMPT}],
        )
    )

    assert set(record) == {
        "source_request_id",
        "started_at",
        "ttft_ms",
        "status",
        "model",
        "model_group",
        "source_key_hash",
        "prompt_tokens",
        "completion_tokens",
        "cost_usd",
    }
    assert record["started_at"] == datetime(2026, 10, 1, 10, tzinfo=timezone.utc)
    assert record["ttft_ms"] == 750
    assert record["cost_usd"] == Decimal("0.000123456789012345")
    assert record["source_key_hash"] == KEY
    written = json.dumps(record, default=str)
    for kept_out in (PROMPT, "ayse", "Ayşe", "secret", "gw.example", "team-alpha"):
        assert kept_out not in written


@pytest.mark.parametrize(
    ("model", "shown"),
    [
        ("gpt-5-nano", "gpt-5-nano"),
        ("kurum-gpt", "kurum-gpt"),
        ("llama-local", "other"),
        ("Ayşe Yılmaz test", "other"),
        ("m" * 300, "other"),
    ],
)
def test_a_model_outside_the_price_book_and_the_registry_is_other(model, shown) -> None:
    record = mapped(_row(1, model=model, model_group=model), frozenset({"kurum-gpt"}))

    assert (record["model"], record["model_group"]) == (shown, shown)


@pytest.mark.parametrize("spend", [float("nan"), "Infinity", -0.5, "-1", 1e12, "x"])
def test_a_cost_that_is_not_a_finite_amount_is_unknown(spend) -> None:
    assert mapped(_row(1, spend=spend))["cost_usd"] is None


def test_a_raw_key_is_stored_only_as_its_digest() -> None:
    raw = "sk-litellm-RAWSECRET0001"

    stored = mapped(_row(1, api_key=raw))["source_key_hash"]

    assert stored == hashlib.sha256(raw.encode()).hexdigest()
    assert mapped(_row(2, api_key=KEY.upper()))["source_key_hash"] == KEY


def test_missing_optional_fields_are_null_and_rows_without_keys_are_skipped() -> None:
    bare = mapped({"request_id": "r-1", "startTime": "2026-10-01T00:00:00"})
    same_end = mapped(
        _row(
            2,
            completionStartTime="2026-10-01T23:00:03",
            endTime="2026-10-01T23:00:03",
        )
    )

    assert {key for key, value in bare.items() if value is not None} == {
        "source_request_id",
        "started_at",
    }
    # LiteLLM writes completionStartTime = endTime when it saw no first token.
    assert same_end["ttft_ms"] is None
    assert mapped(_row(3, request_id=None)) is None
    assert mapped(_row(4, startTime=None)) is None


@pytest.mark.asyncio
async def test_a_file_imports_once_with_content_ignored_and_counted(
    db, tmp_path
) -> None:
    organization, other = await _tenant(db), await _tenant(db)
    await _import(db, other.id, [_row(1)])
    lines = [
        _row(1, messages=[{"role": "user", "content": PROMPT}]),
        _row(2, response={"choices": [{"message": {"content": PROMPT}}]}),
        _row(3),
        _row(4, request_id=None),
        _row(5, startTime="2026-09-30T23:59:59"),
    ]
    path = tmp_path / "spendlogs.jsonl"
    path.write_text("\n".join(json.dumps(line) for line in lines) + "\n")
    ledger = (
        await db.scalar(select(func.count()).select_from(RequestLifecycle)),
        await db.scalar(select(func.count()).select_from(UsageLedger)),
    )

    first = await import_rows(
        db,
        organization.id,
        script["file_rows"](path),
        since=SINCE,
        until=UNTIL,
    )
    again = await import_rows(
        db, organization.id, script["file_rows"](path), since=SINCE, until=UNTIL
    )

    counts = ("rows_read", "rows_inserted", "rows_duplicate", "rows_skipped")
    assert [first[key] for key in counts] == [5, 3, 0, 2]
    assert first["rows_with_content_ignored"] == 2
    assert [again[key] for key in counts] == [5, 0, 3, 2]
    stored = await db.scalar(
        text(
            "SELECT json_agg(r)::text FROM external_usage_records r "
            "WHERE organization_id = :id"
        ),
        {"id": organization.id},
    )
    assert PROMPT not in stored and "secret" not in stored
    assert (
        await db.scalar(
            select(func.count()).where(ExternalUsageRecord.organization_id == other.id)
        )
        == 1
    )
    assert ledger == (
        await db.scalar(select(func.count()).select_from(RequestLifecycle)),
        await db.scalar(select(func.count()).select_from(UsageLedger)),
    )


@pytest.mark.asyncio
async def test_delete_import_removes_only_that_import(db) -> None:
    organization = await _tenant(db)
    first = await _import(db, organization.id, [_row(1), _row(2)])
    await _import(db, organization.id, [_row(3)])

    undone = await delete_import(db, organization.id, first["import_id"])

    assert undone == {"import_id": first["import_id"], "rows_deleted": 2}
    left = await db.scalars(
        select(ExternalUsageRecord.source_request_id).where(
            ExternalUsageRecord.organization_id == organization.id
        )
    )
    assert list(left) == ["fixture-0003"]


@pytest.mark.parametrize(
    ("since", "until"),
    [(SINCE, SINCE + timedelta(days=32)), (UNTIL, SINCE), (None, UNTIL)],
)
@pytest.mark.asyncio
async def test_a_window_over_thirty_one_days_or_backwards_is_refused(
    since, until
) -> None:
    args = argparse.Namespace(
        organization=uuid4(), since=since, until=until, delete_import=None
    )

    with pytest.raises(ImportRefused):
        await main(args)


def _page(rows: int, start: int = 0) -> dict:
    return {"data": [_row(start + index) for index in range(rows)], "total": rows}


@pytest.mark.asyncio
async def test_pages_are_read_until_a_short_one_and_the_key_stays_out(
    caplog,
) -> None:
    caplog.set_level(logging.DEBUG)
    seen: list[httpx.Request] = []

    def answer(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        page = int(request.url.params["page"])
        return httpx.Response(200, json=_page(1000 if page == 1 else 3, page * 1000))

    rows = [
        row
        async for row in url_rows(
            "https://litellm.internal",
            "sk-admin-secret",
            SINCE,
            UNTIL,
            transport=httpx.MockTransport(answer),
        )
    ]

    assert len(rows) == 1003
    assert [request.url.params["page"] for request in seen] == ["1", "2"]
    assert seen[0].url.path == "/spend/logs/v2"
    assert dict(seen[0].url.params) == {
        "start_date": "2026-10-01 00:00:00",
        "end_date": "2026-10-02 00:00:00",
        "page": "1",
        "page_size": "1000",
        "sort_by": "startTime",
        "sort_order": "asc",
    }
    assert seen[0].headers["authorization"] == "Bearer sk-admin-secret"
    assert "sk-admin-secret" not in caplog.text


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (httpx.Response(200, json=_page(1001)), "more than 1000 rows"),
        (
            httpx.Response(302, headers={"location": "https://elsewhere.example/"}),
            "redirect",
        ),
        (httpx.Response(200, json={"rows": []}), "not a spend log page"),
        (httpx.Response(401), "answered 401"),
    ],
)
@pytest.mark.asyncio
async def test_a_page_this_script_will_not_read_past_stops_the_run(
    response, message
) -> None:
    seen: list[httpx.Request] = []

    def answer(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return response

    with pytest.raises(ImportRefused, match=message):
        async for _ in url_rows(
            "https://litellm.internal",
            "sk-admin-secret",
            SINCE,
            UNTIL,
            transport=httpx.MockTransport(answer),
        ):
            pass

    assert len(seen) == 1


@pytest.mark.asyncio
async def test_the_database_is_read_in_order_with_content_only_flagged() -> None:
    url = settings.DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")
    connection = await asyncpg.connect(url)
    try:
        await connection.execute(
            """
            CREATE TABLE "LiteLLM_SpendLogs" (
                request_id TEXT NOT NULL, call_type TEXT, api_key TEXT,
                spend DOUBLE PRECISION, prompt_tokens INTEGER,
                completion_tokens INTEGER, "startTime" TIMESTAMP(3) NOT NULL,
                "endTime" TIMESTAMP(3), "completionStartTime" TIMESTAMP(3),
                request_duration_ms INTEGER, model TEXT, model_group TEXT,
                custom_llm_provider TEXT, api_base TEXT, "user" TEXT,
                cache_hit TEXT, request_tags JSONB, team_id TEXT, status TEXT,
                messages JSONB DEFAULT '{}', response JSONB DEFAULT '{}'
            )
            """
        )
        await connection.executemany(
            'INSERT INTO "LiteLLM_SpendLogs" (request_id, "startTime", messages, '
            "spend) VALUES ($1, $2, $3, 0.1)",
            [
                (
                    f"r-{index:04d}",
                    (START + timedelta(seconds=index // 2)).replace(tzinfo=None),
                    json.dumps([{"content": PROMPT}] if index == 3 else {}),
                )
                for index in range(2_005)
            ]
            + [("late", UNTIL.replace(tzinfo=None), "{}")],
        )

        rows = [row async for row in database_rows(url, SINCE, UNTIL)]
    finally:
        await connection.execute('DROP TABLE IF EXISTS "LiteLLM_SpendLogs"')
        await connection.close()

    assert [row["request_id"] for row in rows] == [
        f"r-{index:04d}" for index in range(2_005)
    ]
    assert [row["request_id"] for row in rows if row["content_present"]] == ["r-0003"]
    assert all("messages" not in row and "response" not in row for row in rows)
    assert mapped(rows[0])["cost_usd"] == Decimal("0.1")


async def _registry(db, organization_id) -> None:
    secret = ProviderSecret(
        id=uuid4(),
        organization_id=organization_id,
        provider="openai",
        secret_ref=f"reference-{uuid4().hex}",
        secret_backend="fernet",
        secret_version="v2",
        masked_key="masked",
    )
    db.add(secret)
    await db.flush()
    db.add(
        ModelDeployment(
            organization_id=organization_id,
            alias="kurum-gpt",
            provider="openai",
            upstream_model="gpt-5-nano",
            base_url="https://a.internal/v1",
            provider_secret_id=secret.id,
            timeout_seconds=5,
            deployment_kind="internal",
            declared_version="v1",
            owner="Platform",
        )
    )
    await db.flush()


@pytest.mark.parametrize("requests", [10, 9])
@pytest.mark.asyncio
async def test_unregistered_model_fires_at_ten_requests(db, requests) -> None:
    organization = await _tenant(db)
    await _registry(db, organization.id)
    rows = [
        _row(index, model="llama-local", model_group=None) for index in range(requests)
    ]
    rows += [_row(100 + index) for index in range(12)]
    # Registered through its model group only.
    rows += [
        _row(200 + index, model="gpt-5-nano-2026", model_group="kurum-gpt")
        for index in range(12)
    ]

    summary = await _import(db, organization.id, rows)

    fired = [row.subject for row in await _findings(db, organization.id)]
    # Not a price-book or registry name: counted, never named.
    assert fired == ([{"model": "other"}] if requests == 10 else [])
    assert summary["findings_opened"] == (
        {service.LITELLM_UNREGISTERED_MODEL: 1} if requests == 10 else {}
    )


@pytest.mark.asyncio
async def test_unregistered_model_is_silent_without_a_registry(db) -> None:
    organization = await _tenant(db)

    await _import(db, organization.id, [_row(index, model="x") for index in range(20)])

    assert await _findings(db, organization.id) == []


@pytest.mark.parametrize(("failed", "fires"), [(3, True), (2, False)])
@pytest.mark.asyncio
async def test_error_rate_needs_fifty_requests_and_five_percent(
    db, failed, fires
) -> None:
    organization = await _tenant(db)
    rows = [
        _row(index, status="failure" if index < failed else "success")
        for index in range(60)
    ]
    # Outside the last 24 hours of the log: never counted.
    rows.append(
        _row(1, request_id="old", startTime="2026-09-30T22:00:00", status="failure")
    )

    await import_rows(
        db,
        organization.id,
        _source(rows),
        since=SINCE - timedelta(days=1),
        until=UNTIL,
    )

    found = await _findings(db, organization.id)
    if not fires:
        assert found == []
        return
    [row] = found
    assert (row.rule_id, row.source, row.subject) == (
        service.LITELLM_ERROR_RATE,
        "litellm",
        {"model": "gpt-5-nano"},
    )
    assert row.evidence["request_ids"] == [
        "fixture-0000",
        "fixture-0001",
        "fixture-0002",
    ]
    assert (row.evidence["requests"], row.evidence["failed_requests"]) == (60, 3)
    assert row.impact["cost_source"] == "litellm" and row.impact["requests"] == 3
    finding = service.finding_from_row(row)
    assert finding.source == "litellm"
    assert FindingV1.model_validate(finding.model_dump(mode="json")) == finding
    assert finding.summary.en == (
        "3 of 60 LiteLLM requests for this model failed in 24 hours of the imported log."
    )


@pytest.mark.parametrize(("slow_ms", "fires"), [(10_000, True), (9_999, False)])
@pytest.mark.asyncio
async def test_slow_first_token_needs_fifty_streams_and_a_ten_second_p95(
    db, slow_ms, fires
) -> None:
    organization = await _tenant(db)
    rows = []
    for index in range(50):
        started = START + timedelta(hours=23, seconds=index)
        # Four of fifty slow put the p95 exactly at their time to first token.
        waited = slow_ms if index < 4 else 1_000
        first = started + timedelta(milliseconds=waited)
        rows.append(
            _row(
                index,
                startTime=started.replace(tzinfo=None).isoformat(),
                completionStartTime=first.replace(tzinfo=None).isoformat(),
                endTime=(first + timedelta(seconds=1)).replace(tzinfo=None).isoformat(),
            )
        )

    await _import(db, organization.id, rows)

    found = await _findings(db, organization.id)
    assert [row.rule_id for row in found] == (
        [service.LITELLM_SLOW_FIRST_TOKEN] if fires else []
    )


@pytest.mark.parametrize(("repeats", "fires"), [(20, True), (19, False)])
@pytest.mark.asyncio
async def test_retry_burst_needs_twenty_equal_requests_in_one_quarter_hour(
    db, repeats, fires
) -> None:
    organization = await _tenant(db)
    rows = [
        _row(index, prompt_tokens=812, request_id=f"burst/{index}")
        for index in range(repeats - 1)
    ]
    # Counted, but a request id a Finding v1 cannot carry stays out of the evidence.
    rows.append(_row(99, prompt_tokens=812, request_id="burst with spaces"))
    # The window ends at the latest imported row: an hour earlier is outside.
    rows += [
        _row(
            200 + index,
            prompt_tokens=812,
            startTime="2026-10-01T21:00:00",
            request_id=f"early-{index}",
        )
        for index in range(30)
    ]

    summary = await _import(db, organization.id, rows)
    again = await _import(db, organization.id, rows)

    found = await _findings(db, organization.id)
    if not fires:
        assert found == []
        return
    [row] = found
    assert row.subject == {"litellm_key": f"litellm:{KEY[:16]}"}
    assert KEY not in json.dumps(row.evidence) + json.dumps(row.subject)
    assert row.evidence["repeated_requests"] == repeats
    assert "burst with spaces" not in row.evidence["request_ids"]
    assert row.occurrences == 2
    assert summary["findings_opened"] == {service.LITELLM_RETRY_BURST: 1}
    assert again["findings_updated"] == {service.LITELLM_RETRY_BURST: 1}
    finding = service.finding_from_row(row)
    assert (finding.subject.kind, finding.subject.id) == ("key", f"litellm:{KEY[:16]}")
    assert "equal token counts" in finding.summary.en


@pytest.mark.asyncio
async def test_the_worker_never_evaluates_litellm_rules(db) -> None:
    organization = await _tenant(db)
    db.add_all(
        ExternalUsageRecord(
            organization_id=organization.id,
            source="litellm",
            source_request_id=f"w-{index}",
            import_id=uuid4(),
            started_at=datetime.now(timezone.utc) - timedelta(minutes=5),
            status="failure",
            model="gpt-5-nano",
        )
        for index in range(60)
    )
    await db.flush()

    await service.evaluate_organization(
        db, organization.id, now=datetime.now(timezone.utc)
    )

    assert await _findings(db, organization.id) == []


@pytest.mark.asyncio
async def test_a_row_without_a_model_is_judged_by_its_model_group(db) -> None:
    organization = await _tenant(db)
    await _registry(db, organization.id)

    await _import(
        db,
        organization.id,
        [_row(index, model=None, model_group="team-pool") for index in range(10)]
        + [
            _row(50 + index, model=None, model_group="kurum-gpt") for index in range(10)
        ],
    )

    assert [row.subject for row in await _findings(db, organization.id)] == [
        {"model": "other"}
    ]
