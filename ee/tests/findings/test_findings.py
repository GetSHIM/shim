from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
import logging
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import event, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import shim_enterprise.api.enterprise_deps as enterprise_deps
from shim_enterprise.api.v1.router import management_router
from shim_enterprise.billing.models import RequestLifecycle, UsageLedger
from shim_enterprise.core.database import get_db
from shim_enterprise.findings import service
from shim_enterprise.findings.models import Finding
from shim_enterprise.gateway.pipeline.quota_reservation import (
    EPHEMERAL_BYOK_SPEND_POLICY_VERSION,
)
from shim_enterprise.tenants.models import (
    ApiKey,
    ModelDeployment,
    Organization,
    ProviderSecret,
    User,
)

NOW = datetime(2026, 10, 8, 12, 7, tzinfo=timezone.utc)
BUCKET = datetime(2026, 10, 8, 12, 0, tzinfo=timezone.utc)


def _request(
    db,
    key,
    started_at: datetime,
    *,
    repeat: int = 1,
    status: str = "completed",
    outcome: str | None = "complete",
    model: str = "gpt-5-mini",
    cost: str | None = None,
    priced: bool = True,
    metadata: dict | None = None,
) -> str:
    request_id = f"req_finding_{uuid4().hex}"
    db.add(
        RequestLifecycle(
            request_id=request_id,
            organization_id=key.organization_id,
            actor_type="api_key",
            api_key_id=key.id,
            source_endpoint="chat.completions",
            status=status,
            provider="openai",
            provider_model=model,
            requested_model=model,
            stream=False,
            started_at=started_at,
            lifecycle_metadata={
                "repeat_chain_length": repeat,
                "completion_outcome": outcome,
                **(metadata or {}),
            },
        )
    )
    if cost is not None:
        ledger = {
            "request_id": request_id,
            "organization_id": key.organization_id,
            "api_key_id": key.id,
            "requested_model": model,
            "provider": "openai",
            "provider_model": model,
            "cost_usd": Decimal(cost),
            "created_at": started_at,
        }
        reservation = uuid4()
        db.add_all(
            [
                UsageLedger(
                    id=reservation,
                    event_type="spend_reservation",
                    idempotency_key=f"{request_id}:spend:reservation",
                    **ledger,
                ),
                UsageLedger(
                    event_type="spend_settlement",
                    idempotency_key=f"{request_id}:spend:settlement",
                    reservation_event_id=reservation,
                    event_metadata=(
                        {} if priced else {"pricing": {"pricing_resolution": "unknown"}}
                    ),
                    **ledger,
                ),
            ]
        )
    return request_id


async def _evaluate(db, key, now: datetime = NOW) -> list[service.Detection]:
    await db.flush()
    detections = await service.evaluate_organization(db, key.organization_id, now=now)
    await db.flush()
    return detections


async def _findings(db, key) -> list[Finding]:
    return list(
        (
            await db.scalars(
                select(Finding)
                .where(Finding.organization_id == key.organization_id)
                .order_by(Finding.first_seen_at, Finding.rule_id)
                .execution_options(populate_existing=True)
            )
        ).all()
    )


@pytest.mark.parametrize("repeated", [20, 19])
@pytest.mark.asyncio
async def test_retry_storm_fires_at_twenty_repeats_in_one_quarter_hour(
    db, test_api_key, repeated: int
) -> None:
    ids = [
        _request(
            db,
            test_api_key,
            BUCKET + timedelta(seconds=index),
            repeat=index + 2,
            cost="0.01",
        )
        for index in range(repeated)
    ]
    for status in ("client_disconnected", "timeout"):
        _request(db, test_api_key, BUCKET, status=status, outcome=None)
    # Earlier buckets and outside the hour never add up to the threshold.
    for started_at in (BUCKET - timedelta(minutes=15), BUCKET - timedelta(hours=1)):
        for index in range(19):
            _request(db, test_api_key, started_at, repeat=2)

    detections = await _evaluate(db, test_api_key)

    storms = [d for d in detections if d.rule_id == service.RETRY_STORM]
    if repeated < 20:
        assert storms == []
        return
    (storm,) = storms
    assert storm.subject_key == f"api_key:{test_api_key.id}"
    assert storm.subject == {"api_key_id": str(test_api_key.id)}
    assert service.RULES[storm.rule_id][1] == 3
    assert storm.evidence == {
        "window_start": BUCKET.isoformat(),
        "window_minutes": 15,
        "repeated_requests": 20,
        "threshold": 20,
        "abandoned_requests": 2,
        "request_ids": ids,
        # Rows without a repeat digest count through repeat_chain_length and are never linked.
        "classes": dict.fromkeys(service.REPEAT_CLASSES, 0),
        "pairs": [],
    }
    assert storm.impact == {"cost_usd": "0.20000000", "requests": 20}
    assert storm.remediation is None


@pytest.mark.parametrize(
    ("repeated_cost", "other_cost", "fires"),
    [("1.00", "9.00", True), ("0.99", "1.00", False), ("1.50", "18.00", False)],
)
@pytest.mark.asyncio
async def test_repeat_spend_needs_a_dollar_and_a_tenth_of_known_spend(
    db, test_api_key, repeated_cost: str, other_cost: str, fires: bool
) -> None:
    start = datetime(2026, 10, 1, 1, tzinfo=timezone.utc)
    repeated_id = _request(db, test_api_key, start, repeat=3, cost=repeated_cost)
    _request(db, test_api_key, start, cost=other_cost)
    _request(db, test_api_key, start - timedelta(days=2), repeat=5, cost="50")

    detections = [
        d
        for d in await _evaluate(db, test_api_key)
        if d.rule_id == service.REPEAT_SPEND
    ]

    if not fires:
        assert detections == []
        return
    (finding,) = detections
    assert finding.subject_key == f"api_key:{test_api_key.id}"
    assert finding.evidence["repeated_cost_usd"] == "1.00000000"
    assert finding.evidence["known_spend_usd"] == "10.00000000"
    assert finding.evidence["share"] == "0.1000"
    assert finding.evidence["request_ids"] == [repeated_id]
    assert finding.impact == {"cost_usd": "1.00000000", "requests": 1}


async def _plans(db, run) -> list[str]:
    """EXPLAIN ANALYZE every SELECT that ``run`` sends, with its parameters."""
    connection = await db.connection()
    sent: list[tuple[str, object]] = []

    def capture(conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith("SELECT"):
            sent.append((statement, parameters))

    event.listen(connection.sync_connection, "before_cursor_execute", capture)
    try:
        await run()
    finally:
        event.remove(connection.sync_connection, "before_cursor_execute", capture)
    return [
        "\n".join(
            row[0]
            for row in await connection.exec_driver_sql(
                f"EXPLAIN ANALYZE {sql}", parameters
            )
        )
        for sql, parameters in sent
    ]


@pytest.mark.asyncio
async def test_retry_rules_sum_priced_settlements_with_one_join(
    db, test_api_key
) -> None:
    def at(second: int) -> datetime:
        return BUCKET + timedelta(seconds=second)

    repeated = [
        _request(db, test_api_key, at(0), repeat=2, cost="0.40"),
        _request(db, test_api_key, at(1), repeat=3, cost="0.70"),
        _request(db, test_api_key, at(2), repeat=4, cost="9", priced=False),
        _request(db, test_api_key, at(3), repeat=5),
    ]
    repeated += [_request(db, test_api_key, at(4 + i), repeat=2) for i in range(16)]
    _request(db, test_api_key, at(30), cost="2.00")
    _request(db, test_api_key, at(31), cost="5", priced=False)
    await db.flush()

    detections: list[service.Detection] = []

    async def run() -> None:
        detections.extend(
            await service._retry_storms(db, test_api_key.organization_id, NOW)
            + await service._repeat_spend(db, test_api_key.organization_id, NOW)
        )

    plans = await _plans(db, run)

    storm, spend = detections
    assert storm.evidence["request_ids"] == repeated
    assert storm.impact == {"cost_usd": "1.10000000", "requests": 20}
    assert spend.evidence["repeated_cost_usd"] == "1.10000000"
    assert spend.evidence["known_spend_usd"] == "3.10000000"
    assert spend.impact == {"cost_usd": "1.10000000", "requests": 20}
    # Spend is joined once per query, not looked up per request.
    assert len(plans) == 2
    assert all("SubPlan" not in plan for plan in plans), plans


async def _deployment(db, key, *, age: timedelta, enabled: bool = True) -> str:
    secret = ProviderSecret(
        id=uuid4(),
        organization_id=key.organization_id,
        provider="openai",
        secret_ref=f"reference-{uuid4().hex}",
        secret_backend="fernet",
        secret_version="v2",
        masked_key="masked",
    )
    db.add(secret)
    await db.flush()
    alias = f"internal-{uuid4().hex[:8]}"
    db.add(
        ModelDeployment(
            organization_id=key.organization_id,
            alias=alias,
            provider="openai",
            upstream_model="custom-model",
            base_url="https://a.internal/v1",
            provider_secret_id=secret.id,
            timeout_seconds=5,
            deployment_kind="internal",
            declared_version="v1",
            owner="Platform",
            enabled=enabled,
            created_at=NOW - age,
        )
    )
    await db.flush()
    return alias


@pytest.mark.asyncio
async def test_unused_deployment_fires_after_thirty_quiet_days(
    db, test_api_key
) -> None:
    unused = await _deployment(db, test_api_key, age=timedelta(days=30))
    await _deployment(db, test_api_key, age=timedelta(days=29, hours=23))
    await _deployment(db, test_api_key, age=timedelta(days=60), enabled=False)
    used = await _deployment(db, test_api_key, age=timedelta(days=60))
    _request(db, test_api_key, NOW - timedelta(days=29), model=used)
    _request(db, test_api_key, NOW - timedelta(days=31), model=unused)

    detections = [
        d
        for d in await _evaluate(db, test_api_key)
        if d.rule_id == service.UNUSED_DEPLOYMENT
    ]

    assert [(d.subject_key, d.subject["alias"]) for d in detections] == [
        (f"deployment:{unused}", unused)
    ]
    assert service.RULES[service.UNUSED_DEPLOYMENT][1] == 2
    assert detections[0].impact is None


@pytest.mark.asyncio
async def test_unused_deployments_read_the_requests_once_for_every_alias(
    db, test_api_key
) -> None:
    aliases = [
        await _deployment(db, test_api_key, age=timedelta(days=40)) for _ in range(4)
    ]
    for alias in aliases[:2]:
        _request(db, test_api_key, NOW - timedelta(days=1), model=alias)
    await db.flush()
    detections: list[service.Detection] = []

    async def run() -> None:
        detections.extend(
            await service._unused_deployments(db, test_api_key.organization_id, NOW)
        )

    plans = await _plans(db, run)

    assert sorted(d.subject["alias"] for d in detections) == sorted(aliases[2:])
    scans = [
        line
        for plan in plans
        for line in plan.splitlines()
        if " on request_lifecycle" in line
    ]
    assert scans, plans
    assert all("loops=1)" in line for line in scans), plans


@pytest.mark.parametrize(
    ("settled", "bad", "fires"),
    [
        (60, {"truncated": 3}, True),
        (60, {"empty": 2, "refused": 1}, True),
        (60, {"truncated": 2, "empty": 2}, False),
        (49, {"truncated": 49}, False),
    ],
)
@pytest.mark.asyncio
async def test_answer_quality_needs_fifty_answers_and_five_percent(
    db, test_api_key, settled: int, bad: dict[str, int], fires: bool
) -> None:
    started = NOW - timedelta(hours=1)
    outcomes = [name for name, count in bad.items() for _ in range(count)]
    outcomes += ["complete"] * (settled - len(outcomes))
    for outcome in outcomes:
        _request(db, test_api_key, started, outcome=outcome)
    for _ in range(10):
        _request(db, test_api_key, started, status="rejected", outcome=None)
        _request(db, test_api_key, NOW - timedelta(hours=25), outcome="truncated")

    detections = [
        d
        for d in await _evaluate(db, test_api_key)
        if d.rule_id == service.ANSWER_QUALITY
    ]

    if not fires:
        assert detections == []
        return
    (finding,) = detections
    assert finding.subject == {"model": "gpt-5-mini"}
    assert finding.evidence["settled_requests"] == settled
    assert finding.evidence["truncated"] == bad.get("truncated", 0)
    assert len(finding.evidence["request_ids"]) == len(outcomes) - outcomes.count(
        "complete"
    )


async def _storm(db, key, start: datetime = BUCKET) -> None:
    for index in range(20):
        _request(db, key, start + timedelta(seconds=index), repeat=2)


@pytest.mark.asyncio
async def test_findings_update_resolve_reopen_and_stay_suppressed(
    db, test_api_key
) -> None:
    await _storm(db, test_api_key)
    await _evaluate(db, test_api_key)
    await _evaluate(db, test_api_key, NOW + timedelta(minutes=1))

    (finding,) = await _findings(db, test_api_key)
    assert (finding.occurrences, finding.status_id) == (2, 1)
    assert finding.first_seen_at == NOW
    assert finding.last_seen_at == NOW + timedelta(minutes=1)

    await db.execute(update(Finding).values(status_id=3))
    await _evaluate(db, test_api_key, NOW + timedelta(minutes=2))
    (suppressed,) = await _findings(db, test_api_key)
    assert (suppressed.status_id, suppressed.occurrences) == (3, 3)

    later = NOW + timedelta(days=8)
    await _evaluate(db, test_api_key, later)
    (resolved,) = await _findings(db, test_api_key)
    assert (resolved.status_id, resolved.resolved_by) == (4, "system")
    assert resolved.resolved_at == later

    await _storm(db, test_api_key, BUCKET + timedelta(days=8))
    await _evaluate(db, test_api_key, later + timedelta(minutes=1))
    old, new = await _findings(db, test_api_key)
    assert (old.id, old.status_id) == (finding.id, 4)
    assert (new.status_id, new.occurrences) == (1, 1)


@pytest.mark.asyncio
async def test_one_failing_organization_does_not_stop_the_others(
    db, test_api_key, monkeypatch: pytest.MonkeyPatch, caplog
) -> None:
    archived = Organization(
        id=uuid4(),
        name="Archived",
        slug=f"archived-{uuid4().hex}",
        archived_at=NOW,
        archived_reason="joined_organization",
    )
    failing = Organization(id=uuid4(), name="Failing", slug=f"failing-{uuid4().hex}")
    db.add_all([archived, failing])
    await db.flush()
    seen = []

    async def evaluate(session, tenant_id, *, now):
        seen.append(tenant_id)
        if tenant_id == failing.id:
            raise RuntimeError("synthetic failure")
        return []

    monkeypatch.setattr(service, "evaluate_organization", evaluate)
    factory = async_sessionmaker(
        await db.connection(),
        class_=AsyncSession,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    )

    with caplog.at_level(logging.ERROR, logger=service.__name__):
        await service.evaluate_findings(factory, now=NOW)

    assert {failing.id, test_api_key.organization_id} <= set(seen)
    assert archived.id not in seen
    assert f"organization_id={failing.id} type=RuntimeError" in caplog.text
    assert "synthetic failure" not in caplog.text


def _client(db, user) -> httpx.AsyncClient:
    application = FastAPI()
    application.include_router(management_router, prefix="/api/v1")
    application.dependency_overrides[enterprise_deps.get_current_user] = lambda: user
    application.dependency_overrides[get_db] = lambda: db
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="http://test"
    )


@pytest.mark.asyncio
async def test_findings_api_filters_audits_and_exports_ocsf(
    db, test_api_key, test_user_with_org, audit_events
) -> None:
    user = test_user_with_org
    await _storm(db, test_api_key)
    await _deployment(db, test_api_key, age=timedelta(days=40))
    await _evaluate(db, test_api_key)
    storm, unused = await _findings(db, test_api_key)
    other = Organization(id=uuid4(), name="Other", slug=f"other-{uuid4().hex}")
    db.add(other)
    await db.flush()
    db.add(Finding(**{**_copy(storm), "id": uuid4(), "organization_id": other.id}))
    await db.flush()
    url = "/api/v1/management/findings"

    async with _client(db, user) as client:
        user.role = "member"
        member = [
            (await client.get(path)).status_code
            for path in (url, f"{url}/export", f"{url}/{storm.id}")
        ]
        user.role = "auditor"
        listed = (await client.get(url)).json()
        by_rule = (
            await client.get(url, params={"rule_id": service.RETRY_STORM})
        ).json()
        by_severity = (await client.get(url, params={"severity_id": 2})).json()
        by_status = (await client.get(url, params={"status": "resolved"})).json()
        exported = await client.get(f"{url}/export")
        auditor_patch = await client.patch(
            f"{url}/{storm.id}", json={"status": "resolved"}
        )
        user.role = "admin"
        detail = await client.get(f"{url}/{storm.id}")
        foreign = await client.get(f"{url}/{uuid4()}")
        resolved = await client.patch(f"{url}/{storm.id}", json={"status": "resolved"})
        await _storm(db, test_api_key, BUCKET + timedelta(minutes=1))
        await _evaluate(db, test_api_key, NOW + timedelta(minutes=1))
        conflict = await client.patch(f"{url}/{storm.id}", json={"status": "new"})
        bad_status = await client.patch(f"{url}/{storm.id}", json={"status": "closed"})

    assert member == [403, 403, 403]
    assert listed["total"] == 2
    assert {item["id"] for item in listed["items"]} == {str(storm.id), str(unused.id)}
    assert [item["rule_id"] for item in by_rule["items"]] == [service.RETRY_STORM]
    assert [item["rule_id"] for item in by_severity["items"]] == [
        service.UNUSED_DEPLOYMENT
    ]
    assert by_status["items"] == []
    assert exported.status_code == 200
    assert exported.headers["content-type"] == "application/x-ndjson"
    records = [json.loads(line) for line in exported.text.splitlines()]
    assert len(records) == 2
    record = next(r for r in records if r["finding_info"]["uid"] == str(storm.id))
    assert {
        key: record[key]
        for key in (
            "class_uid",
            "category_uid",
            "activity_id",
            "type_uid",
            "severity_id",
            "status_id",
        )
    } == {
        "class_uid": 2004,
        "category_uid": 2,
        "activity_id": 1,
        "type_uid": 200401,
        "severity_id": 3,
        "status_id": 1,
    }
    assert record["time"] == int(NOW.timestamp() * 1000)
    assert record["metadata"] == {
        "version": service.OCSF_VERSION,
        "product": {"name": "shim", "vendor_name": "shim"},
    }
    assert record["finding_info"] == {
        "uid": str(storm.id),
        "title": storm.title,
        "desc": storm.summary,
        "first_seen_time": int(NOW.timestamp() * 1000),
        "last_seen_time": int(NOW.timestamp() * 1000),
    }
    assert record["unmapped"]["evidence"]["repeated_requests"] == 20
    assert record["unmapped"]["remediation"]["doc"].startswith("ee/docs/FINDINGS.md#")
    assert auditor_patch.status_code == 403
    assert detail.json()["status"] == "new"
    assert foreign.status_code == 404
    assert resolved.status_code == 200
    assert (resolved.json()["status"], resolved.json()["resolved_by"]) == (
        "resolved",
        str(user.id),
    )
    assert conflict.status_code == 409
    assert bad_status.status_code == 422
    events = [
        event
        for event in await audit_events(user.organization_id)
        if event["endpoint"] == "tenant.finding_status_changed"
    ]
    assert [event["extra"] for event in events] == [
        {
            "subject_id": str(storm.id),
            "actor_type": "user_jwt",
            "rule_id": service.RETRY_STORM,
            "before": {"status": "new"},
            "after": {"status": "resolved"},
        }
    ]


@pytest.mark.asyncio
async def test_reopen_racing_the_worker_answers_409(
    db, test_api_key, test_user_with_org
) -> None:
    await _storm(db, test_api_key)
    await _evaluate(db, test_api_key)
    (finding,) = await _findings(db, test_api_key)
    finding.status_id = service.STATUS_RESOLVED
    await db.flush()

    def worker_reopens(session, flush_context, instances) -> None:
        # The worker's new open finding commits after the API's existence check.
        session.connection().execute(
            insert(Finding).values(**{**_copy(finding), "id": uuid4(), "status_id": 1})
        )

    event.listen(db.sync_session, "before_flush", worker_reopens, once=True)
    test_user_with_org.role = "admin"
    async with _client(db, test_user_with_org) as client:
        response = await client.patch(
            f"/api/v1/management/findings/{finding.id}", json={"status": "new"}
        )

    assert response.status_code == 409
    assert response.json()["detail"] == "Another open finding exists for this subject"


def _copy(finding: Finding) -> dict:
    return {
        column.key: getattr(finding, column.key) for column in Finding.__table__.columns
    }


def test_ocsf_activity_follows_the_finding_lifecycle() -> None:
    def activity(**values) -> tuple[int, int]:
        record = service.ocsf_detection_finding(
            SimpleNamespace(
                id=uuid4(),
                title="t",
                summary="s",
                severity_id=2,
                rule_id=service.ANSWER_QUALITY,
                rule_version=1,
                subject={},
                evidence={},
                impact=None,
                remediation={},
                first_seen_at=NOW,
                last_seen_at=NOW,
                resolved_at=None,
                **values,
            )
        )
        return record["activity_id"], record["type_uid"]

    assert activity(status_id=1, occurrences=1) == (1, 200401)
    assert activity(status_id=1, occurrences=2) == (2, 200402)
    assert activity(status_id=3, occurrences=1) == (2, 200402)
    assert activity(status_id=4, occurrences=1) == (3, 200403)


async def _with_digest(db, request_ids: dict[str, str]) -> None:
    await db.flush()
    for request_id, digest in request_ids.items():
        row = await db.scalar(
            select(RequestLifecycle).where(RequestLifecycle.request_id == request_id)
        )
        row.lifecycle_metadata = {**row.lifecycle_metadata, "repeat_digest": digest}
    await db.flush()


async def _pairs(db, key, start: datetime, end: datetime) -> list[tuple]:
    return [
        (row.request_id, row.previous_id, row.repeat_class, row.previous_billed)
        for row in await service.linked_repeats(db, key.organization_id, start, end)
    ]


@pytest.mark.asyncio
async def test_a_repeat_links_to_the_previous_request_inside_the_link_window(
    db, test_api_key
) -> None:
    other_key = ApiKey(
        id=uuid4(),
        organization_id=test_api_key.organization_id,
        user_id=test_api_key.user_id,
        key_hash=uuid4().hex,
        prefix="sk-shim-oth",
        tier=test_api_key.tier,
        is_active=True,
    )
    db.add(other_key)
    await db.flush()
    start = BUCKET
    before = _request(db, test_api_key, start - timedelta(seconds=100))
    first = _request(db, test_api_key, start + timedelta(seconds=10))
    at_limit = _request(db, test_api_key, start + timedelta(seconds=910))
    too_late = _request(db, test_api_key, start + timedelta(seconds=1811))
    other_digest = _request(db, test_api_key, start + timedelta(seconds=20))
    other = _request(db, other_key, start + timedelta(seconds=30))
    undigested = _request(db, test_api_key, start + timedelta(seconds=40), repeat=2)
    await _with_digest(
        db,
        {
            before: "d1",
            first: "d1",
            at_limit: "d1",
            too_late: "d1",
            other_digest: "d2",
            other: "d1",
        },
    )

    pairs = await _pairs(db, test_api_key, start, start + timedelta(hours=1))

    assert pairs == [
        (first, before, "after_success", False),
        (at_limit, first, "after_success", False),
    ]
    assert undigested not in {pair[0] for pair in pairs}


@pytest.mark.asyncio
async def test_rows_started_together_link_in_id_order(db, test_api_key) -> None:
    ids = [_request(db, test_api_key, BUCKET) for _ in range(2)]
    await _with_digest(db, dict.fromkeys(ids, "same"))
    rows = (
        (
            await db.execute(
                select(RequestLifecycle.request_id)
                .where(RequestLifecycle.request_id.in_(ids))
                .order_by(RequestLifecycle.id)
            )
        )
        .scalars()
        .all()
    )

    pairs = await _pairs(db, test_api_key, BUCKET, BUCKET + timedelta(minutes=1))

    assert [(pair[0], pair[1]) for pair in pairs] == [(rows[1], rows[0])]


@pytest.mark.parametrize(
    ("status", "repeat_class"),
    [
        ("client_disconnected", "after_timeout"),
        ("timeout", "after_timeout"),
        ("provider_error", "after_error"),
        ("failed", "after_error"),
        ("rejected", "after_error"),
        ("internal_error", "after_error"),
        ("cancelled", "after_error"),
        ("completed", "after_success"),
        ("provider_started", "pending"),
    ],
)
@pytest.mark.asyncio
async def test_a_repeat_is_classed_by_how_its_predecessor_ended(
    db, test_api_key, status: str, repeat_class: str
) -> None:
    previous = _request(db, test_api_key, BUCKET, status=status)
    repeat = _request(db, test_api_key, BUCKET + timedelta(seconds=5))
    await _with_digest(db, {previous: "d", repeat: "d"})

    assert await _pairs(db, test_api_key, BUCKET, NOW) == [
        (repeat, previous, repeat_class, False)
    ]


async def _other_tenant_key(db, key) -> ApiKey:
    organization = Organization(id=uuid4(), name="Other", slug=f"other-{uuid4().hex}")
    db.add(organization)
    await db.flush()
    user = User(
        id=uuid4(),
        organization_id=organization.id,
        email=f"other-{uuid4().hex}@example.com",
        role="owner",
        is_active=True,
    )
    db.add(user)
    await db.flush()
    other = ApiKey(
        id=uuid4(),
        organization_id=organization.id,
        user_id=user.id,
        key_hash=uuid4().hex,
        prefix="sk-shim-oth",
        tier=key.tier,
        is_active=True,
    )
    db.add(other)
    await db.flush()
    return other


@pytest.mark.asyncio
async def test_only_a_settled_predecessor_counts_as_billed(
    db, test_api_key, test_user_with_org
) -> None:
    other_key = await _other_tenant_key(db, test_api_key)
    other_org = SimpleNamespace(id=other_key.organization_id)
    billed = _request(db, test_api_key, BUCKET, cost="0.10")
    refunded = _request(db, test_api_key, BUCKET + timedelta(seconds=1))
    elsewhere = _request(db, test_api_key, BUCKET + timedelta(seconds=2))
    reservation, elsewhere_reservation = uuid4(), uuid4()
    db.add_all(
        [
            UsageLedger(
                id=reservation,
                request_id=refunded,
                organization_id=test_api_key.organization_id,
                api_key_id=test_api_key.id,
                requested_model="gpt-5-mini",
                provider="openai",
                provider_model="gpt-5-mini",
                event_type="spend_reservation",
                idempotency_key=f"{refunded}:spend:reservation",
                cost_usd=Decimal("0.10"),
                created_at=BUCKET,
            ),
            UsageLedger(
                request_id=refunded,
                organization_id=test_api_key.organization_id,
                api_key_id=test_api_key.id,
                requested_model="gpt-5-mini",
                provider="openai",
                provider_model="gpt-5-mini",
                event_type="spend_refund",
                idempotency_key=f"{refunded}:spend:refund",
                reservation_event_id=reservation,
                cost_usd=Decimal("0.10"),
                created_at=BUCKET,
            ),
            *(
                UsageLedger(
                    id=event_id,
                    request_id=elsewhere,
                    organization_id=other_org.id,
                    api_key_id=other_key.id,
                    requested_model="gpt-5-mini",
                    provider="openai",
                    provider_model="gpt-5-mini",
                    event_type=f"spend_{event}",
                    idempotency_key=f"{elsewhere}:spend:{event}",
                    reservation_event_id=reference,
                    cost_usd=Decimal("0.10"),
                    created_at=BUCKET,
                )
                for event_id, event, reference in (
                    (elsewhere_reservation, "reservation", None),
                    (uuid4(), "settlement", elsewhere_reservation),
                )
            ),
        ]
    )
    repeats = {
        previous: _request(db, test_api_key, BUCKET + timedelta(seconds=10 + index))
        for index, previous in enumerate((billed, refunded, elsewhere))
    }
    await _with_digest(
        db,
        {
            **{previous: f"d{index}" for index, previous in enumerate(repeats)},
            **{repeat: f"d{index}" for index, repeat in enumerate(repeats.values())},
        },
    )

    pairs = await _pairs(db, test_api_key, BUCKET, NOW)

    assert {pair[1]: pair[3] for pair in pairs} == {
        billed: True,
        refunded: False,
        elsewhere: False,
    }


@pytest.mark.parametrize("repeats", [20, 19])
@pytest.mark.asyncio
async def test_a_storm_of_linked_repeats_names_its_cause(
    db, test_api_key, repeats: int
) -> None:
    previous = [
        _request(
            db, test_api_key, BUCKET + timedelta(seconds=index), status="provider_error"
        )
        for index in range(repeats)
    ]
    retried = [
        _request(db, test_api_key, BUCKET + timedelta(seconds=index + 2))
        for index in range(repeats)
    ]
    await _with_digest(
        db,
        {
            **{request: f"d{index}" for index, request in enumerate(previous)},
            **{request: f"d{index}" for index, request in enumerate(retried)},
        },
    )

    storms = [
        d for d in await _evaluate(db, test_api_key) if d.rule_id == service.RETRY_STORM
    ]

    if repeats < 20:
        assert storms == []
        return
    (storm,) = storms
    assert storm.evidence["repeated_requests"] == 20
    assert storm.evidence["classes"] == {
        "after_timeout": 0,
        "after_error": 20,
        "after_success": 0,
        "pending": 0,
    }
    assert storm.evidence["pairs"][0] == {
        "repeat": retried[0],
        "previous": previous[0],
        "class": "after_error",
        "gap_seconds": 2,
    }
    assert len(storm.evidence["pairs"]) == 20
    (finding,) = await _findings(db, test_api_key)
    assert finding.rule_version == 2
    assert finding.remediation["text"] == service.STORM_FIXES["after_error"]


@pytest.mark.asyncio
async def test_a_version_one_finding_is_updated_in_place(db, test_api_key) -> None:
    await _storm(db, test_api_key)
    await _evaluate(db, test_api_key)
    await db.execute(update(Finding).values(rule_version=1))

    await _evaluate(db, test_api_key, NOW + timedelta(minutes=1))

    (finding,) = await _findings(db, test_api_key)
    assert (finding.rule_version, finding.occurrences) == (2, 2)
    assert finding.remediation["text"] == service.RULES[service.RETRY_STORM][2]


@pytest.mark.parametrize(("repeat_cost", "fires"), [("1.00", True), ("0.99", False)])
@pytest.mark.asyncio
async def test_repeat_spend_counts_only_repeats_of_billed_requests(
    db, test_api_key, repeat_cost: str, fires: bool
) -> None:
    start = datetime(2026, 10, 1, 1, tzinfo=timezone.utc)
    timed_out = _request(db, test_api_key, start, status="timeout", cost="0.50")
    late_retry = _request(
        db, test_api_key, start + timedelta(seconds=700), cost=repeat_cost
    )
    refunded = _request(
        db, test_api_key, start + timedelta(hours=1), status="provider_error"
    )
    after_refund = _request(
        db, test_api_key, start + timedelta(hours=1, seconds=5), cost="5"
    )
    _request(db, test_api_key, start + timedelta(hours=2), cost="3")
    await _with_digest(
        db, {timed_out: "a", late_retry: "a", refunded: "b", after_refund: "b"}
    )

    spends = [
        d
        for d in await _evaluate(db, test_api_key)
        if d.rule_id == service.REPEAT_SPEND
    ]

    if not fires:
        assert spends == []
        return
    (spend,) = spends
    assert spend.impact == {"cost_usd": "1.00000000", "requests": 1}
    assert spend.evidence["request_ids"] == [late_retry]
    assert (spend.evidence["billed_repeats"], spend.evidence["unbilled_repeats"]) == (
        1,
        1,
    )
    assert spend.evidence["classes"]["after_timeout"] == 1
    assert spend.evidence["classes"]["after_error"] == 1


@pytest.mark.asyncio
async def test_a_renamed_alias_keeps_its_traffic(db, test_api_key) -> None:
    alias = await _deployment(db, test_api_key, age=timedelta(days=60))
    deployment = await db.scalar(
        select(ModelDeployment).where(ModelDeployment.alias == alias)
    )
    request = _request(db, test_api_key, NOW - timedelta(days=1), model="old-alias")
    await db.flush()
    row = await db.scalar(
        select(RequestLifecycle).where(RequestLifecycle.request_id == request)
    )
    row.lifecycle_metadata = {
        **row.lifecycle_metadata,
        "deployment_id": str(deployment.id),
    }

    detections = await _evaluate(db, test_api_key)

    assert [d for d in detections if d.rule_id == service.UNUSED_DEPLOYMENT] == []


async def _kind(db, alias: str, **values) -> ModelDeployment:
    deployment = await db.scalar(
        select(ModelDeployment).where(ModelDeployment.alias == alias)
    )
    for field, value in values.items():
        setattr(deployment, field, value)
    await db.flush()
    return deployment


@pytest.mark.parametrize(("requests", "fires"), [(1, True), (299, True), (300, False)])
@pytest.mark.asyncio
async def test_an_internal_deployment_with_little_traffic_is_idle(
    db, test_api_key, requests: int, fires: bool
) -> None:
    alias = await _deployment(db, test_api_key, age=timedelta(days=40))
    deployment = await _kind(db, alias)
    for index in range(requests):
        _request(db, test_api_key, NOW - timedelta(hours=index % 48), model=alias)

    detections = await _evaluate(db, test_api_key)

    idle = [d for d in detections if d.rule_id == service.IDLE_INTERNAL_DEPLOYMENT]
    assert [d for d in detections if d.rule_id == service.UNUSED_DEPLOYMENT] == []
    if not fires:
        assert idle == []
        return
    (finding,) = idle
    assert finding.subject_key == str(deployment.id)
    assert finding.subject == {"deployment_id": str(deployment.id), "alias": alias}
    assert finding.evidence["requests"] == requests
    assert finding.evidence["active_days"] == (1 if requests == 1 else 3)
    assert finding.evidence["api_keys"] == 1
    assert finding.evidence["hardware_cost"] == "not recorded"
    assert len(finding.evidence["request_ids"]) == min(requests, 20)
    assert finding.impact == {"cost_usd": None, "requests": requests}
    assert service.RULES[finding.rule_id][1] == 2


@pytest.mark.asyncio
async def test_external_young_disabled_and_unused_deployments_are_never_idle(
    db, test_api_key
) -> None:
    external = await _deployment(db, test_api_key, age=timedelta(days=40))
    await _kind(db, external, deployment_kind="external")
    young = await _deployment(db, test_api_key, age=timedelta(days=20))
    disabled = await _deployment(
        db, test_api_key, age=timedelta(days=40), enabled=False
    )
    unused = await _deployment(db, test_api_key, age=timedelta(days=40))
    for alias in (external, young, disabled):
        _request(db, test_api_key, NOW - timedelta(days=1), model=alias)

    detections = await _evaluate(db, test_api_key)

    assert [
        d for d in detections if d.rule_id == service.IDLE_INTERNAL_DEPLOYMENT
    ] == []
    assert [
        d.subject["alias"] for d in detections if d.rule_id == service.UNUSED_DEPLOYMENT
    ] == [unused]


@pytest.mark.asyncio
async def test_another_tenants_traffic_never_counts_for_a_deployment(
    db, test_api_key
) -> None:
    alias = await _deployment(db, test_api_key, age=timedelta(days=40))
    deployment = await _kind(db, alias)
    other_key = await _other_tenant_key(db, test_api_key)
    request = _request(db, other_key, NOW - timedelta(days=1), model=alias)
    await db.flush()
    row = await db.scalar(
        select(RequestLifecycle).where(RequestLifecycle.request_id == request)
    )
    row.lifecycle_metadata = {
        **row.lifecycle_metadata,
        "deployment_id": str(deployment.id),
    }

    detections = await _evaluate(db, test_api_key)

    assert [d.rule_id for d in detections if d.subject.get("alias") == alias] == [
        service.UNUSED_DEPLOYMENT
    ]


def _catalog_request(db, key, model: str = "gpt-5-mini", *, byok: bool = False) -> str:
    version = EPHEMERAL_BYOK_SPEND_POLICY_VERSION if byok else "spend:provider:v1"
    return _request(
        db,
        key,
        NOW - timedelta(days=1),
        model=model,
        cost="0.10",
        metadata={
            "deployment_id": None,
            "deployment_kind": "unknown",
            "policy_verdicts": [
                {"rule_id": "spend.provider_monthly", "policy_version": version}
            ],
        },
    )


async def _secret(db, key, provider: str = "openai") -> None:
    db.add(
        ProviderSecret(
            id=uuid4(),
            organization_id=key.organization_id,
            provider=provider,
            secret_ref=f"reference-{uuid4().hex}",
            secret_backend="fernet",
            secret_version="v2",
            masked_key="masked",
        )
    )
    await db.flush()


@pytest.mark.parametrize(("requests", "fires"), [(5, True), (4, False)])
@pytest.mark.asyncio
async def test_catalog_traffic_beside_a_registry_is_an_unregistered_model(
    db, test_api_key, requests: int, fires: bool
) -> None:
    await _deployment(db, test_api_key, age=timedelta(days=1))
    ids = [
        _catalog_request(db, test_api_key, byok=index == 0) for index in range(requests)
    ]

    found = [
        d
        for d in await _evaluate(db, test_api_key)
        if d.rule_id == service.UNREGISTERED_MODEL
    ]

    if not fires:
        assert found == []
        return
    (finding,) = found
    assert finding.subject == {"provider": "openai", "model": "gpt-5-mini"}
    assert finding.subject_key == "openai:gpt-5-mini"
    assert finding.evidence["requests"] == 5
    assert finding.evidence["api_key_ids"] == [str(test_api_key.id)]
    assert finding.evidence["byok_requests"] == 1
    assert sorted(finding.evidence["request_ids"]) == sorted(ids)
    assert finding.impact == {"cost_usd": "0.50000000", "requests": 5}
    assert service.RULES[finding.rule_id][1] == 3


@pytest.mark.asyncio
async def test_a_tenant_without_a_registry_never_has_unregistered_models(
    db, test_api_key
) -> None:
    for _ in range(6):
        _catalog_request(db, test_api_key)

    detections = await _evaluate(db, test_api_key)

    assert [d for d in detections if d.rule_id == service.UNREGISTERED_MODEL] == []


@pytest.mark.asyncio
async def test_a_suppressed_unregistered_model_is_not_recreated(
    db, test_api_key
) -> None:
    await _deployment(db, test_api_key, age=timedelta(days=1))
    for _ in range(5):
        _catalog_request(db, test_api_key)
    await _evaluate(db, test_api_key)
    await db.execute(update(Finding).values(status_id=service.STATUS_IDS["suppressed"]))

    await _evaluate(db, test_api_key, NOW + timedelta(minutes=1))

    (finding,) = [
        f
        for f in await _findings(db, test_api_key)
        if f.rule_id == service.UNREGISTERED_MODEL
    ]
    assert (finding.status_id, finding.occurrences) == (3, 2)


@pytest.mark.parametrize(("requests", "fires"), [(5, True), (4, False)])
@pytest.mark.asyncio
async def test_a_key_sending_its_own_provider_key_past_a_stored_one_is_byok_usage(
    db, test_api_key, requests: int, fires: bool
) -> None:
    await _secret(db, test_api_key)
    other_key = ApiKey(
        id=uuid4(),
        organization_id=test_api_key.organization_id,
        user_id=test_api_key.user_id,
        key_hash=uuid4().hex,
        prefix="sk-shim-oth",
        tier=test_api_key.tier,
        is_active=True,
    )
    db.add(other_key)
    await db.flush()
    for _ in range(requests):
        _catalog_request(db, test_api_key, byok=True)
    for _ in range(3):
        _catalog_request(db, test_api_key)
        _catalog_request(db, other_key, byok=True)

    found = [
        d for d in await _evaluate(db, test_api_key) if d.rule_id == service.BYOK_USAGE
    ]

    if not fires:
        assert found == []
        return
    (finding,) = found
    assert finding.subject == {"api_key_id": str(test_api_key.id)}
    assert finding.evidence["requests"] == {"openai": 5}
    assert finding.evidence["models"] == ["gpt-5-mini"]
    assert finding.impact == {"cost_usd": "0.50000000", "requests": 5}
    assert "spend limit" in finding.evidence["note"]


@pytest.mark.asyncio
async def test_byok_without_a_stored_key_for_the_provider_is_its_only_mode(
    db, test_api_key
) -> None:
    await _secret(db, test_api_key, provider="anthropic")
    for _ in range(6):
        _catalog_request(db, test_api_key, byok=True)

    detections = await _evaluate(db, test_api_key)

    assert [d for d in detections if d.rule_id == service.BYOK_USAGE] == []


def _other_key(db, key) -> ApiKey:
    other = ApiKey(
        id=uuid4(),
        organization_id=key.organization_id,
        user_id=key.user_id,
        key_hash=uuid4().hex,
        prefix="sk-shim-rat",
        tier=key.tier,
        is_active=True,
    )
    db.add(other)
    return other


@pytest.mark.parametrize(
    ("rule", "settled", "bad", "fires"),
    [
        (service.TRUNCATION_RATE, 50, {"truncated": 3}, True),
        (service.TRUNCATION_RATE, 60, {"truncated": 3}, True),
        (service.TRUNCATION_RATE, 1000, {"truncated": 49}, False),
        (service.TRUNCATION_RATE, 49, {"truncated": 49}, False),
        (service.REFUSAL_RATE, 50, {"empty": 3}, True),
        (service.REFUSAL_RATE, 60, {"refused": 1, "filtered": 1, "empty": 1}, True),
        (service.REFUSAL_RATE, 1000, {"refused": 49}, False),
        (service.REFUSAL_RATE, 49, {"filtered": 49}, False),
    ],
)
@pytest.mark.asyncio
async def test_rate_findings_need_fifty_answers_and_five_percent_per_key(
    db, test_api_key, rule: str, settled: int, bad: dict[str, int], fires: bool
) -> None:
    started = NOW - timedelta(hours=1)
    outcomes = [name for name, count in bad.items() for _ in range(count)]
    outcomes += ["complete"] * (settled - len(outcomes))
    ids = [_request(db, test_api_key, started, outcome=o) for o in outcomes]
    other = _other_key(db, test_api_key)
    await db.flush()
    for _ in range(10):
        _request(db, test_api_key, started, status="rejected", outcome=None)
        _request(db, test_api_key, NOW - timedelta(hours=25), outcome="truncated")
        _request(db, other, started, outcome="truncated")
        _request(db, other, started, outcome="refused")

    found = [d for d in await _evaluate(db, test_api_key) if d.rule_id == rule]

    if not fires:
        assert found == []
        return
    (finding,) = found
    count = sum(bad.values())
    assert finding.subject == {"api_key_id": str(test_api_key.id)}
    assert finding.subject_key == f"api_key:{test_api_key.id}"
    assert finding.evidence["settled_requests"] == settled
    assert {name: finding.evidence.get(name, 0) for name in bad} == bad
    assert finding.evidence["rate"] == str(round(Decimal(count) / settled, 4))
    (model,) = finding.evidence["models"]
    assert (model["model"], model["settled"]) == ("gpt-5-mini", settled)
    assert {name: model[name] for name in bad} == bad
    assert sorted(finding.evidence["request_ids"]) == sorted(
        request_id for request_id, o in zip(ids, outcomes) if o != "complete"
    )
    assert finding.impact == {"cost_usd": None, "requests": count}
    assert service.RULES[rule][1] == 2


@pytest.mark.asyncio
async def test_rate_findings_break_down_up_to_five_models(db, test_api_key) -> None:
    started = NOW - timedelta(hours=1)
    for outcome in ["complete"] * 30 + ["truncated"] * 4:
        _request(db, test_api_key, started, outcome=outcome, model="model-0")
    for index in range(1, 6):
        for _ in range(4):
            _request(db, test_api_key, started, model=f"model-{index}")

    detections = await _evaluate(db, test_api_key)

    (finding,) = [d for d in detections if d.rule_id == service.TRUNCATION_RATE]
    assert finding.evidence["models"] == [
        {"model": "model-0", "settled": 34, "truncated": 4},
        *(
            {"model": f"model-{index}", "settled": 4, "truncated": 0}
            for index in range(1, 5)
        ),
    ]
    assert "completion_outcome=truncated" in service.RULES[finding.rule_id][2]
    assert [d for d in detections if d.rule_id == service.REFUSAL_RATE] == []
    assert [d for d in detections if d.rule_id == service.ANSWER_QUALITY] == []
