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
from shim.findings import Finding as FindingV1
from shim_enterprise.api.v1.router import management_router
from shim_enterprise.billing.models import RequestLifecycle, UsageLedger
from shim_enterprise.core.database import get_db
from shim_enterprise.findings import service
from shim_enterprise.findings.models import Finding
from shim_enterprise.tenants.models import ModelDeployment, Organization, ProviderSecret

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
    assert service.RULES[storm.rule_id].SEVERITY_ID == 3
    assert storm.evidence == {
        "window_start": BUCKET.isoformat(),
        "window_minutes": 15,
        "repeated_requests": 20,
        "threshold": 20,
        "abandoned_requests": 2,
        "request_ids": ids,
    }
    assert storm.impact == {"cost_usd": "0.20000000", "requests": 20}


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
    assert service.RULES[service.UNUSED_DEPLOYMENT].SEVERITY_ID == 2
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
    assert record["unmapped"]["schema_version"] == "1"
    assert record["unmapped"]["measurements"]["repeated_requests"] == 20
    assert record["unmapped"]["remediation"]["max_mode"] == "suggest"
    assert record["unmapped"]["summary_tr"].startswith("Bir API anahtarı")
    assert all(
        FindingV1.model_validate(item) for item in listed["items"] + [detail.json()]
    )
    assert auditor_patch.status_code == 403
    assert (detail.json()["status"], detail.json()["status_detail"]) == ("open", "new")
    assert foreign.status_code == 404
    assert resolved.status_code == 200
    assert (resolved.json()["status"], resolved.json()["status_detail"]) == (
        "resolved",
        "resolved",
    )
    assert FindingV1.model_validate(resolved.json()).id == str(storm.id)
    await db.refresh(storm)
    assert storm.resolved_by == str(user.id)
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
        record = service.ocsf_detection_finding(_row(**values))
        return record["activity_id"], record["type_uid"]

    assert activity(status_id=1, occurrences=1) == (1, 200401)
    assert activity(status_id=1, occurrences=2) == (2, 200402)
    assert activity(status_id=3, occurrences=1) == (2, 200402)
    assert activity(status_id=4, occurrences=1) == (3, 200403)


_SUBJECTS = {
    service.RETRY_STORM: {"api_key_id": "11111111-1111-1111-1111-111111111111"},
    service.REPEAT_SPEND: {"api_key_id": "11111111-1111-1111-1111-111111111111"},
    service.UNUSED_DEPLOYMENT: {
        "deployment_id": "22222222-2222-2222-2222-222222222222",
        "alias": "kurum-llama",
    },
    service.ANSWER_QUALITY: {"model": "gpt-5-mini"},
}
_EVIDENCE = {
    service.RETRY_STORM: {
        "window_start": BUCKET.isoformat(),
        "window_minutes": 15,
        "repeated_requests": 20,
        "threshold": 20,
        "abandoned_requests": 2,
        "request_ids": ["req_a", "req_b"],
    },
    service.REPEAT_SPEND: {
        "period_start": BUCKET.isoformat(),
        "repeated_cost_usd": "1.25000000",
        "known_spend_usd": "9.00000000",
        "share": "0.1389",
        "repeated_requests": 30,
        "request_ids": ["req_c"],
    },
    service.UNUSED_DEPLOYMENT: {
        "created_at": BUCKET.isoformat(),
        "window_days": 30,
        "requests": 0,
    },
    service.ANSWER_QUALITY: {
        "window_hours": 24,
        "settled_requests": 60,
        "truncated": 4,
        "empty": 1,
        "refused": 2,
        "truncated_rate": "0.0667",
        "empty_or_refused_rate": "0.0500",
        "threshold_rate": "0.05",
        "request_ids": [],
    },
}


def _row(rule_id: str = service.ANSWER_QUALITY, **values) -> SimpleNamespace:
    spec = service.RULES[rule_id]
    return SimpleNamespace(
        **{
            "id": uuid4(),
            "source": "gateway",
            "rule_id": rule_id,
            "rule_version": 1,
            "subject": _SUBJECTS[rule_id],
            "title": spec.TITLE,
            "summary": "stored",
            "severity_id": spec.SEVERITY_ID,
            "status_id": 1,
            "first_seen_at": NOW,
            "last_seen_at": NOW + timedelta(minutes=5),
            "occurrences": 1,
            "evidence": _EVIDENCE[rule_id],
            "impact": None,
            "remediation": {"text": "stored", "reversible": True, "doc": spec.PLAYBOOK},
            "resolved_at": None,
            **values,
        }
    )


@pytest.mark.parametrize(
    ("status_id", "status", "detail"),
    [
        (1, "open", "new"),
        (2, "open", "in_progress"),
        (3, "dismissed", "suppressed"),
        (4, "resolved", "resolved"),
    ],
)
def test_a_row_status_maps_to_status_and_detail(status_id, status, detail) -> None:
    finding = service.finding_from_row(_row(status_id=status_id))

    assert (finding.status, finding.status_detail) == (status, detail)


@pytest.mark.parametrize(
    ("severity_id", "severity"),
    list(enumerate(("informational", "low", "medium", "high", "critical"), start=1)),
)
def test_a_row_severity_maps_to_its_name(severity_id, severity) -> None:
    assert service.finding_from_row(_row(severity_id=severity_id)).severity == severity


@pytest.mark.parametrize(
    ("rule_id", "kind", "subject_id"),
    [
        (service.RETRY_STORM, "key", "11111111-1111-1111-1111-111111111111"),
        (
            service.UNUSED_DEPLOYMENT,
            "deployment",
            "22222222-2222-2222-2222-222222222222",
        ),
        (service.ANSWER_QUALITY, "model", "gpt-5-mini"),
    ],
)
def test_a_row_subject_maps_to_kind_and_id(rule_id, kind, subject_id) -> None:
    subject = service.finding_from_row(_row(rule_id)).subject

    assert (subject.kind, subject.id) == (kind, subject_id)


def test_every_rule_gives_a_finding_that_round_trips_through_v1() -> None:
    for rule_id, spec in service.RULES.items():
        finding = service.finding_from_row(
            _row(rule_id, impact={"cost_usd": "2E-7", "requests": 3})
        )
        dumped = finding.model_dump(mode="json")

        assert FindingV1.model_validate(dumped) == finding
        assert dumped["schema_version"] == "1"
        assert finding.title == spec.TITLE
        assert finding.playbook == spec.PLAYBOOK
        assert (finding.impact.usd, finding.impact.requests) == ("0.0000002", 3)
        assert finding.impact.risk_class == spec.RISK_CLASS
        assert finding.remediation.mode == "observe"
        assert (finding.remediation.max_mode, finding.remediation.blast_radius) == (
            spec.MAX_MODE,
            spec.BLAST_RADIUS,
        )
        assert finding.remediation.text.model_dump() == dict(spec.REMEDIATION_TEXT)
        assert finding.window.start == NOW and finding.window.end > NOW
        assert all(
            isinstance(value, (int, float)) for value in finding.measurements.values()
        )
        assert "request_ids" not in finding.measurements
        assert [ref.id for ref in finding.evidence] == list(
            _EVIDENCE[rule_id].get("request_ids", [])
        )
    storm = service.finding_from_row(_row(service.RETRY_STORM))
    assert "window_start" not in storm.measurements
    assert storm.summary.en == (
        "One API key sent 20 repeated requests within 15 minutes; the threshold is 20."
    )
    spend = service.finding_from_row(_row(service.REPEAT_SPEND))
    assert spend.measurements["share"] == 0.1389
    assert "1.25 USD" in spend.summary.en and "1.25 USD" in spend.summary.tr


def test_measurements_keep_finite_numbers_only() -> None:
    assert service.measurements(
        {
            "count": 3,
            "rate": "0.25",
            "flag": True,
            "when": "2026-10-08T12:00:00+00:00",
            "nan": "NaN",
            "inf": float("inf"),
            "request_ids": ["req_a"],
        }
    ) == {"count": 3, "rate": 0.25}


def test_templates_use_measurement_names_and_carry_no_other_number() -> None:
    import re
    from string import Formatter

    for rule_id, spec in service.RULES.items():
        names = set(service.measurements(_EVIDENCE[rule_id]))
        for language in ("en", "tr"):
            fields = {
                field
                for _, field, _, _ in Formatter().parse(spec.SUMMARY[language])
                if field
            }
            assert fields <= names, (rule_id, language, fields - names)
            values = {name: 1000 + index for index, name in enumerate(sorted(names))}
            rendered = service.render(spec.SUMMARY[language], values)
            numbers = set(re.findall(r"\d+(?:\.\d+)?", rendered))
            allowed = {str(v) for v in values.values()} | {
                f"{v:.2f}" for v in values.values()
            }
            assert numbers <= allowed, (rule_id, language, numbers - allowed)
            assert not re.search(r"\d", spec.REMEDIATION_TEXT[language])
    with pytest.raises(KeyError):
        service.render("{not_measured} requests", {"count": 1})


def test_every_rule_has_its_playbook_section() -> None:
    from pathlib import Path
    import re

    document = (Path(__file__).parents[3] / "ee" / "docs" / "FINDINGS.md").read_text()
    headings = re.findall(r"^## (\S+)$", document, flags=re.MULTILINE)
    for rule_id, spec in service.RULES.items():
        assert rule_id in headings
        slug = re.sub(r"[^a-z0-9 _-]", "", rule_id.lower()).replace(" ", "-")
        assert spec.PLAYBOOK == f"ee/docs/FINDINGS.md#{slug}"


@pytest.mark.asyncio
async def test_the_four_rules_on_seeded_rows_give_valid_findings(
    db, test_api_key
) -> None:
    await _storm(db, test_api_key)
    _request(db, test_api_key, NOW - timedelta(minutes=30), repeat=2, cost="1.00")
    _request(db, test_api_key, NOW - timedelta(minutes=31), cost="9.00")
    await _deployment(db, test_api_key, age=timedelta(days=40))
    for index in range(50):
        _request(
            db,
            test_api_key,
            NOW - timedelta(hours=2, seconds=index),
            outcome="truncated" if index < 3 else "complete",
            model="gpt-5-nano",
        )

    await _evaluate(db, test_api_key)
    rows = await _findings(db, test_api_key)

    assert {row.rule_id for row in rows} == set(service.RULES)
    for row in rows:
        finding = service.finding_from_row(row)
        assert FindingV1.model_validate(finding.model_dump(mode="json")) == finding
        assert row.summary == finding.summary.en
