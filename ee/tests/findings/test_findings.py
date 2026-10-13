from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
import logging
from types import SimpleNamespace
from pathlib import Path
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import event, insert, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import shim_enterprise.api.enterprise_deps as enterprise_deps
from shim.findings import Finding as FindingV1
from shim.jsonschema_subset import check
from shim_enterprise.api.v1.router import management_router
from shim_enterprise.billing.models import RequestLifecycle, UsageLedger
from shim_enterprise.core.config import settings
from shim_enterprise.core.database import get_db
from shim_enterprise.findings import service
from shim_enterprise.findings.models import Finding
from shim_enterprise.gateway.pipeline.quota_reservation import (
    EPHEMERAL_BYOK_SPEND_POLICY_VERSION,
)
from shim_enterprise.observability.model_inventory import UNSPECIFIED_MODEL
from shim_enterprise.policy import allowlist
from shim_enterprise.policy.models import PolicyRemediation
from shim_enterprise.tenants.gateway_settings import GatewaySettings, classify_change
from shim_enterprise.tenants.models import (
    ApiKey,
    ModelDeployment,
    Organization,
    OrganizationGatewaySettings,
    ProviderSecret,
    User,
)
from shim.gateway.kernel.result import UNSPECIFIED_PROVIDER_MODEL

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
    assert service.RULES[storm.rule_id].SEVERITY_ID == 3
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
    assert (
        service.remediation_text(storm.rule_id, storm.evidence)
        == service.RULES[service.RETRY_STORM].REMEDIATION_TEXT
    )


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
        if statement.lstrip().upper().startswith(("SELECT", "WITH")):
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
async def test_deployment_rules_read_the_requests_once_for_every_alias(
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
            await service._deployments(db, test_api_key.organization_id, NOW)
        )

    plans = await _plans(db, run)

    unused = [d for d in detections if d.rule_id == service.UNUSED_DEPLOYMENT]
    assert sorted(d.subject["alias"] for d in unused) == sorted(aliases[2:])
    assert len(plans) == 2
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
    assert record["unmapped"]["remediation"]["max_mode"] == "observe"
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
    service.UNREGISTERED_MODEL: {"provider": "openai", "model": "gpt-5-mini"},
    service.BYOK_USAGE: {"api_key_id": "11111111-1111-1111-1111-111111111111"},
    service.TRUNCATION_RATE: {"api_key_id": "11111111-1111-1111-1111-111111111111"},
    service.REFUSAL_RATE: {"api_key_id": "11111111-1111-1111-1111-111111111111"},
    service.LANGUAGE_DRIFT: {"api_key_id": "11111111-1111-1111-1111-111111111111"},
    service.SCHEMA_ERRORS: {"api_key_id": "11111111-1111-1111-1111-111111111111"},
    service.SOFT_REFUSALS: {"api_key_id": "11111111-1111-1111-1111-111111111111"},
    service.OVERSIZED_PARTS: {"api_key_id": "11111111-1111-1111-1111-111111111111"},
    service.DEAD_TOOLS: {"api_key_id": "11111111-1111-1111-1111-111111111111"},
    service.CACHE_ORDER_CHURN: {"api_key_id": "11111111-1111-1111-1111-111111111111"},
    service.COLD_START: {"deployment_id": "22222222-2222-2222-2222-222222222222"},
    service.QUEUEING: {"deployment_id": "22222222-2222-2222-2222-222222222222"},
    service.IDLE_INTERNAL_DEPLOYMENT: {
        "deployment_id": "22222222-2222-2222-2222-222222222222",
        "alias": "kurum-llama",
    },
    service.LITELLM_RETRY_BURST: {"litellm_key": "litellm:ce77089fa9483163"},
}
_EVIDENCE = {
    service.LITELLM_UNREGISTERED_MODEL: {
        "requests": 12,
        "window_days": 7,
        "threshold": 10,
        "import_id": "4b8871a5-a837-49cc-aab8-f33294a6693b",
        "request_ids": ["chatcmpl-1", "fixture-0002"],
    },
    service.LITELLM_ERROR_RATE: {
        "requests": 60,
        "failed_requests": 6,
        "failure_share": "0.1000",
        "threshold": "0.05",
        "window_hours": 24,
        "import_id": "4b8871a5-a837-49cc-aab8-f33294a6693b",
        "request_ids": ["fixture-0007"],
    },
    service.LITELLM_SLOW_FIRST_TOKEN: {
        "requests": 50,
        "ttft_ms_p95": 12000,
        "threshold_ms": 10000,
        "window_hours": 24,
        "import_id": "4b8871a5-a837-49cc-aab8-f33294a6693b",
        "request_ids": ["fixture-0008"],
    },
    service.LITELLM_RETRY_BURST: {
        "window_start": BUCKET.isoformat(),
        "window_minutes": 15,
        "repeated_requests": 24,
        "threshold": 20,
        "prompt_tokens": 812,
        "import_id": "4b8871a5-a837-49cc-aab8-f33294a6693b",
        "request_ids": ["fixture-0070"],
    },
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
    service.UNREGISTERED_MODEL: {
        "window_days": 7,
        "requests": 6,
        "threshold": 5,
        "api_keys": 1,
        "api_key_ids": ["11111111-1111-1111-1111-111111111111"],
        "teams": 0,
        "first_seen": BUCKET.isoformat(),
        "last_seen": BUCKET.isoformat(),
        "request_ids": ["req_d"],
        "byok_requests": 0,
    },
    service.BYOK_USAGE: {
        "window_days": 7,
        "requests": {"openai": 6},
        "threshold": 5,
        "models": ["gpt-5-mini"],
        "request_ids": ["req_e"],
        "cost_usd": "0.40000000",
        "note": "These requests skipped the provider spend limit and the "
        "tenant's stored provider key.",
    },
    service.TRUNCATION_RATE: {
        "window_hours": 24,
        "settled_requests": 60,
        "truncated": 4,
        "rate": "0.0667",
        "threshold_rate": "0.05",
        "models": [{"model": "gpt-5-mini", "settled": 60, "truncated": 4}],
        "request_ids": [],
    },
    service.REFUSAL_RATE: {
        "window_hours": 24,
        "settled_requests": 60,
        "refused": 2,
        "filtered": 1,
        "empty": 1,
        "rate": "0.0667",
        "threshold_rate": "0.05",
        "models": [
            {
                "model": "gpt-5-mini",
                "settled": 60,
                "refused": 2,
                "filtered": 1,
                "empty": 1,
            }
        ],
        "request_ids": [],
    },
    service.IDLE_INTERNAL_DEPLOYMENT: {
        "window_days": 30,
        "requests": 12,
        "threshold": 300,
        "active_days": 3,
        "last_request_at": BUCKET.isoformat(),
        "api_keys": 1,
        "request_ids": ["req_f"],
        "hardware_cost": "not recorded",
    },
    service.LANGUAGE_DRIFT: {
        "window_hours": 24,
        "analysed_requests": 20,
        "drifts": 4,
        "rate": "0.2",
        "threshold_rate": "0.10",
        "models": [{"model": "gpt-5-mini", "analysed": 20, "drifts": 4}],
        "prompt_versions": ["hmac-sha256:v1:" + "a" * 64],
        "request_ids": ["req_g"],
    },
    service.SCHEMA_ERRORS: {
        "window_hours": 24,
        "checked_requests": 20,
        "invalid": 2,
        "rate": "0.1",
        "threshold_rate": "0.05",
        "checked_json_schema": 20,
        "invalid_json_schema": 2,
        "models": [{"model": "gpt-5-mini", "checked": 20, "invalid": 2}],
        "request_ids": ["req_h"],
    },
    service.SOFT_REFUSALS: {
        "window_hours": 24,
        "analysed_requests": 50,
        "soft_refusals": 3,
        "rate": "0.06",
        "threshold_rate": "0.05",
        "marker_tr_yardimci_olamam": 3,
        "models": [{"model": "gpt-5-mini", "analysed": 50, "soft_refusals": 3}],
        "request_ids": ["req_i"],
    },
    service.OVERSIZED_PARTS: {
        "window_hours": 24,
        "analysed_requests": 20,
        "crossed_kinds": 1,
        "tool_definitions_median": 45000,
        "tool_definitions_p95": 46000,
        "tokens_estimated": True,
        "request_ids": ["req_j"],
    },
    service.DEAD_TOOLS: {
        "window_days": 30,
        "offering_requests": 50,
        "dead_tools": 2,
        "called_tools": 1,
        "tools": [{"name": "create", "offered": 50}, {"name": "delete", "offered": 50}],
    },
    service.CACHE_ORDER_CHURN: {
        "window_hours": 24,
        "tool_sets": 1,
        "churned_requests": 20,
        "orders": 2,
        "cache_read_share": "0.0000",
        "sets": [
            {
                "requests": 20,
                "orders": 2,
                "requests_per_order": [10, 10],
                "cache_read_share": "0.0000",
                "providers": ["anthropic"],
            }
        ],
        "request_ids": ["req_k"],
    },
    service.COLD_START: {
        "window_hours": 24,
        "cold_starts": 3,
        "timeouts": 1,
        "median_gap_seconds": 7200,
        "cold_first_byte_ms": 15000,
        "warm_first_byte_ms": 300,
        "request_ids": ["req_l"],
    },
    service.QUEUEING: {
        "window_hours": 24,
        "congested_hours": 2,
        "baseline_ttft_ms": 200,
        "worst_ttft_p95_ms": 1000,
        "peak_concurrency": 5,
        "hours": [
            {
                "hour": "2026-10-08T10:00:00+00:00",
                "ttft_p95_ms": 1000,
                "streams": 10,
                "peak_concurrency": 5,
            }
        ],
        "request_ids": ["req_m"],
    },
}


def _row(rule_id: str = service.ANSWER_QUALITY, **values) -> SimpleNamespace:
    spec = service.RULES.get(rule_id) or service.RULES[service.ANSWER_QUALITY]
    return SimpleNamespace(
        **{
            "id": uuid4(),
            "source": "gateway",
            "rule_id": rule_id,
            "rule_version": 1,
            "subject": _SUBJECTS.get(rule_id, {"model": "gpt-5-mini"}),
            "title": spec.TITLE,
            "summary": "stored",
            "severity_id": spec.SEVERITY_ID,
            "status_id": 1,
            "first_seen_at": NOW,
            "last_seen_at": NOW + timedelta(minutes=5),
            "occurrences": 1,
            "evidence": _EVIDENCE.get(rule_id, {}),
            "impact": None,
            "remediation": {"text": "stored", "reversible": True, "doc": spec.PLAYBOOK},
            "resolved_at": None,
            "resolved_by": None,
            "organization_id": UUID(int=9),
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


def test_repeat_classes_and_pairs_reach_the_api_under_bounded_names() -> None:
    pairs = [
        {
            "repeat": f"req_r{index}",
            "previous": f"req_p{index}",
            "class": "after_success",
            "gap_seconds": 1,
        }
        for index in range(20)
    ]
    for rule_id in (service.RETRY_STORM, service.REPEAT_SPEND):
        evidence = {
            **_EVIDENCE[rule_id],
            "request_ids": [f"req_r{index}" for index in range(20)],
            "classes": {
                "after_timeout": 1,
                "after_error": 0,
                "after_success": 29,
                "pending": 0,
                "Free text": 7,
            },
            "pairs": pairs,
        }

        finding = service.finding_from_row(_row(rule_id, evidence=evidence))

        assert {
            name: value
            for name, value in finding.measurements.items()
            if name.startswith(("repeats_", "pairs"))
        } == {
            "repeats_after_timeout": 1,
            "repeats_after_error": 0,
            "repeats_after_success": 29,
            "repeats_pending": 0,
            "pairs": 10,
            "pairs_omitted": 20,
        }
        ids = [ref.id for ref in finding.evidence]
        assert ids[:4] == ["req_r0", "req_p0", "req_r1", "req_p1"]
        assert ids[20:] == [f"req_r{index}" for index in range(10, 20)]
        assert {ref.kind for ref in finding.evidence} == {"request"}
        assert _published(finding)


def test_byok_requests_per_provider_reach_the_api_without_model_names() -> None:
    evidence = {
        **_EVIDENCE[service.BYOK_USAGE],
        "requests": {"openai": 6, "anthropic": 2, "Mistral Large": 1, "x": 3},
    }

    finding = service.finding_from_row(_row(service.BYOK_USAGE, evidence=evidence))

    assert {
        name: value
        for name, value in finding.measurements.items()
        if name.startswith("requests_")
    } == {"requests_openai": 6, "requests_anthropic": 2, "requests_other": 4}
    assert "gpt-5-mini" not in finding.model_dump_json()
    assert _published(finding)


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

    assert {row.rule_id for row in rows} == {
        service.RETRY_STORM,
        service.REPEAT_SPEND,
        service.UNUSED_DEPLOYMENT,
        service.ANSWER_QUALITY,
    }
    for row in rows:
        finding = service.finding_from_row(row)
        assert FindingV1.model_validate(finding.model_dump(mode="json")) == finding
        assert row.summary == finding.summary.en


_SCHEMA = json.loads(
    (Path(__file__).parents[3] / "docs" / "schemas" / "finding-v1.json").read_text()
)


def _published(finding: FindingV1) -> bool:
    """Valid against the published file, as far as the repository's validator reads it."""

    result = check(finding.model_dump(mode="json"), _SCHEMA)
    return result.valid is None and result.unsupported == (
        "pattern",
        "patternProperties",
    )


def test_every_rules_finding_validates_against_the_published_schema() -> None:
    for rule_id in service.RULES:
        assert _published(service.finding_from_row(_row(rule_id)))
    resolved = service.finding_from_row(
        _row(status_id=4, resolved_at=NOW, resolved_by="system")
    )
    assert (resolved.resolved_at, resolved.resolved_by) == (NOW, "system")
    assert _published(resolved)


@pytest.mark.parametrize(
    "row",
    [
        _row("gateway.retired_rule"),
        _row(service.RETRY_STORM, evidence={"request_ids": ["req_a"]}),
        _row(
            service.RETRY_STORM,
            evidence={**_EVIDENCE[service.RETRY_STORM], "Not A Name": 1},
        ),
        _row(subject={"team_id": "t-1"}),
    ],
    ids=["unknown-rule", "missing-measurement", "bad-measurement", "new-subject"],
)
def test_a_row_this_build_cannot_render_keeps_its_stored_text(row, caplog) -> None:
    caplog.set_level(logging.WARNING, logger=service.__name__)

    finding = service.finding_from_row(row)

    assert (finding.title, finding.summary.en, finding.summary.tr) == (
        row.title,
        "stored",
        "stored",
    )
    assert (finding.subject.kind, finding.subject.id) == ("tenant", str(UUID(int=9)))
    assert finding.measurements == {} and finding.evidence == []
    assert finding.remediation.text.en == "stored"
    assert _published(finding)
    assert f"id={row.id}" in caplog.text and "stored" not in caplog.text
    assert service.ocsf_detection_finding(row)["unmapped"]["rule_id"] == row.rule_id


def test_the_ocsf_export_keeps_rule_subject_and_occurrences() -> None:
    row = _row(service.UNUSED_DEPLOYMENT, occurrences=3, rule_version=1)

    unmapped = service.ocsf_detection_finding(row)["unmapped"]

    assert {
        key: unmapped[key]
        for key in ("rule_id", "rule_version", "subject", "occurrences")
    } == {
        "rule_id": service.UNUSED_DEPLOYMENT,
        "rule_version": 1,
        "subject": {
            "kind": "deployment",
            "id": "22222222-2222-2222-2222-222222222222",
        },
        "occurrences": 3,
    }


@pytest.mark.asyncio
async def test_one_status_vocabulary_for_the_filter_the_patch_and_the_answer(
    db, test_api_key, test_user_with_org
) -> None:
    user = test_user_with_org
    await _storm(db, test_api_key)
    await _deployment(db, test_api_key, age=timedelta(days=40))
    await _evaluate(db, test_api_key)
    storm, unused = await _findings(db, test_api_key)
    unused.status_id = 2
    db.add(
        Finding(
            **{
                **_copy(storm),
                "id": uuid4(),
                "rule_id": "gateway.retired_rule",
                "subject_key": "retired",
            }
        )
    )
    await db.flush()
    url = "/api/v1/management/findings"
    user.role = "admin"

    async with _client(db, user) as client:
        listed = await client.get(url, params={"status": "open"})
        exported = await client.get(f"{url}/export", params={"status": "open"})
        legacy = (await client.get(url, params={"status": "in_progress"})).json()
        dismissed = await client.patch(
            f"{url}/{storm.id}", json={"status": "dismissed"}
        )
        by_v1 = (await client.get(url, params={"status": "dismissed"})).json()
        kept = await client.patch(f"{url}/{unused.id}", json={"status": "open"})
        reopened = await client.patch(f"{url}/{storm.id}", json={"status": "open"})

    assert listed.status_code == exported.status_code == 200
    assert listed.json()["total"] == 3
    assert {item["status"] for item in listed.json()["items"]} == {"open"}
    assert len(exported.text.splitlines()) == 3
    assert [item["id"] for item in legacy["items"]] == [str(unused.id)]
    assert (dismissed.json()["status"], dismissed.json()["status_detail"]) == (
        "dismissed",
        "suppressed",
    )
    assert [item["id"] for item in by_v1["items"]] == [str(storm.id)]
    assert kept.json()["status_detail"] == "in_progress"
    assert reopened.json()["status_detail"] == "new"


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
    served = service.finding_from_row(finding)
    assert served.measurements["repeats_after_error"] == 20
    assert (served.measurements["pairs"], served.measurements["pairs_omitted"]) == (
        10,
        10,
    )
    assert [ref.id for ref in served.evidence[:2]] == [
        str(retried[0]),
        str(previous[0]),
    ]
    assert _published(served)
    assert finding.rule_version == 2
    assert finding.remediation["text"] == service.STORM_FIXES["after_error"]["en"]
    assert (
        service.finding_from_row(finding).remediation.text.tr
        == service.STORM_FIXES["after_error"]["tr"]
    )


@pytest.mark.asyncio
async def test_a_version_one_finding_is_updated_in_place(db, test_api_key) -> None:
    await _storm(db, test_api_key)
    await _evaluate(db, test_api_key)
    await db.execute(update(Finding).values(rule_version=1))

    await _evaluate(db, test_api_key, NOW + timedelta(minutes=1))

    (finding,) = await _findings(db, test_api_key)
    assert (finding.rule_version, finding.occurrences) == (2, 2)
    assert (
        finding.remediation["text"]
        == service.RULES[service.RETRY_STORM].REMEDIATION_TEXT["en"]
    )


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
async def test_a_retry_with_personal_data_after_a_refund_is_not_waste(
    db, test_api_key
) -> None:
    start = datetime(2026, 10, 1, 1, tzinfo=timezone.utc)
    # Personal data clears the digest to JSON null; only the chain is left.
    pii = {"repeat_digest": None}
    other = _other_key(db, test_api_key)
    await db.flush()
    _request(db, test_api_key, start, status="provider_error", metadata=pii)
    _request(db, other, start + timedelta(seconds=1), cost="1", metadata=pii)
    _request(
        db, test_api_key, start + timedelta(seconds=5), repeat=2, cost="5", metadata=pii
    )
    _request(db, test_api_key, start + timedelta(hours=1), cost="1", metadata=pii)
    again = _request(
        db,
        test_api_key,
        start + timedelta(hours=1, seconds=5),
        repeat=2,
        cost="2",
        metadata=pii,
    )

    (spend,) = [
        d
        for d in await _evaluate(db, test_api_key)
        if d.rule_id == service.REPEAT_SPEND
    ]
    stored = await db.scalar(
        select(RequestLifecycle.lifecycle_metadata).where(
            RequestLifecycle.request_id == again
        )
    )

    assert "repeat_digest" in stored and stored["repeat_digest"] is None
    assert spend.impact == {"cost_usd": "2.00000000", "requests": 1}
    assert spend.evidence["request_ids"] == [again]


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
    assert service.RULES[finding.rule_id].SEVERITY_ID == 2


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
    assert service.RULES[finding.rule_id].SEVERITY_ID == 3


@pytest.mark.asyncio
async def test_an_oversized_or_unspecified_model_keys_a_bounded_finding(
    db, test_api_key
) -> None:
    await _deployment(db, test_api_key, age=timedelta(days=1))
    for _ in range(5):
        _catalog_request(db, test_api_key, "gpt-5-mini-" + "x" * 13_000)
        _catalog_request(db, test_api_key, UNSPECIFIED_PROVIDER_MODEL)

    found = {
        d.subject_key: d.subject
        for d in await _evaluate(db, test_api_key)
        if d.rule_id == service.UNREGISTERED_MODEL
    }

    assert found == {
        "openai:gpt-5-mini": {"provider": "openai", "model": "gpt-5-mini"},
        f"openai:{UNSPECIFIED_MODEL}": {
            "provider": "openai",
            "model": UNSPECIFIED_MODEL,
        },
    }
    assert len(await _findings(db, test_api_key)) == 2


@pytest.mark.asyncio
async def test_one_failing_rule_leaves_the_others_and_its_findings(
    db, test_api_key, monkeypatch: pytest.MonkeyPatch, caplog
) -> None:
    await _storm(db, test_api_key)
    await _deployment(db, test_api_key, age=timedelta(days=60))
    await _evaluate(db, test_api_key)

    async def broken(session, tenant_id, now):
        await session.execute(text("SELECT 1 / 0"))

    monkeypatch.setattr(service, "_retry_storms", broken)
    later = NOW + timedelta(days=8)
    with caplog.at_level(logging.ERROR, logger=service.__name__):
        detections = await _evaluate(db, test_api_key, later)

    by_rule = {f.rule_id: f for f in await _findings(db, test_api_key)}
    assert service.UNUSED_DEPLOYMENT in {d.rule_id for d in detections}
    assert by_rule[service.UNUSED_DEPLOYMENT].last_seen_at == later
    # A rule that could not run says nothing about its open findings.
    assert by_rule[service.RETRY_STORM].status_id != service.STATUS_RESOLVED
    assert "Findings rule failed" in caplog.text


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
    (row,) = [
        row
        for row in await _findings(db, test_api_key)
        if row.rule_id == service.BYOK_USAGE
    ]
    assert service.finding_from_row(row).measurements["requests_openai"] == 5


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
    assert service.RULES[rule].SEVERITY_ID == 2


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
    assert (
        "completion_outcome=truncated"
        in service.RULES[finding.rule_id].REMEDIATION_TEXT["en"]
    )
    assert [d for d in detections if d.rule_id == service.REFUSAL_RATE] == []
    assert [d for d in detections if d.rule_id == service.ANSWER_QUALITY] == []


# --- E42: finding modes ---------------------------------------------------------


async def _set_modes(db, organization_id: UUID, modes: dict) -> None:
    row = await db.get(OrganizationGatewaySettings, organization_id)
    if row is None:
        row = OrganizationGatewaySettings(organization_id=organization_id, settings={})
        db.add(row)
    row.settings = {"finding_modes": modes}
    await db.flush()


def _admin(organization_id: UUID, role: str = "owner") -> User:
    return User(
        id=uuid4(),
        organization_id=organization_id,
        email=f"modes-{uuid4().hex}@example.com",
        role=role,
        is_active=True,
        is_verified=True,
    )


async def _deployment_id(db, key, **values) -> str:
    alias = await _deployment(db, key, **values)
    return str(
        await db.scalar(
            select(ModelDeployment.id).where(
                ModelDeployment.organization_id == key.organization_id,
                ModelDeployment.alias == alias,
            )
        )
    )


async def _owner(db, organization_id: UUID, role: str = "owner") -> User:
    user = _admin(organization_id, role)
    db.add(user)
    await db.flush()
    return user


def test_the_ladder_puts_auto_only_on_unused_deployments() -> None:
    by_mode = {
        mode: {rule for rule, spec in service.RULES.items() if spec.MAX_MODE == mode}
        for mode in service.MODES
    }
    assert by_mode["auto"] == {service.UNUSED_DEPLOYMENT}
    assert by_mode["suggest"] == {service.IDLE_INTERNAL_DEPLOYMENT}
    assert {
        rule: spec.ACTION_KIND
        for rule, spec in service.RULES.items()
        if spec.ACTION_KIND
    } == {
        service.UNUSED_DEPLOYMENT: "deployment.disable",
        service.IDLE_INTERNAL_DEPLOYMENT: "deployment.disable",
    }


@pytest.mark.parametrize(
    ("modes", "error"),
    [
        ({"gateway.nope": "suggest"}, "unknown finding rule: gateway.nope"),
        (
            {service.RETRY_STORM: "suggest"},
            "gateway.retry_storm goes at most to observe",
        ),
        (
            {service.IDLE_INTERNAL_DEPLOYMENT: "auto"},
            "gateway.idle_internal_deployment goes at most to suggest",
        ),
        ({service.UNUSED_DEPLOYMENT: "always"}, "Input should be"),
    ],
)
@pytest.mark.asyncio
async def test_finding_modes_are_checked_against_the_ladder(
    db, test_org, modes, error
) -> None:
    async with _client(db, await _owner(db, test_org.id)) as client:
        refused = await client.patch(
            "/api/v1/management/gateway-settings", json={"finding_modes": modes}
        )

    assert refused.status_code == 422
    assert error in json.dumps(refused.json())


@pytest.mark.asyncio
async def test_finding_modes_merge_per_rule_and_version_with_the_settings(
    db, test_org
) -> None:
    async with _client(db, await _owner(db, test_org.id)) as client:
        default = (await client.get("/api/v1/management/gateway-settings")).json()
        await client.patch(
            "/api/v1/management/gateway-settings",
            json={"finding_modes": {service.UNUSED_DEPLOYMENT: "suggest"}},
        )
        both = await client.patch(
            "/api/v1/management/gateway-settings",
            json={"finding_modes": {service.IDLE_INTERNAL_DEPLOYMENT: "suggest"}},
        )
        lowered = await client.patch(
            "/api/v1/management/gateway-settings",
            json={"finding_modes": {service.UNUSED_DEPLOYMENT: "observe"}},
        )
        version = (await client.get("/api/v1/management/policy/versions/3")).json()

    assert default["settings"]["finding_modes"] == {}
    assert both.json()["settings"]["finding_modes"] == {
        service.UNUSED_DEPLOYMENT: "suggest",
        service.IDLE_INTERNAL_DEPLOYMENT: "suggest",
    }
    assert lowered.json()["settings"]["finding_modes"] == {
        service.IDLE_INTERNAL_DEPLOYMENT: "suggest"
    }
    assert version["snapshot"]["gateway_settings"]["_"]["finding_modes"] == {
        service.IDLE_INTERNAL_DEPLOYMENT: "suggest"
    }
    assert version["risk"] == "neutral"


def test_moving_a_rule_to_auto_relaxes_and_anything_else_is_neutral() -> None:
    auto = GatewaySettings(finding_modes={service.UNUSED_DEPLOYMENT: "auto"})
    suggest = GatewaySettings(finding_modes={service.UNUSED_DEPLOYMENT: "suggest"})

    assert classify_change(suggest, auto) == ("relaxing", ["finding_modes"])
    assert classify_change(GatewaySettings(), auto) == ("relaxing", ["finding_modes"])
    assert classify_change(GatewaySettings(), suggest) == ("neutral", [])
    assert classify_change(auto, suggest) == ("neutral", [])
    assert classify_change(auto, GatewaySettings()) == ("neutral", [])


@pytest.mark.asyncio
async def test_four_eyes_refuses_a_direct_move_to_auto(db, test_org) -> None:
    owner, admin = _admin(test_org.id), _admin(test_org.id, "admin")
    db.add_all([owner, admin])
    await db.flush()
    async with _client(db, owner) as client:
        await client.patch(
            "/api/v1/management/gateway-settings", json={"four_eyes": "relaxing"}
        )
        refused = await client.patch(
            "/api/v1/management/gateway-settings",
            json={"finding_modes": {service.UNUSED_DEPLOYMENT: "auto"}},
        )
        allowed = await client.patch(
            "/api/v1/management/gateway-settings",
            json={"finding_modes": {service.UNUSED_DEPLOYMENT: "suggest"}},
        )

    assert refused.status_code == 409
    assert refused.json()["detail"]["relaxed"] == ["gateway_settings._.finding_modes"]
    assert allowed.status_code == 200


@pytest.mark.asyncio
async def test_the_worker_writes_the_mode_and_action_each_pass(
    db, test_api_key
) -> None:
    tenant = test_api_key.organization_id
    deployment_id = await _deployment_id(db, test_api_key, age=timedelta(days=40))
    await _storm(db, test_api_key)
    await _evaluate(db, test_api_key)
    observed = {
        row.rule_id: dict(row.remediation) for row in await _findings(db, test_api_key)
    }

    await _set_modes(db, tenant, {service.UNUSED_DEPLOYMENT: "suggest"})
    await _evaluate(db, test_api_key)
    suggested = {
        row.rule_id: dict(row.remediation) for row in await _findings(db, test_api_key)
    }
    await _set_modes(db, tenant, {service.UNUSED_DEPLOYMENT: "auto"})
    await _evaluate(db, test_api_key)
    automatic = {
        row.rule_id: dict(row.remediation) for row in await _findings(db, test_api_key)
    }

    action = {
        "kind": "deployment.disable",
        "params": {"deployment_id": deployment_id},
    }
    unused, storm = observed[service.UNUSED_DEPLOYMENT], observed[service.RETRY_STORM]
    assert (unused["mode"], unused["max_mode"], unused["action"]) == (
        "observe",
        "auto",
        None,
    )
    assert (storm["mode"], storm["max_mode"], storm["action"]) == (
        "observe",
        "observe",
        None,
    )
    assert (unused["reversible"], unused["blast_radius"], unused["proof_after"]) == (
        True,
        "deployment",
        None,
    )
    assert (
        suggested[service.UNUSED_DEPLOYMENT]["mode"],
        suggested[service.UNUSED_DEPLOYMENT]["action"],
    ) == ("suggest", action)
    assert suggested[service.RETRY_STORM]["action"] is None
    assert (
        automatic[service.UNUSED_DEPLOYMENT]["mode"],
        automatic[service.UNUSED_DEPLOYMENT]["action"],
        automatic[service.UNUSED_DEPLOYMENT]["proof_after"],
    ) == (
        "auto",
        action,
        {
            "metric": "refusals",
            "window_hours": 24,
            "baseline": None,
            "threshold": None,
            "comparison": "lte",
        },
    )
    assert all(
        _published(service.finding_from_row(row))
        for row in await _findings(db, test_api_key)
    )


@pytest.mark.parametrize(
    "reason", ["auto_paused", "proof_unavailable", "no_allowlist_entry"]
)
@pytest.mark.asyncio
async def test_auto_works_as_suggest_while_it_cannot_run(
    db, test_api_key, monkeypatch, reason
) -> None:
    tenant = test_api_key.organization_id
    await _deployment(db, test_api_key, age=timedelta(days=40))
    await _set_modes(db, tenant, {service.UNUSED_DEPLOYMENT: "auto"})
    if reason == "auto_paused":
        row = await db.get(OrganizationGatewaySettings, tenant)
        row.settings = {**row.settings, "auto_remediation_paused": True}
    elif reason == "proof_unavailable":
        monkeypatch.setattr(settings, "AI_ACT_AUDIT_ENABLED", False)
    else:
        monkeypatch.setattr(allowlist, "ALLOWLIST", ())
    await _evaluate(db, test_api_key)
    [finding] = await _findings(db, test_api_key)

    async with _client(db, await _owner(db, tenant, "auditor")) as client:
        rules = (await client.get("/api/v1/management/findings/rules")).json()

    unused = next(
        item for item in rules if item["rule_id"] == service.UNUSED_DEPLOYMENT
    )
    assert (unused["effective_mode"], unused["unavailable_reason"]) == (
        "suggest",
        reason,
    )
    assert (finding.remediation["mode"], finding.remediation["proof_after"]) == (
        "suggest",
        None,
    )


@pytest.mark.asyncio
async def test_a_finding_whose_fix_was_set_back_only_suggests(db, test_api_key) -> None:
    tenant = test_api_key.organization_id
    await _deployment(db, test_api_key, age=timedelta(days=40))
    await _set_modes(db, tenant, {service.UNUSED_DEPLOYMENT: "auto"})
    await _evaluate(db, test_api_key)
    [finding] = await _findings(db, test_api_key)
    db.add(
        PolicyRemediation(
            organization_id=tenant,
            finding_id=finding.id,
            actor_type="system",
            items=[],
            status="restored",
        )
    )
    await _evaluate(db, test_api_key)
    [finding] = await _findings(db, test_api_key)
    ladder = await service.finding_ladder(db, tenant)

    assert finding.remediation["mode"] == "suggest"
    assert (
        service.auto_unavailable(service.UNUSED_DEPLOYMENT, ladder, str(finding.id))
        == "remediation_restored"
    )
    assert service.auto_unavailable(service.UNUSED_DEPLOYMENT, ladder) is None


@pytest.mark.asyncio
async def test_a_mode_change_reaches_an_open_finding_that_did_not_fire(
    db, test_api_key
) -> None:
    tenant = test_api_key.organization_id
    await _deployment(db, test_api_key, age=timedelta(days=40))
    await _evaluate(db, test_api_key)
    [finding] = await _findings(db, test_api_key)
    await db.execute(
        update(ModelDeployment)
        .where(ModelDeployment.organization_id == tenant)
        .values(enabled=False)
    )
    other = Organization(id=uuid4(), name="Other", slug=f"other-{uuid4().hex}")
    db.add(other)
    await db.flush()
    await _set_modes(db, other.id, {service.UNUSED_DEPLOYMENT: "suggest"})

    await _evaluate(db, test_api_key, NOW + timedelta(hours=1))
    [untouched] = await _findings(db, test_api_key)
    await _set_modes(db, tenant, {service.UNUSED_DEPLOYMENT: "suggest"})
    await _evaluate(db, test_api_key, NOW + timedelta(hours=2))
    [raised] = await _findings(db, test_api_key)
    raised_remediation = dict(raised.remediation)
    await _set_modes(db, tenant, {})
    await _evaluate(db, test_api_key, NOW + timedelta(hours=3))
    [lowered] = await _findings(db, test_api_key)

    assert untouched.id == finding.id and untouched.last_seen_at == NOW
    assert untouched.remediation["mode"] == "observe"
    assert raised_remediation["mode"] == "suggest"
    assert raised_remediation["action"]["kind"] == "deployment.disable"
    assert (lowered.remediation["mode"], lowered.remediation["action"]) == (
        "observe",
        None,
    )
    assert service.finding_from_row(lowered).remediation.action is None


@pytest.mark.asyncio
async def test_lowering_a_mode_clears_the_stored_action_at_once(
    db, test_api_key
) -> None:
    tenant = test_api_key.organization_id
    await _deployment(db, test_api_key, age=timedelta(days=40))
    await _set_modes(db, tenant, {service.UNUSED_DEPLOYMENT: "suggest"})
    await _evaluate(db, test_api_key)
    [finding] = await _findings(db, test_api_key)
    assert finding.remediation["action"] is not None

    async with _client(db, await _owner(db, tenant)) as client:
        lowered = await client.patch(
            "/api/v1/management/gateway-settings",
            json={"finding_modes": {service.UNUSED_DEPLOYMENT: "observe"}},
        )
        planned = await client.post(f"/api/v1/management/findings/{finding.id}/plan")

    assert lowered.status_code == 200, lowered.text
    await db.refresh(finding)
    # No pass in between: the PATCH itself took the action away.
    assert (finding.remediation["mode"], finding.remediation["action"]) == (
        "observe",
        None,
    )
    assert planned.status_code == 409


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "action",
    [
        {"kind": "deployment.delete", "params": {"deployment_id": "x"}},
        {"kind": "deployment.disable", "params": {}},
        {"params": {"deployment_id": "x"}},
    ],
)
async def test_a_stored_action_this_build_cannot_plan_is_a_409(
    db, test_api_key, action
) -> None:
    tenant = test_api_key.organization_id
    await _deployment(db, test_api_key, age=timedelta(days=40))
    await _set_modes(db, tenant, {service.UNUSED_DEPLOYMENT: "suggest"})
    await _evaluate(db, test_api_key)
    [finding] = await _findings(db, test_api_key)
    finding.remediation = {**finding.remediation, "action": action}
    await db.flush()

    async with _client(db, await _owner(db, tenant)) as client:
        refused = await client.post(f"/api/v1/management/findings/{finding.id}/plan")

    assert (refused.status_code, refused.json()["detail"]) == (
        409,
        "This build cannot plan the finding's action",
    )


@pytest.mark.asyncio
async def test_the_rules_read_lists_every_rule_with_its_modes(db, test_api_key) -> None:
    tenant = test_api_key.organization_id
    await _deployment(db, test_api_key, age=timedelta(days=40))
    await _evaluate(db, test_api_key)
    await _set_modes(db, tenant, {service.UNUSED_DEPLOYMENT: "auto"})
    member = await _owner(db, tenant, "member")

    async with _client(db, await _owner(db, tenant, "auditor")) as client:
        read = await client.get("/api/v1/management/findings/rules")
    async with _client(db, member) as client:
        refused = await client.get("/api/v1/management/findings/rules")

    items = read.json()
    assert read.status_code == 200
    assert [item["rule_id"] for item in items] == sorted(service.RULES)
    unused = next(
        item for item in items if item["rule_id"] == service.UNUSED_DEPLOYMENT
    )
    assert unused == {
        "rule_id": service.UNUSED_DEPLOYMENT,
        "rule_version": 2,
        "max_mode": "auto",
        "action_kind": "deployment.disable",
        "mode": "auto",
        "effective_mode": "auto",
        "unavailable_reason": None,
        "open_findings": 1,
    }
    storm = next(item for item in items if item["rule_id"] == service.RETRY_STORM)
    assert (storm["mode"], storm["effective_mode"], storm["unavailable_reason"]) == (
        "observe",
        "observe",
        None,
    )
    assert refused.status_code == 403


@pytest.mark.asyncio
async def test_a_suggested_action_becomes_a_plan_that_applies_and_restores(
    db, test_api_key, monkeypatch
) -> None:
    monkeypatch.setattr(
        settings, "MODEL_DEPLOYMENT_ALLOWED_ORIGINS", ["https://a.internal"]
    )
    tenant = test_api_key.organization_id
    owner = await _owner(db, tenant)
    deployment_id = await _deployment_id(db, test_api_key, age=timedelta(days=40))
    await _storm(db, test_api_key)
    await _set_modes(db, tenant, {service.UNUSED_DEPLOYMENT: "suggest"})
    await _evaluate(db, test_api_key)
    findings = {row.rule_id: row for row in await _findings(db, test_api_key)}
    unused, storm = findings[service.UNUSED_DEPLOYMENT], findings[service.RETRY_STORM]
    other = Organization(id=uuid4(), name="Other", slug=f"other-{uuid4().hex}")
    db.add(other)
    await db.flush()
    stranger, auditor = _admin(other.id), _admin(tenant, "auditor")
    db.add_all([stranger, auditor])
    await db.flush()

    async with _client(db, stranger) as client:
        cross = await client.post(f"/api/v1/management/findings/{unused.id}/plan")
    async with _client(db, auditor) as client:
        forbidden = await client.post(f"/api/v1/management/findings/{unused.id}/plan")
    async with _client(db, owner) as client:
        no_action = await client.post(f"/api/v1/management/findings/{storm.id}/plan")
        created = await client.post(f"/api/v1/management/findings/{unused.id}/plan")
        plan = created.json()
        applied = await client.post(
            f"/api/v1/management/policy/plans/{plan['id']}/apply"
        )
        disabled = await db.get(
            ModelDeployment, UUID(deployment_id), populate_existing=True
        )
        disabled_state = disabled.enabled
        restored = await client.post(
            f"/api/v1/management/policy/versions/{applied.json()['applied_version'] - 1}/restore",
            json={},
        )
        await db.execute(
            update(Finding)
            .where(Finding.id == unused.id)
            .values(status_id=service.STATUS_RESOLVED)
        )
        resolved = await client.post(f"/api/v1/management/findings/{unused.id}/plan")

    assert cross.status_code == 404
    assert forbidden.status_code == 403
    assert (no_action.status_code, no_action.json()["detail"]) == (
        409,
        "The finding suggests no action",
    )
    assert created.status_code == 201, created.text
    assert (plan["status"], plan["reason"]) == ("draft", f"finding:{unused.id}")
    [change] = plan["changes"]
    assert (change["resource"], change["item"], change["risk"]) == (
        "deployments",
        deployment_id,
        "tightening",
    )
    assert (change["before"]["enabled"], change["after"]["enabled"]) == (True, False)
    assert applied.json()["status"] == "applied"
    assert disabled_state is False
    assert restored.json()["plan"]["status"] == "applied"
    assert (
        await db.get(ModelDeployment, UUID(deployment_id), populate_existing=True)
    ).enabled
    assert (resolved.status_code, resolved.json()["detail"]) == (
        409,
        "The finding is not open",
    )
