from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import event, select, text

from shim_enterprise.api.enterprise_deps import get_current_user
from shim_enterprise.api.v1.router import management_router
from shim_enterprise.billing.models import RequestLifecycle
from shim_enterprise.core.database import get_db
from shim_enterprise.findings import service
from shim_enterprise.observability.analytics_projection import RequestLog
from shim_enterprise.api.v1 import management
from shim_enterprise.findings.models import Finding
from shim_enterprise.tenants.models import (
    ApiKey,
    ModelDeployment,
    Organization,
    ProviderSecret,
    Team,
    User,
)

NOW = datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc)
HOUR = datetime(2026, 10, 11, 10, 0, tzinfo=timezone.utc)
LATENCY = "/api/v1/management/latency"


async def _tenant(db, role: str = "owner") -> tuple[User, ApiKey]:
    organization = Organization(
        id=uuid4(), name="Latency", slug=f"latency-{uuid4().hex}", tier="enterprise"
    )
    db.add(organization)
    await db.flush()
    user = User(
        id=uuid4(),
        organization_id=organization.id,
        email=f"latency-{uuid4().hex}@example.com",
        role=role,
        is_active=True,
        is_verified=True,
    )
    db.add(user)
    await db.flush()
    key = ApiKey(
        id=uuid4(),
        organization_id=organization.id,
        user_id=user.id,
        key_hash=uuid4().hex,
        prefix="sk-shim-lat",
        name="app-one",
        tier="enterprise",
        is_active=True,
    )
    db.add(key)
    await db.flush()
    return user, key


def _request(
    db,
    key: ApiKey,
    started_at: datetime,
    *,
    seconds: float = 2.0,
    stream: bool = True,
    first_byte: float | None = 300.0,
    queue_ms: float = 20.0,
    status: str = "completed",
    model: str = "gpt-5-mini",
    prompt_tokens: int = 100,
    completion_tokens: int = 100,
    stream_seconds: float | None = None,
    log_details: dict | None = None,
    **metadata,
) -> str:
    request_id = f"req_latency_{uuid4().hex}"
    provider_started = started_at + timedelta(milliseconds=queue_ms)
    completed = provider_started + timedelta(seconds=seconds)
    db.add(
        RequestLifecycle(
            request_id=request_id,
            organization_id=key.organization_id,
            actor_type="api_key",
            api_key_id=key.id,
            source_endpoint="chat.completions",
            status=status,
            requested_model=model,
            stream=stream,
            started_at=started_at,
            provider_started_at=provider_started,
            stream_started_at=None
            if stream_seconds is None
            else completed - timedelta(seconds=stream_seconds),
            completed_at=completed,
            lifecycle_metadata={
                ("ttft_ms" if stream else "provider_latency_ms"): first_byte,
                **metadata,
            },
        )
    )
    db.add(
        RequestLog(
            request_id=request_id,
            api_key_id=key.id,
            organization_id=key.organization_id,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            details=log_details or {},
        )
    )
    return request_id


async def _read(db, user: User, **params) -> httpx.Response:
    await db.flush()
    app = FastAPI()
    app.include_router(management_router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_db] = lambda: db
    query = {
        "start": (NOW - timedelta(hours=24)).isoformat(),
        "end": NOW.isoformat(),
        **params,
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        return await client.get(LATENCY, params=query)


def _bucket(body: dict, group_id, start: datetime = HOUR) -> dict:
    group = next(item for item in body["groups"] if item["id"] == group_id)
    return next(
        item
        for item in group["buckets"]
        if item["start"].startswith(start.strftime("%Y-%m-%dT%H"))
    )


@pytest.mark.asyncio
async def test_first_byte_queue_and_output_speed_per_bucket(db) -> None:
    user, key = await _tenant(db)
    _request(
        db,
        key,
        HOUR,
        first_byte=200.0,
        queue_ms=10,
        stream_seconds=2.0,
        completion_tokens=100,
    )
    _request(
        db,
        key,
        HOUR + timedelta(minutes=1),
        first_byte=400.0,
        queue_ms=30,
        stream_seconds=4.0,
        completion_tokens=100,
    )
    _request(db, key, HOUR + timedelta(minutes=2), stream=False, first_byte=900.0)
    # Not an output speed: estimated usage, reasoning, under a second.
    _request(
        db,
        key,
        HOUR + timedelta(minutes=5),
        stream_seconds=2.0,
        log_details={"usage_estimated": True},
    )
    _request(db, key, HOUR + timedelta(minutes=3), stream_seconds=0.5)
    _request(
        db, key, HOUR + timedelta(minutes=4), stream_seconds=3.0, reasoning_seen=True
    )

    body = (await _read(db, user, group_by="api_key", bucket="hour")).json()
    bucket = _bucket(body, str(key.id))

    assert body["groups"][0]["name"] == "app-one"
    assert (bucket["requests"], bucket["streams"]) == (6, 5)
    assert bucket["first_byte_ms"]["json"] == {"p50": 900.0, "p95": 900.0}
    assert bucket["first_byte_ms"]["stream"]["p50"] == 300.0
    assert bucket["shim_queue_ms"]["p50"] == 20.0
    assert bucket["output_tokens_per_second"] == {"p50": 37.5, "count": 2}


@pytest.mark.asyncio
async def test_peak_concurrency_sweeps_overlaps_and_bucket_edges(db) -> None:
    user, key = await _tenant(db)
    for minute in (0, 1, 2):
        _request(db, key, HOUR + timedelta(minutes=minute), queue_ms=0, seconds=600)
    # Touching: one ends exactly when the next starts.
    _request(db, key, HOUR + timedelta(minutes=30), queue_ms=0, seconds=60)
    _request(db, key, HOUR + timedelta(minutes=31), queue_ms=0, seconds=60)
    # Open past the bucket's end: counts in both hours.
    _request(db, key, HOUR + timedelta(minutes=59), queue_ms=0, seconds=600)

    body = (await _read(db, user, group_by="api_key", bucket="hour")).json()

    assert _bucket(body, str(key.id))["peak_concurrency"] == 3
    assert (
        _bucket(body, str(key.id), HOUR + timedelta(hours=1))["peak_concurrency"] == 1
    )


@pytest.mark.asyncio
async def test_groups_by_team_tag_model_and_deployment(db) -> None:
    user, key = await _tenant(db)
    team = Team(id=uuid4(), organization_id=key.organization_id, name="risk")
    db.add(team)
    await db.flush()
    deployment = str(uuid4())
    _request(
        db,
        key,
        HOUR,
        team_id=str(team.id),
        tags=["chat", "eu"],
        deployment_id=deployment,
    )
    _request(db, key, HOUR, model="gpt-5-nano", tags=["chat"])

    teams = (await _read(db, user, group_by="team")).json()["groups"]
    tags = (await _read(db, user, group_by="tag")).json()["groups"]
    models = (await _read(db, user, group_by="model")).json()["groups"]
    deployments = (await _read(db, user, group_by="deployment")).json()["groups"]

    assert {(item["id"], item["name"], item["requests"]) for item in teams} == {
        (str(team.id), "risk", 1),
        (None, None, 1),
    }
    assert {(item["id"], item["requests"]) for item in tags} == {("chat", 2), ("eu", 1)}
    assert {item["id"] for item in models} == {"gpt-5-mini", "gpt-5-nano"}
    assert {(item["id"], item["requests"]) for item in deployments} == {
        (deployment, 1),
        (None, 1),
    }


@pytest.mark.asyncio
async def test_twenty_groups_at_most_in_four_statements(db) -> None:
    user, key = await _tenant(db)
    for index in range(22):
        _request(db, key, HOUR, model=f"model-{index:02d}")
    await db.flush()
    connection = await db.connection()
    sent: list[str] = []

    def capture(_conn, _cursor, statement, *_args) -> None:
        if "request_lifecycle" in statement:
            sent.append(statement)

    event.listen(connection.sync_connection, "before_cursor_execute", capture)
    try:
        body = (await _read(db, user, group_by="model")).json()
    finally:
        event.remove(connection.sync_connection, "before_cursor_execute", capture)

    assert len(body["groups"]) == 20 and body["truncated"] is True
    assert len(sent) <= 4


@pytest.mark.parametrize(
    ("bucket", "days", "status"),
    [("hour", 7, 200), ("hour", 8, 422), ("day", 31, 200), ("day", 32, 422)],
)
@pytest.mark.asyncio
async def test_windows_are_bounded_per_bucket(db, bucket, days, status) -> None:
    user, _ = await _tenant(db)

    answered = await _read(
        db,
        user,
        bucket=bucket,
        group_by="model",
        start=(NOW - timedelta(days=days)).isoformat(),
    )

    assert answered.status_code == status


@pytest.mark.asyncio
async def test_readers_only_and_tenants_apart(db) -> None:
    owner, key = await _tenant(db)
    other, _ = await _tenant(db)
    _request(db, key, HOUR)
    member = User(
        id=uuid4(),
        organization_id=owner.organization_id,
        email=f"latency-{uuid4().hex}@example.com",
        role="member",
        is_active=True,
        is_verified=True,
    )
    db.add(member)

    refused = await _read(db, member, group_by="model")
    elsewhere = (await _read(db, other, group_by="model")).json()

    assert refused.status_code == 403
    assert elsewhere["groups"] == []


@pytest.mark.asyncio
async def test_head_of_line_compares_short_streams_with_and_without_a_long_request(
    db,
) -> None:
    user, key = await _tenant(db)
    _request(db, key, HOUR, queue_ms=0, seconds=300, prompt_tokens=30_000)
    for minute in (1, 2, 3):
        _request(
            db,
            key,
            HOUR + timedelta(minutes=minute),
            first_byte=2_000.0,
            prompt_tokens=500,
        )
    for minute in (20, 21):
        _request(
            db,
            key,
            HOUR + timedelta(minutes=minute),
            first_byte=200.0,
            prompt_tokens=500,
        )
    # At the long request's start it is in flight; at its end it no longer is.
    _request(db, key, HOUR, first_byte=2_000.0, prompt_tokens=500)
    _request(db, key, HOUR + timedelta(minutes=5), first_byte=200.0, prompt_tokens=500)

    model = (await _read(db, user, group_by="model")).json()["groups"][0]
    by_key = (await _read(db, user, group_by="api_key")).json()["groups"][0]
    long_window = (
        await _read(
            db,
            user,
            group_by="model",
            bucket="day",
            start=(NOW - timedelta(hours=49)).isoformat(),
        )
    ).json()["groups"][0]

    assert model["head_of_line"] == {
        "behind_long": {"ttft_ms_p50": 2_000.0, "streams": 4},
        "alone": {"ttft_ms_p50": 200.0, "streams": 3},
    }
    assert (by_key["head_of_line"], by_key["head_of_line_unavailable_reason"]) == (
        None,
        "group_by",
    )
    assert long_window["head_of_line_unavailable_reason"] == "window_over_48h"


def _deployment_request(
    db,
    key,
    deployment: str,
    started_at: datetime,
    first_byte: float,
    status: str = "completed",
    stream: bool = True,
    seconds: float = 2.0,
) -> None:
    _request(
        db,
        key,
        started_at,
        first_byte=first_byte,
        status=status,
        stream=stream,
        seconds=seconds,
        deployment_id=deployment,
    )


@pytest.mark.parametrize("cold_starts", [3, 2])
@pytest.mark.asyncio
async def test_cold_start_fires_at_three_idle_slow_starts(db, cold_starts: int) -> None:
    _, key = await _tenant(db)
    deployment = str(uuid4())
    start = NOW - timedelta(hours=20)
    for index in range(cold_starts):
        burst = start + timedelta(hours=index * 2)
        _deployment_request(db, key, deployment, burst, 15_000.0)
        for second in (1, 2, 3):
            _deployment_request(
                db, key, deployment, burst + timedelta(seconds=second), 300.0
            )
    # Not cold: slow without a gap, and a gap with a normal first byte.
    _deployment_request(
        db, key, deployment, start + timedelta(hours=9, seconds=1), 400.0
    )
    _deployment_request(
        db, key, deployment, start + timedelta(hours=9, seconds=2), 20_000.0
    )
    # Catalog requests are never subjects.
    _request(db, key, start, first_byte=50_000.0)
    await db.flush()

    found = await service._cold_starts(db, key.organization_id, NOW)

    if cold_starts == 2:
        assert found == []
        return
    [detection] = found
    assert detection.subject == {"deployment_id": deployment}
    assert detection.evidence["cold_starts"] == 3
    assert detection.evidence["warm_first_byte_ms"] == 300


@pytest.mark.asyncio
async def test_a_timeout_after_a_gap_is_a_cold_start(db) -> None:
    _, key = await _tenant(db)
    deployment = str(uuid4())
    for index in range(3):
        _deployment_request(
            db,
            key,
            deployment,
            NOW - timedelta(hours=10 - index * 2),
            None,
            status="timeout",
        )
    await db.flush()

    [detection] = await service._cold_starts(db, key.organization_id, NOW)

    assert (detection.evidence["cold_starts"], detection.evidence["timeouts"]) == (3, 3)


async def _baseline(db, key, deployment: str, ttft: float = 200.0) -> None:
    for index in range(50):
        _deployment_request(
            db, key, deployment, NOW - timedelta(days=2, minutes=index), ttft
        )


async def _busy_hour(
    db,
    key,
    deployment: str,
    hour: datetime,
    *,
    together: int = 5,
    ttft: float = 1_000.0,
) -> None:
    for index in range(10):
        # The first `together` overlap for a minute.
        _deployment_request(
            db,
            key,
            deployment,
            hour + timedelta(seconds=index if index < together else 120 + index * 120),
            ttft,
            seconds=60,
        )


@pytest.mark.parametrize("hours", [2, 1])
@pytest.mark.asyncio
async def test_queueing_fires_at_two_congested_hours(db, hours: int) -> None:
    _, key = await _tenant(db)
    deployment = str(uuid4())
    await _baseline(db, key, deployment)
    for index in range(hours):
        await _busy_hour(db, key, deployment, NOW - timedelta(hours=5 - index))
    await db.flush()

    found = await service._queueing(db, key.organization_id, NOW)

    if hours == 1:
        assert found == []
        return
    [detection] = found
    assert detection.evidence["congested_hours"] == 2
    assert detection.evidence["baseline_ttft_ms"] == 200
    assert detection.evidence["peak_concurrency"] >= 4


@pytest.mark.asyncio
async def test_no_queueing_without_baseline_or_concurrency(db) -> None:
    _, key = await _tenant(db)
    no_baseline, quiet = str(uuid4()), str(uuid4())
    for index in range(2):
        await _busy_hour(db, key, no_baseline, NOW - timedelta(hours=5 - index))
    await _baseline(db, key, quiet)
    for index in range(2):
        await _busy_hour(db, key, quiet, NOW - timedelta(hours=5 - index), together=1)
    await db.flush()

    assert await service._queueing(db, key.organization_id, NOW) == []


@pytest.mark.parametrize(("measured", "fires"), [(10, True), (1, False)])
@pytest.mark.asyncio
async def test_an_hour_is_judged_on_ten_measured_streams(
    db, measured: int, fires: bool
) -> None:
    _, key = await _tenant(db)
    deployment = str(uuid4())
    await _baseline(db, key, deployment)
    for index in range(2):
        hour = NOW - timedelta(hours=5 - index)
        # A stream that never sent a first byte is not part of the p95's sample.
        for second in range(10):
            _request(
                db,
                key,
                hour + timedelta(seconds=second),
                first_byte=1_000.0 if second < measured else None,
                seconds=60,
                deployment_id=deployment,
            )
    await db.flush()

    found = await service._queueing(db, key.organization_id, NOW)

    assert len(found) == int(fires)


@pytest.mark.asyncio
async def test_slow_json_answers_after_a_gap_are_not_cold_starts(db) -> None:
    _, key = await _tenant(db)
    deployment = str(uuid4())
    # A JSON answer's first byte includes its generation: 12 s is a long answer.
    for index in range(5):
        _deployment_request(
            db,
            key,
            deployment,
            NOW - timedelta(hours=4) + timedelta(minutes=30 * index),
            12_000.0,
            stream=False,
            seconds=12,
        )
    await db.flush()

    assert await service._cold_starts(db, key.organization_id, NOW) == []


@pytest.mark.asyncio
async def test_peak_concurrency_of_queueing_counts_json_requests_too(db) -> None:
    _, key = await _tenant(db)
    deployment = str(uuid4())
    await _baseline(db, key, deployment)
    for index in range(2):
        hour = NOW - timedelta(hours=5 - index)
        await _busy_hour(db, key, deployment, hour, together=1)
        for second in range(1, 5):
            _deployment_request(
                db,
                key,
                deployment,
                hour + timedelta(seconds=second),
                30_000.0,
                stream=False,
                seconds=60,
            )
    await db.flush()

    [detection] = await service._queueing(db, key.organization_id, NOW)

    assert detection.evidence["peak_concurrency"] == 5
    assert detection.impact["requests"] == 20


async def _registry(db, key) -> str:
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
    deployment = ModelDeployment(
        id=uuid4(),
        organization_id=key.organization_id,
        alias=f"internal-{uuid4().hex[:8]}",
        provider="openai",
        upstream_model="custom-model",
        base_url="https://a.internal/v1",
        provider_secret_id=secret.id,
        timeout_seconds=5,
        deployment_kind="internal",
        declared_version="v1",
        owner="Platform",
    )
    db.add(deployment)
    await db.flush()
    return str(deployment.id)


def _cold_burst(db, key, deployment: str) -> None:
    for index in range(3):
        burst = NOW - timedelta(hours=20 - index * 2)
        _deployment_request(db, key, deployment, burst, 15_000.0)
        for second in (1, 2, 3):
            _deployment_request(
                db, key, deployment, burst + timedelta(seconds=second), 300.0
            )


@pytest.mark.asyncio
async def test_the_worker_runs_the_deployment_rules_only_with_a_registry(db) -> None:
    _, without = await _tenant(db)
    _, registered = await _tenant(db)
    _cold_burst(db, without, str(uuid4()))
    _cold_burst(db, registered, await _registry(db, registered))
    await db.flush()

    for key in (without, registered):
        await service.evaluate_organization(db, key.organization_id, now=NOW)

    found = {
        (row.organization_id, row.rule_id)
        for row in await db.scalars(
            select(Finding).where(
                Finding.organization_id.in_(
                    [without.organization_id, registered.organization_id]
                )
            )
        )
    }
    assert found == {(registered.organization_id, service.COLD_START)}


@pytest.mark.asyncio
async def test_the_new_findings_rules_run_under_a_statement_timeout(
    db, monkeypatch
) -> None:
    _, key = await _tenant(db)
    await _registry(db, key)
    seen: dict[str, str] = {}

    def watched(name: str):
        rule = getattr(service, name)

        async def run(session, tenant_id, now):
            seen[name] = await session.scalar(text("SHOW statement_timeout"))
            return await rule(session, tenant_id, now)

        return run

    for name in ("_retry_storms", "_cold_starts", "_queueing"):
        monkeypatch.setattr(service, name, watched(name))

    await service.evaluate_organization(db, key.organization_id, now=NOW)

    assert seen == {"_retry_storms": "0", "_cold_starts": "10s", "_queueing": "10s"}


@pytest.mark.asyncio
async def test_the_read_runs_under_a_statement_timeout_and_a_slow_one_is_503(
    db, monkeypatch
) -> None:
    user, _ = await _tenant(db)

    answered = await _read(db, user)
    bound = await db.scalar(text("SHOW statement_timeout"))

    async def slow(session, *_args, **_kwargs):
        await session.execute(text("SET LOCAL statement_timeout = '50ms'"))
        await session.execute(text("SELECT pg_sleep(1)"))

    monkeypatch.setattr(management, "latency_by_group", slow)
    refused = await _read(db, user)

    assert answered.status_code == 200
    assert bound == "10s"
    assert refused.status_code == 503
    assert refused.json()["detail"]["code"] == "QUERY_TIMEOUT"
