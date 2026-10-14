"""Model servers' own load: parsed, scraped on a cadence, aggregated, read, judged."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json
import logging
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ee.tests.aws.test_bedrock_management import _admin, _call
from ee.tests.billing.test_hardware_cost import _deployment
from shim_enterprise.core.config import settings
from shim_enterprise.findings import service
from shim_enterprise.observability import inference_metrics
from shim_enterprise.observability.inference_metrics import (
    ScrapeError,
    parse_ollama,
    parse_prometheus,
    read_sample,
    scrape_inference_metrics,
)
from shim_enterprise.observability.models import InferenceMetricsHourly
from shim_enterprise.tenants.models import (
    DeploymentHardwareCost,
    OrganizationGatewaySettings,
)

VLLM = """# HELP vllm:num_requests_running Number of requests in model execution batches.
# TYPE vllm:num_requests_running gauge
vllm:num_requests_running{model_name="a"} 2.0
vllm:num_requests_running{model_name="b"} 1.0
vllm:num_requests_waiting{model_name="a"} 4.0
vllm:kv_cache_usage_perc{model_name="a"} 0.4
vllm:kv_cache_usage_perc{model_name="b"} 1.7
vllm:gpu_cache_usage_perc{model_name="a"} 0.1
vllm:time_to_first_token_seconds_bucket{model_name="a",le="0.1"} 9
vllm:num_requests_waiting{model_name="b"} not-a-number
unrelated_metric 7
"""
TGI = "tgi_queue_size 3\ntgi_batch_current_size 5\ntgi_request_count 9\n"
OLLAMA = json.dumps(
    {"models": [{"name": "llama:latest", "model": "llama:latest", "size_vram": 4_000}]}
)


def test_the_parser_keeps_only_the_allow_listed_gauges() -> None:
    vllm = parse_prometheus("vllm", VLLM)
    legacy = parse_prometheus("vllm", 'vllm:gpu_cache_usage_perc{model_name="a"} 0.3\n')
    tgi = parse_prometheus("tgi", TGI)

    # Running and waiting summed over models; cache the max, clamped to 1.
    assert (vllm.running, vllm.waiting, vllm.cache_usage) == (3, 4, 1.0)
    assert legacy.cache_usage == 0.3
    assert (tgi.running, tgi.waiting, tgi.cache_usage) == (5, 3, None)
    for page in ("", "# HELP x\nunrelated 1\n"):
        with pytest.raises(ScrapeError, match="unrecognized"):
            parse_prometheus("vllm", page)


def test_ollama_reports_whether_the_model_is_loaded() -> None:
    assert parse_ollama(OLLAMA, "llama:latest") == inference_metrics.Sample(
        loaded=True, vram_bytes=4_000
    )
    assert parse_ollama(
        json.dumps({"models": [{"name": "x", "model": "llama:latest"}]}), "llama:latest"
    ).loaded
    assert parse_ollama(OLLAMA, "other").loaded is False
    with pytest.raises(ScrapeError, match="unrecognized"):
        parse_ollama("not json", "x")


async def _read(handler, *, base_url="https://a.internal/v1", credential=None):
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        return await read_sample(client, "vllm", base_url, "llama", credential)


@pytest.mark.asyncio
async def test_a_read_goes_to_the_origin_and_sends_a_credential_only_when_asked(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        settings, "MODEL_DEPLOYMENT_ALLOWED_ORIGINS", ["https://a.internal"]
    )
    seen: list[httpx.Request] = []

    def server(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, text=VLLM)

    await _read(server)
    await _read(server, credential="secret-value")

    assert [str(r.url) for r in seen] == ["https://a.internal/metrics"] * 2
    assert "authorization" not in seen[0].headers
    assert seen[1].headers["authorization"] == "Bearer secret-value"


@pytest.mark.parametrize(
    ("answer", "code"),
    [
        (lambda request: httpx.Response(401), "unauthorized"),
        (
            lambda request: httpx.Response(302, headers={"location": "https://evil/"}),
            "http_302",
        ),
        (
            lambda request: httpx.Response(200, content=b"x" * (1_048_576 + 1)),
            "too_large",
        ),
        (
            lambda request: (_ for _ in ()).throw(
                httpx.ConnectError("no", request=request)
            ),
            "connection",
        ),
    ],
)
@pytest.mark.asyncio
async def test_a_failed_read_names_its_reason(monkeypatch, answer, code) -> None:
    monkeypatch.setattr(
        settings, "MODEL_DEPLOYMENT_ALLOWED_ORIGINS", ["https://a.internal"]
    )

    with pytest.raises(ScrapeError) as failed:
        await _read(answer)

    assert failed.value.code == code


@pytest.mark.asyncio
async def test_a_slow_server_times_out_and_a_disapproved_origin_is_never_contacted(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        settings, "MODEL_DEPLOYMENT_ALLOWED_ORIGINS", ["https://a.internal"]
    )
    monkeypatch.setattr(inference_metrics, "SCRAPE_SECONDS", 0.05)
    seen: list[httpx.Request] = []

    async def slow(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        await asyncio.sleep(1)
        return httpx.Response(200, text=VLLM)

    with pytest.raises(ScrapeError, match="timeout"):
        await _read(slow)
    with pytest.raises(ScrapeError, match="origin_not_approved"):
        await _read(slow, base_url="https://b.internal/v1")

    assert len(seen) == 1


def _sessions(connection):
    return lambda: AsyncSession(
        bind=connection, join_transaction_mode="create_savepoint"
    )


async def _listed(db, user, sources) -> None:
    db.add(
        OrganizationGatewaySettings(
            organization_id=user.organization_id,
            settings={"inference_metrics": sources},
        )
    )
    await db.flush()


@pytest.mark.asyncio
async def test_a_pass_reads_listed_servers_and_aggregates_by_hour(
    db, monkeypatch, caplog
) -> None:
    user = await _admin(db)
    vllm = await _deployment(db, user.organization_id)
    failing = await _deployment(db, user.organization_id)
    await _listed(
        db,
        user,
        [
            {"deployment_id": str(vllm.id), "server": "vllm"},
            {"deployment_id": str(failing.id), "server": "tgi"},
        ],
    )
    samples = iter(
        [
            inference_metrics.Sample(running=3, waiting=4, cache_usage=1.0),
            inference_metrics.Sample(running=8, waiting=0, cache_usage=0.4),
        ]
    )

    async def server(client, kind, *args):
        if kind == "tgi":
            raise ScrapeError("unauthorized")
        return next(samples)

    monkeypatch.setattr(inference_metrics, "read_sample", server)
    connection = await db.connection()
    now = datetime.now(timezone.utc)
    caplog.set_level(logging.INFO)
    async with httpx.AsyncClient() as client:
        first = await scrape_inference_metrics(
            _sessions(connection), client, now=now, interval_seconds=60
        )
        second = await scrape_inference_metrics(
            _sessions(connection), client, now=now, interval_seconds=60
        )

    rows = {
        row.deployment_id: row
        for row in await db.scalars(
            select(InferenceMetricsHourly)
            .where(InferenceMetricsHourly.organization_id == user.organization_id)
            .execution_options(populate_existing=True)
        )
    }
    good, bad = rows[vllm.id], rows[failing.id]
    assert (first, second) == (2, 2)
    # Two samples in one hour: counts and sums add up, maxima are kept.
    assert (good.samples, good.busy_samples, good.queued_samples) == (2, 2, 1)
    assert (good.running_sum, good.running_max, good.waiting_max) == (11, 8, 4)
    assert (good.cache_usage_sum, good.cache_usage_max, good.errors) == (1.4, 1.0, 0)
    assert (bad.samples, bad.errors, bad.last_error) == (0, 2, "unauthorized")
    assert "a.internal" not in caplog.text


@pytest.mark.asyncio
async def test_a_credential_the_store_cannot_return_is_never_read_without(
    db, monkeypatch
) -> None:
    user = await _admin(db)
    deployment = await _deployment(db, user.organization_id)
    await _listed(
        db,
        user,
        [
            {
                "deployment_id": str(deployment.id),
                "server": "tgi",
                "send_credential": True,
            }
        ],
    )
    reads = []

    class Store:
        async def get_secret(self, *args, **kwargs):
            raise RuntimeError("store down")

    async def server(*args):
        reads.append(args)
        return inference_metrics.Sample(running=1, waiting=0)

    monkeypatch.setattr(inference_metrics, "get_secret_store", Store)
    monkeypatch.setattr(inference_metrics, "read_sample", server)
    connection = await db.connection()
    async with httpx.AsyncClient() as client:
        await scrape_inference_metrics(
            _sessions(connection),
            client,
            now=datetime.now(timezone.utc),
            interval_seconds=60,
        )

    row = await db.scalar(
        select(InferenceMetricsHourly)
        .where(InferenceMetricsHourly.deployment_id == deployment.id)
        .execution_options(populate_existing=True)
    )
    assert reads == []
    assert (row.samples, row.errors, row.last_error) == (
        0,
        1,
        "credential_unavailable",
    )


@pytest.mark.asyncio
async def test_no_listed_server_means_no_http_at_all(db) -> None:
    user = await _admin(db)
    seen: list[httpx.Request] = []
    connection = await db.connection()

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda request: seen.append(request) or httpx.Response(200)
        )
    ) as client:
        sampled = await scrape_inference_metrics(
            _sessions(connection),
            client,
            now=datetime.now(timezone.utc),
            interval_seconds=60,
        )

    assert (sampled, seen) == (0, [])
    assert user


@pytest.mark.asyncio
async def test_at_most_eight_reads_at_once_and_the_deadline_skips_the_rest(
    db, monkeypatch
) -> None:
    user = await _admin(db)
    deployments = [await _deployment(db, user.organization_id) for _ in range(12)]
    await _listed(
        db, user, [{"deployment_id": str(d.id), "server": "vllm"} for d in deployments]
    )
    running = peak = calls = 0
    eight_at_once = asyncio.Event()

    async def slow(client, server, *args):
        nonlocal running, peak, calls
        calls += 1
        running += 1
        peak = max(peak, running)
        if running == 8:
            eight_at_once.set()
        try:
            # The first eight return once all eight run together; the other four never
            # return, so the deadline, not the machine's speed, is what skips them.
            await (eight_at_once if calls <= 8 else asyncio.Event()).wait()
        finally:
            running -= 1
        return inference_metrics.Sample(running=1, waiting=0)

    monkeypatch.setattr(inference_metrics, "read_sample", slow)
    connection = await db.connection()
    async with httpx.AsyncClient() as client:
        sampled = await scrape_inference_metrics(
            _sessions(connection),
            client,
            now=datetime.now(timezone.utc),
            interval_seconds=6,
        )

    # The pass deadline is interval - 5 = 1 s: the first eight finish, the other four
    # are still reading at the deadline and are skipped this pass.
    assert peak == 8
    assert sampled == 8


@pytest.mark.asyncio
async def test_rows_older_than_ninety_days_are_deleted(db) -> None:
    user = await _admin(db)
    deployment = await _deployment(db, user.organization_id)
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    for days in (91, 89):
        db.add(
            InferenceMetricsHourly(
                organization_id=user.organization_id,
                deployment_id=deployment.id,
                hour=now - timedelta(days=days),
                server="vllm",
                samples=1,
            )
        )
    await _listed(db, user, [{"deployment_id": str(deployment.id), "server": "vllm"}])
    connection = await db.connection()

    async def quiet(client, server, *args):
        raise ScrapeError("timeout")

    original = inference_metrics.read_sample
    inference_metrics.read_sample = quiet
    try:
        async with httpx.AsyncClient() as client:
            await scrape_inference_metrics(
                _sessions(connection), client, now=now, interval_seconds=60
            )
    finally:
        inference_metrics.read_sample = original

    left = await db.scalar(
        select(func.count()).where(
            InferenceMetricsHourly.deployment_id == deployment.id,
            InferenceMetricsHourly.hour < now - timedelta(days=90),
        )
    )
    assert left == 0


@pytest.mark.asyncio
async def test_the_setting_lists_only_internal_deployments_once(db) -> None:
    user = await _admin(db)
    internal = await _deployment(db, user.organization_id)
    external = await _deployment(db, user.organization_id, kind="external")
    foreign = await _deployment(db, (await _admin(db)).organization_id)

    def patch(sources):
        return _call(
            db,
            user,
            "PATCH",
            "/api/v1/management/gateway-settings",
            json={"inference_metrics": sources},
        )

    ok = await patch([{"deployment_id": str(internal.id), "server": "vllm"}])
    refused = [
        (await patch(sources)).status_code
        for sources in (
            [{"deployment_id": str(external.id), "server": "vllm"}],
            [{"deployment_id": str(foreign.id), "server": "vllm"}],
            [{"deployment_id": str(internal.id), "server": "vllm"}] * 2,
            [{"deployment_id": str(uuid4()), "server": "vllm"} for _ in range(65)],
            [{"deployment_id": str(internal.id), "server": "triton"}],
        )
    ]

    assert ok.status_code == 200, ok.text
    assert ok.json()["settings"]["inference_metrics"] == [
        {"deployment_id": str(internal.id), "server": "vllm", "send_credential": False}
    ]
    assert refused == [422, 422, 422, 422, 422]


@pytest.mark.asyncio
async def test_the_read_gives_shares_averages_and_utilisation(db) -> None:
    user = await _admin(db)
    vllm = await _deployment(db, user.organization_id, alias="vllm-a")
    vllm.capacity_concurrent_requests = 4
    ollama = await _deployment(db, user.organization_id, alias="ollama-a")
    quiet = await _deployment(db, user.organization_id, alias="tgi-quiet")
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    db.add_all(
        [
            InferenceMetricsHourly(
                organization_id=user.organization_id,
                deployment_id=vllm.id,
                hour=now,
                server="vllm",
                samples=10,
                busy_samples=5,
                queued_samples=2,
                running_sum=20,
                running_max=4,
                waiting_sum=5,
                waiting_max=3,
                cache_usage_sum=4.0,
                cache_usage_max=0.8,
            ),
            InferenceMetricsHourly(
                organization_id=user.organization_id,
                deployment_id=ollama.id,
                hour=now,
                server="ollama",
                samples=4,
                loaded_samples=3,
                vram_bytes_max=4_000,
            ),
        ]
    )
    await _listed(
        db,
        user,
        [
            {"deployment_id": str(vllm.id), "server": "vllm"},
            {"deployment_id": str(ollama.id), "server": "ollama"},
            {"deployment_id": str(quiet.id), "server": "tgi"},
        ],
    )
    unconfigured = await _admin(db)

    read = await _call(db, user, "GET", "/api/v1/management/inference-metrics")
    empty = await _call(db, unconfigured, "GET", "/api/v1/management/inference-metrics")
    bounds = [
        (
            await _call(
                db,
                user,
                "GET",
                "/api/v1/management/inference-metrics",
                params={"hours": h},
            )
        ).status_code
        for h in (0, 745)
    ]

    items = {item["alias"]: item for item in read.json()["items"]}
    v, o, q = items["vllm-a"], items["ollama-a"], items["tgi-quiet"]
    assert (
        v["busy_share"],
        v["queued_share"],
        v["running_avg"],
        v["running_peak"],
    ) == (0.5, 0.2, 2.0, 4)
    assert (v["cache_usage_avg"], v["cache_usage_peak"], v["utilisation"]) == (
        0.4,
        0.8,
        0.5,
    )
    assert (
        o["loaded_share"],
        o["vram_bytes_peak"],
        o["utilisation_unavailable_reason"],
    ) == (
        0.75,
        4_000,
        "server_reports_no_running",
    )
    assert (q["samples"], q["utilisation_unavailable_reason"]) == (0, "no_capacity")
    assert empty.json() == {
        "items": [],
        "unavailable_reason": "off, needs gateway setting inference_metrics",
    }
    assert bounds == [422, 422]


async def _hours(db, tenant, deployment, server, rows) -> None:
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    for index, values in enumerate(rows):
        db.add(
            InferenceMetricsHourly(
                organization_id=tenant,
                deployment_id=deployment.id,
                hour=now - timedelta(hours=index + 1),
                server=server,
                **values,
            )
        )
    await db.flush()


@pytest.mark.parametrize(
    ("samples", "busy", "server", "fires"),
    [
        (1_000, 89, "vllm", True),
        (1_000, 100, "vllm", False),
        (999, 0, "vllm", False),
        (1_000, 0, "ollama", False),
    ],
)
@pytest.mark.asyncio
async def test_the_idle_rule(db, samples, busy, server, fires) -> None:
    user = await _admin(db)
    deployment = await _deployment(db, user.organization_id)
    db.add(
        DeploymentHardwareCost(
            organization_id=user.organization_id,
            deployment_id=deployment.id,
            period=f"{datetime.now(timezone.utc):%Y-%m}",
            amount="120000.00",
            currency="TRY",
        )
    )
    await _hours(
        db,
        user.organization_id,
        deployment,
        server,
        [
            {
                "samples": samples,
                "busy_samples": busy,
                "running_max": 1,
                "cache_usage_sum": 100.0,
            }
        ],
    )

    found = await service._server_load(
        db, user.organization_id, datetime.now(timezone.utc)
    )

    idle = [d for d in found if d.rule_id == service.IDLE_INFERENCE_CAPACITY]
    assert bool(idle) == fires
    if idle:
        assert idle[0].evidence["hardware_cost_month"] == "120000.00"
        assert idle[0].evidence["currency"] == "TRY"
        assert idle[0].subject == {"deployment_id": str(deployment.id)}


@pytest.mark.parametrize(
    ("hours", "fires"),
    [
        ([{"samples": 60, "queued_samples": 40}] * 2, True),
        ([{"samples": 60, "queued_samples": 40}], False),
        ([{"samples": 29, "queued_samples": 29}] * 2, False),
    ],
)
@pytest.mark.asyncio
async def test_the_queue_rule(db, hours, fires) -> None:
    user = await _admin(db)
    deployment = await _deployment(db, user.organization_id)
    await _hours(
        db,
        user.organization_id,
        deployment,
        "tgi",
        [{**values, "waiting_max": 4, "running_max": 8} for values in hours],
    )
    other = await _admin(db)
    await _hours(
        db,
        other.organization_id,
        await _deployment(db, other.organization_id),
        "tgi",
        [{"samples": 60, "queued_samples": 60}] * 3,
    )

    found = await service._server_load(
        db, user.organization_id, datetime.now(timezone.utc)
    )

    queued = [d for d in found if d.rule_id == service.INFERENCE_QUEUE_SATURATED]
    assert bool(queued) == fires
    if queued:
        assert queued[0].evidence["saturated_hours"] == 2
        assert service.RULES[service.INFERENCE_QUEUE_SATURATED].MAX_MODE == "observe"


@pytest.mark.parametrize(
    ("page", "running", "waiting"),
    [
        ("vllm:num_requests_running inf\nvllm:num_requests_waiting 2\n", None, 2),
        ("vllm:num_requests_running -inf\nvllm:num_requests_waiting 2\n", None, 2),
        (
            "vllm:num_requests_running 1e12\nvllm:num_requests_waiting -3\n",
            2_147_483_647,
            0,
        ),
    ],
)
def test_values_a_column_cannot_hold_are_dropped_or_clamped(
    page, running, waiting
) -> None:
    sample = parse_prometheus("vllm", page)

    assert (sample.running, sample.waiting) == (running, waiting)


def test_a_vram_size_a_column_cannot_hold_is_clamped() -> None:
    huge = json.dumps({"models": [{"name": "m", "size_vram": 2**70}]})
    flag = json.dumps({"models": [{"name": "m", "size_vram": True}]})

    assert parse_ollama(huge, "m").vram_bytes == 2**63 - 1
    assert parse_ollama(flag, "m").vram_bytes is None


@pytest.mark.asyncio
async def test_a_slow_credential_read_counts_against_the_scrape_timeout(
    db, monkeypatch
) -> None:
    user = await _admin(db)
    deployment = await _deployment(db, user.organization_id)
    await _listed(db, user, [{"deployment_id": str(deployment.id), "server": "vllm"}])

    async def slow(target):
        await asyncio.sleep(10)

    monkeypatch.setattr(inference_metrics, "_credential", slow)
    monkeypatch.setattr(inference_metrics, "SCRAPE_SECONDS", 0.1)
    connection = await db.connection()
    async with httpx.AsyncClient() as client:
        await scrape_inference_metrics(
            _sessions(connection),
            client,
            now=datetime.now(timezone.utc),
            interval_seconds=6,
        )

    row = await db.scalar(
        select(InferenceMetricsHourly).where(
            InferenceMetricsHourly.deployment_id == deployment.id
        )
    )
    assert row is not None and (row.errors, row.last_error) == (1, "timeout")


@pytest.mark.asyncio
async def test_the_retention_delete_reads_an_index_on_the_hour(db) -> None:
    definition = await db.scalar(
        text(
            "SELECT indexdef FROM pg_indexes "
            "WHERE indexname = 'ix_inference_metrics_hourly_hour'"
        )
    )

    # Every pass deletes hours older than 90 days; the key leads with the tenant.
    assert definition is not None and definition.endswith("(hour)")
