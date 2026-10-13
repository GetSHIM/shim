"""The capacity forecast: busy-hour concurrency from gateway records against capacity."""

from __future__ import annotations

from datetime import datetime, time, timedelta, timezone
import math
from uuid import uuid4

import pytest

from ee.tests.aws.test_bedrock_management import _admin, _call
from ee.tests.billing.test_hardware_cost import _deployment, _key
from shim_enterprise.api.v1.management.hardware import FORECAST_DAYS, forecast_status
from shim_enterprise.billing.models import RequestLifecycle

FORECAST = "/api/v1/management/capacity/forecast"
TODAY = datetime.now(timezone.utc).date()
FIRST = TODAY - timedelta(days=FORECAST_DAYS - 1)


@pytest.mark.parametrize(
    ("days", "capacity", "peak", "slope", "intercept", "status"),
    [
        (13, 10, 1.0, 0.1, 0.0, "not_enough_data"),
        (20, None, 1.0, 0.1, 0.0, "no_capacity"),
        (20, 4, 4.0, 0.1, 0.0, "at_capacity"),
        (20, 10, 1.0, 0.0, 1.0, "not_growing"),
        (20, 10, 1.0, -0.1, 3.0, "not_growing"),
        (20, 10, 1.0, 0.001, 1.0, "beyond_horizon"),
        (20, 10, 5.0, 0.1, 0.05, "projected"),
    ],
)
def test_each_status(days, capacity, peak, slope, intercept, status) -> None:
    assert (
        forecast_status(days, capacity, peak, slope, intercept, FORECAST_DAYS - 1)[0]
        == status
    )


async def _busy(
    db, key, deployment, day_index: int, hours: float, *, failed: bool = False
) -> None:
    """One request on that day starting at 12:00, running `hours`: that hour's load."""
    start = datetime.combine(FIRST + timedelta(days=day_index), time(12), timezone.utc)
    end = start + timedelta(seconds=round(hours * 3600))
    db.add(
        RequestLifecycle(
            request_id=f"req_cap_{uuid4().hex}",
            organization_id=key.organization_id,
            actor_type="api_key",
            api_key_id=key.id,
            source_endpoint="chat.completions",
            status="failed" if failed else "completed",
            requested_model="gpu",
            stream=False,
            started_at=start,
            provider_started_at=start,
            completed_at=None if failed else end,
            failed_at=end if failed else None,
            lifecycle_metadata={"deployment_id": str(deployment.id)},
        )
    )


@pytest.mark.asyncio
async def test_a_growing_line_reaches_capacity_on_the_closed_form_day(db) -> None:
    user = await _admin(db)
    tenant = user.organization_id
    growing = await _deployment(db, tenant, alias="gpu-growing")
    growing.capacity_concurrent_requests = 10
    young = await _deployment(db, tenant, alias="gpu-young")
    young.capacity_concurrent_requests = 10
    key = await _key(db, user)
    for day in range(FORECAST_DAYS):
        # Busy hour 0.1 * day + 0.05, every other day through a failed request.
        await _busy(db, key, growing, day, 0.1 * day + 0.05, failed=day % 2 == 1)
    for day in range(FORECAST_DAYS - 13, FORECAST_DAYS):
        await _busy(db, key, young, day, 2.0)
    await db.flush()

    read = await _call(db, user, "GET", FORECAST)

    body = read.json()
    rows = {row["alias"]: row for row in body["deployments"]}
    expected = FIRST + timedelta(days=math.ceil((10 - 0.05) / 0.1))
    assert read.status_code == 200, read.text
    assert body["measure"].startswith("busy-hour average concurrency")
    assert rows["gpu-growing"] | {"deployment_id": None} == {
        "deployment_id": None,
        "alias": "gpu-growing",
        "days_with_traffic": FORECAST_DAYS,
        "current_peak": pytest.approx(0.1 * (FORECAST_DAYS - 1) + 0.05, abs=1e-3),
        "slope_per_day": pytest.approx(0.1, abs=1e-4),
        "capacity": 10,
        "capacity_source": "entered",
        "measured_peak": None,
        "measured_capacity": None,
        "projected_date": expected.isoformat(),
        "status": "projected",
    }
    assert (rows["gpu-young"]["days_with_traffic"], rows["gpu-young"]["status"]) == (
        13,
        "not_enough_data",
    )


@pytest.mark.asyncio
async def test_the_servers_own_queue_gives_a_measured_capacity(db) -> None:
    from shim_enterprise.observability.models import InferenceMetricsHourly

    user = await _admin(db)
    tenant = user.organization_id
    measured = await _deployment(db, tenant, alias="gpu-measured")
    entered = await _deployment(db, tenant, alias="gpu-entered")
    entered.capacity_concurrent_requests = 9
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    for deployment in (measured, entered):
        for hours_ago, running, queued in ((2, 3, 0), (30, 6, 10), (24 * 20, 7, 0)):
            db.add(
                InferenceMetricsHourly(
                    organization_id=tenant,
                    deployment_id=deployment.id,
                    hour=now - timedelta(hours=hours_ago),
                    server="vllm",
                    samples=60,
                    queued_samples=queued,
                    running_max=running,
                )
            )
    await db.flush()

    rows = {
        row["alias"]: row
        for row in (await _call(db, user, "GET", FORECAST)).json()["deployments"]
    }

    assert (
        rows["gpu-measured"]["measured_peak"],
        rows["gpu-measured"]["measured_capacity"],
        rows["gpu-measured"]["capacity"],
        rows["gpu-measured"]["capacity_source"],
    ) == (6, 6, 6, "measured")
    assert (
        rows["gpu-entered"]["capacity"],
        rows["gpu-entered"]["capacity_source"],
    ) == (
        9,
        "entered",
    )
