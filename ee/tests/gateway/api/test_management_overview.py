from datetime import datetime, timedelta, timezone
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.dialects import postgresql

from shim_enterprise.api.v1 import management
from shim_enterprise.core.database import get_db
from shim_enterprise.observability.overview import (
    OverviewProjection,
    OverviewReadModel,
    OverviewSetupRecord,
    OverviewSummaryRecord,
    _exceptions_statement,
    _exception_category,
    _fill_trend,
    _setup_statement,
    _summary_from_row,
    _summary_statement,
    _trend_statement,
)


def _empty_summary() -> OverviewSummaryRecord:
    return OverviewSummaryRecord(
        requests=0,
        technical_failures=0,
        policy_rejections=0,
        technical_success_rate=None,
        p95_completed_latency_ms=None,
        settled_spend_usd=Decimal("0"),
        status_counts={
            "completed": 0,
            "provider_error": 0,
            "client_disconnected": 0,
            "timeout": 0,
            "cancelled": 0,
            "internal_error": 0,
            "rejected": 0,
            "failed": 0,
        },
    )


def _application() -> FastAPI:
    application = FastAPI()
    application.include_router(management.router, prefix="/api/v1/management")
    application.dependency_overrides[get_db] = lambda: AsyncMock()
    return application


def test_overview_metric_definitions_exclude_policy_and_client_outcomes() -> None:
    row = SimpleNamespace(
        requests=13,
        completed=6,
        provider_error=1,
        client_disconnected=1,
        timeout=0,
        cancelled=1,
        internal_error=1,
        rejected=1,
        failed=2,
        policy_failed=1,
        p95_completed_latency_ms=401.2,
        settled_spend_usd=Decimal("1.25000000"),
    )

    summary = _summary_from_row(row)

    assert summary.requests == 13
    assert summary.technical_failures == 3
    assert summary.policy_rejections == 2
    assert summary.technical_success_rate == pytest.approx(6 / 9)
    assert summary.p95_completed_latency_ms == 401
    assert summary.settled_spend_usd == Decimal("1.25000000")
    assert _exception_category("failed", spend_denied=True) == "policy_rejection"
    assert _exception_category("client_disconnected", False) == "client_cancelled"
    assert _exception_category("provider_error", False) == "technical_failure"


def test_overview_trend_zero_fills_utc_buckets() -> None:
    rows = [
        SimpleNamespace(
            start=datetime(2026, 8, 2),
            requests=2,
            settled_spend_usd=Decimal("0.5"),
        )
    ]

    trend = _fill_trend(
        rows,
        datetime(2026, 8, 1, tzinfo=timezone.utc),
        datetime(2026, 8, 4, tzinfo=timezone.utc),
        "day",
    )

    assert [point.start.isoformat() for point in trend] == [
        "2026-08-01T00:00:00+00:00",
        "2026-08-02T00:00:00+00:00",
        "2026-08-03T00:00:00+00:00",
    ]
    assert [point.requests for point in trend] == [0, 2, 0]


def test_overview_trend_does_not_label_partial_bucket_before_period() -> None:
    start = datetime(2026, 8, 1, 12, 30, tzinfo=timezone.utc)

    trend = _fill_trend(
        [],
        start,
        datetime(2026, 8, 2, 12, 30, tzinfo=timezone.utc),
        "day",
    )

    assert trend[0].start == start


def test_overview_summary_query_is_tenant_scoped_and_uses_denial_exists() -> None:
    tenant_id = uuid4()
    statement = _summary_statement(
        tenant_id,
        datetime(2026, 8, 1, tzinfo=timezone.utc),
        datetime(2026, 8, 8, tzinfo=timezone.utc),
    )
    compiled = statement.compile(dialect=postgresql.dialect())
    sql = str(compiled)

    assert "request_lifecycle.organization_id =" in sql
    assert "request_lifecycle.reconciled_at >=" in sql
    assert "request_lifecycle.reconciled_at <" in sql
    assert "request_lifecycle.source_endpoint !=" in sql
    assert "usage_ledger.event_type =" in sql
    assert "spend_settlement" in compiled.params.values()
    assert "percentile_cont" in sql
    assert "EXISTS (SELECT audit_intent.id" in sql
    assert "audit_intent.request_id = request_lifecycle.request_id" in sql
    assert "JOIN audit_intent" not in sql
    assert all(
        value == tenant_id
        for name, value in compiled.params.items()
        if name.startswith("organization_id")
    )


def test_every_overview_query_uses_only_the_authenticated_tenant() -> None:
    tenant_id = uuid4()
    start = datetime(2026, 8, 1, tzinfo=timezone.utc)
    end = datetime(2026, 8, 8, tzinfo=timezone.utc)

    for statement in (
        _trend_statement(tenant_id, start, end, "day"),
        _exceptions_statement(tenant_id, start, end),
        _setup_statement(tenant_id, end),
    ):
        compiled = statement.compile(dialect=postgresql.dialect())
        organization_ids = [
            value
            for name, value in compiled.params.items()
            if name.startswith("organization_id")
        ]
        assert organization_ids
        assert set(organization_ids) == {tenant_id}


@pytest.mark.asyncio
async def test_overview_requires_jwt_authentication() -> None:
    async with AsyncClient(
        transport=ASGITransport(app=_application()), base_url="http://test"
    ) as client:
        response = await client.get("/api/v1/management/overview")

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_overview_uses_authenticated_users_tenant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant_id = uuid4()
    application = _application()
    application.dependency_overrides[management.get_current_user] = lambda: (
        SimpleNamespace(organization_id=tenant_id, role="member")
    )
    projection = OverviewProjection(
        current=_empty_summary(),
        previous=_empty_summary(),
        trend=[],
        recent_exceptions=[],
        setup=OverviewSetupRecord(False, False, False, False),
    )
    read = AsyncMock(return_value=projection)
    monkeypatch.setattr(OverviewReadModel, "read", read)

    async with AsyncClient(
        transport=ASGITransport(app=application), base_url="http://test"
    ) as client:
        response = await client.get(
            "/api/v1/management/overview",
            params={"start": "2026-08-01T00:00:00Z", "end": "2026-08-08T00:00:00Z"},
        )

    assert response.status_code == 200
    assert response.json()["period"] == {
        "start": "2026-08-01T00:00:00Z",
        "end": "2026-08-08T00:00:00Z",
        "previous_start": "2026-07-25T00:00:00Z",
        "previous_end": "2026-08-01T00:00:00Z",
        "bucket": "day",
    }
    assert response.json()["current"]["settled_spend_usd"] == "0"
    assert response.json()["setup"]["complete"] is False
    assert read.await_args.kwargs["tenant_id"] == tenant_id


@pytest.mark.asyncio
async def test_overview_normalizes_offset_boundaries_to_utc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    application = _application()
    application.dependency_overrides[management.get_current_user] = lambda: (
        SimpleNamespace(organization_id=uuid4(), role="member")
    )
    projection = OverviewProjection(
        current=_empty_summary(),
        previous=_empty_summary(),
        trend=[],
        recent_exceptions=[],
        setup=OverviewSetupRecord(False, False, False, False),
    )
    monkeypatch.setattr(OverviewReadModel, "read", AsyncMock(return_value=projection))

    async with AsyncClient(
        transport=ASGITransport(app=application), base_url="http://test"
    ) as client:
        response = await client.get(
            "/api/v1/management/overview",
            params={
                "start": "2026-08-01T03:00:00+03:00",
                "end": "2026-08-08T03:00:00+03:00",
            },
        )

    assert response.status_code == 200
    assert response.json()["period"]["start"] == "2026-08-01T00:00:00Z"
    assert response.json()["period"]["end"] == "2026-08-08T00:00:00Z"


@pytest.mark.asyncio
@pytest.mark.parametrize("days", [0, 32])
async def test_overview_rejects_invalid_windows_before_query(
    monkeypatch: pytest.MonkeyPatch,
    days: int,
) -> None:
    application = _application()
    application.dependency_overrides[management.get_current_user] = lambda: (
        SimpleNamespace(organization_id=uuid4(), role="member")
    )
    read = AsyncMock()
    monkeypatch.setattr(OverviewReadModel, "read", read)
    end = datetime(2026, 8, 8, tzinfo=timezone.utc)

    async with AsyncClient(
        transport=ASGITransport(app=application), base_url="http://test"
    ) as client:
        response = await client.get(
            "/api/v1/management/overview",
            params={
                "start": (end - timedelta(days=days)).isoformat(),
                "end": end.isoformat(),
            },
        )

    assert response.status_code == 422
    read.assert_not_awaited()
