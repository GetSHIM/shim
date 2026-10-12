"""Overview, latency, language cost and outcome read models."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import AwareDatetime, BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.api.enterprise_deps import READER_REQUIRED, require
from shim_enterprise.core.database import bounded_read, get_db
from shim_enterprise.observability.outcomes import OutcomeGroup, OutcomeRatesReadModel
from shim_enterprise.observability.language_cost import LanguageCostGroup, language_cost
from shim_enterprise.observability.latency import (
    LatencyBucket,
    LatencyGroup,
    latency_by_group,
)
from shim_enterprise.observability.overview import OverviewReadModel
from shim_enterprise.tenants.models import User
from shim_enterprise.api.v1.management._common import (
    _aware,
    _sync_window,
    _tenant_id,
    _validate_sync_window,
)


router = APIRouter()


class OverviewPeriodView(BaseModel):
    start: datetime
    end: datetime
    previous_start: datetime
    previous_end: datetime
    bucket: Literal["hour", "day"]


class OverviewStatusCountsView(BaseModel):
    completed: int = Field(ge=0)
    provider_error: int = Field(ge=0)
    client_disconnected: int = Field(ge=0)
    timeout: int = Field(ge=0)
    cancelled: int = Field(ge=0)
    internal_error: int = Field(ge=0)
    rejected: int = Field(ge=0)
    failed: int = Field(ge=0)


class OverviewSummaryView(BaseModel):
    requests: int = Field(ge=0)
    technical_failures: int = Field(ge=0)
    policy_rejections: int = Field(ge=0)
    technical_success_rate: float | None = Field(ge=0, le=1)
    p95_completed_shim_latency_ms: int | None = Field(
        ge=0, title="p95 completed shim latency (ms)"
    )
    settled_spend_usd: Decimal | None = Field(ge=0)
    cost_complete: bool
    unpriced_requests: int = Field(ge=0)
    status_counts: OverviewStatusCountsView


class OverviewTrendPointView(BaseModel):
    start: datetime
    requests: int = Field(ge=0)
    settled_spend_usd: Decimal | None = Field(ge=0)
    cost_complete: bool
    unpriced_requests: int = Field(ge=0)


class OverviewExceptionView(BaseModel):
    request_id: str
    occurred_at: datetime
    status: Literal[
        "provider_error",
        "client_disconnected",
        "timeout",
        "cancelled",
        "internal_error",
        "rejected",
        "failed",
    ]
    category: Literal["technical_failure", "policy_rejection", "client_cancelled"]
    provider: str | None
    model: str | None
    error_code: str | None


class OverviewSetupView(BaseModel):
    verified_provider: bool
    active_gateway_key: bool
    protection_enabled: bool
    first_successful_request: bool
    complete: bool


class OverviewDashboardView(BaseModel):
    generated_at: datetime
    period: OverviewPeriodView
    current: OverviewSummaryView
    previous: OverviewSummaryView
    trend: list[OverviewTrendPointView]
    recent_exceptions: list[OverviewExceptionView]
    setup: OverviewSetupView


@router.get("/overview", response_model=OverviewDashboardView)
async def dashboard_overview(
    start: datetime | None = Query(
        default=None,
        description="Inclusive UTC start; defaults to seven days before end.",
    ),
    end: datetime | None = Query(
        default=None,
        description="Exclusive UTC end; defaults to the current time.",
    ),
    user: User = Depends(require("usage.read", legacy_detail=READER_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> OverviewDashboardView:
    generated_at = datetime.now(timezone.utc)
    end_at = _aware(end or generated_at).astimezone(timezone.utc)
    start_at = _aware(start or end_at - timedelta(days=7)).astimezone(timezone.utc)
    if start_at >= end_at:
        raise HTTPException(status_code=422, detail="start must be before end")
    _validate_sync_window(start_at, end_at)
    duration = end_at - start_at
    previous_start_at = start_at - duration
    bucket: Literal["hour", "day"] = "hour" if duration <= timedelta(days=2) else "day"
    projection = await OverviewReadModel().read(
        session,
        tenant_id=_tenant_id(user),
        start_at=start_at,
        end_at=end_at,
        previous_start_at=previous_start_at,
        bucket=bucket,
        generated_at=generated_at,
    )
    return OverviewDashboardView(
        generated_at=generated_at,
        period=OverviewPeriodView(
            start=start_at,
            end=end_at,
            previous_start=previous_start_at,
            previous_end=start_at,
            bucket=bucket,
        ),
        current=OverviewSummaryView.model_validate(
            projection.current, from_attributes=True
        ),
        previous=OverviewSummaryView.model_validate(
            projection.previous, from_attributes=True
        ),
        trend=[
            OverviewTrendPointView.model_validate(row, from_attributes=True)
            for row in projection.trend
        ],
        recent_exceptions=[
            OverviewExceptionView.model_validate(row, from_attributes=True)
            for row in projection.recent_exceptions
        ],
        setup=OverviewSetupView.model_validate(projection.setup, from_attributes=True),
    )


class OutcomeRatesView(BaseModel):
    group: str | None = Field(
        description="The model, API key id or team id; null groups requests "
        "without a team."
    )
    name: str | None = Field(description="The API key or team name.")
    settled: int = Field(ge=0)
    complete: int = Field(ge=0)
    truncated: int = Field(ge=0)
    empty: int = Field(ge=0)
    refused: int = Field(ge=0)
    filtered: int = Field(ge=0)
    truncation_rate: float | None = Field(ge=0, le=1)
    refusal_rate: float | None = Field(
        ge=0, le=1, description="(refused + filtered + empty) / settled."
    )
    analysed: int = Field(ge=0, description="Answers the refusal analyzer read.")
    soft_refused: int = Field(ge=0)
    soft_refusal_rate: float | None = Field(ge=0, le=1)


class OutcomeRatesPage(BaseModel):
    start: datetime
    end: datetime
    group_by: OutcomeGroup
    groups: list[OutcomeRatesView]
    truncated: bool
    totals: OutcomeRatesView


class LatencyPercentiles(BaseModel):
    p50: float | None
    p95: float | None


class OutputSpeedView(BaseModel):
    p50: float | None
    count: int = Field(description="Streams the median is based on.")


class LatencyBucketView(BaseModel):
    start: datetime
    requests: int
    streams: int
    first_byte_ms: dict[Literal["stream", "json"], LatencyPercentiles]
    shim_queue_ms: LatencyPercentiles
    output_tokens_per_second: OutputSpeedView
    peak_concurrency: int
    timeouts: int
    provider_errors: int


class HeadOfLineSide(BaseModel):
    ttft_ms_p50: float | None
    streams: int


class HeadOfLineView(BaseModel):
    behind_long: HeadOfLineSide
    alone: HeadOfLineSide


class LatencyGroupView(BaseModel):
    id: str | None
    name: str | None
    requests: int
    buckets: list[LatencyBucketView]
    head_of_line: HeadOfLineView | None
    head_of_line_unavailable_reason: Literal["window_over_48h", "group_by"] | None


class LatencyView(BaseModel):
    start: datetime
    end: datetime
    group_by: LatencyGroup
    bucket: LatencyBucket
    truncated: bool
    groups: list[LatencyGroupView]


_LATENCY_WINDOWS = {"hour": timedelta(days=7), "day": timedelta(days=31)}


@router.get("/latency", response_model=LatencyView)
async def latency(
    start: AwareDatetime | None = Query(
        default=None, description="Inclusive; defaults to 24 hours before end."
    ),
    end: AwareDatetime | None = Query(
        default=None, description="Exclusive; defaults to now."
    ),
    group_by: LatencyGroup = Query(
        default="api_key",
        description="An app is an API key; apps behind one key separate by tag.",
    ),
    bucket: LatencyBucket = Query(default="hour"),
    user: User = Depends(require("usage.read", legacy_detail=READER_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    end_at = (end or datetime.now(timezone.utc)).astimezone(timezone.utc)
    start_at = (start or end_at - timedelta(hours=24)).astimezone(timezone.utc)
    if start_at >= end_at:
        raise HTTPException(status_code=422, detail="start must be before end")
    if end_at - start_at > _LATENCY_WINDOWS[bucket]:
        raise HTTPException(
            status_code=422,
            detail="hour buckets cover at most 7 days, day buckets at most 31",
        )
    async with bounded_read(session):
        return await latency_by_group(
            session,
            _tenant_id(user),
            start=start_at,
            end=end_at,
            group_by=group_by,
            bucket=bucket,
        )


class LanguageCostGroupView(BaseModel):
    id: str | None
    name: str | None


class LanguageCostItem(BaseModel):
    group: LanguageCostGroupView
    language: Literal["tr", "en"]
    requests: int
    answer_characters: int
    completion_tokens: int
    tokens_per_1000_characters: float
    ratio_p25: float
    ratio_p75: float
    output_usd_per_1000_characters: str | None
    priced_requests: int
    tr_vs_en: float | None
    comparison_unavailable_reason: Literal["not_enough_answers"] | None


class LanguageCostView(BaseModel):
    start: datetime
    end: datetime
    group_by: LanguageCostGroup
    items: list[LanguageCostItem]
    truncated: bool
    excluded: dict[str, int] = Field(
        description="Settled complete answers left out, by reason."
    )
    analysed_share: float | None = Field(
        description="Eligible answers over settled complete answers."
    )


@router.get("/language-cost", response_model=LanguageCostView)
async def read_language_cost(
    start: AwareDatetime | None = Query(
        default=None, description="Inclusive; defaults to 30 days before end."
    ),
    end: AwareDatetime | None = Query(
        default=None, description="Exclusive; defaults to now."
    ),
    group_by: LanguageCostGroup = Query(default="model"),
    user: User = Depends(require("usage.read", legacy_detail=READER_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    end_at = (end or datetime.now(timezone.utc)).astimezone(timezone.utc)
    start_at = (start or end_at - timedelta(days=30)).astimezone(timezone.utc)
    if start_at >= end_at:
        raise HTTPException(status_code=422, detail="start must be before end")
    _validate_sync_window(start_at, end_at)
    async with bounded_read(session):
        return await language_cost(
            session, _tenant_id(user), start=start_at, end=end_at, group_by=group_by
        )


@router.get("/outcomes", response_model=OutcomeRatesPage)
async def outcome_rates(
    start: datetime | None = Query(
        default=None, description="Inclusive start; defaults to seven days before end."
    ),
    end: datetime | None = Query(
        default=None, description="Exclusive end; defaults to the current time."
    ),
    group_by: OutcomeGroup = Query(default="model"),
    user: User = Depends(require("usage.read", legacy_detail=READER_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> OutcomeRatesPage:
    start_at, end_at = _sync_window(start, end, days=7)
    report = await OutcomeRatesReadModel().read(
        session,
        tenant_id=_tenant_id(user),
        start_at=start_at,
        end_at=end_at,
        group_by=group_by,
    )
    return OutcomeRatesPage.model_validate(
        {**asdict(report), "start": start_at, "end": end_at, "group_by": group_by}
    )
