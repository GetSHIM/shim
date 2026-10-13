"""Hardware cost of internal deployments, shared out by tokens, and a capacity forecast.

The cost is what the admin enters per month and deployment, in its own currency.
The allocation is a report: it never settles a price, and it never adds amounts of
different currencies. The forecast reads only gateway records and says what it
measures.
"""

from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone
from decimal import ROUND_FLOOR, Decimal
import math
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Date, Integer, Text, and_, case, cast, func, literal, select
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.api.enterprise_deps import ADMIN_REQUIRED, READER_REQUIRED, require
from shim_enterprise.api.v1.management._common import _tenant_id
from shim_enterprise.billing.models import RequestLifecycle, UsageLedger
from shim_enterprise.core.database import bounded_read, get_db
from shim_enterprise.tenants.audit import record_management_action as _audit
from shim_enterprise.tenants.models import (
    ApiKey,
    DeploymentHardwareCost,
    ModelDeployment,
    Team,
    User,
)

router = APIRouter()
PERIOD = r"^[0-9]{4}-(0[1-9]|1[0-2])$"
CARRY_MONTHS = 12
REPORT_MONTHS = 24
FORECAST_DAYS = 56
MIN_TRAFFIC_DAYS = 14
HORIZON_DAYS = 365
MEASURE = (
    "busy-hour average concurrency from gateway records; instantaneous peaks are higher"
)


def _month(period: str) -> date:
    return date(int(period[:4]), int(period[5:]), 1)


def _shift(month: date, months: int) -> date:
    index = month.year * 12 + month.month - 1 + months
    return date(index // 12, index % 12 + 1, 1)


def _period(month: date) -> str:
    return f"{month:%Y-%m}"


class HardwareCostInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    amount: Decimal = Field(gt=0, max_digits=18, decimal_places=2)
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    note: str | None = Field(default=None, max_length=200)


class HardwareCostView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    period: str
    amount: Decimal
    currency: str
    note: str | None
    entered_by: str | None
    updated_at: datetime


async def _internal_deployment(
    session: AsyncSession, user: User, deployment_id: UUID, *, write: bool
) -> ModelDeployment:
    row = await session.scalar(
        select(ModelDeployment).where(
            ModelDeployment.organization_id == _tenant_id(user),
            ModelDeployment.id == deployment_id,
        )
    )
    if row is None:
        raise HTTPException(404, detail="Model deployment not found")
    if write and row.deployment_kind != "internal":
        raise HTTPException(
            422, detail="Hardware cost is entered for internal deployments only"
        )
    return row


def _cost_details(row: DeploymentHardwareCost | None) -> dict[str, str] | None:
    return (
        None if row is None else {"amount": str(row.amount), "currency": row.currency}
    )


async def _entry(
    session: AsyncSession, user: User, deployment_id: UUID, period: str
) -> DeploymentHardwareCost | None:
    return await session.scalar(
        select(DeploymentHardwareCost)
        .where(
            DeploymentHardwareCost.organization_id == _tenant_id(user),
            DeploymentHardwareCost.deployment_id == deployment_id,
            DeploymentHardwareCost.period == period,
        )
        .with_for_update()
    )


@router.get(
    "/model-deployments/{deployment_id}/hardware-costs",
    response_model=list[HardwareCostView],
)
async def list_hardware_costs(
    deployment_id: UUID,
    user: User = Depends(require("deployments.read", legacy_detail=READER_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> list[DeploymentHardwareCost]:
    await _internal_deployment(session, user, deployment_id, write=False)
    return list(
        await session.scalars(
            select(DeploymentHardwareCost)
            .where(
                DeploymentHardwareCost.organization_id == _tenant_id(user),
                DeploymentHardwareCost.deployment_id == deployment_id,
            )
            .order_by(DeploymentHardwareCost.period.desc())
        )
    )


@router.put(
    "/model-deployments/{deployment_id}/hardware-costs/{period}",
    response_model=HardwareCostView,
)
async def set_hardware_cost(
    deployment_id: UUID,
    payload: HardwareCostInput,
    period: str = Path(pattern=PERIOD),
    user: User = Depends(require("deployments.manage", legacy_detail=ADMIN_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> DeploymentHardwareCost:
    await _internal_deployment(session, user, deployment_id, write=True)
    row = await _entry(session, user, deployment_id, period)
    before = _cost_details(row)
    if row is None:
        row = DeploymentHardwareCost(
            organization_id=_tenant_id(user), deployment_id=deployment_id, period=period
        )
        session.add(row)
    row.amount, row.currency, row.note = payload.amount, payload.currency, payload.note
    row.entered_by = str(user.id)
    await session.flush()
    await _audit(
        session,
        user,
        "tenant.deployment_hardware_cost_set",
        str(deployment_id),
        details={"period": period, "before": before, "after": _cost_details(row)},
    )
    await session.commit()
    await session.refresh(row)
    return row


@router.delete(
    "/model-deployments/{deployment_id}/hardware-costs/{period}",
    status_code=204,
    response_model=None,
)
async def delete_hardware_cost(
    deployment_id: UUID,
    period: str = Path(pattern=PERIOD),
    user: User = Depends(require("deployments.manage", legacy_detail=ADMIN_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> Response:
    await _internal_deployment(session, user, deployment_id, write=False)
    row = await _entry(session, user, deployment_id, period)
    if row is None:
        raise HTTPException(404, detail="No hardware cost for this period")
    before = _cost_details(row)
    await session.delete(row)
    await _audit(
        session,
        user,
        "tenant.deployment_hardware_cost_deleted",
        str(deployment_id),
        details={"period": period, "before": before, "after": None},
    )
    await session.commit()
    return Response(status_code=204)


def largest_remainder(
    total: Decimal, weights: list[tuple[Any, int]]
) -> dict[Any, Decimal]:
    """`total` split by weight into cents that sum exactly to it; the leftover cents
    go to the largest remainders, ties to the smaller key."""
    cents = int(total * 100)
    whole = sum(weight for _, weight in weights)
    shares = {key: Decimal(cents) * weight / whole for key, weight in weights}
    floors = {
        key: int(share.to_integral_value(ROUND_FLOOR)) for key, share in shares.items()
    }
    leftover = cents - sum(floors.values())
    order = sorted(shares, key=lambda key: (-(shares[key] - floors[key]), key))
    for key in order[:leftover]:
        floors[key] += 1
    return {key: Decimal(value).scaleb(-2) for key, value in floors.items()}


class KeyShare(BaseModel):
    api_key_id: UUID | None
    name: str | None
    team_id: UUID | None
    tokens: int
    share: float
    amount: Decimal


class TeamShare(BaseModel):
    team_id: UUID | None
    name: str = Field(description='The team, or "no team".')
    tokens: int
    share: float
    amount: Decimal


class DeploymentAllocation(BaseModel):
    deployment_id: UUID
    alias: str
    amount: Decimal
    currency: str
    carried_from: str | None = Field(
        description="The earlier month whose entry applies, when this one has none."
    )
    tokens: int
    estimated_share: float
    by_key: list[KeyShare]
    by_team: list[TeamShare]
    unattributed: Decimal | None = Field(
        description="The whole amount, when the deployment served no tokens."
    )


class CurrencyTotal(BaseModel):
    currency: str
    amount: Decimal


class HardwareAllocation(BaseModel):
    period: str
    allocation: Literal["tokens"] = "tokens"
    attributed_since: datetime | None = Field(
        description="The earliest request of the month that names its deployment."
    )
    deployments: list[DeploymentAllocation]
    totals: list[CurrencyTotal] = Field(description="One per currency; never summed.")


@router.get("/cost/hardware", response_model=HardwareAllocation)
async def hardware_allocation(
    period: str = Query(pattern=PERIOD),
    user: User = Depends(require("usage.read", legacy_detail=READER_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> HardwareAllocation:
    """Each internal deployment's hardware cost for the month, shared by tokens."""
    tenant_id = _tenant_id(user)
    month = _month(period)
    current = date.today().replace(day=1)
    if month > current or month < _shift(current, -REPORT_MONTHS):
        raise HTTPException(
            422,
            detail=f"period is the current month or one of the last {REPORT_MONTHS}",
        )
    entries = await session.execute(
        select(DeploymentHardwareCost, ModelDeployment.alias)
        .join(
            ModelDeployment, ModelDeployment.id == DeploymentHardwareCost.deployment_id
        )
        .where(
            DeploymentHardwareCost.organization_id == tenant_id,
            ModelDeployment.deployment_kind == "internal",
            DeploymentHardwareCost.period <= period,
            DeploymentHardwareCost.period >= _period(_shift(month, -CARRY_MONTHS)),
        )
        .order_by(DeploymentHardwareCost.period.desc())
    )
    costs: dict[UUID, tuple[DeploymentHardwareCost, str]] = {}
    for entry, alias in entries.all():
        costs.setdefault(entry.deployment_id, (entry, alias))
    start = datetime.combine(month, time(), timezone.utc)
    end = datetime.combine(_shift(month, 1), time(), timezone.utc)
    deployment_id = RequestLifecycle.lifecycle_metadata["deployment_id"].as_string()
    team_id = RequestLifecycle.lifecycle_metadata["team_id"].as_string()
    tokens = UsageLedger.prompt_tokens + UsageLedger.completion_tokens
    rows = []
    if costs:
        async with bounded_read(session):
            rows = (
                await session.execute(
                    select(
                        deployment_id,
                        RequestLifecycle.api_key_id,
                        ApiKey.name,
                        team_id,
                        Team.name,
                        func.sum(tokens),
                        func.sum(case((UsageLedger.estimated, tokens), else_=0)),
                        func.min(RequestLifecycle.started_at),
                    )
                    .join(
                        UsageLedger,
                        and_(
                            UsageLedger.organization_id
                            == RequestLifecycle.organization_id,
                            UsageLedger.request_id == RequestLifecycle.request_id,
                            # Settled token counts live on the quota settlement.
                            UsageLedger.event_type == "quota_settlement",
                        ),
                    )
                    .outerjoin(ApiKey, ApiKey.id == RequestLifecycle.api_key_id)
                    .outerjoin(
                        Team,
                        and_(
                            Team.organization_id == RequestLifecycle.organization_id,
                            cast(Team.id, Text) == team_id,
                        ),
                    )
                    .where(
                        RequestLifecycle.organization_id == tenant_id,
                        RequestLifecycle.started_at >= start,
                        RequestLifecycle.started_at < end,
                        deployment_id.in_([str(key) for key in costs]),
                    )
                    .group_by(
                        deployment_id,
                        RequestLifecycle.api_key_id,
                        ApiKey.name,
                        team_id,
                        Team.name,
                    )
                )
            ).all()
    attributed_since = min((row[7] for row in rows), default=None)
    reports = []
    for deployment, (entry, alias) in sorted(
        costs.items(), key=lambda item: item[1][1]
    ):
        mine = [row for row in rows if row[0] == str(deployment)]
        total = sum(int(row[5]) for row in mine)
        estimated = sum(int(row[6]) for row in mine)
        groups = [
            ((str(row[1] or ""), str(row[3] or "")), int(row[5]))
            for row in mine
            if int(row[5]) > 0
        ]
        split = largest_remainder(entry.amount, groups) if total else {}
        keys: dict[str, KeyShare] = {}
        teams: dict[str, TeamShare] = {}
        for row in mine:
            group = (str(row[1] or ""), str(row[3] or ""))
            amount = split.get(group, Decimal(0))
            found = keys.setdefault(
                group[0],
                KeyShare(
                    api_key_id=row[1],
                    name=row[2],
                    team_id=UUID(row[3]) if row[3] else None,
                    tokens=0,
                    share=0,
                    amount=Decimal(0),
                ),
            )
            found.tokens += int(row[5])
            found.amount += amount
            team = teams.setdefault(
                group[1],
                TeamShare(
                    team_id=UUID(row[3]) if row[3] else None,
                    name=row[4] or "no team",
                    tokens=0,
                    share=0,
                    amount=Decimal(0),
                ),
            )
            team.tokens += int(row[5])
            team.amount += amount
        key_shares = sorted(keys.values(), key=lambda share: -share.tokens)
        team_shares = sorted(teams.values(), key=lambda share: -share.tokens)
        for share in (*key_shares, *team_shares):
            share.share = share.tokens / total if total else 0
        reports.append(
            DeploymentAllocation(
                deployment_id=deployment,
                alias=alias,
                amount=entry.amount,
                currency=entry.currency,
                carried_from=None if entry.period == period else entry.period,
                tokens=total,
                estimated_share=estimated / total if total else 0,
                by_key=key_shares,
                by_team=team_shares,
                unattributed=None if total else entry.amount,
            )
        )
    totals: dict[str, Decimal] = {}
    for report in reports:
        totals[report.currency] = (
            totals.get(report.currency, Decimal(0)) + report.amount
        )
    return HardwareAllocation(
        period=period,
        attributed_since=attributed_since,
        deployments=reports,
        totals=[CurrencyTotal(currency=c, amount=a) for c, a in sorted(totals.items())],
    )


ForecastStatus = Literal[
    "not_enough_data",
    "no_capacity",
    "at_capacity",
    "not_growing",
    "projected",
    "beyond_horizon",
]


class DeploymentForecast(BaseModel):
    deployment_id: UUID
    alias: str
    days_with_traffic: int
    current_peak: float = Field(description="The busiest hour of the last 7 days.")
    slope_per_day: float | None
    capacity: int | None
    capacity_source: Literal["entered"] | None
    projected_date: date | None
    status: ForecastStatus


class CapacityForecast(BaseModel):
    measure: str = MEASURE
    window_days: int = FORECAST_DAYS
    deployments: list[DeploymentForecast]


def forecast_status(
    days_with_traffic: int,
    capacity: int | None,
    current_peak: float,
    slope: float | None,
    intercept: float | None,
    today_index: int,
) -> tuple[ForecastStatus, int | None]:
    """The status and, when projected, the day index the fitted line reaches capacity."""
    if days_with_traffic < MIN_TRAFFIC_DAYS:
        return "not_enough_data", None
    if capacity is None:
        return "no_capacity", None
    if current_peak >= capacity:
        return "at_capacity", None
    if slope is None or intercept is None or slope <= 0:
        return "not_growing", None
    reached = max(today_index, math.ceil((capacity - intercept) / slope))
    if reached - today_index > HORIZON_DAYS:
        return "beyond_horizon", None
    return "projected", reached


@router.get("/capacity/forecast", response_model=CapacityForecast)
async def capacity_forecast(
    user: User = Depends(require("usage.read", legacy_detail=READER_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> CapacityForecast:
    """Per internal deployment: the daily busy hour over 56 days, its trend, and
    when the trend reaches the entered capacity."""
    tenant_id = _tenant_id(user)
    deployments = list(
        await session.scalars(
            select(ModelDeployment)
            .where(
                ModelDeployment.organization_id == tenant_id,
                ModelDeployment.deployment_kind == "internal",
            )
            .order_by(ModelDeployment.alias)
        )
    )
    today = datetime.now(timezone.utc).date()
    first = today - timedelta(days=FORECAST_DAYS - 1)
    ended = func.coalesce(RequestLifecycle.completed_at, RequestLifecycle.failed_at)
    deployment_id = RequestLifecycle.lifecycle_metadata["deployment_id"].as_string()
    started = func.timezone("UTC", RequestLifecycle.provider_started_at)
    hour = func.date_trunc("hour", started)
    hourly = (
        select(
            deployment_id.label("deployment"),
            cast(started, Date).label("day"),
            (
                func.sum(
                    func.extract("epoch", ended - RequestLifecycle.provider_started_at)
                )
                / 3600.0
            ).label("load"),
        )
        .where(
            RequestLifecycle.organization_id == tenant_id,
            RequestLifecycle.started_at
            >= datetime.combine(first, time(), timezone.utc),
            RequestLifecycle.provider_started_at.is_not(None),
            ended.is_not(None),
            deployment_id.in_([str(row.id) for row in deployments]),
        )
        # Each request's duration counts in the hour it started.
        .group_by(deployment_id, cast(started, Date), hour)
        .subquery()
    )
    # A day's value is its busiest hour.
    daily = (
        select(
            hourly.c.deployment,
            hourly.c.day,
            func.max(hourly.c.load).label("peak"),
        )
        .group_by(hourly.c.deployment, hourly.c.day)
        .subquery()
    )
    days = select(
        func.generate_series(first, today, timedelta(days=1)).label("day")
    ).subquery()
    fits: dict[str, Any] = {}
    if deployments:
        listed = (
            select(
                func.unnest(
                    literal([str(row.id) for row in deployments], type_=ARRAY(Text))
                ).label("deployment")
            )
        ).subquery()
        grid = (
            select(
                listed.c.deployment,
                cast(days.c.day, Date).label("day"),
                func.coalesce(daily.c.peak, 0).label("peak"),
                (daily.c.peak.is_not(None)).label("traffic"),
            )
            .select_from(listed.join(days, literal(True)))
            .outerjoin(
                daily,
                and_(
                    daily.c.deployment == listed.c.deployment,
                    daily.c.day == cast(days.c.day, Date),
                ),
            )
            .subquery()
        )
        number = cast(grid.c.day - first, Integer)
        async with bounded_read(session):
            fits = {
                row.deployment: row
                for row in await session.execute(
                    select(
                        grid.c.deployment,
                        func.count().filter(grid.c.traffic).label("traffic_days"),
                        func.max(grid.c.peak)
                        .filter(grid.c.day >= today - timedelta(days=6))
                        .label("current_peak"),
                        func.regr_slope(grid.c.peak, number).label("slope"),
                        func.regr_intercept(grid.c.peak, number).label("intercept"),
                    ).group_by(grid.c.deployment)
                )
            }
    today_index = FORECAST_DAYS - 1
    reports = []
    for row in deployments:
        fit = fits.get(str(row.id))
        traffic_days = int(fit.traffic_days) if fit else 0
        peak = float(fit.current_peak or 0) if fit else 0.0
        slope = float(fit.slope) if fit and fit.slope is not None else None
        intercept = float(fit.intercept) if fit and fit.intercept is not None else None
        status, reached = forecast_status(
            traffic_days,
            row.capacity_concurrent_requests,
            peak,
            slope,
            intercept,
            today_index,
        )
        reports.append(
            DeploymentForecast(
                deployment_id=row.id,
                alias=row.alias,
                days_with_traffic=traffic_days,
                current_peak=round(peak, 4),
                slope_per_day=None if slope is None else round(slope, 6),
                capacity=row.capacity_concurrent_requests,
                capacity_source=None
                if row.capacity_concurrent_requests is None
                else "entered",
                projected_date=None
                if reached is None
                else first + timedelta(days=reached),
                status=status,
            )
        )
    return CapacityForecast(deployments=reports)
