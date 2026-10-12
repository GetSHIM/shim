"""Personal usage and billing usage, breakdown and export."""

from __future__ import annotations

from collections.abc import Sequence
import asyncio
import csv
from datetime import date, datetime, timezone
from decimal import Decimal
import io
import itertools
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.api.enterprise_deps import (
    READER_REQUIRED,
    get_current_user,
    require,
)
from shim_enterprise.billing.read_models import (
    MAX_BILLING_DAILY_ROWS,
    MAX_BILLING_BREAKDOWN_ROWS,
    BillingBreakdown,
    BillingBreakdownGroup,
    BillingReadModels,
    DailyUsage,
)
from shim_enterprise.compliance.reporting import (
    build_pdf,
    evidence_table,
    report_styles,
    safe_csv,
)
from shim_enterprise.core.database import get_db
from shim.gateway.contracts.ids import TenantId
from shim_enterprise.tenants.audit import (
    export_details,
    record_management_action as _audit,
)
from shim_enterprise.tenants.models import ApiKey, Team, User
from shim_enterprise.api.v1.management._common import (
    _ATTACHMENT,
    _aware,
    _BINARY,
    _own_or_administered_key,
    _sync_window,
    _tenant_id,
    _validate_sync_window,
    BillingPeriodView,
)


router = APIRouter()


_BILLING_EXPORT_RESPONSES: dict[int | str, dict[str, Any]] = {
    200: {
        "description": "CSV or PDF attachment.",
        "content": {"application/pdf": _BINARY, "text/csv": _BINARY},
        "headers": _ATTACHMENT,
    }
}


class DailyUsageView(BaseModel):
    date: date
    model: str
    request_count: int
    prompt_tokens: int
    completion_tokens: int
    cost_usd: float | None
    unpriced_requests: int = 0
    cost_complete: bool = True


class BillingUsageView(BaseModel):
    period: BillingPeriodView
    daily_usage: list[DailyUsageView]
    total_cost: float | None
    unpriced_requests: int = 0
    cost_complete: bool = True


class UsageTotalsView(BaseModel):
    requests: int
    input_tokens: int
    output_tokens: int
    cost_usd: Decimal | None
    cost_complete: bool
    unpriced_requests: int


class UsageDayView(UsageTotalsView):
    date: date


class UsageModelView(UsageTotalsView):
    model: str


class UsageKeyView(UsageTotalsView):
    api_key_id: UUID
    name: str | None
    prefix: str


class MyUsageView(BaseModel):
    period: BillingPeriodView
    totals: UsageTotalsView
    daily: list[UsageDayView]
    by_model: list[UsageModelView]
    by_api_key: list[UsageKeyView]


class BillingBreakdownRow(BaseModel):
    unpriced_requests: int = 0
    cost_complete: bool = True
    key: str = Field(min_length=1)
    label: str | None = Field(
        default=None, description="The team's current name when grouped by team_id."
    )
    request_count: int = Field(ge=0)
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    cost_usd: Decimal | None = Field(ge=0)


class BillingBreakdownView(BaseModel):
    period: BillingPeriodView
    group_by: BillingBreakdownGroup
    rows: list[BillingBreakdownRow]
    limit: int = Field(ge=1, le=500)


@router.get("/usage/mine", response_model=MyUsageView)
async def my_usage(
    start: datetime | None = Query(default=None),
    end: datetime | None = Query(default=None),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> MyUsageView:
    end_at = _aware(end or datetime.now(timezone.utc))
    start_at = _aware(
        start
        or end_at.astimezone(timezone.utc).replace(
            day=1, hour=0, minute=0, second=0, microsecond=0
        )
    )
    _validate_sync_window(start_at, end_at)
    keys = {
        key_id: (name, prefix)
        for key_id, name, prefix in await session.execute(
            select(ApiKey.id, ApiKey.name, ApiKey.prefix).where(
                ApiKey.organization_id == _tenant_id(user),
                _own_or_administered_key(user),
            )
        )
    }
    read_models = BillingReadModels()
    window = {
        "tenant_id": TenantId(_tenant_id(user)),
        "start_at": start_at,
        "end_at": end_at,
        "api_key_ids": list(keys),
    }
    daily = await read_models.daily_usage(session, **window)
    if len(daily) > MAX_BILLING_DAILY_ROWS:
        raise HTTPException(
            status_code=422,
            detail=f"synchronous usage is limited to {MAX_BILLING_DAILY_ROWS} rows",
        )
    by_model = await read_models.breakdown(
        session, **window, group_by="model", limit=None
    )
    by_key = await read_models.breakdown(
        session, **window, group_by="api_key_id", limit=None
    )
    return MyUsageView(
        period=BillingPeriodView(start=start_at, end=end_at),
        totals=UsageTotalsView(**_usage_totals(by_model)),
        daily=[
            UsageDayView(date=day, **_usage_totals(list(rows)))
            for day, rows in itertools.groupby(daily, key=lambda row: row.usage_date)
        ],
        by_model=[
            UsageModelView(model=row.key, **_usage_totals([row])) for row in by_model
        ],
        by_api_key=[
            UsageKeyView(
                api_key_id=UUID(row.key),
                name=keys[UUID(row.key)][0],
                prefix=keys[UUID(row.key)][1],
                **_usage_totals([row]),
            )
            for row in by_key
        ],
    )


def _usage_totals(rows: Sequence[BillingBreakdown | DailyUsage]) -> dict[str, Any]:
    unpriced = sum(row.unpriced_requests for row in rows)
    return {
        "requests": sum(row.request_count for row in rows),
        "input_tokens": sum(row.prompt_tokens for row in rows),
        "output_tokens": sum(row.completion_tokens for row in rows),
        "cost_usd": None
        if unpriced
        else sum((row.cost_usd for row in rows), Decimal()),
        "cost_complete": not unpriced,
        "unpriced_requests": unpriced,
    }


@router.get("/billing/usage", response_model=BillingUsageView)
async def billing_usage(
    start_date: datetime | None = Query(default=None),
    end_date: datetime | None = Query(default=None),
    user: User = Depends(require("usage.read", legacy_detail=READER_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> BillingUsageView:
    start, end = _sync_window(start_date, end_date, days=30)
    records = await BillingReadModels().daily_usage(
        session,
        tenant_id=TenantId(_tenant_id(user)),
        start_at=start,
        end_at=end,
    )
    if len(records) > MAX_BILLING_DAILY_ROWS:
        raise HTTPException(
            status_code=422,
            detail=(
                f"synchronous billing usage is limited to {MAX_BILLING_DAILY_ROWS} rows"
            ),
        )
    rows = [record.as_public_record() for record in records]
    unpriced_requests = sum(record.unpriced_requests for record in records)
    return BillingUsageView(
        period=BillingPeriodView(start=start, end=end),
        daily_usage=[DailyUsageView.model_validate(row) for row in rows],
        total_cost=None
        if unpriced_requests
        else sum(float(record.cost_usd) for record in records),
        unpriced_requests=unpriced_requests,
        cost_complete=not unpriced_requests,
    )


@router.get("/billing/breakdown", response_model=BillingBreakdownView)
async def billing_breakdown(
    start_date: datetime | None = Query(
        default=None,
        description="Inclusive timestamp; values without an offset are UTC.",
    ),
    end_date: datetime | None = Query(
        default=None,
        description="Inclusive timestamp; values without an offset are UTC.",
    ),
    group_by: BillingBreakdownGroup = Query(
        default="model",
        description=(
            "Tag grouping counts a multi-tag request once in each matching row."
        ),
    ),
    limit: int = Query(default=100, ge=1, le=500),
    user: User = Depends(require("usage.read", legacy_detail=READER_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> BillingBreakdownView:
    start, end = _sync_window(start_date, end_date, days=30)
    records = await BillingReadModels().breakdown(
        session,
        tenant_id=TenantId(_tenant_id(user)),
        start_at=start,
        end_at=end,
        group_by=group_by,
        limit=limit,
    )
    labels = await _team_labels(session, user, group_by)
    return BillingBreakdownView(
        period=BillingPeriodView(start=start, end=end),
        group_by=group_by,
        rows=[
            BillingBreakdownRow.model_validate(
                record.as_public_record() | {"label": labels.get(record.key)}
            )
            for record in records
        ],
        limit=limit,
    )


@router.get(
    "/billing/export",
    response_class=Response,
    responses=_BILLING_EXPORT_RESPONSES,
)
async def export_billing_breakdown(
    start_date: datetime | None = Query(default=None),
    end_date: datetime | None = Query(default=None),
    group_by: BillingBreakdownGroup = Query(default="model"),
    format: Literal["csv", "pdf"] = Query(default="csv"),
    user: User = Depends(require("usage.read", legacy_detail=READER_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> Response:
    start, end = _sync_window(start_date, end_date, days=30)
    records = await BillingReadModels().breakdown(
        session,
        tenant_id=TenantId(_tenant_id(user)),
        start_at=start,
        end_at=end,
        group_by=group_by,
        limit=MAX_BILLING_BREAKDOWN_ROWS + 1,
    )
    if len(records) > MAX_BILLING_BREAKDOWN_ROWS:
        raise HTTPException(
            status_code=422,
            detail=(
                "synchronous billing exports are limited to "
                f"{MAX_BILLING_BREAKDOWN_ROWS} groups"
            ),
        )
    labels = await _team_labels(session, user, group_by)
    await _audit(
        session,
        user,
        "tenant.billing_exported",
        str(_tenant_id(user)),
        details=export_details(
            start, end, rows=len(records), group_by=group_by, format=format
        ),
    )
    await session.commit()
    content = (
        _billing_breakdown_csv(records, labels)
        if format == "csv"
        else await asyncio.to_thread(
            _billing_breakdown_pdf, records, labels, group_by, start, end
        )
    )
    return Response(
        content,
        media_type="text/csv" if format == "csv" else "application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="shim_billing_{group_by}.{format}"'
        },
    )


async def _team_labels(
    session: AsyncSession, user: User, group_by: BillingBreakdownGroup
) -> dict[str, str]:
    if group_by != "team_id":
        return {}
    rows = await session.execute(
        select(Team.id, Team.name).where(Team.organization_id == _tenant_id(user))
    )
    return {str(team_id): name for team_id, name in rows}


def _billing_breakdown_csv(records: list[Any], labels: dict[str, str]) -> bytes:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        (
            "key",
            "request_count",
            "prompt_tokens",
            "completion_tokens",
            "cost_usd",
            "unpriced_requests",
            "cost_complete",
            "label",
        )
    )
    for record in records:
        writer.writerow(
            safe_csv(value)
            for value in (
                record.key,
                record.request_count,
                record.prompt_tokens,
                record.completion_tokens,
                None if record.unpriced_requests else record.cost_usd,
                record.unpriced_requests,
                record.unpriced_requests == 0,
                labels.get(record.key),
            )
        )
    return output.getvalue().encode("utf-8-sig")


def _billing_breakdown_pdf(
    records: list[Any],
    labels: dict[str, str],
    group_by: BillingBreakdownGroup,
    start: datetime,
    end: datetime,
) -> bytes:
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, Spacer

    styles = report_styles()
    return build_pdf(
        [
            Paragraph("shim Cost Showback", styles["Title"]),
            Paragraph(
                f"Group: {group_by}<br/>Period: {start:%Y-%m-%d} – {end:%Y-%m-%d}",
                styles["Normal"],
            ),
            Spacer(1, 5 * mm),
            evidence_table(
                [
                    [
                        labels.get(record.key, record.key),
                        str(record.request_count),
                        str(record.prompt_tokens + record.completion_tokens),
                        str(record.cost_usd)
                        if record.unpriced_requests == 0
                        else f"Unknown ({record.unpriced_requests} unpriced)",
                    ]
                    for record in records
                ],
                ["Group", "Requests", "Tokens", "Cost (USD)"],
            ),
        ],
        "shim Cost Showback",
    )
