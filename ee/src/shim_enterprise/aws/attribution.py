"""What the region lock would refuse, and each team's Bedrock cost next to AWS's bill.

The attribution read groups shim's own records of Bedrock requests by day and STS
session tag (the `iamPrincipal/<tag key>` column of Cost Explorer and CUR 2.0); the
comparison takes numbers an administrator copied from AWS. shim calls no AWS
billing API and stores no AWS figure.
"""

from __future__ import annotations

import csv
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal
import io
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import Date, Integer, and_, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from shim_enterprise.api.enterprise_deps import require
from shim_enterprise.api.v1.management._common import _tenant_id
from shim_enterprise.aws.regions import (
    ceiling_allows,
    lock_reasons,
    profile_scope,
    tier_ceiling,
)
from shim_enterprise.billing.models import RequestLifecycle, UsageLedger
from shim_enterprise.compliance.reporting import safe_csv
from shim_enterprise.core.database import bounded_read, get_db
from shim_enterprise.tenants.gateway_settings import (
    BedrockRegionLock,
    GatewaySettings,
    LockMode,
    stored_settings,
)
from shim_enterprise.tenants.models import (
    ModelDeployment,
    Organization,
    OrganizationGatewaySettings,
    User,
)

router = APIRouter()
MAX_DAYS = 93
MAX_COMPARED = 5_000
UNTAGGED = "untagged"


async def _settings(session: AsyncSession, tenant_id: Any) -> GatewaySettings:
    stored = await session.scalar(
        select(OrganizationGatewaySettings.settings).where(
            OrganizationGatewaySettings.organization_id == tenant_id
        )
    )
    return GatewaySettings() if stored is None else stored_settings(stored)


class LockPreviewItem(BaseModel):
    deployment_id: str
    alias: str
    aws_region: str | None
    upstream_model: str
    scope: str
    destinations: list[str] | None
    allowed: bool
    reasons: list[Literal["scope", "region", "unknown_destinations", "ceiling"]]
    requests_7d: int


class LockPreview(BaseModel):
    lock: BedrockRegionLock
    ceiling: list[str]
    deployments: list[LockPreviewItem]


@router.get("/aws/region-lock/preview", response_model=LockPreview)
async def preview_region_lock(
    mode: LockMode | None = None,
    scopes: list[str] | None = Query(default=None),
    regions: list[str] | None = Query(default=None),
    user: User = Depends(require("settings.read")),
    session: AsyncSession = Depends(get_db),
) -> LockPreview:
    """Had this lock been on for the last 7 days: what each Bedrock deployment would
    have met. With no query, the tenant's current lock."""
    tenant_id = _tenant_id(user)
    current = (await _settings(session, tenant_id)).bedrock_region_lock
    candidate = {
        name: value
        for name, value in (("mode", mode), ("scopes", scopes), ("regions", regions))
        if value is not None
    }
    try:
        lock = BedrockRegionLock.model_validate(current.model_dump() | candidate)
    except ValidationError as error:
        raise HTTPException(
            status_code=422, detail=error.errors(include_url=False, include_input=False)
        ) from None
    organization = await session.get(Organization, tenant_id)
    ceiling = await tier_ceiling(session, organization.tier if organization else None)
    rows = list(
        await session.scalars(
            select(ModelDeployment)
            .where(
                ModelDeployment.organization_id == tenant_id,
                ModelDeployment.upstream == "aws_bedrock",
            )
            .order_by(ModelDeployment.alias)
        )
    )
    since = datetime.now(timezone.utc) - timedelta(days=7)
    deployment_id = RequestLifecycle.lifecycle_metadata["deployment_id"].as_string()
    async with bounded_read(session):
        counted = await session.execute(
            select(deployment_id, func.count())
            .where(
                RequestLifecycle.organization_id == tenant_id,
                RequestLifecycle.started_at >= since,
                deployment_id.in_([str(row.id) for row in rows]),
            )
            .group_by(deployment_id)
        )
        counts: dict[str, int] = {found: count for found, count in counted.all()}
    items = []
    for row in rows:
        scope = profile_scope(row.upstream_model)
        destinations = row.aws_destination_regions
        reasons: list[Any] = (
            [] if lock.mode == "off" else lock_reasons(lock, scope, destinations)
        )
        if not ceiling_allows(ceiling, destinations):
            reasons.append("ceiling")
        items.append(
            LockPreviewItem(
                deployment_id=str(row.id),
                alias=row.alias,
                aws_region=row.aws_region,
                upstream_model=row.upstream_model,
                scope=scope,
                destinations=destinations,
                allowed=not reasons,
                reasons=reasons,
                requests_7d=counts.get(str(row.id), 0),
            )
        )
    return LockPreview(lock=lock, ceiling=list(ceiling), deployments=items)


class AttributionRow(BaseModel):
    day: date
    session_tag: str
    region: str | None
    model: str | None
    requests: int
    prompt_tokens: int
    completion_tokens: int
    cache_read_tokens: int
    cache_write_tokens: int
    cost_usd: Decimal | None = Field(description="Null when any request is unpriced.")
    unpriced_requests: int


class Attribution(BaseModel):
    tag_key: str
    aws_column: str = Field(description="The Cost Explorer and CUR 2.0 column.")
    rows: list[AttributionRow]


def _range(start: date, end: date) -> tuple[datetime, datetime]:
    if end < start or (end - start).days >= MAX_DAYS:
        raise HTTPException(
            status_code=422, detail=f"from and to span 1 to {MAX_DAYS} UTC days"
        )
    return (
        datetime.combine(start, time(), timezone.utc),
        datetime.combine(end + timedelta(days=1), time(), timezone.utc),
    )


async def _attribution_rows(
    session: AsyncSession, tenant_id: Any, start: date, end: date
) -> list[AttributionRow]:
    lower, upper = _range(start, end)
    record = RequestLifecycle.lifecycle_metadata["aws_bedrock"]
    pricing = UsageLedger.event_metadata["pricing"]
    day = cast(func.timezone("UTC", RequestLifecycle.started_at), Date)
    tag = func.coalesce(record["session_tag"].as_string(), UNTAGGED)
    region, model = record["region"].as_string(), record["model"].as_string()
    unpriced = func.count(UsageLedger.id).filter(
        pricing["pricing_resolution"].as_string() == "unknown"
    )

    def tokens(name: str) -> Any:
        return func.coalesce(func.sum(cast(pricing[name].as_string(), Integer)), 0)

    # Token counts are settled on the quota row, cost and the cache split on the
    # spend row; a request has at most one of each.
    quota = aliased(UsageLedger)

    statement = (
        select(
            day,
            tag,
            region,
            model,
            func.count(RequestLifecycle.request_id),
            func.coalesce(func.sum(quota.prompt_tokens), 0),
            func.coalesce(func.sum(quota.completion_tokens), 0),
            tokens("cache_read_tokens"),
            tokens("cache_write_tokens") + tokens("cache_write_1h_tokens"),
            func.coalesce(func.sum(UsageLedger.cost_usd), 0),
            unpriced,
        )
        .select_from(RequestLifecycle)
        .outerjoin(
            UsageLedger,
            and_(
                UsageLedger.organization_id == RequestLifecycle.organization_id,
                UsageLedger.request_id == RequestLifecycle.request_id,
                UsageLedger.event_type == "spend_settlement",
            ),
        )
        .outerjoin(
            quota,
            and_(
                quota.organization_id == RequestLifecycle.organization_id,
                quota.request_id == RequestLifecycle.request_id,
                quota.event_type == "quota_settlement",
            ),
        )
        .where(
            RequestLifecycle.organization_id == tenant_id,
            RequestLifecycle.lifecycle_metadata.has_key("aws_bedrock"),
            RequestLifecycle.started_at >= lower,
            RequestLifecycle.started_at < upper,
        )
        .group_by(day, tag, region, model)
        .order_by(day, tag, region, model)
    )
    async with bounded_read(session):
        found = (await session.execute(statement)).all()
    return [
        AttributionRow(
            day=row[0],
            session_tag=row[1],
            region=row[2],
            model=row[3],
            requests=row[4],
            prompt_tokens=row[5],
            completion_tokens=row[6],
            cache_read_tokens=row[7],
            cache_write_tokens=row[8],
            cost_usd=None if row[10] else row[9],
            unpriced_requests=row[10],
        )
        for row in found
    ]


@router.get("/aws/attribution", response_model=Attribution)
async def bedrock_attribution(
    start: date = Query(alias="from"),
    end: date = Query(alias="to"),
    format: Literal["json", "csv"] = "json",
    user: User = Depends(require("usage.read")),
    session: AsyncSession = Depends(get_db),
) -> Any:
    tenant_id = _tenant_id(user)
    tag_key = (await _settings(session, tenant_id)).bedrock_attribution.tag_key
    rows = await _attribution_rows(session, tenant_id, start, end)
    if format == "csv":
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(list(AttributionRow.model_fields))
        for row in rows:
            writer.writerow(map(safe_csv, row.model_dump(mode="json").values()))
        return Response(out.getvalue(), media_type="text/csv")
    return Attribution(tag_key=tag_key, aws_column=f"iamPrincipal/{tag_key}", rows=rows)


class AwsCost(BaseModel):
    model_config = ConfigDict(extra="forbid")

    day: date
    tag: str = Field(min_length=1, max_length=256)
    usd: Decimal = Field(ge=0, max_digits=18, decimal_places=8)


class CompareInput(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    start: date = Field(alias="from")
    end: date = Field(alias="to")
    rows: list[AwsCost] = Field(max_length=MAX_COMPARED)


class ComparedRow(BaseModel):
    day: date
    tag: str
    shim_usd: Decimal
    aws_usd: Decimal
    difference_usd: Decimal
    ratio: Decimal | None = Field(
        description="aws_usd / shim_usd; null when shim is 0."
    )


class DayTag(BaseModel):
    day: date
    tag: str


class Comparison(BaseModel):
    rows: list[ComparedRow]
    only_in_shim: list[DayTag]
    only_in_aws: list[DayTag]


@router.post("/aws/attribution/compare", response_model=Comparison)
async def compare_bedrock_attribution(
    payload: CompareInput,
    user: User = Depends(require("usage.read")),
    session: AsyncSession = Depends(get_db),
) -> Comparison:
    """shim's settled cost per day and tag next to the numbers copied from AWS."""
    outside = [
        row.day for row in payload.rows if not payload.start <= row.day <= payload.end
    ]
    if outside:
        raise HTTPException(
            status_code=422,
            detail=f"days outside from and to: {sorted(set(outside))[:5]}",
        )
    shim: dict[tuple[date, str], Decimal] = {}
    for row in await _attribution_rows(
        session, _tenant_id(user), payload.start, payload.end
    ):
        key = (row.day, row.session_tag)
        shim[key] = shim.get(key, Decimal(0)) + (row.cost_usd or Decimal(0))
    aws: dict[tuple[date, str], Decimal] = {}
    for row in payload.rows:
        aws[(row.day, row.tag)] = aws.get((row.day, row.tag), Decimal(0)) + row.usd
    both = sorted(shim.keys() & aws.keys())
    return Comparison(
        rows=[
            ComparedRow(
                day=day,
                tag=tag,
                shim_usd=shim[(day, tag)],
                aws_usd=aws[(day, tag)],
                difference_usd=shim[(day, tag)] - aws[(day, tag)],
                ratio=None
                if not shim[(day, tag)]
                else aws[(day, tag)] / shim[(day, tag)],
            )
            for day, tag in both
        ],
        only_in_shim=[
            DayTag(day=d, tag=t) for d, t in sorted(shim.keys() - aws.keys())
        ],
        only_in_aws=[DayTag(day=d, tag=t) for d, t in sorted(aws.keys() - shim.keys())],
    )
