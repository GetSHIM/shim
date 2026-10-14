"""The reviews of archived requests: what was read, against which questions, with what result."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import AwareDatetime, BaseModel, ConfigDict
from sqlalchemy import Float, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.api.enterprise_deps import require
from shim_enterprise.api.v1.management._common import _tenant_id
from shim_enterprise.core.database import get_db
from shim_enterprise.billing.models import RequestLifecycle, UsageLedger
from shim_enterprise.semantic.live import counter_key
from shim_enterprise.semantic.models import SemanticReview
from shim_enterprise.tenants.gateway_settings import stored_settings
from shim_enterprise.tenants.models import OrganizationGatewaySettings, User

router = APIRouter(prefix="/management/semantic-reviews", tags=["findings"])
MAX_WINDOW = timedelta(days=31)
ReviewStatus = Literal[
    "pending",
    "matched",
    "clear",
    "invalid_answer",
    "failed",
    "skipped_guard",
    "skipped_empty",
]


class SemanticReviewView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    request_id: str
    api_key_id: UUID | None
    status: str
    matched_question_ids: list[str]
    questions_revision: int
    review_request_id: str | None
    cost_usd: Decimal | None
    completed_at: datetime | None


class SemanticReviewPage(BaseModel):
    items: list[SemanticReviewView]
    total: int
    limit: int
    offset: int


@router.get("", response_model=SemanticReviewPage)
async def list_semantic_reviews(
    start: AwareDatetime | None = Query(default=None),
    end: AwareDatetime | None = Query(default=None),
    status: ReviewStatus | None = Query(default=None),
    request_id: str | None = Query(default=None, min_length=1, max_length=255),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    user: User = Depends(require("findings.read")),
    session: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    end_at = end or datetime.now(timezone.utc)
    start_at = start or end_at - timedelta(days=7)
    if not start_at < end_at <= start_at + MAX_WINDOW:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "WINDOW_INVALID",
                "message": "start is before end, at most 31 days apart.",
            },
        )
    filters = [
        SemanticReview.organization_id == _tenant_id(user),
        SemanticReview.created_at >= start_at,
        SemanticReview.created_at < end_at,
    ]
    if status is not None:
        filters.append(SemanticReview.status == status)
    if request_id is not None:
        filters.append(SemanticReview.request_id == request_id)
    total = await session.scalar(select(func.count()).where(*filters))
    rows = await session.scalars(
        select(SemanticReview)
        .where(*filters)
        .order_by(SemanticReview.created_at.desc(), SemanticReview.id)
        .limit(limit)
        .offset(offset)
    )
    return {"items": list(rows), "total": total or 0, "limit": limit, "offset": offset}


check_router = APIRouter(prefix="/management/semantic-check", tags=["findings"])
CHECK_OUTCOMES = (
    "matched",
    "clear",
    "invalid_answer",
    "failed",
    "timeout",
    "skipped_guard",
    "skipped_cap",
    "skipped_empty",
)


@check_router.get("")
async def read_semantic_check(
    request: Request,
    hours: int = Query(default=24, ge=1, le=168),
    user: User = Depends(require("usage.read")),
    session: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """The marked check: its scope, today's count, and outcomes, latency and cost."""
    tenant_id = _tenant_id(user)
    stored = await session.scalar(
        select(OrganizationGatewaySettings.settings).where(
            OrganizationGatewaySettings.organization_id == tenant_id
        )
    )
    check = stored_settings(stored or {}).semantic_check
    start = datetime.now(timezone.utc) - timedelta(hours=hours)
    record = RequestLifecycle.lifecycle_metadata["semantic_check"]
    latency = cast(record["latency_ms"].astext, Float)
    rows = (
        await session.execute(
            select(
                *(
                    func.count().filter(record["outcome"].astext == outcome)
                    for outcome in CHECK_OUTCOMES
                ),
                func.percentile_cont(0.5).within_group(latency),
                func.percentile_cont(0.95).within_group(latency),
                func.count(record["check_request_id"].astext),
            ).where(
                RequestLifecycle.organization_id == tenant_id,
                RequestLifecycle.started_at >= start,
                record.isnot(None),
            )
        )
    ).one()
    checked = select(record["check_request_id"].astext).where(
        RequestLifecycle.organization_id == tenant_id,
        RequestLifecycle.started_at >= start,
        record["check_request_id"].astext.isnot(None),
    )
    cost = await session.scalar(
        select(func.sum(UsageLedger.cost_usd)).where(
            UsageLedger.organization_id == tenant_id,
            UsageLedger.event_type == "spend_settlement",
            UsageLedger.request_id.in_(checked),
        )
    )
    checks = rows[-1]
    return {
        "enabled": check.enabled,
        "scope": {
            field: len(getattr(check.scope, field))
            for field in ("api_key_ids", "tags", "models")
        },
        "checks_today": await _checks_today(request, tenant_id),
        "max_checks_per_day": check.max_checks_per_day,
        "hours": hours,
        "outcomes": dict(zip(CHECK_OUTCOMES, rows[: len(CHECK_OUTCOMES)])),
        "latency_ms_p50": rows[len(CHECK_OUTCOMES)],
        "latency_ms_p95": rows[len(CHECK_OUTCOMES) + 1],
        "cost_usd": None if cost is None else str(cost),
        "cost_usd_per_check": None
        if cost is None or not checks
        else str(cost / checks),
    }


async def _checks_today(request: Request, tenant_id: UUID) -> int | None:
    redis = getattr(getattr(request.app.state, "cache", None), "redis", None)
    if redis is None:
        return None
    try:
        value = await redis.get(counter_key(tenant_id, datetime.now(timezone.utc)))
    except Exception:
        return None
    return int(value or 0)
