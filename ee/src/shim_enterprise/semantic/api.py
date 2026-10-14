"""The reviews of archived requests: what was read, against which questions, with what result."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import AwareDatetime, BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.api.enterprise_deps import require
from shim_enterprise.api.v1.management._common import _tenant_id
from shim_enterprise.core.database import get_db
from shim_enterprise.semantic.models import SemanticReview
from shim_enterprise.tenants.models import User

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
