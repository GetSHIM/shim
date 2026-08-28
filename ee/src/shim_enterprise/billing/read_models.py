"""Tenant-scoped projections over the immutable usage ledger."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from typing import Literal

from sqlalchemy import case, cast, func, select, true
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.billing.models import RequestLifecycle, UsageLedger
from shim.billing.attribution import UNTAGGED
from shim.gateway.contracts.ids import TenantId


MAX_BILLING_BREAKDOWN_ROWS = 500
MAX_BILLING_DAILY_ROWS = 500


@dataclass(frozen=True, slots=True)
class DailyUsage:
    usage_date: date
    model: str
    request_count: int
    prompt_tokens: int
    completion_tokens: int
    cost_usd: Decimal

    def as_public_record(self) -> dict[str, object]:
        return {
            "date": self.usage_date.isoformat(),
            "model": self.model,
            "request_count": self.request_count,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "cost_usd": float(self.cost_usd),
        }


BillingBreakdownGroup = Literal["model", "tag", "cost_center", "provider", "team"]


@dataclass(frozen=True, slots=True)
class BillingBreakdown:
    key: str
    request_count: int
    prompt_tokens: int
    completion_tokens: int
    cost_usd: Decimal

    def as_public_record(self) -> dict[str, object]:
        return {
            "key": self.key,
            "request_count": self.request_count,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "cost_usd": self.cost_usd,
        }


class BillingReadModels:
    """Build tenant billing views from durable settlement events."""

    async def daily_usage(
        self,
        session: AsyncSession,
        *,
        tenant_id: TenantId,
        start_at: datetime,
        end_at: datetime,
    ) -> list[DailyUsage]:
        if start_at.tzinfo is None or end_at.tzinfo is None:
            raise ValueError("billing read boundaries must be timezone-aware")
        if start_at > end_at:
            raise ValueError("billing read start must not follow end")

        # Every accepted request has exactly one quota settlement. Cache-hit rows
        # are additional provenance facts and must not count the request twice.
        is_usage = UsageLedger.event_type == "quota_settlement"
        is_spend = UsageLedger.event_type == "spend_settlement"
        usage_date = func.date(func.timezone("UTC", UsageLedger.created_at))
        statement = (
            select(
                usage_date.label("usage_date"),
                UsageLedger.requested_model.label("model"),
                func.sum(case((is_usage, UsageLedger.request_count), else_=0)).label(
                    "request_count"
                ),
                func.sum(case((is_usage, UsageLedger.prompt_tokens), else_=0)).label(
                    "prompt_tokens"
                ),
                func.sum(
                    case((is_usage, UsageLedger.completion_tokens), else_=0)
                ).label("completion_tokens"),
                func.sum(case((is_spend, UsageLedger.cost_usd), else_=0)).label(
                    "cost_usd"
                ),
            )
            .where(
                UsageLedger.organization_id == tenant_id,
                UsageLedger.created_at >= start_at,
                UsageLedger.created_at <= end_at,
                UsageLedger.event_type.in_(("quota_settlement", "spend_settlement")),
            )
            .group_by(usage_date, UsageLedger.requested_model)
            .order_by(usage_date, UsageLedger.requested_model)
            .limit(MAX_BILLING_DAILY_ROWS + 1)
        )
        rows = (await session.execute(statement)).all()
        return [
            DailyUsage(
                usage_date=row.usage_date,
                model=row.model,
                request_count=int(row.request_count or 0),
                prompt_tokens=int(row.prompt_tokens or 0),
                completion_tokens=int(row.completion_tokens or 0),
                cost_usd=Decimal(str(row.cost_usd or 0)),
            )
            for row in rows
        ]

    async def breakdown(
        self,
        session: AsyncSession,
        *,
        tenant_id: TenantId,
        start_at: datetime,
        end_at: datetime,
        group_by: BillingBreakdownGroup,
        limit: int | None,
    ) -> list[BillingBreakdown]:
        if start_at.tzinfo is None or end_at.tzinfo is None:
            raise ValueError("billing read boundaries must be timezone-aware")
        if start_at > end_at:
            raise ValueError("billing read start must not follow end")
        if limit is not None and not 1 <= limit <= MAX_BILLING_BREAKDOWN_ROWS + 1:
            raise ValueError(
                "billing breakdown limit must be within "
                f"[1, {MAX_BILLING_BREAKDOWN_ROWS + 1}]"
            )

        joined = RequestLifecycle.__table__.join(
            UsageLedger.__table__,
            (RequestLifecycle.organization_id == UsageLedger.organization_id)
            & (RequestLifecycle.request_id == UsageLedger.request_id),
        )
        if group_by == "tag":
            lifecycle_tags = RequestLifecycle.lifecycle_metadata["tags"]
            tags = func.jsonb_array_elements_text(
                case(
                    (
                        func.jsonb_array_length(
                            func.coalesce(lifecycle_tags, cast([], JSONB))
                        )
                        > 0,
                        lifecycle_tags,
                    ),
                    else_=func.jsonb_build_array(UNTAGGED),
                )
            ).table_valued("value")
            joined = joined.join(tags, true())
            group_key = tags.c.value
        elif group_by == "cost_center":
            group_key = func.coalesce(
                RequestLifecycle.lifecycle_metadata["cost_center"].as_string(),
                UNTAGGED,
            )
        elif group_by == "provider":
            group_key = func.coalesce(RequestLifecycle.provider, "unknown")
        elif group_by == "team":
            group_key = func.coalesce(
                RequestLifecycle.lifecycle_metadata["team"].as_string(),
                UNTAGGED,
            )
        else:
            group_key = func.coalesce(
                RequestLifecycle.provider_model,
                RequestLifecycle.requested_model,
                "unknown",
            )

        is_usage = UsageLedger.event_type == "quota_settlement"
        is_spend = UsageLedger.event_type == "spend_settlement"
        request_count = func.sum(
            case((is_usage, UsageLedger.request_count), else_=0)
        ).label("request_count")
        prompt_tokens = func.sum(
            case((is_usage, UsageLedger.prompt_tokens), else_=0)
        ).label("prompt_tokens")
        completion_tokens = func.sum(
            case((is_usage, UsageLedger.completion_tokens), else_=0)
        ).label("completion_tokens")
        cost_usd = func.sum(
            case((is_spend, UsageLedger.cost_usd), else_=Decimal("0"))
        ).label("cost_usd")
        statement = (
            select(
                group_key.label("key"),
                request_count,
                prompt_tokens,
                completion_tokens,
                cost_usd,
            )
            .select_from(joined)
            .where(
                RequestLifecycle.organization_id == tenant_id,
                UsageLedger.organization_id == tenant_id,
                RequestLifecycle.reconciled_at >= start_at,
                RequestLifecycle.reconciled_at <= end_at,
                UsageLedger.event_type.in_(("quota_settlement", "spend_settlement")),
            )
            .group_by(group_key)
            .order_by(cost_usd.desc(), group_key)
        )
        if limit is not None:
            statement = statement.limit(limit)
        rows = (await session.execute(statement)).all()
        return [
            BillingBreakdown(
                key=str(row.key),
                request_count=int(row.request_count or 0),
                prompt_tokens=int(row.prompt_tokens or 0),
                completion_tokens=int(row.completion_tokens or 0),
                cost_usd=Decimal(str(row.cost_usd or 0)),
            )
            for row in rows
        ]
