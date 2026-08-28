"""Ledger-backed budget alert evaluation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.billing.models import (
    CostBudget,
    CostBudgetAlertState,
    RequestLifecycle,
    UsageLedger,
)
from shim.billing.attribution import UNTAGGED
from shim.gateway.contracts.ids import TenantId
from shim_enterprise.outbox.publisher import OutboxWriter


MAX_BUDGET_ALERT_THRESHOLDS = 10
MAX_BUDGET_NOTIFY_TARGETS = 10


class BudgetConfigurationError(ValueError):
    """Raised when persisted budget configuration is unsafe to evaluate."""


def validate_budget_notification_config(budget: CostBudget) -> list[Decimal]:
    thresholds = budget.alert_thresholds
    targets = budget.notify_targets
    error = "budget notification configuration is invalid"
    if (
        not isinstance(thresholds, list)
        or len(thresholds) > MAX_BUDGET_ALERT_THRESHOLDS
        or not isinstance(targets, list)
        or len(targets) > MAX_BUDGET_NOTIFY_TARGETS
    ):
        raise BudgetConfigurationError(error)
    try:
        normalized = [Decimal(str(value)) for value in thresholds]
    except (InvalidOperation, ValueError):
        raise BudgetConfigurationError(error) from None
    if any(
        not value.is_finite() or not Decimal("0") < value <= Decimal("5")
        for value in normalized
    ) or len(normalized) != len(set(normalized)):
        raise BudgetConfigurationError(error)
    for target in targets:
        if not isinstance(target, Mapping) or target.get("kind") not in (
            "slack",
            "webhook",
        ):
            raise BudgetConfigurationError(error)
        for field in ("endpoint_origin", "secret_ref"):
            value = target.get(field)
            if not isinstance(value, str) or not value.strip():
                raise BudgetConfigurationError(error)
    return normalized


@dataclass(frozen=True, slots=True)
class BudgetUsage:
    cost_usd: Decimal
    tokens: int
    top_contributors: tuple[dict[str, object], ...]

    def fraction_of(self, budget: CostBudget) -> Decimal:
        fractions: list[Decimal] = []
        if budget.limit_usd is not None and Decimal(str(budget.limit_usd)) > 0:
            fractions.append(self.cost_usd / Decimal(str(budget.limit_usd)))
        if budget.limit_tokens is not None and budget.limit_tokens > 0:
            fractions.append(Decimal(self.tokens) / Decimal(budget.limit_tokens))
        return max(fractions, default=Decimal("0"))


class BudgetEvaluator:
    """Evaluate one budget from immutable settlement events and enqueue alerts."""

    async def evaluate(
        self,
        session: AsyncSession,
        budget: CostBudget,
        *,
        now: datetime,
    ) -> dict[str, object]:
        thresholds = validate_budget_notification_config(budget)
        period_start = _month_start(now)
        period_key = _period_key(now)
        usage = await self._aggregate(session, budget, period_start)
        fraction = usage.fraction_of(budget)
        fired = await self._fired_thresholds(session, budget, period_key)
        candidates = sorted(
            threshold
            for threshold in thresholds
            if fraction >= threshold and threshold not in fired
        )
        enqueued: list[Decimal] = []
        for threshold in candidates:
            inserted = await self._record_threshold(
                session,
                budget,
                period_key=period_key,
                threshold=threshold,
                fired_at=now,
            )
            if not inserted:
                continue
            await self._enqueue_alert(
                session,
                budget,
                usage,
                fraction=fraction,
                threshold=threshold,
                period_key=period_key,
                now=now,
            )
            enqueued.append(threshold)
        return {
            "budget_id": str(budget.id),
            "fraction": float(fraction),
            "fired": [float(value) for value in enqueued],
            "enqueued": len(enqueued),
        }

    async def _aggregate(
        self,
        session: AsyncSession,
        budget: CostBudget,
        period_start: datetime,
    ) -> BudgetUsage:
        spend_filters = self._scope_filters(budget, RequestLifecycle)
        spend_statement = (
            select(func.coalesce(func.sum(UsageLedger.cost_usd), Decimal("0")))
            .select_from(UsageLedger)
            .join(
                RequestLifecycle,
                (RequestLifecycle.organization_id == UsageLedger.organization_id)
                & (RequestLifecycle.request_id == UsageLedger.request_id),
            )
            .where(
                UsageLedger.organization_id == budget.organization_id,
                UsageLedger.event_type == "spend_settlement",
                UsageLedger.created_at >= period_start,
                *spend_filters,
            )
        )
        quota_statement = (
            select(func.coalesce(func.sum(UsageLedger.total_tokens), 0))
            .select_from(UsageLedger)
            .join(
                RequestLifecycle,
                (RequestLifecycle.organization_id == UsageLedger.organization_id)
                & (RequestLifecycle.request_id == UsageLedger.request_id),
            )
            .where(
                UsageLedger.organization_id == budget.organization_id,
                UsageLedger.event_type == "quota_settlement",
                UsageLedger.created_at >= period_start,
                *spend_filters,
            )
        )
        contributor = RequestLifecycle.lifecycle_metadata["cost_center"].as_string()
        contributor_statement = (
            select(
                contributor.label("cost_center"),
                func.sum(UsageLedger.cost_usd).label("cost_usd"),
            )
            .select_from(UsageLedger)
            .join(
                RequestLifecycle,
                (RequestLifecycle.organization_id == UsageLedger.organization_id)
                & (RequestLifecycle.request_id == UsageLedger.request_id),
            )
            .where(
                UsageLedger.organization_id == budget.organization_id,
                UsageLedger.event_type == "spend_settlement",
                UsageLedger.created_at >= period_start,
                *spend_filters,
            )
            .group_by(contributor)
            .order_by(func.sum(UsageLedger.cost_usd).desc())
            .limit(3)
        )
        cost = Decimal(str((await session.execute(spend_statement)).scalar_one()))
        tokens = int((await session.execute(quota_statement)).scalar_one())
        contributors = tuple(
            {
                "cost_center": center or UNTAGGED,
                "cost_usd": float(Decimal(str(value))),
            }
            for center, value in (await session.execute(contributor_statement)).all()
        )
        return BudgetUsage(cost_usd=cost, tokens=tokens, top_contributors=contributors)

    @staticmethod
    def _scope_filters(
        budget: CostBudget,
        lifecycle: type[RequestLifecycle],
    ) -> tuple[Any, ...]:
        if budget.scope_type == "org":
            return ()
        if budget.scope_type == "tag":
            return (
                lifecycle.lifecycle_metadata["tags"].contains([budget.scope_value]),
            )
        return (lifecycle.lifecycle_metadata["team"].as_string() == budget.scope_value,)

    @staticmethod
    async def _fired_thresholds(
        session: AsyncSession,
        budget: CostBudget,
        period_key: str,
    ) -> set[Decimal]:
        statement = select(CostBudgetAlertState.threshold).where(
            CostBudgetAlertState.budget_id == budget.id,
            CostBudgetAlertState.period_key == period_key,
        )
        return {
            Decimal(str(value))
            for value in (await session.execute(statement)).scalars().all()
        }

    @staticmethod
    async def _record_threshold(
        session: AsyncSession,
        budget: CostBudget,
        *,
        period_key: str,
        threshold: Decimal,
        fired_at: datetime,
    ) -> bool:
        statement = (
            insert(CostBudgetAlertState)
            .values(
                budget_id=budget.id,
                period_key=period_key,
                threshold=float(threshold),
                fired_at=fired_at,
            )
            .on_conflict_do_nothing(
                index_elements=[
                    CostBudgetAlertState.budget_id,
                    CostBudgetAlertState.period_key,
                    CostBudgetAlertState.threshold,
                ]
            )
            .returning(CostBudgetAlertState.id)
        )
        return (await session.execute(statement)).scalar_one_or_none() is not None

    @staticmethod
    async def _enqueue_alert(
        session: AsyncSession,
        budget: CostBudget,
        usage: BudgetUsage,
        *,
        fraction: Decimal,
        threshold: Decimal,
        period_key: str,
        now: datetime,
    ) -> None:
        for position, target in enumerate(budget.notify_targets or []):
            await OutboxWriter().append(
                session,
                organization_id=TenantId(budget.organization_id),
                values={
                    "event_type": "budget.threshold_crossed",
                    "aggregate_type": "budget",
                    "aggregate_id": str(budget.id),
                    "idempotency_key": (
                        f"budget:{budget.id}:{period_key}:{threshold}:target:{position}"
                    ),
                    "payload": {
                        "organization_id": str(budget.organization_id),
                        "budget_id": str(budget.id),
                        "scope_type": budget.scope_type,
                        "scope_value": budget.scope_value,
                        "period": period_key,
                        "threshold": float(threshold),
                        "percent_used": float(fraction * 100),
                        "current_usd": float(usage.cost_usd),
                        "limit_usd": (
                            float(budget.limit_usd)
                            if budget.limit_usd is not None
                            else None
                        ),
                        "current_tokens": usage.tokens,
                        "limit_tokens": budget.limit_tokens,
                        "top_contributors": list(usage.top_contributors),
                        "target": dict(target),
                    },
                    "status": "pending",
                    "next_attempt_at": now,
                },
            )


def _period_key(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m")


def _month_start(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("budget evaluation time must be timezone-aware")
    utc = value.astimezone(timezone.utc)
    return datetime(utc.year, utc.month, 1, tzinfo=timezone.utc)
