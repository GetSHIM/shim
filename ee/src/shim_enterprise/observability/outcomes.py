"""How answers ended, as rates per model, API key or team."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from sqlalchemy import Text, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.billing.models import RequestLifecycle
from shim_enterprise.tenants.models import ApiKey, Team

OutcomeGroup = Literal["model", "api_key", "team"]
MAX_OUTCOME_GROUPS = 200
OUTCOMES = ("complete", "truncated", "empty", "refused", "filtered")
_COUNTS = ("settled", *OUTCOMES, "analysed", "soft_refused")


@dataclass(frozen=True, slots=True)
class OutcomeRates:
    group: str | None
    name: str | None
    settled: int
    complete: int
    truncated: int
    empty: int
    refused: int
    filtered: int
    truncation_rate: float | None
    refusal_rate: float | None
    analysed: int
    soft_refused: int
    soft_refusal_rate: float | None


@dataclass(frozen=True, slots=True)
class OutcomeReport:
    groups: list[OutcomeRates]
    truncated: bool
    totals: OutcomeRates


def _rates(group: str | None, name: str | None, counts: dict[str, int]) -> OutcomeRates:
    settled, analysed = counts["settled"], counts["analysed"]
    unanswered = counts["refused"] + counts["filtered"] + counts["empty"]
    return OutcomeRates(
        group=group,
        name=name,
        **counts,
        truncation_rate=counts["truncated"] / settled if settled else None,
        refusal_rate=unanswered / settled if settled else None,
        soft_refusal_rate=counts["soft_refused"] / analysed if analysed else None,
    )


async def _names(
    session: AsyncSession, tenant_id: UUID, group_by: OutcomeGroup, groups: list[Any]
) -> dict[str, str | None]:
    ids = [group for group in groups if group]
    if group_by == "model" or not ids:
        return {}
    named = ApiKey if group_by == "api_key" else Team
    found = await session.execute(
        select(cast(named.id, Text), named.name).where(
            named.organization_id == tenant_id, cast(named.id, Text).in_(ids)
        )
    )
    return dict(found.tuples().all())


class OutcomeRatesReadModel:
    async def read(
        self,
        session: AsyncSession,
        *,
        tenant_id: UUID,
        start_at: datetime,
        end_at: datetime,
        group_by: OutcomeGroup,
    ) -> OutcomeReport:
        metadata = RequestLifecycle.lifecycle_metadata
        outcome = metadata["completion_outcome"].as_string()
        # Written by the refusal analyzer only when the tenant enabled it.
        soft_refusal = metadata["response_analysis"]["refusal"][
            "soft_refusal"
        ].as_string()
        key = {
            "model": RequestLifecycle.requested_model,
            "api_key": cast(RequestLifecycle.api_key_id, Text),
            "team": metadata["team_id"].as_string(),
        }[group_by]
        rows = (
            await session.execute(
                select(
                    key.label("group"),
                    func.count().label("settled"),
                    *(
                        func.count().filter(outcome == name).label(name)
                        for name in OUTCOMES
                    ),
                    func.count()
                    .filter(soft_refusal.in_(("true", "false")))
                    .label("analysed"),
                    func.count().filter(soft_refusal == "true").label("soft_refused"),
                )
                .where(
                    RequestLifecycle.organization_id == tenant_id,
                    RequestLifecycle.started_at >= start_at,
                    RequestLifecycle.started_at < end_at,
                    outcome.is_not(None),
                )
                .group_by(key)
                .order_by(func.count().desc(), key)
            )
        ).all()
        shown = rows[:MAX_OUTCOME_GROUPS]
        names = await _names(session, tenant_id, group_by, [row.group for row in shown])
        return OutcomeReport(
            groups=[
                _rates(
                    row.group,
                    names.get(row.group),
                    {field: getattr(row, field) for field in _COUNTS},
                )
                for row in shown
            ],
            truncated=len(rows) > MAX_OUTCOME_GROUPS,
            totals=_rates(
                None,
                None,
                {field: sum(getattr(row, field) for row in rows) for field in _COUNTS},
            ),
        )
