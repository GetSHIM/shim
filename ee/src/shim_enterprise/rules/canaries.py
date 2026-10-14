"""Gradual model rollouts: both sides of each split rule, and a one-step rollback."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import Float, case, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.api.enterprise_deps import require
from shim_enterprise.api.v1.management._common import _tenant_id
from shim_enterprise.billing.models import RequestLifecycle, UsageLedger
from shim_enterprise.core.database import bounded_read, get_db
from shim_enterprise.observability.outcomes import OUTCOMES
from shim_enterprise.policy.api import (
    _after_commit,
    _apply_plan,
    new_plan,
    planned_change,
)
from shim_enterprise.policy.plans import current_version, lock_at_version
from shim_enterprise.rules.models import OrganizationRuleSet
from shim_enterprise.rules.preview import stored_rules
from shim_enterprise.rules.resource import RULES
from shim_enterprise.tenants.models import User

router = APIRouter(prefix="/management/canaries", tags=["rules"])
MAX_SPLIT_RULES = 50
_FAILED = ("provider_error", "timeout", "failed")


class CanarySide(BaseModel):
    requests: int
    completion_outcomes: dict[str, int]
    failed: int
    shim_latency_ms_p50: float | None
    shim_latency_ms_p95: float | None
    ttft_ms_p50: float | None
    ttft_ms_p95: float | None
    cost_usd: Decimal | None
    cost_usd_per_request: Decimal | None


class CanaryView(BaseModel):
    rule_id: str
    from_alias: str
    to_alias: str
    share_percent: float
    state: Literal["monitor", "enforced"]
    stable: CanarySide
    candidate: CanarySide
    would_move: int


class RollbackView(BaseModel):
    rule_id: str
    plan_id: str
    policy_version: int


def _sides(organization_id, rule_id: str, start: datetime):
    metadata = RequestLifecycle.lifecycle_metadata
    decision = metadata["route_decision"]
    # Monitor serves every request from the stable alias.
    side = case(
        (
            decision["state"].as_string() == "enforced",
            decision["canary_side"].as_string(),
        ),
        else_="stable",
    ).label("side")
    spend = (
        select(func.sum(UsageLedger.cost_usd))
        .where(
            UsageLedger.organization_id == organization_id,
            UsageLedger.request_id == RequestLifecycle.request_id,
            UsageLedger.event_type == "spend_settlement",
        )
        .correlate(RequestLifecycle)
        .scalar_subquery()
    )
    unpriced = (
        select(UsageLedger.id)
        .where(
            UsageLedger.organization_id == organization_id,
            UsageLedger.request_id == RequestLifecycle.request_id,
            UsageLedger.event_type == "spend_settlement",
            UsageLedger.event_metadata["pricing"]["pricing_resolution"].as_string()
            == "unknown",
        )
        .correlate(RequestLifecycle)
        .exists()
    )
    latency = cast(metadata["shim_latency_ms"].as_string(), Float)
    ttft = cast(metadata["ttft_ms"].as_string(), Float)
    return (
        select(
            side,
            func.count().label("requests"),
            *(
                func.count()
                .filter(metadata["completion_outcome"].as_string() == outcome)
                .label(outcome)
                for outcome in OUTCOMES
            ),
            func.count().filter(RequestLifecycle.status.in_(_FAILED)).label("failed"),
            func.percentile_cont(0.5).within_group(latency).label("latency_p50"),
            func.percentile_cont(0.95).within_group(latency).label("latency_p95"),
            func.percentile_cont(0.5).within_group(ttft).label("ttft_p50"),
            func.percentile_cont(0.95).within_group(ttft).label("ttft_p95"),
            func.sum(func.coalesce(spend, Decimal("0"))).label("cost"),
            func.bool_or(unpriced).label("unpriced"),
            func.count()
            .filter(
                decision["state"].as_string() == "monitor",
                decision["canary_side"].as_string() == "candidate",
            )
            .label("would_move"),
        )
        .where(
            RequestLifecycle.organization_id == organization_id,
            RequestLifecycle.started_at >= start,
            decision["rule_id"].as_string() == rule_id,
        )
        .group_by(side)
    )


def _side(row: Any | None) -> dict[str, Any]:
    if row is None:
        return {
            "requests": 0,
            "completion_outcomes": dict.fromkeys(OUTCOMES, 0),
            "failed": 0,
            "shim_latency_ms_p50": None,
            "shim_latency_ms_p95": None,
            "ttft_ms_p50": None,
            "ttft_ms_p95": None,
            "cost_usd": Decimal("0"),
            "cost_usd_per_request": None,
        }
    cost = None if row.unpriced else row.cost
    return {
        "requests": row.requests,
        "completion_outcomes": {outcome: getattr(row, outcome) for outcome in OUTCOMES},
        "failed": row.failed,
        "shim_latency_ms_p50": row.latency_p50,
        "shim_latency_ms_p95": row.latency_p95,
        "ttft_ms_p50": row.ttft_p50,
        "ttft_ms_p95": row.ttft_p95,
        "cost_usd": cost,
        "cost_usd_per_request": None if cost is None else cost / row.requests,
    }


@router.get("", response_model=list[CanaryView])
async def list_canaries(
    hours: int = Query(default=24, ge=1, le=744),
    user: User = Depends(require("usage.read")),
    session: AsyncSession = Depends(get_db),
) -> list[dict[str, Any]]:
    organization_id = _tenant_id(user)
    stored = stored_rules(await session.get(OrganizationRuleSet, organization_id))
    splits = [
        rule
        for rule in (stored.rules if stored is not None else ())
        if rule.kind == "route" and rule.match.get("on") == "split"
    ][:MAX_SPLIT_RULES]
    start = datetime.now(timezone.utc) - timedelta(hours=hours)
    views = []
    async with bounded_read(session):
        for rule in splits:
            rows = {
                row.side: row
                for row in await session.execute(
                    _sides(organization_id, rule.id, start)
                )
            }
            views.append(
                {
                    "rule_id": rule.id,
                    "from_alias": rule.match["from"],
                    "to_alias": rule.match["to"],
                    "share_percent": rule.match["share_percent"],
                    "state": rule.state,
                    "stable": _side(rows.get("stable")),
                    "candidate": _side(rows.get("candidate")),
                    "would_move": sum(row.would_move for row in rows.values()),
                }
            )
    return views


@router.post("/{rule_id}/rollback", response_model=RollbackView)
async def rollback_canary(
    rule_id: str,
    request: Request,
    user: User = Depends(require("rules.write")),
    session: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    organization_id = _tenant_id(user)
    # Planned without the tenant lock; a policy write in between is caught under it.
    version = await current_version(session, organization_id)
    before = (await RULES.snapshot(session, organization_id, [rule_id])).get(rule_id)
    if before is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "RULE_NOT_FOUND", "message": "No rule has this id."},
        )
    if before["kind"] != "route" or before["match"].get("on") != "split":
        raise HTTPException(
            status_code=409,
            detail={"code": "RULE_NOT_A_SPLIT", "message": "The rule is not a split."},
        )
    after = {**before, "match": {**before["match"], "share_percent": 0}}
    change = await planned_change(
        session, organization_id, "rules", rule_id, before, after, 7
    )
    await lock_at_version(session, organization_id, version)
    plan = await new_plan(
        session,
        user,
        organization_id,
        [change],
        source="api",
        reason="canary rollback",
    )
    cleanups = await _apply_plan(session, user, plan)
    # The share change is neutral, so four eyes never holds it.
    assert cleanups is not None and plan.applied_version is not None
    await session.commit()
    await _after_commit(request, plan, cleanups)
    return {
        "rule_id": rule_id,
        "plan_id": str(plan.id),
        "policy_version": plan.applied_version,
    }
