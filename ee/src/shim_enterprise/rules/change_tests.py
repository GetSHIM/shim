"""Change tests: what each `shadow` rule copied and how the two answers compared, and
a one-step stop."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import AwareDatetime
from sqlalchemy import Float, and_, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from shim.rules import Rule
from shim_enterprise.api.enterprise_deps import require
from shim_enterprise.api.v1.management._common import _tenant_id
from shim_enterprise.billing.models import RequestLifecycle
from shim_enterprise.core.database import bounded_read, get_db
from shim_enterprise.gateway.change_test import copies_so_far
from shim_enterprise.observability.outcomes import OUTCOMES
from shim_enterprise.policy.api import (
    _after_commit,
    _apply_plan,
    new_plan,
    planned_change,
)
from shim_enterprise.policy.plans import current_version, lock_at_version
from shim_enterprise.rules.estimators import change_test_estimate
from shim_enterprise.rules.models import OrganizationRuleSet
from shim_enterprise.rules.preview import RULE_PREVIEW_DEFAULT_DAYS, stored_rules
from shim_enterprise.rules.resource import RULES
from shim_enterprise.rules.route_triggers import MAX_SHADOW_WINDOW, ShadowMatch
from shim_enterprise.tenants.models import User

router = APIRouter(prefix="/management/change-tests", tags=["rules"])
CAVEATS = (
    "copy_after_primary",
    "masked_payload",
    "share_not_random_over_time",
    "no_human_review",
)
_SIDES = ("primary", "candidate")
_LANGUAGES = ("tr", "en", "other", "unknown")


def _shadow_rules(row: OrganizationRuleSet | None) -> list[Rule]:
    stored = stored_rules(row)
    return [
        rule
        for rule in (stored.rules if stored is not None else ())
        if rule.kind == "route" and rule.match.get("on") == "shadow"
    ]


async def _rule(session: AsyncSession, organization_id: UUID, rule_id: str) -> Rule:
    """The rule, 404 when the set has none with this id, 409 when it is no test."""
    stored = stored_rules(await session.get(OrganizationRuleSet, organization_id))
    rule = next(
        (
            rule
            for rule in (stored.rules if stored is not None else ())
            if rule.id == rule_id
        ),
        None,
    )
    if rule is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "RULE_NOT_FOUND", "message": "No rule has this id."},
        )
    if rule.kind != "route" or rule.match.get("on") != "shadow":
        raise HTTPException(
            status_code=409,
            detail={
                "code": "RULE_NOT_A_CHANGE_TEST",
                "message": "The rule is not a change test.",
            },
        )
    return rule


def _status(
    rule: Rule, match: ShadowMatch, copies: int, cost: Any, now: datetime
) -> tuple[str, str | None]:
    if rule.state == "monitor":
        return "monitor", None
    if now < match.starts_at:
        return "scheduled", None
    if now >= match.ends_at:
        return "ended", "ends_at"
    if copies >= match.max_requests:
        return "ended", "max_requests"
    if cost >= match.max_cost_usd:
        return "ended", "max_cost"
    return "running", None


@router.get("")
async def list_change_tests(
    user: User = Depends(require("usage.read")),
    session: AsyncSession = Depends(get_db),
) -> list[dict[str, Any]]:
    organization_id = _tenant_id(user)
    now = datetime.now(timezone.utc)
    tests = []
    async with bounded_read(session):
        for rule in _shadow_rules(
            await session.get(OrganizationRuleSet, organization_id)
        ):
            match = ShadowMatch.model_validate(rule.match)
            copies, cost = await copies_so_far(
                session, organization_id, rule.id, match.starts_at
            )
            status, end_reason = _status(rule, match, copies, cost, now)
            test = {
                "rule_id": rule.id,
                "from": match.from_,
                "to": match.to,
                "share_percent": match.share_percent,
                "state": rule.state,
                "starts_at": match.starts_at,
                "ends_at": match.ends_at,
                "max_requests": match.max_requests,
                "max_cost_usd": str(match.max_cost_usd),
                "status": status,
                "end_reason": end_reason,
                "copies": copies,
                "candidate_cost_usd": str(cost),
            }
            if rule.state == "monitor":
                estimate = await change_test_estimate(
                    session,
                    organization_id,
                    rule,
                    now - timedelta(days=RULE_PREVIEW_DEFAULT_DAYS),
                    now,
                )
                test["estimate"] = {
                    key: value for key, value in estimate.items() if key != "by_scope"
                } | {"window_days": RULE_PREVIEW_DEFAULT_DAYS}
            tests.append(test)
    return tests


def _number(path: Any) -> Any:
    return cast(path.astext, Float)


async def change_test_results(
    session: AsyncSession,
    organization_id: UUID,
    rule_id: str,
    start: datetime,
    end: datetime,
) -> dict[str, Any]:
    """Both sides of a test's copies over the window, in one query; works for a rule no
    longer in the set, since the copy rows keep `shadow_rule_id`."""

    metadata = RequestLifecycle.lifecycle_metadata
    record = metadata["shadow_comparison"]
    side = {name: record[name] for name in _SIDES}
    compared = record.isnot(None)

    def count(*conditions: Any) -> Any:
        return func.count().filter(*conditions)

    def percentile(fraction: float, value: Any, *conditions: Any) -> Any:
        return func.percentile_cont(fraction).within_group(value).filter(*conditions)

    chars = {name: _number(side[name]["answer_chars"]) for name in _SIDES}
    costs = {name: cast(side[name]["cost_usd"].astext, Float) for name in _SIDES}
    valid = {name: side[name]["schema_valid"].astext for name in _SIDES}
    checked = and_(
        record["schema_expected"].astext.notin_(["none"]),
        *(valid[name].in_(["true", "false"]) for name in _SIDES),
    )
    pairs = and_(*(chars[name] > 0 for name in _SIDES))
    priced = and_(*(costs[name].isnot(None) for name in _SIDES))
    ratio = chars["candidate"] / chars["primary"]
    columns = {
        "copies": func.count(),
        "compared": count(compared),
        "failed_copies": count(side["candidate"]["outcome"].astext == "failed"),
        "same_outcome": count(
            side["primary"]["outcome"].astext == side["candidate"]["outcome"].astext
        ),
        "checked": count(checked),
        **{f"{name}_valid": count(checked, valid[name] == "true") for name in _SIDES},
        "primary_only_valid": count(
            checked, valid["primary"] == "true", valid["candidate"] == "false"
        ),
        "candidate_only_valid": count(
            checked, valid["primary"] == "false", valid["candidate"] == "true"
        ),
        "pairs": count(pairs),
        **{f"{name}_chars": func.sum(chars[name]).filter(pairs) for name in _SIDES},
        "ratio_p25": percentile(0.25, ratio, pairs),
        "ratio_p50": percentile(0.5, ratio, pairs),
        "ratio_p75": percentile(0.75, ratio, pairs),
        "comparable_pairs": count(priced),
        **{f"{name}_usd": func.sum(costs[name]).filter(priced) for name in _SIDES},
        "candidate_unpriced": count(
            compared,
            side["candidate"]["status"].astext == "completed",
            costs["candidate"].is_(None),
        ),
        "mismatched": count(
            *(side[name]["language"].astext.isnot(None) for name in _SIDES),
            side["primary"]["language"].astext != side["candidate"]["language"].astext,
        ),
    }
    for name in _SIDES:
        for outcome in (*OUTCOMES, "failed"):
            columns[f"{name}_outcome_{outcome}"] = count(
                side[name]["outcome"].astext == outcome
            )
        for measure in ("provider_latency_ms", "ttft_ms"):
            value = _number(side[name][measure])
            columns[f"{name}_{measure}_p50"] = percentile(0.5, value, value.isnot(None))
            columns[f"{name}_{measure}_p95"] = percentile(
                0.95, value, value.isnot(None)
            )
        for language in _LANGUAGES:
            columns[f"{name}_language_{language}"] = count(
                side[name]["language"].astext == language
            )
        columns[f"{name}_soft_refusals"] = count(
            side[name]["soft_refusal"].astext == "true"
        )
        columns[f"{name}_refusal_checked"] = count(
            side[name]["soft_refusal"].astext.in_(["true", "false"])
        )
    row = (
        (
            await session.execute(
                select(*(value.label(key) for key, value in columns.items())).where(
                    RequestLifecycle.organization_id == organization_id,
                    RequestLifecycle.started_at >= start,
                    RequestLifecycle.started_at < end,
                    metadata["shadow_rule_id"].astext == rule_id,
                )
            )
        )
        .one()
        ._mapping
    )

    def rate(part: int, whole: int) -> float | None:
        return part / whole if whole else None

    primary_usd, candidate_usd = row["primary_usd"], row["candidate_usd"]
    delta = (
        None
        if primary_usd is None or candidate_usd is None
        else candidate_usd - primary_usd
    )
    results: dict[str, Any] = {
        "rule_id": rule_id,
        "window": {"start": start, "end": end},
        "copies": row["copies"],
        "compared": row["compared"],
        "failed_copies": row["failed_copies"],
        "outcome_mix": {
            name: {
                outcome: row[f"{name}_outcome_{outcome}"]
                for outcome in (*OUTCOMES, "failed")
            }
            for name in _SIDES
        },
        "same_outcome_share": rate(row["same_outcome"], row["compared"]),
        "schema": {
            "checked": row["checked"],
            "primary_valid_rate": rate(row["primary_valid"], row["checked"]),
            "candidate_valid_rate": rate(row["candidate_valid"], row["checked"]),
            "primary_only_valid": row["primary_only_valid"],
            "candidate_only_valid": row["candidate_only_valid"],
        },
        "length": {
            "pairs": row["pairs"],
            "ratio_of_sums": rate(
                row["candidate_chars"] or 0, row["primary_chars"] or 0
            ),
            "median_ratio": row["ratio_p50"],
            "p25_ratio": row["ratio_p25"],
            "p75_ratio": row["ratio_p75"],
        },
        "latency_ms": {
            name: {
                "p50": row[f"{name}_provider_latency_ms_p50"],
                "p95": row[f"{name}_provider_latency_ms_p95"],
            }
            for name in _SIDES
        },
        "ttft_ms": {
            name: {
                "p50": row[f"{name}_ttft_ms_p50"],
                "p95": row[f"{name}_ttft_ms_p95"],
            }
            for name in _SIDES
        },
        "cost": {
            "comparable_pairs": row["comparable_pairs"],
            "primary_usd": primary_usd,
            "candidate_usd": candidate_usd,
            "delta_usd": delta,
            "delta_per_request_usd": rate(delta, row["comparable_pairs"])
            if delta is not None
            else None,
            "candidate_unpriced": row["candidate_unpriced"],
        },
        "caveats": list(CAVEATS),
    }
    if any(
        row[f"{name}_language_{language}"] for name in _SIDES for language in _LANGUAGES
    ):
        results["language"] = {
            **{
                name: {
                    language: row[f"{name}_language_{language}"]
                    for language in _LANGUAGES
                }
                for name in _SIDES
            },
            "mismatched": row["mismatched"],
        }
    if any(row[f"{name}_refusal_checked"] for name in _SIDES):
        results["refusal"] = {
            name: {"soft_refusals": row[f"{name}_soft_refusals"]} for name in _SIDES
        }
    return results


@router.get("/{rule_id}")
async def get_change_test(
    rule_id: str,
    start: AwareDatetime | None = Query(default=None),
    end: AwareDatetime | None = Query(default=None),
    user: User = Depends(require("usage.read")),
    session: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    organization_id = _tenant_id(user)
    match = ShadowMatch.model_validate(
        (await _rule(session, organization_id, rule_id)).match
    )
    start = start or match.starts_at
    end = end or min(datetime.now(timezone.utc), match.ends_at)
    if not start < end <= start + MAX_SHADOW_WINDOW:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "WINDOW_INVALID",
                "message": "start is before end, at most 31 days apart.",
            },
        )
    async with bounded_read(session):
        return await change_test_results(session, organization_id, rule_id, start, end)


@router.post("/{rule_id}/stop")
async def stop_change_test(
    rule_id: str,
    request: Request,
    user: User = Depends(require("rules.write")),
    session: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    organization_id = _tenant_id(user)
    # Planned without the tenant lock; a policy write in between is caught under it.
    version = await current_version(session, organization_id)
    await _rule(session, organization_id, rule_id)
    before = (await RULES.snapshot(session, organization_id, [rule_id]))[rule_id]
    change = await planned_change(
        session,
        organization_id,
        "rules",
        rule_id,
        before,
        {**before, "state": "monitor"},
        RULE_PREVIEW_DEFAULT_DAYS,
    )
    await lock_at_version(session, organization_id, version)
    plan = await new_plan(
        session,
        user,
        organization_id,
        [change],
        source="api",
        reason="change test stopped",
    )
    cleanups = await _apply_plan(session, user, plan)
    # Back to monitor tightens, so four eyes never holds it.
    assert cleanups is not None and plan.applied_version is not None
    await session.commit()
    await _after_commit(request, plan, cleanups)
    return {
        "rule_id": rule_id,
        "plan_id": str(plan.id),
        "policy_version": plan.applied_version,
    }
