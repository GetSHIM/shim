from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
from sqlalchemy import select

from ee.tests.observability.test_tasks import _request, _tenant
from ee.tests.rules.test_rules_resource import (
    MANAGEMENT,
    POLICY,
    _aliases,
    _call,
    _organization,
    _put,
    _stored,
    _versions,
)
from shim_enterprise.policy.models import PolicyPlan
from shim_enterprise.rules.models import OrganizationRuleSet

CANARIES = f"{MANAGEMENT}/canaries"


def _split(state: str = "monitor", share: float = 5) -> dict:
    return {
        "id": "llama4_kanarya",
        "name": "Llama 4 to 5 percent",
        "kind": "route",
        "action": "route",
        "state": state,
        "match": {
            "on": "split",
            "from": "llama-a",
            "to": "llama-b",
            "share_percent": share,
            "fallback_to_stable": False,
        },
    }


async def _enforced_split(db):
    users = await _organization(db, "admin")
    owner = users["owner"]
    await _aliases(
        db, owner.organization_id, {"llama-a": "openai", "llama-b": "openai"}
    )
    assert (await _put(db, owner, [_split()])).status_code == 200
    assert (await _put(db, owner, [_split("enforced")])).status_code == 200
    return users


@pytest.mark.asyncio
async def test_a_rollback_is_one_neutral_plan_and_one_version(db) -> None:
    users = await _enforced_split(db)
    owner = users["owner"]
    tenant = owner.organization_id
    versions = len(await _versions(db, tenant))

    rolled = await _call(
        db, users["admin"], "POST", f"{CANARIES}/llama4_kanarya/rollback"
    )

    assert rolled.status_code == 200, rolled.text
    body = rolled.json()
    newest = await _versions(db, tenant)
    assert len(newest) == versions + 1
    assert body["policy_version"] == newest[-1].version
    assert newest[-1].reason == "canary rollback"
    plan = await db.scalar(select(PolicyPlan).where(PolicyPlan.id == body["plan_id"]))
    assert (plan.status, plan.risk, plan.reason) == (
        "applied",
        "neutral",
        "canary rollback",
    )
    stored = (await _stored(db, tenant))[0]
    assert (stored["state"], stored["match"]["share_percent"]) == ("enforced", 0)

    restored = await _call(
        db,
        owner,
        "POST",
        f"{POLICY}/versions/{body['policy_version'] - 1}/restore",
        json={"reason": "undo the rollback"},
    )

    assert restored.status_code in (200, 201), restored.text
    assert (await _stored(db, tenant))[0]["match"]["share_percent"] == 5


@pytest.mark.asyncio
async def test_four_eyes_never_holds_a_rollback(db) -> None:
    users = await _enforced_split(db)
    owner = users["owner"]
    switched = await _call(
        db,
        owner,
        "PATCH",
        f"{MANAGEMENT}/gateway-settings",
        json={"four_eyes": "relaxing"},
    )
    assert switched.status_code == 200, switched.text

    rolled = await _call(db, owner, "POST", f"{CANARIES}/llama4_kanarya/rollback")

    assert rolled.status_code == 200, rolled.text
    assert (await _stored(db, owner.organization_id))[0]["match"]["share_percent"] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("share", [50, 1])
async def test_a_share_only_change_is_neutral_in_both_directions(db, share) -> None:
    users = await _enforced_split(db)
    owner = users["owner"]
    switched = await _call(
        db,
        owner,
        "PATCH",
        f"{MANAGEMENT}/gateway-settings",
        json={"four_eyes": "relaxing"},
    )
    assert switched.status_code == 200, switched.text

    # D13: privacy runs after the move and internal never splits to external.
    changed = await _put(db, owner, [_split("enforced", share)])

    assert changed.status_code == 200, changed.text
    stored = (await _stored(db, owner.organization_id))[0]
    assert stored["match"]["share_percent"] == share


@pytest.mark.asyncio
async def test_a_second_rollback_answers_409_not_a_server_error(db) -> None:
    users = await _enforced_split(db)
    path = f"{CANARIES}/llama4_kanarya/rollback"

    first = await _call(db, users["admin"], "POST", path)
    again = await _call(db, users["admin"], "POST", path)

    assert first.status_code == 200, first.text
    assert again.status_code == 409, again.text
    assert again.json()["detail"]["code"] == "NOTHING_TO_CHANGE"


@pytest.mark.asyncio
async def test_a_rollback_needs_a_split_rule_and_rules_write(db) -> None:
    users = await _organization(db, "admin")
    owner = users["owner"]
    term = {
        "id": "falcon",
        "name": "Project names",
        "kind": "term",
        "action": "block",
        "state": "monitor",
        "match": {"terms": ["Project Falcon"]},
    }
    assert (await _put(db, owner, [term])).status_code == 200
    auditor = users["admin"]
    auditor.role = "auditor"
    await db.flush()

    missing = await _call(db, owner, "POST", f"{CANARIES}/nothing_here/rollback")
    not_split = await _call(db, owner, "POST", f"{CANARIES}/falcon/rollback")
    read_only = await _call(db, auditor, "POST", f"{CANARIES}/falcon/rollback")

    assert (missing.status_code, missing.json()["detail"]["code"]) == (
        404,
        "RULE_NOT_FOUND",
    )
    assert (not_split.status_code, not_split.json()["detail"]["code"]) == (
        409,
        "RULE_NOT_A_SPLIT",
    )
    assert read_only.status_code == 403


def _decision(state: str, side: str) -> dict:
    return {
        "rule_id": "llama4_kanarya",
        "state": state,
        "from": "llama-a",
        "to": "llama-b" if state == "enforced" and side == "candidate" else "llama-a",
        "reason": "canary",
        "conversation_id": None,
        "canary_side": side,
    }


async def _seed(db, state: str = "enforced"):
    user, key, _ = await _tenant(db)
    db.add(
        OrganizationRuleSet(
            organization_id=user.organization_id,
            revision=1,
            rules=[{**_split(state), "scope": {}}],
        )
    )
    recent = datetime.now(timezone.utc) - timedelta(hours=1)
    for cost, latency, outcome, status in (
        ("0.010", 100, "complete", "completed"),
        ("0.020", 200, "truncated", "completed"),
        ("0.030", 300, None, "provider_error"),
    ):
        _request(
            db,
            key,
            None,
            cost=cost,
            outcome=outcome,
            status=status,
            started_at=recent,
            route_decision=_decision(state, "candidate"),
            shim_latency_ms=latency,
        )
    for unpriced in (False, True):
        _request(
            db,
            key,
            None,
            unpriced=unpriced,
            started_at=recent,
            route_decision=_decision(state, "stable"),
            shim_latency_ms=50,
        )
    _request(
        db,
        key,
        None,
        started_at=datetime.now(timezone.utc) - timedelta(hours=30),
        route_decision=_decision(state, "candidate"),
    )
    await db.flush()
    return user, key


@pytest.mark.asyncio
async def test_both_sides_are_read_side_by_side(db) -> None:
    user, _ = await _seed(db)
    # Another tenant's rows under the same rule id are not counted.
    await _seed(db)

    day = await _call(db, user, "GET", CANARIES)
    two_days = await _call(db, user, "GET", CANARIES, params={"hours": 48})

    assert day.status_code == 200, day.text
    [view] = day.json()
    assert (view["rule_id"], view["state"], view["share_percent"]) == (
        "llama4_kanarya",
        "enforced",
        5,
    )
    candidate, stable = view["candidate"], view["stable"]
    assert candidate["requests"] == 3
    assert candidate["completion_outcomes"] == {
        "complete": 1,
        "truncated": 1,
        "empty": 0,
        "refused": 0,
        "filtered": 0,
    }
    assert candidate["failed"] == 1
    assert candidate["shim_latency_ms_p50"] == 200
    assert Decimal(candidate["cost_usd"]) == Decimal("0.060")
    assert Decimal(candidate["cost_usd_per_request"]) == Decimal("0.020")
    assert candidate["ttft_ms_p50"] is None
    # One unpriced row makes the side's cost unknown.
    assert (stable["requests"], stable["cost_usd"]) == (2, None)
    assert view["would_move"] == 0
    assert two_days.json()[0]["candidate"]["requests"] == 4


@pytest.mark.asyncio
async def test_in_monitor_every_row_is_stable_and_the_would_move_count_is_shown(
    db,
) -> None:
    user, _ = await _seed(db, "monitor")

    [view] = (await _call(db, user, "GET", CANARIES)).json()

    assert (view["stable"]["requests"], view["candidate"]["requests"]) == (5, 0)
    assert view["would_move"] == 3


@pytest.mark.asyncio
async def test_a_tenant_without_split_rules_reads_nothing(db) -> None:
    user, *_ = await _tenant(db)

    answered = await _call(db, user, "GET", CANARIES, params={"hours": 744})
    too_long = await _call(db, user, "GET", CANARIES, params={"hours": 745})

    assert (answered.status_code, answered.json()) == (200, [])
    assert too_long.status_code == 422
