from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi import FastAPI, HTTPException
from sqlalchemy import func, select

from shim_enterprise.api.enterprise_deps import get_current_user
from shim_enterprise.api.v1.router import management_router
from shim_enterprise.core.database import get_db
from shim_enterprise.policy.models import PolicyVersion
from shim_enterprise.policy.resources import REGISTRY
from shim_enterprise.rules.models import OrganizationRuleSet, RulePreview
from shim_enterprise.rules.preview import preview_digest
from shim_enterprise.rules.resource import RULES
from shim_enterprise.tenants.models import Organization, User
from shim.rules import Rule

MANAGEMENT = "/api/v1/management"
POLICY = f"{MANAGEMENT}/policy"


def _rule(rule_id: str = "falcon", **values) -> dict:
    return {
        "id": rule_id,
        "name": "Project names",
        "kind": "term",
        "action": "block",
        "state": "monitor",
        "match": {"terms": ["Project Falcon"]},
        **values,
    }


def _state(**values) -> dict:
    rule = Rule.model_validate(_rule(**values))
    return rule.model_dump(mode="json", exclude={"id"}) | {
        "match": {**rule.match, "label": "TERM", "suffixes": "tr"}
    }


class _DeletingCache:
    def __init__(self) -> None:
        self.deleted: list[str] = []

    async def delete(self, key: str) -> bool:
        self.deleted.append(key)
        return True


async def _organization(db, *roles: str) -> dict[str, User]:
    organization = Organization(
        id=uuid4(), name="Rules", slug=f"rules-{uuid4().hex}", tier="enterprise"
    )
    db.add(organization)
    await db.flush()
    users = {}
    for name in ("owner", *roles):
        users[name] = User(
            id=uuid4(),
            organization_id=organization.id,
            email=f"rules-{uuid4().hex}@example.com",
            role="owner" if name == "owner" else "admin",
            is_active=True,
            is_verified=True,
        )
        db.add(users[name])
    await db.flush()
    return users


async def _call(
    db, user: User, method: str, path: str, cache=None, **kwargs
) -> httpx.Response:
    app = FastAPI()
    app.include_router(management_router, prefix="/api/v1")
    app.state.cache = cache
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_db] = lambda: db
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        return await client.request(method, path, **kwargs)


async def _put(db, user: User, rules: list[dict]) -> httpx.Response:
    current = (await _call(db, user, "GET", f"{MANAGEMENT}/rules")).json()
    return await _call(
        db,
        user,
        "PUT",
        f"{MANAGEMENT}/rules",
        json={"revision": current["revision"], "rules": rules},
    )


async def _versions(db, organization_id: UUID) -> list[PolicyVersion]:
    return list(
        await db.scalars(
            select(PolicyVersion)
            .where(PolicyVersion.organization_id == organization_id)
            .order_by(PolicyVersion.version)
        )
    )


async def _plan(db, user: User, *changes: dict) -> httpx.Response:
    return await _call(
        db, user, "POST", f"{POLICY}/plans", json={"changes": list(changes)}
    )


async def _stored(db, organization_id: UUID) -> list[dict]:
    row = await db.get(OrganizationRuleSet, organization_id, populate_existing=True)
    return [] if row is None else row.rules


@pytest.mark.asyncio
async def test_the_snapshot_holds_each_rule_without_its_id(db) -> None:
    users = await _organization(db)
    tenant = users["owner"].organization_id

    empty = await RULES.snapshot(db, tenant, None)
    await _put(db, users["owner"], [_rule(), _rule("heron")])
    both = await RULES.snapshot(db, tenant, None)
    one = await RULES.snapshot(db, tenant, ["heron", "missing"])

    assert empty == {}
    assert set(both) == {"falcon", "heron"}
    assert both["falcon"] == _state()
    assert set(one) == {"heron"}
    assert REGISTRY["rules"] is RULES
    assert (RULES.permission, RULES.creatable, RULES.deletable) == (
        "rules.write",
        True,
        True,
    )


@pytest.mark.asyncio
async def test_validate_refuses_as_the_put_does(db) -> None:
    users = await _organization(db)
    owner = users["owner"]
    short = _rule(match={"terms": ["ab"]})

    put = await _put(db, owner, [short])
    with pytest.raises(HTTPException) as validated:
        await RULES.validate(db, owner, None, None, short)
    await _put(db, owner, [_rule()])
    with pytest.raises(HTTPException) as again:
        await RULES.validate(db, owner, None, None, _rule())
    with pytest.raises(HTTPException) as renamed:
        await RULES.validate(db, owner, "falcon", _state(), {"id": "other"})

    assert put.status_code == validated.value.status_code == 422
    assert put.json()["detail"] == validated.value.detail
    assert again.value.detail["code"] == "RULE_ID_DUPLICATE"
    assert renamed.value.detail["message"] == "A rule keeps its id."
    assert await RULES.validate(
        db, owner, "falcon", _state(), {"action": "mask"}
    ) == _state(action="mask")


@pytest.mark.asyncio
async def test_a_put_and_a_plan_each_record_one_version(db) -> None:
    users = await _organization(db)
    owner = users["owner"]
    tenant = owner.organization_id

    put = await _put(db, owner, [_rule(), _rule("heron")])
    again = await _put(db, owner, [_rule(), _rule("heron")])
    plan = await _plan(
        db, owner, {"resource": "rules", "item": "heron", "set": {"action": "mask"}}
    )
    applied = await _call(
        db, owner, "POST", f"{POLICY}/plans/{plan.json()['id']}/apply"
    )

    assert (put.json()["revision"], again.json()["revision"]) == (1, 2)
    assert applied.json()["status"] == "applied"
    first, second = await _versions(db, tenant)
    assert (first.source, sorted(first.snapshot["rules"])) == (
        "api",
        ["falcon", "heron"],
    )
    assert first.previous["rules"] == {"falcon": None, "heron": None}
    assert (second.source, list(second.snapshot["rules"])) == ("plan", ["heron"])
    assert second.snapshot["rules"]["heron"]["action"] == "mask"
    row = await db.get(OrganizationRuleSet, tenant, populate_existing=True)
    assert row.revision == 3
    assert [rule["action"] for rule in row.rules] == ["block", "mask"]


@pytest.mark.asyncio
async def test_a_plan_creates_and_deletes_rules_by_their_ids(db) -> None:
    users = await _organization(db)
    owner = users["owner"]
    tenant = owner.organization_id
    await _put(db, owner, [_rule()])

    plan = await _plan(
        db,
        owner,
        {"resource": "rules", "item": None, "set": _rule("heron")},
        {"resource": "rules", "item": "falcon", "delete": True},
    )
    applied = await _call(
        db, owner, "POST", f"{POLICY}/plans/{plan.json()['id']}/apply"
    )

    assert plan.status_code == 201, plan.text
    assert [change["item"] for change in plan.json()["changes"]] == ["heron", "falcon"]
    assert applied.json()["status"] == "applied"
    assert [rule["id"] for rule in await _stored(db, tenant)] == ["heron"]


def _enforced(**values) -> dict:
    return _state(state="enforced", **values)


@pytest.mark.parametrize(
    ("before", "after", "risk"),
    [
        (None, _enforced(), "tightening"),
        (None, _state(), "neutral"),
        (_state(), _enforced(), "tightening"),
        (_enforced(action="mask"), _enforced(), "tightening"),
        (_enforced(), _enforced(action="mask"), "relaxing"),
        (
            _enforced(),
            _enforced(match={"terms": ["Project Falcon", "Project Heron"]}),
            "tightening",
        ),
        (
            _enforced(match={"terms": ["Project Falcon", "Project Heron"]}),
            _enforced(),
            "relaxing",
        ),
        # A wider scope protects more requests; a narrower one fewer.
        (_enforced(scope={"models": ["gpt-5-nano"]}), _enforced(), "tightening"),
        (
            _enforced(scope={"models": ["gpt-5-nano"]}),
            _enforced(scope={"models": ["gpt-5-nano", "gpt-5"]}),
            "tightening",
        ),
        (_enforced(), _enforced(scope={"models": ["gpt-5-nano"]}), "relaxing"),
        (_state(scope={"models": ["gpt-5-nano"]}), _state(), "neutral"),
        # A field the classifier does not weigh relaxes, whichever way it moves.
        (_enforced(), _enforced(kind="pattern"), "relaxing"),
        (_enforced(kind="pattern"), _enforced(), "relaxing"),
        (_enforced(), _enforced(name="Renamed"), "neutral"),
        (_enforced(), None, "relaxing"),
        (_state(), None, "neutral"),
        (_state(), _state(name="Renamed"), "neutral"),
    ],
)
def test_each_rule_change_classifies(before, after, risk) -> None:
    assert RULES.classify(before, after) == risk


@pytest.mark.asyncio
async def test_a_plan_apply_invalidates_the_policy_cache_after_commit(db) -> None:
    users = await _organization(db)
    owner = users["owner"]
    cache = _DeletingCache()
    plan = await _plan(db, owner, {"resource": "rules", "item": None, "set": _rule()})

    await _call(db, owner, "POST", f"{POLICY}/plans/{plan.json()['id']}/apply", cache)

    assert cache.deleted == [f"config:pii:v2:{owner.organization_id}"]


@pytest.mark.parametrize("four_eyes", ["relaxing", "off"])
@pytest.mark.asyncio
async def test_four_eyes_refuses_a_put_that_relaxes_an_enforced_rule(
    db, four_eyes: str
) -> None:
    users = await _organization(db, "admin")
    owner = users["owner"]
    tenant = owner.organization_id
    await _put(db, owner, [_rule()])
    await _put(db, owner, [_rule(state="enforced")])
    await _call(
        db,
        owner,
        "PATCH",
        f"{MANAGEMENT}/gateway-settings",
        json={"four_eyes": four_eyes},
    )
    versions = len(await _versions(db, tenant))

    relaxed = await _put(db, owner, [_rule()])

    [rule] = await _stored(db, tenant)
    if four_eyes == "off":
        assert relaxed.status_code == 200
        assert rule["state"] == "monitor"
        return
    assert relaxed.status_code == 409
    assert relaxed.json()["detail"]["code"] == "CHANGE_REQUIRES_APPROVAL"
    assert relaxed.json()["detail"]["relaxed"] == ["rules.falcon.state"]
    assert rule["state"] == "enforced"
    assert len(await _versions(db, tenant)) == versions


@pytest.mark.asyncio
async def test_a_new_enforced_rule_in_a_plan_is_noted_and_refused_on_apply(db) -> None:
    users = await _organization(db)
    owner = users["owner"]

    plan = await _plan(
        db, owner, {"resource": "rules", "item": None, "set": _rule(state="enforced")}
    )
    applied = await _call(
        db, owner, "POST", f"{POLICY}/plans/{plan.json()['id']}/apply"
    )

    impact = plan.json()["changes"][0]["impact"]
    assert impact == {
        "requests": None,
        "basis": "none",
        "window_days": 7,
        "note": "apply will refuse: new rules start in monitor "
        "(RULE_MUST_START_IN_MONITOR)",
    }
    assert applied.status_code == 422
    assert applied.json()["detail"]["code"] == "RULE_MUST_START_IN_MONITOR"


@pytest.mark.asyncio
async def test_a_plan_with_a_valid_preview_creates_the_rule_enforced(db) -> None:
    users = await _organization(db)
    owner = users["owner"]
    tenant = owner.organization_id
    enforced = _rule(state="enforced")
    rule = Rule.model_validate(
        {**enforced, "match": {**enforced["match"], "label": "TERM", "suffixes": "tr"}}
    )
    now = datetime.now(timezone.utc)
    db.add(
        RulePreview(
            organization_id=tenant,
            rule_id="falcon",
            preview_digest=preview_digest(rule),
            basis="metadata",
            requests=0,
            window_days=7,
            window_start=now - timedelta(days=7),
            window_end=now,
            expires_at=now + timedelta(hours=24),
        )
    )
    await db.flush()

    plan = await _plan(db, owner, {"resource": "rules", "item": None, "set": enforced})
    applied = await _call(
        db, owner, "POST", f"{POLICY}/plans/{plan.json()['id']}/apply"
    )

    assert plan.json()["changes"][0]["impact"]["note"] is not None
    assert "apply will refuse" not in plan.json()["changes"][0]["impact"]["note"]
    assert applied.json()["status"] == "applied"
    assert (await _stored(db, tenant))[0]["state"] == "enforced"


@pytest.mark.asyncio
async def test_a_destination_rule_previewed_from_metadata_is_created_enforced(
    db,
) -> None:
    users = await _organization(db)
    owner = users["owner"]
    destination = _rule(
        "tckn",
        kind="destination",
        action="mask",
        state="enforced",
        scope={"deployment_kinds": ["external"]},
        match={"entity_types": ["TR_NATIONAL_ID"]},
    )
    change = {"resource": "rules", "item": None, "set": destination}

    refused = await _call(
        db,
        owner,
        "POST",
        f"{POLICY}/plans/{(await _plan(db, owner, change)).json()['id']}/apply",
    )
    preview = await _call(
        db,
        owner,
        "POST",
        f"{MANAGEMENT}/rules/preview",
        json={"rule": destination, "window_days": 7},
    )
    plan = await _plan(db, owner, change)
    applied = await _call(
        db, owner, "POST", f"{POLICY}/plans/{plan.json()['id']}/apply"
    )

    assert refused.json()["detail"]["code"] == "RULE_MUST_START_IN_MONITOR"
    assert (preview.json()["basis"], preview.json()["enforce_on_create"]) == (
        "metadata",
        True,
    )
    assert plan.json()["changes"][0]["impact"]["basis"] == "metadata"
    assert applied.json()["status"] == "applied"
    assert (await _stored(db, owner.organization_id))[0]["state"] == "enforced"


@pytest.mark.asyncio
async def test_a_restore_brings_back_a_deleted_enforced_rule_without_a_preview(
    db,
) -> None:
    users = await _organization(db)
    owner = users["owner"]
    tenant = owner.organization_id
    await _put(db, owner, [_rule()])
    await _put(db, owner, [_rule(state="enforced")])
    await _put(db, owner, [])

    restored = await _call(db, owner, "POST", f"{POLICY}/versions/2/restore", json={})

    assert restored.status_code == 200, restored.text
    assert restored.json()["plan"]["status"] == "applied"
    [rule] = await _stored(db, tenant)
    assert (rule["id"], rule["state"]) == ("falcon", "enforced")
    assert (
        await db.scalar(
            select(func.count()).where(RulePreview.organization_id == tenant)
        )
        == 0
    )
