from __future__ import annotations

import inspect
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from uuid import UUID, uuid4

from fastapi import FastAPI, HTTPException
import httpx
import pytest
from sqlalchemy import func, select

import shim_enterprise.tenants.policy as policy_module
from shim.privacy.policies import PrivacyAction, PrivacyOutcome
from shim.rules import KINDS, LIMITS, Rule, RuleSet, validate_rule_set
from shim.rules.model import RuleMatch
import shim_enterprise.api.enterprise_deps as enterprise_deps
from shim_enterprise.api.enterprise_deps import ADMIN_REQUIRED, READER_REQUIRED
from shim_enterprise.api.v1 import management
from shim_enterprise.api.v1.router import management_router
from shim_enterprise.core.database import get_db
from shim_enterprise.gateway.pipeline.quota_reservation import (
    DurableAccountingCoordinator,
)
from shim_enterprise.rules.changes import classify_rule_changes
from shim_enterprise.rules.models import OrganizationRuleSet
from shim_enterprise.tenants.models import ApiKey, Organization, Team, User


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


class _DeletingCache:
    def __init__(self) -> None:
        self.deleted: list[str] = []

    async def delete(self, key: str) -> bool:
        self.deleted.append(key)
        return True


def _request(cache=None, length: int = 0):
    return SimpleNamespace(
        headers={"content-length": str(length)},
        app=SimpleNamespace(state=SimpleNamespace(cache=cache)),
    )


async def _admin(db, organization_id: UUID, role: str = "admin") -> User:
    user = User(
        id=uuid4(),
        email=f"rules-{uuid4().hex}@example.com",
        full_name="Rules Admin",
        is_active=True,
        is_verified=True,
        organization_id=organization_id,
        role=role,
    )
    db.add(user)
    await db.flush()
    return user


async def _put(db, user: User, revision: int, rules: list[dict], cache=None):
    return await management.replace_rules(
        management.RuleSetPut(revision=revision, rules=rules),
        _request(cache),
        user,
        db,
    )


async def _refused(db, user: User, revision: int, rules: list[dict]) -> dict:
    with pytest.raises(HTTPException) as refused:
        await _put(db, user, revision, rules)
    return {"status": refused.value.status_code, **refused.value.detail}


@pytest.mark.asyncio
async def test_a_new_row_holds_an_empty_set_at_revision_zero(db, test_org) -> None:
    db.add(OrganizationRuleSet(organization_id=test_org.id))
    await db.flush()
    row = await db.get(OrganizationRuleSet, test_org.id)
    await db.refresh(row)

    assert (row.rules, row.revision, row.updated_by) == ([], 0, None)


@pytest.mark.asyncio
async def test_get_without_a_row_lists_the_kinds_and_writes_nothing(
    db, test_user_with_org
) -> None:
    view = await management.get_rules(test_user_with_org, db)

    assert (view.revision, view.rules, view.updated_by, view.updated_at) == (
        0,
        [],
        None,
        None,
    )
    assert view.limits == LIMITS
    assert set(view.kinds) == set(KINDS)
    assert {name for name, kind in view.kinds.items() if kind.available} == {
        "term",
        "pattern",
        "destination",
    }
    assert all("require_approval" not in kind.actions for kind in view.kinds.values())
    count = select(func.count()).where(
        OrganizationRuleSet.organization_id == test_user_with_org.organization_id
    )
    assert await db.scalar(count) == 0


@pytest.mark.asyncio
async def test_put_round_trip_audits_ids_kinds_and_counts_but_no_term(
    db, test_org, audit_events
) -> None:
    admin = await _admin(db, test_org.id)
    cache = _DeletingCache()

    view = await _put(db, admin, 0, [_rule()], cache)
    again = await management.get_rules(admin, db)
    changed = await _put(
        db,
        admin,
        1,
        [_rule(match={"terms": ["Project Heron"]}, scope={"models": ["gpt-5-nano"]})],
    )

    assert (view.revision, view.updated_by) == (1, str(admin.id))
    assert view.rules[0].match == {
        "terms": ["Project Falcon"],
        "label": "TERM",
        "suffixes": "tr",
    }
    assert again == view
    assert view.kinds["term"].available is True
    assert changed.revision == 2
    assert cache.deleted == [f"config:pii:v2:{test_org.id}"]
    first, second = await audit_events(test_org.id)
    assert first["endpoint"] == second["endpoint"] == "tenant.rules_updated"
    assert first["extra"]["added"] == [
        {
            "id": "falcon",
            "kind": "term",
            "action": "block",
            "state": "monitor",
            "scope": [],
            "match_changed": False,
            "counts": {"terms": 1},
        }
    ]
    assert first["extra"]["changed"] == first["extra"]["removed"] == []
    assert second["extra"]["revision"] == 2
    assert second["extra"]["changed"][0]["match_changed"] is True
    assert second["extra"]["changed"][0]["scope"] == ["models"]
    for event in (first, second):
        text = json.dumps(event)
        assert "Falcon" not in text and "Heron" not in text
        assert "Project names" not in text


@pytest.mark.asyncio
async def test_a_stale_revision_is_refused_with_the_current_one(db, test_org) -> None:
    admin = await _admin(db, test_org.id)

    assert (await _put(db, admin, 0, [])).revision == 1

    assert await _refused(db, admin, 0, []) == {
        "status": 409,
        "code": "RULE_SET_REVISION_CONFLICT",
        "message": "The rule set changed since it was read; read it again.",
        "revision": 1,
    }


@pytest.mark.asyncio
async def test_a_new_rule_starts_in_monitor_and_may_then_be_enforced(
    db, test_org
) -> None:
    admin = await _admin(db, test_org.id)

    refused = await _refused(db, admin, 0, [_rule(state="enforced")])
    await _put(db, admin, 0, [_rule()])
    enforced = await _put(db, admin, 1, [_rule(state="enforced")])

    assert (refused["status"], refused["code"], refused["path"]) == (
        422,
        "RULE_MUST_START_IN_MONITOR",
        "rules[0].state",
    )
    assert (enforced.revision, enforced.rules[0].state) == (2, "enforced")


@pytest.mark.asyncio
async def test_scope_ids_must_belong_to_the_organization(
    db, test_org, test_tier
) -> None:
    admin = await _admin(db, test_org.id)
    other = Organization(id=uuid4(), name="Other", slug=f"other-{uuid4().hex}")
    db.add(other)
    await db.flush()
    stranger = await _admin(db, other.id)
    keys = [
        ApiKey(
            id=uuid4(),
            user_id=owner.id,
            organization_id=owner.organization_id,
            key_hash=uuid4().hex,
            prefix="sk-shim-rules",
            name="Rules key",
            tier=test_tier,
            is_active=True,
        )
        for owner in (admin, stranger)
    ]
    own_team = Team(id=uuid4(), organization_id=test_org.id, name="Risk")
    db.add_all([*keys, own_team])
    await db.flush()
    own_key, foreign_key = (str(key.id) for key in keys)

    foreign = await _refused(
        db, admin, 0, [_rule(scope={"api_key_ids": [own_key, foreign_key]})]
    )
    unknown_team = await _refused(
        db, admin, 0, [_rule(scope={"team_ids": [str(uuid4())]})]
    )
    stored = await _put(
        db,
        admin,
        0,
        [_rule(scope={"api_key_ids": [own_key], "team_ids": [str(own_team.id)]})],
    )

    assert (foreign["status"], foreign["code"], foreign["path"]) == (
        422,
        "RULE_SCOPE_UNKNOWN",
        "rules[0].scope.api_key_ids[1]",
    )
    assert (unknown_team["code"], unknown_team["path"]) == (
        "RULE_SCOPE_UNKNOWN",
        "rules[0].scope.team_ids[0]",
    )
    assert stored.rules[0].scope.api_key_ids == (own_key,)


@pytest.mark.asyncio
async def test_unavailable_kinds_and_actions_are_refused_with_their_path(
    db, test_org
) -> None:
    admin = await _admin(db, test_org.id)

    unavailable = await _refused(db, admin, 0, [_rule(kind="record_set")])
    approval = await _refused(db, admin, 0, [_rule(action="require_approval")])
    unknown_key = await _refused(
        db, admin, 0, [_rule(match={"terms": ["Project"], "regex": "y"})]
    )

    assert (unavailable["status"], unavailable["code"], unavailable["path"]) == (
        422,
        "RULE_KIND_UNAVAILABLE",
        "rules[0].kind",
    )
    assert (approval["code"], approval["path"]) == (
        "RULE_ACTION_UNAVAILABLE",
        "rules[0].action",
    )
    assert (unknown_key["code"], unknown_key["path"]) == (
        "RULE_MATCH_INVALID",
        "rules[0].match.regex",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("chunked", [False, True])
async def test_a_body_over_the_size_limit_is_refused_while_it_arrives(
    test_user_with_org, chunked
) -> None:
    session = SimpleNamespace(execute=AsyncMock())
    application = FastAPI()
    application.include_router(management_router, prefix="/api/v1")
    application.dependency_overrides[enterprise_deps.get_current_user] = lambda: (
        test_user_with_org
    )
    application.dependency_overrides[get_db] = lambda: session
    padding = b" " * LIMITS["request_bytes"]

    async def chunks():
        yield b'{"revision": 0, "rules": []'
        for start in range(0, len(padding), 65_536):
            yield padding[start : start + 65_536]
        yield b"}"

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="http://test"
    ) as client:
        response = await client.put(
            "/api/v1/management/rules",
            content=chunks()
            if chunked
            else b'{"revision": 0, "rules": []' + padding + b"}",
            headers={"content-type": "application/json"},
        )

    assert response.status_code == 413
    assert response.json()["detail"]["code"] == "REQUEST_TOO_LARGE"
    session.execute.assert_not_awaited()


def test_readers_read_and_admins_write() -> None:
    guards = {
        (method, route.path): inspect.getclosurevars(dependency.call).nonlocals
        for route in management.router.routes
        if route.path == "/rules"
        for method in route.methods
        for dependency in route.dependant.dependencies
        if dependency.call.__qualname__ == "require.<locals>.guard"
    }

    assert guards["GET", "/rules"] == {
        "permissions": ("rules.read",),
        "legacy_detail": READER_REQUIRED,
    }
    assert guards["PUT", "/rules"] == {
        "permissions": ("rules.write",),
        "legacy_detail": ADMIN_REQUIRED,
    }


@pytest.mark.asyncio
async def test_relaxing_an_enforced_rule_writes_the_relaxed_event(
    db, test_org, audit_events
) -> None:
    admin = await _admin(db, test_org.id)

    await _put(db, admin, 0, [_rule()])
    await _put(db, admin, 1, [_rule(state="enforced")])
    tightened = [event["endpoint"] for event in await audit_events(test_org.id)]
    await _put(db, admin, 2, [])

    events = await audit_events(test_org.id)
    assert "tenant.privacy_protection_relaxed" not in tightened
    assert [event["endpoint"] for event in events[len(tightened) :]] == [
        "tenant.rules_updated",
        "tenant.privacy_protection_relaxed",
    ]
    assert events[-1]["extra"]["relaxed"] == ["rules.falcon"]


def _set(*rules: dict) -> RuleSet:
    return RuleSet(revision=1, rules=tuple(Rule.model_validate(rule) for rule in rules))


_ENFORCED = _rule(state="enforced", scope={"models": ["a", "b"]})


@pytest.mark.parametrize(
    "after",
    [
        pytest.param([], id="removed"),
        pytest.param([{**_ENFORCED, "state": "monitor"}], id="to-monitor"),
        pytest.param([{**_ENFORCED, "action": "warn"}], id="weaker-action"),
        pytest.param([{**_ENFORCED, "scope": {"models": ["a"]}}], id="fewer-models"),
        pytest.param(
            [{**_ENFORCED, "scope": {"models": ["a", "b"], "tags": ["x"]}}],
            id="names-tags",
        ),
        pytest.param(
            [{**_ENFORCED, "match": {"terms": ["Project Heron"]}}], id="term-replaced"
        ),
    ],
)
def test_every_weakening_of_an_enforced_rule_relaxes(after) -> None:
    assert classify_rule_changes(_set(_ENFORCED), _set(*after)) == ["rules.falcon"]


@pytest.mark.parametrize(
    ("before", "after"),
    [
        pytest.param(None, [_ENFORCED], id="first-set"),
        pytest.param([_ENFORCED], [_ENFORCED, _rule("heron")], id="new-rule"),
        pytest.param(
            [_ENFORCED],
            [{**_ENFORCED, "match": {"terms": ["Project Falcon", "Heron"]}}],
            id="term-added",
        ),
        pytest.param(
            [{**_ENFORCED, "action": "warn"}], [_ENFORCED], id="stronger-action"
        ),
        pytest.param(
            [_ENFORCED],
            [{**_ENFORCED, "scope": {"models": ["a", "b", "c"]}}],
            id="more-models",
        ),
        pytest.param([_ENFORCED], [{**_ENFORCED, "scope": {}}], id="everyone"),
        pytest.param([_ENFORCED], [{**_ENFORCED, "name": "Renamed"}], id="renamed"),
        pytest.param([_rule()], [], id="monitor-rule-removed"),
    ],
)
def test_additions_and_tightening_do_not_relax(before, after) -> None:
    previous = _set(*before) if before is not None else None

    assert classify_rule_changes(previous, _set(*after)) == []


class _PolicyCache:
    def __init__(self, pii: dict | None = None) -> None:
        self.pii = pii
        self.stored: dict | None = None

    async def get_pii_config(self, _tenant_id: str) -> dict | None:
        return self.pii

    async def set_pii_config(self, _tenant_id: str, value: dict) -> None:
        self.stored = value

    async def get_gateway_settings(self, _tenant_id: str) -> dict:
        return {}

    async def get_tier_definition(self, _slug: str) -> dict:
        return {"features": {}}


def _key(organization_id: UUID) -> SimpleNamespace:
    return SimpleNamespace(organization_id=organization_id, tier="managed")


@pytest.mark.asyncio
async def test_the_cache_entry_carries_the_revision_of_a_non_empty_set(
    db, test_org
) -> None:
    empty = Organization(id=uuid4(), name="Empty", slug=f"empty-{uuid4().hex}")
    bare = Organization(id=uuid4(), name="Bare", slug=f"bare-{uuid4().hex}")
    db.add_all([empty, bare])
    await db.flush()
    db.add_all(
        [
            OrganizationRuleSet(
                organization_id=test_org.id, revision=3, rules=[_rule()]
            ),
            OrganizationRuleSet(organization_id=empty.id, revision=2, rules=[]),
        ]
    )
    await db.flush()
    resolved = {}
    stored = {}
    for organization in (test_org, empty, bare):
        cache = _PolicyCache()
        service = policy_module.TenantPolicyService(cache)
        resolved[organization.id] = await service.resolve(_key(organization.id), db)
        stored[organization.id] = cache.stored

    assert stored[test_org.id] == {"rules_revision": 3}
    assert resolved[test_org.id].rules.revision == 3
    assert [rule.id for rule in resolved[test_org.id].rules.rules] == ["falcon"]
    assert stored[empty.id] == stored[bare.id] == {"rules_revision": 0}
    assert resolved[empty.id].rules is resolved[bare.id].rules is None
    assert resolved[bare.id].pii_config is None


@pytest.mark.asyncio
async def test_an_entry_cached_before_rules_existed_means_no_rules() -> None:
    cache = _PolicyCache({"block_email": True})

    resolved = await policy_module.TenantPolicyService(cache).resolve(
        _key(UUID(int=5)), session=None
    )

    assert resolved.rules is None and resolved.pii_config == {"block_email": True}


@pytest.mark.asyncio
async def test_the_process_reloads_a_set_on_a_new_revision_and_keeps_a_bound(
    db, test_org, monkeypatch
) -> None:
    other = Organization(id=uuid4(), name="Other", slug=f"other-{uuid4().hex}")
    db.add(other)
    await db.flush()
    row = OrganizationRuleSet(organization_id=test_org.id, revision=3, rules=[_rule()])
    db.add_all(
        [
            row,
            OrganizationRuleSet(
                organization_id=other.id, revision=1, rules=[_rule("heron")]
            ),
        ]
    )
    await db.flush()
    cache = _PolicyCache({"rules_revision": 3})
    service = policy_module.TenantPolicyService(cache)

    first = await service.resolve(_key(test_org.id), db)
    # Same revision: the set comes from process memory, with no session at all.
    again = await service.resolve(_key(test_org.id), session=None)
    row.revision, row.rules = 4, [_rule("osprey")]
    await db.flush()
    cache.pii = {"rules_revision": 4}
    reloaded = await service.resolve(_key(test_org.id), db)
    monkeypatch.setattr(policy_module, "_RULE_SETS_PER_PROCESS", 1)
    cache.pii = {"rules_revision": 1}
    await service.resolve(_key(other.id), db)

    assert again.rules is first.rules
    assert [rule.id for rule in reloaded.rules.rules] == ["osprey"]
    assert list(service._rule_sets) == [other.id]


@pytest.mark.asyncio
async def test_the_lifecycle_metadata_carries_the_rule_matches() -> None:
    rule = Rule.model_validate(_rule())
    checked = SimpleNamespace(
        policy_verdicts=[],
        rules=RuleSet(revision=1, rules=(rule,)),
        rules_evaluated=True,
        rule_matches=[
            RuleMatch(
                rule_id="falcon", kind="term", action="block", state="monitor", count=2
            )
        ],
        tenant_id=uuid4(),
        request_id=f"req_{uuid4().hex}",
        privacy=PrivacyOutcome(action=PrivacyAction.DISABLED, pii_detected=False),
    )
    session = SimpleNamespace(commit=AsyncMock(), rollback=AsyncMock())

    with patch(
        "shim_enterprise.gateway.pipeline.quota_reservation.RequestLifecycleRepository.update",
        new=AsyncMock(return_value=SimpleNamespace()),
    ) as update:
        await DurableAccountingCoordinator().record_privacy(checked, session)

    metadata = update.await_args.kwargs["values"]["lifecycle_metadata"]
    [written] = metadata.compile(
        compile_kwargs={"literal_binds": False}
    ).params.values()
    assert written["rule_matches"] == [
        {
            "rule_id": "falcon",
            "kind": "term",
            "action": "block",
            "state": "monitor",
            "count": 2,
        }
    ]
    assert written["rule_matches_truncated"] is False


_FUTURE = {
    "id": "geo",
    "name": "A kind of a later release",
    "kind": "geo_fence",
    "action": "block",
    "state": "enforced",
    "match": {"regions": ["eu"]},
}


@pytest.mark.asyncio
async def test_a_rule_this_release_cannot_run_is_shown_kept_and_never_unavailable(
    db, test_org, caplog
) -> None:
    admin = await _admin(db, test_org.id)
    db.add(
        OrganizationRuleSet(
            organization_id=test_org.id, revision=5, rules=[_rule(), _FUTURE]
        )
    )
    await db.flush()
    service = policy_module.TenantPolicyService(_PolicyCache())

    view = await management.get_rules(admin, db)
    resolved = await service.resolve(_key(test_org.id), db)
    await service.resolve(_key(test_org.id), db)
    updated = await _put(db, admin, 5, [_rule(state="enforced")])
    clash = await _refused(db, admin, 6, [_rule(), _rule("geo")])
    row = await db.get(OrganizationRuleSet, test_org.id)

    assert [rule.id for rule in view.rules] == ["falcon"]
    assert view.unavailable_rules == [_FUTURE]
    assert [rule.id for rule in resolved.rules.rules] == ["falcon"]
    assert [rule.id for rule in resolved.rules.unusable] == ["geo"]
    assert caplog.text.count("rule_id=geo") == 1 and "eu" not in caplog.text
    assert updated.unavailable_rules == [_FUTURE]
    assert row.rules[-1] == _FUTURE and row.rules[0]["state"] == "enforced"
    assert (clash["status"], clash["code"], clash["path"]) == (
        422,
        "RULE_ID_DUPLICATE",
        "rules[1].id",
    )


_CODES = {
    "id": "codes",
    "name": "Codes",
    "kind": "pattern",
    "action": "block",
    "state": "enforced",
    "match": {"templates": ["PRJ-####"], "regexes": [r"INV\d{6}"]},
}


@pytest.mark.parametrize(
    ("match", "relaxed"),
    [
        ({"templates": ["PRJ-####", "KOD-##"], "regexes": [r"INV\d{6}"]}, []),
        ({"templates": ["PRJ-####"], "regexes": [r"INV\d{6}", r"FTR\d+"]}, []),
        ({"templates": [], "regexes": [r"INV\d{6}"]}, ["rules.codes"]),
        ({"templates": ["PRJ-####"], "regexes": [r"INV\d{5}"]}, ["rules.codes"]),
    ],
)
def test_adding_templates_or_regexes_does_not_relax_and_removing_does(
    match, relaxed
) -> None:
    def rule_set(values: dict) -> RuleSet:
        return validate_rule_set(
            {"revision": 1, "rules": [{**_CODES, "match": values}]}
        )

    assert classify_rule_changes(rule_set(_CODES["match"]), rule_set(match)) == relaxed
