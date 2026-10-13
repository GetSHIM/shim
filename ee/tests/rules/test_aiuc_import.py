from __future__ import annotations

import hashlib
import json
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select

from shim.rules import RuleSet, validate_rule_set
from shim_enterprise.api.enterprise_deps import get_current_user
from shim_enterprise.api.v1.router import management_router
from shim_enterprise.core.database import get_db
from shim_enterprise.outbox.models import OutboxEvent
from shim_enterprise.rules import api as rules_api
from shim_enterprise.rules.aiuc import AiucPolicy, map_policy
from shim_enterprise.tenants.models import Organization, OrganizationRole, User

MANAGEMENT = "/api/v1/management"
IMPORT = f"{MANAGEMENT}/rules/import/aiuc"
TERMS = ["Kule Projesi", "Atlas Raporu", "Şişli Kule"]
_PRIVACY = {
    "block_email": True,
    "block_phone": True,
    "block_credit_card": True,
    "block_secrets": True,
    "block_pii_tr": True,
    "entity_actions": {},
    "bulk_threshold": None,
    "response_scan": "off",
    "placeholder_mode": "random",
}


def _term_rule(aiuc_id: str = "projects", terms=TERMS, action: str = "mask") -> dict:
    return {"id": aiuc_id, "category": "term", "action": action, "terms": list(terms)}


def _policy(*rules: dict, **fields) -> AiucPolicy:
    return AiucPolicy.model_validate({"rules": list(rules), **fields})


async def _owner(db, role: str = "owner", custom: list[str] | None = None) -> User:
    organization = Organization(
        id=uuid4(), name="AIUC", slug=f"aiuc-{uuid4().hex}", tier="enterprise"
    )
    db.add(organization)
    await db.flush()
    custom_role = None
    if custom is not None:
        custom_role = OrganizationRole(
            id=uuid4(),
            organization_id=organization.id,
            slug="importer",
            name="Importer",
            permissions=custom,
        )
        db.add(custom_role)
        await db.flush()
    user = User(
        id=uuid4(),
        organization_id=organization.id,
        email=f"aiuc-{uuid4().hex}@example.com",
        role="member" if custom is not None else role,
        custom_role_id=None if custom_role is None else custom_role.id,
        is_active=True,
        is_verified=True,
    )
    db.add(user)
    await db.flush()
    return user


async def _call(db, user: User, method: str, path: str, **kwargs) -> httpx.Response:
    app = FastAPI()
    app.include_router(management_router, prefix="/api/v1")
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


def _stored(*rules: dict) -> RuleSet:
    return validate_rule_set({"revision": 1, "rules": list(rules)})


def _gateway_rule(rule_id: str, kind: str = "term", **values) -> dict:
    match = (
        {"terms": ["Existing Term"]} if kind == "term" else {"templates": ["PRJ-####"]}
    )
    return {
        "id": rule_id,
        "name": "Existing",
        "kind": kind,
        "action": "block",
        "state": "monitor",
        "match": match,
        **values,
    }


@pytest.mark.parametrize(
    "body",
    [
        {"rules": [_term_rule()], "unknown": 1},
        {"rules": [_term_rule(f"r{index}") for index in range(33)]},
        {"rules": [_term_rule(), _term_rule()]},
        {"rules": [_term_rule()], "schemaVersion": 2},
        {"rules": [{"id": "t", "category": "term", "action": "mask"}]},
        {"rules": [{**_term_rule(), "extra": True}]},
        {"rules": []},
    ],
)
@pytest.mark.asyncio
async def test_the_file_is_checked_strictly(db, body: dict) -> None:
    owner = await _owner(db)

    refused = await _call(db, owner, "POST", IMPORT, json=body)

    assert refused.status_code == 422


@pytest.mark.asyncio
@pytest.mark.parametrize("chunked", [False, True])
async def test_a_file_over_256_kb_is_refused_while_it_arrives(db, chunked) -> None:
    owner = await _owner(db)
    head = json.dumps({"rules": [_term_rule()]})[:-1].encode()
    padding = b" " * (256 * 1024)
    sent = []

    async def chunks():
        for chunk in (
            head,
            *[padding[i : i + 65_536] for i in range(0, len(padding), 65_536)],
            b"not json",
        ):
            sent.append(chunk)
            yield chunk

    refused = await _call(
        db,
        owner,
        "POST",
        IMPORT,
        content=chunks() if chunked else head + padding + b"not json",
        headers={"content-type": "application/json"},
    )

    # Counted as it arrives: never parsed, so the broken tail is not a 422.
    assert refused.status_code == 413
    assert refused.json()["detail"]["code"] == "REQUEST_TOO_LARGE"
    if chunked:
        assert b"not json" not in sent


@pytest.mark.parametrize(
    ("aiuc_ids", "rule_ids"),
    [
        (["Şirket İçi Proje"], ["aiuc_sirket_ici_proje"]),
        (["Çağrı-Merkezi #2"], ["aiuc_cagri_merkezi_2"]),
        (["a b", "a-b", "A_B"], ["aiuc_a_b", "aiuc_a_b_2", "aiuc_a_b_3"]),
        (["x" * 64], ["aiuc_" + "x" * 43]),
        (["x" * 64, "x" * 63], ["aiuc_" + "x" * 43, "aiuc_" + "x" * 41 + "_2"]),
    ],
)
def test_ids_become_gateway_rule_ids(aiuc_ids, rule_ids) -> None:
    changes, _, report = map_policy(
        _policy(*(_term_rule(aiuc_id) for aiuc_id in aiuc_ids)), None, _PRIVACY
    )

    assert [change[0] for change in changes] == rule_ids
    assert [item["rule_id"] for item in report["mapped"]] == rule_ids
    assert all(len(rule_id) <= 48 for rule_id in rule_ids)


def test_an_id_of_symbols_only_takes_its_digest() -> None:
    [(rule_id, _, after)], _, _ = map_policy(_policy(_term_rule("!!!")), None, _PRIVACY)

    assert rule_id == "aiuc_" + hashlib.sha256(b"!!!").hexdigest()[:8]
    assert after["name"] == "AIUC !!!"


def test_short_and_fold_duplicate_terms_are_dropped_by_position() -> None:
    [(_, _, after)], _, report = map_policy(
        _policy(
            _term_rule(terms=["AB", "Kule Projesi", "KULE PROJESİ", "!!!", "  Atlas  "])
        ),
        None,
        _PRIVACY,
    )

    assert after["match"] == {
        "terms": ["Kule Projesi", "Atlas"],
        "label": "TERM",
        "suffixes": "tr",
    }
    assert (after["state"], after["action"], after["scope"]["models"]) == (
        "monitor",
        "mask",
        [],
    )
    assert report["dropped_terms"] == [
        {"aiuc_rule_id": "projects", "term_index": 0, "reason": "term_too_short"},
        {"aiuc_rule_id": "projects", "term_index": 2, "reason": "duplicate_after_fold"},
        {"aiuc_rule_id": "projects", "term_index": 3, "reason": "term_invalid"},
    ]


def test_a_term_rule_left_without_terms_is_not_mapped() -> None:
    changes, _, report = map_policy(
        _policy(_term_rule(terms=["AB", "CD"])), None, _PRIVACY
    )

    assert changes == []
    assert report["not_mapped"] == [
        {"aiuc_rule_id": "projects", "reason": "no_usable_terms"}
    ]


def test_set_limits_skip_a_rule_and_later_rules_are_still_tried() -> None:
    stored = _stored(
        *(
            {
                **_gateway_rule(f"r{index}"),
                "match": {"terms": [f"T{index:03d}{n}" for n in range(20)]},
            }
            for index in range(99)
        )
    )
    many = _term_rule("many", terms=[f"Kule{index:02d}" for index in range(30)])
    few = _term_rule("few", terms=["Kule Projesi"])
    more = _term_rule("more", terms=["Atlas Raporu"])

    changes, _, report = map_policy(_policy(many, few, more), stored, _PRIVACY)

    assert [change[0] for change in changes] == ["aiuc_few"]
    assert report["not_mapped"] == [
        {"aiuc_rule_id": "many", "reason": "set_limit_reached"},
        {"aiuc_rule_id": "more", "reason": "set_limit_reached"},
    ]


def test_an_existing_term_rule_is_updated_and_another_kind_is_not_mapped() -> None:
    stored = _stored(
        _gateway_rule(
            "aiuc_projects", scope={"models": ["gpt-5-nano"]}, state="enforced"
        ),
        _gateway_rule("aiuc_codes", "pattern"),
    )

    changes, _, report = map_policy(
        _policy(_term_rule(), _term_rule("codes")), stored, _PRIVACY
    )

    [(rule_id, before, after)] = changes
    assert rule_id == "aiuc_projects"
    assert before["state"] == "enforced"
    assert (after["state"], after["scope"]["models"], after["name"]) == (
        "monitor",
        ["gpt-5-nano"],
        "AIUC projects",
    )
    assert report["mapped"] == [
        {"aiuc_rule_id": "projects", "rule_id": "aiuc_projects", "change": "update"}
    ]
    assert report["not_mapped"] == [
        {"aiuc_rule_id": "codes", "reason": "id_taken_by_other_kind"}
    ]


@pytest.mark.parametrize(
    ("switch", "overrides", "change", "after"),
    [
        (True, {}, "none", None),
        (
            False,
            {"PHONE_NUMBER": "monitor"},
            "set_monitor",
            {"PHONE_NUMBER": "monitor", "EMAIL_ADDRESS": "monitor"},
        ),
    ],
)
def test_built_in_types_are_raised_from_off_to_monitor_only(
    switch, overrides, change, after
) -> None:
    privacy = {**_PRIVACY, "block_email": switch, "entity_actions": overrides}

    _, privacy_after, report = map_policy(
        _policy(
            {"id": "mail", "category": "email", "action": "warn", "terms": ["ignored"]},
            {"id": "mail2", "category": "email", "action": "block"},
            {"id": "keys", "category": "secret", "action": "monitor"},
        ),
        None,
        privacy,
    )

    assert report["built_in_types"] == [
        {
            "category": "email",
            "entity_type": "EMAIL_ADDRESS",
            "current_action": "mask" if switch else "off",
            "aiuc_action": "block",
            "change": change,
        },
        {
            "category": "secret",
            "entity_type": "SECRET",
            "current_action": "mask",
            "aiuc_action": "monitor",
            "change": "none",
        },
    ]
    assert report["ignored_fields"] == ["rules[0].terms"]
    if after is None:
        assert privacy_after is None
    else:
        assert privacy_after == {**privacy, "entity_actions": after}


@pytest.mark.asyncio
async def test_an_import_is_a_draft_plan_that_applies_in_monitor_and_once(db) -> None:
    owner = await _owner(db)
    body = {
        "schemaVersion": 1,
        "revision": 7,
        "offlineAction": "warn",
        "updatedAt": "2026-10-01T00:00:00Z",
        "rules": [
            _term_rule(terms=[*TERMS, "AB"]),
            {"id": "mail", "category": "email", "action": "block"},
        ],
    }

    imported = await _call(db, owner, "POST", IMPORT, json=body)
    plan = imported.json()["plan"]
    applied = await _call(
        db, owner, "POST", f"{MANAGEMENT}/policy/plans/{plan['id']}/apply"
    )
    rules = (await _call(db, owner, "GET", f"{MANAGEMENT}/rules")).json()["rules"]
    again = await _call(db, owner, "POST", IMPORT, json=body)

    assert imported.status_code == 201, imported.text
    report = imported.json()["report"]
    assert (plan["status"], plan["source"], plan["reason"]) == (
        "draft",
        "import",
        "AIUC rule import",
    )
    assert plan["context"] == report
    assert (report["format"], report["import_version"]) == ("aiuc", 1)
    assert (report["schema_version"], report["source_revision"]) == (1, 7)
    assert report["ignored_fields"] == ["offlineAction", "updatedAt"]
    assert report["dropped_terms"] == [
        {"aiuc_rule_id": "projects", "term_index": 3, "reason": "term_too_short"}
    ]
    assert report["built_in_types"][0]["change"] == "none"
    assert len(report["notes"]) == 4
    assert [change["resource"] for change in plan["changes"]] == ["rules"]
    assert applied.json()["status"] == "applied"
    assert [(rule["id"], rule["state"]) for rule in rules] == [
        ("aiuc_projects", "monitor")
    ]
    assert again.status_code == 200
    assert again.json()["plan"] is None
    assert again.json()["report"]["mapped"][0]["change"] == "unchanged"
    audits = [
        event.payload
        for event in await db.scalars(
            select(OutboxEvent)
            .where(
                OutboxEvent.organization_id == owner.organization_id,
                OutboxEvent.payload["endpoint"].astext == "tenant.rules_imported",
            )
            .order_by(OutboxEvent.next_attempt_at)
        )
    ]
    assert [audit["extra"]["plan_id"] for audit in audits] == [plan["id"], None]
    assert audits[0]["extra"]["mapped"] == 1
    assert audits[0]["extra"]["source_revision"] == 7
    written = json.dumps(report) + json.dumps(audits)
    for term in [*TERMS, "AB"]:
        assert term not in written


@pytest.mark.asyncio
async def test_an_email_type_that_is_off_is_planned_to_monitor_with_its_map_merged(
    db,
) -> None:
    owner = await _owner(db)
    await _call(
        db,
        owner,
        "PUT",
        f"{MANAGEMENT}/settings/pii",
        json={"block_email": False, "entity_actions": {"PHONE_NUMBER": "monitor"}},
    )

    imported = await _call(
        db,
        owner,
        "POST",
        IMPORT,
        json={"rules": [{"id": "mail", "category": "email", "action": "mask"}]},
    )

    [change] = imported.json()["plan"]["changes"]
    assert change["resource"] == "privacy"
    assert change["after"]["entity_actions"] == {
        "PHONE_NUMBER": "monitor",
        "EMAIL_ADDRESS": "monitor",
    }


@pytest.mark.asyncio
async def test_the_import_needs_rules_write_besides_plans_create(db) -> None:
    planner = await _owner(db, custom=["plans.create"])
    member = await _owner(db, role="member")

    refused = await _call(db, planner, "POST", IMPORT, json={"rules": [_term_rule()]})
    member_refused = await _call(
        db, member, "POST", IMPORT, json={"rules": [_term_rule()]}
    )

    assert (refused.status_code, refused.json()["detail"]) == (
        403,
        "Permission required: rules.write",
    )
    assert member_refused.json()["detail"] == "Permission required: plans.create"


@pytest.mark.asyncio
async def test_the_import_plans_its_changes_before_it_takes_the_tenant_lock(
    db, monkeypatch, tenant_lock
) -> None:
    owner = await _owner(db)
    locked: list[bool] = []
    planned_change = rules_api.planned_change

    async def planned(*args, **kwargs):
        locked.append(tenant_lock())
        return await planned_change(*args, **kwargs)

    monkeypatch.setattr(rules_api, "planned_change", planned)
    body = {"rules": [_term_rule(), _term_rule("atlas", terms=["Atlas Raporu"])]}

    imported = await _call(db, owner, "POST", IMPORT, json=body)

    assert imported.status_code == 201, imported.text
    # The history queries behind each planned change run without the lock.
    assert locked == [False, False]


@pytest.mark.asyncio
async def test_a_policy_change_while_the_import_plans_is_a_409(db, monkeypatch) -> None:
    owner = await _owner(db)
    original = rules_api.planned_change

    async def planned(*args, **kwargs):
        monkeypatch.setattr(rules_api, "planned_change", original)
        assert (await _put(db, owner, [_gateway_rule("other")])).status_code == 200
        return await original(*args, **kwargs)

    monkeypatch.setattr(rules_api, "planned_change", planned)

    refused = await _call(db, owner, "POST", IMPORT, json={"rules": [_term_rule()]})

    assert refused.status_code == 409
    assert refused.json()["detail"]["code"] == "POLICY_VERSION_CHANGED"
