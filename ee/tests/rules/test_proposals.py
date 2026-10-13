from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import logging
from uuid import uuid4

import pytest
from sqlalchemy import func, select

from ee.tests.config_file.test_config_api import call, file_mode, tenant
from shim_enterprise.outbox.models import OutboxEvent
from shim_enterprise.policy.models import PolicyPlan
from shim_enterprise.rules import proposals
from shim_enterprise.rules.models import OrganizationRuleSet
from shim_enterprise.rules.proposals import sentence_digest
from shim_enterprise.tenants.models import User

PROPOSALS = "/api/v1/management/rules/proposals"
SENTENCE = "Atlaszeta projesi gizli; proje kodlarımız PRJ-1234 biçiminde."
MATCH = "Atlaszeta'nın bütçesi onaylandı"
NO_MATCH = "Atlantik rotası açıldı"


def term(
    rule_id: str = "project_atlas",
    terms=("Atlaszeta",),
    match=(MATCH,),
    no_match=(NO_MATCH,),
) -> dict:
    return {
        "id": rule_id,
        "name": "Atlas projesi",
        "kind": "term",
        "action": "mask",
        "scope": {},
        "match": {"terms": list(terms), "label": "PROJECT"},
        "examples": {"match": list(match), "no_match": list(no_match)},
    }


def pattern(rule_id: str = "project_code", **match) -> dict:
    return {
        "id": rule_id,
        "name": "Proje kodu",
        "kind": "pattern",
        "action": "mask",
        "match": {"label": "PROJECT_CODE", **(match or {"templates": ["PRJ-####"]})},
        "examples": {"match": ["PRJ-4821 için rapor"], "no_match": ["PRJ-48211"]},
    }


def destination(**scope) -> dict:
    return {
        "id": "emails_inside",
        "name": "E-postalar içeride",
        "kind": "destination",
        "action": "block",
        "scope": scope,
        "match": {"entity_types": ["EMAIL_ADDRESS"]},
    }


async def propose(db, user: User, *rules: dict, sentence: str = SENTENCE):
    return await call(
        db,
        user,
        "POST",
        PROPOSALS,
        json={"sentence": sentence, "language": "tr", "rules": list(rules)},
    )


def detail(response) -> dict:
    return response.json()["detail"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("change", "path", "code"),
    [
        (lambda r: {**r, "state": "enforced"}, "rules[0].state", "extra_forbidden"),
        (lambda r: {**r, "kind": "route"}, "rules[0].kind", "literal_error"),
        (lambda r: {**r, "kind": "nonsense"}, "rules[0].kind", "literal_error"),
        (
            lambda r: {**r, "examples": {"match": ["x"] * 11, "no_match": []}},
            "rules[0].examples.match",
            "too_long",
        ),
        (
            lambda r: {**r, "examples": {"match": ["y" * 501], "no_match": []}},
            "rules[0].examples.match[0]",
            "string_too_long",
        ),
        (lambda r: {**r, "match": {"label": "PROJECT"}}, "rules[0].match.terms", None),
    ],
)
async def test_shape_errors_carry_the_requests_own_paths(
    db, change, path, code
) -> None:
    owner = (await tenant(db))["owner"]

    response = await propose(db, owner, term(), change(term("second")))

    assert response.status_code == 422, response.text
    body = detail(response)
    assert (body["code"], body["hint"]) == (
        "RULE_PROPOSAL_INVALID",
        "Fix the listed fields and call again.",
    )
    first = body["errors"][0]
    assert first["path"] == path.replace("rules[0]", "rules[1]")
    if code is not None:
        assert first["code"] == code
    assert "Atlaszeta" not in json.dumps(body)


@pytest.mark.asyncio
async def test_too_many_rules_a_long_sentence_and_s35_codes_are_invalid(db) -> None:
    owner = (await tenant(db))["owner"]

    many = await propose(db, owner, *[term(f"r{n}") for n in range(21)])
    long = await propose(db, owner, term(), sentence="x" * 1001)
    unsafe = await propose(db, owner, pattern(regexes=["(a+)+$"]))
    duplicate = await propose(db, owner, term(), term())
    unscoped = await propose(db, owner, destination())

    assert detail(many)["errors"][0]["path"] == "rules"
    assert detail(long)["errors"][0]["path"] == "sentence"
    assert detail(unsafe)["errors"][0]["code"] == "RULE_PATTERN_UNSAFE"
    assert detail(unsafe)["errors"][0]["path"].startswith("rules[0].match")
    assert detail(duplicate)["errors"][0]["code"] == "RULE_ID_DUPLICATE"
    assert detail(unscoped)["errors"][0]["code"] == "RULE_SCOPE_REQUIRED"


def _questions(response) -> list[tuple]:
    assert response.status_code == 422, response.text
    body = detail(response)
    assert body["code"] == "RULE_PROPOSAL_NEEDS_EXAMPLES"
    assert body["hint"].startswith("Ask the user for the exact names")
    return [
        (q["rule_id"], q["reason"], q["term_index"], q["example_index"])
        for q in body["questions"]
    ]


@pytest.mark.asyncio
async def test_each_concreteness_question_on_its_own(db) -> None:
    owner = (await tenant(db))["owner"]
    cases = [
        ((), [(None, "no_rules", None, None)]),
        (
            (term(match=(), no_match=()),),
            [("project_atlas", "missing_examples", None, None)],
        ),
        (
            (term(terms=("Atlaszeta", "GİZLİ")),),
            [("project_atlas", "too_generic", 1, None)],
        ),
        (
            (term(terms=("Gizlilik",)),),
            [
                ("project_atlas", "too_generic", 0, None),
                ("project_atlas", "example_not_matched", None, 0),
            ],
        ),
        (
            (pattern(regexes=[r"\d{4}"]),),
            [
                ("project_code", "too_broad", None, None),
                ("project_code", "no_match_example_matched", None, 0),
            ],
        ),
        (
            (term(match=["Atlantik"], no_match=[NO_MATCH]),),
            [("project_atlas", "example_not_matched", None, 0)],
        ),
        (
            (term(match=[MATCH], no_match=["atlaszeta çantası"]),),
            [("project_atlas", "no_match_example_matched", None, 0)],
        ),
    ]
    for rules, expected in cases:
        assert _questions(await propose(db, owner, *rules)) == expected, rules


@pytest.mark.asyncio
async def test_all_questions_of_all_rules_come_in_request_order(db) -> None:
    owner = (await tenant(db))["owner"]

    response = await propose(
        db,
        owner,
        term("first", terms=("proje",), match=["Atlaszeta"], no_match=[]),
        pattern("second", regexes=[r"\d{4}"]),
    )

    assert _questions(response) == [
        ("first", "too_generic", 0, None),
        ("first", "example_not_matched", None, 0),
        ("second", "too_broad", None, None),
        ("second", "no_match_example_matched", None, 0),
    ]


@pytest.mark.asyncio
async def test_a_search_that_times_out_is_never_a_pass(db, monkeypatch) -> None:
    owner = (await tenant(db))["owner"]
    monkeypatch.setattr(
        proposals, "count_rule_matches", lambda rule_set, text: {"project_code": -1}
    )

    response = await propose(db, owner, pattern())

    assert _questions(response) == [
        ("project_code", "too_broad", None, None),
        ("project_code", "example_not_matched", None, 0),
        ("project_code", "no_match_example_matched", None, 0),
    ]


@pytest.mark.asyncio
async def test_a_concrete_proposal_becomes_a_monitor_plan(db, caplog) -> None:
    users = await tenant(db)
    owner = users["owner"]
    caplog.set_level(logging.INFO)

    response = await propose(
        db, owner, term(), pattern(), destination(deployment_kinds=["external"])
    )

    assert response.status_code == 201, response.text
    body = response.json()
    plan = body["plan"]
    assert (body["status"], plan["source"], plan["status"], plan["reason"]) == (
        "proposed",
        "proposal",
        "draft",
        "rule proposal",
    )
    assert [(c["resource"], c["item"], c["before"]) for c in plan["changes"]] == [
        ("rules", "project_atlas", None),
        ("rules", "project_code", None),
        ("rules", "emails_inside", None),
    ]
    assert {c["after"]["state"] for c in plan["changes"]} == {"monitor"}
    context = plan["context"]["proposal"]
    assert set(context) == {
        "checks_version",
        "sentence_digest",
        "sentence_chars",
        "language",
        "channel",
        "rules",
    }
    assert (context["sentence_chars"], context["language"], context["channel"]) == (
        len(SENTENCE),
        "tr",
        "api",
    )
    assert context["rules"]["project_atlas"] == {
        "match_examples": 1,
        "no_match_examples": 1,
    }
    assert context["rules"]["emails_inside"] == {
        "match_examples": 0,
        "no_match_examples": 0,
    }
    assert len(context["sentence_digest"]) == 64
    events = list(
        await db.scalars(
            select(OutboxEvent).where(
                OutboxEvent.organization_id == owner.organization_id
            )
        )
    )
    audit = next(
        event.payload["extra"]
        for event in events
        if event.payload.get("endpoint") == "tenant.rule_proposal_created"
    )
    assert {key: audit[key] for key in ("rules", "kinds", "terms", "channel")} == {
        "rules": 3,
        "kinds": {"term": 1, "pattern": 1, "destination": 1},
        "terms": 1,
        "channel": "api",
    }
    stored = (
        json.dumps(plan["context"])
        + json.dumps([event.payload for event in events])
        + caplog.text
    )
    for secret in (
        SENTENCE,
        MATCH,
        NO_MATCH,
        "PRJ-4821",
        "PRJ-48211",
        "Atlas projesi gizli",
    ):
        assert secret not in stored
    assert context["sentence_digest"] not in json.dumps([e.payload for e in events])


def test_the_digest_ignores_spacing_and_is_keyed() -> None:
    import hashlib

    first = sentence_digest(SENTENCE)

    assert sentence_digest("  " + SENTENCE.replace(" ", "   \n ") + " ") == first
    assert sentence_digest(SENTENCE + ".") != first
    assert first != hashlib.sha256(SENTENCE.encode()).hexdigest()
    assert len(first) == 64 and int(first, 16) >= 0


@pytest.mark.asyncio
async def test_proposals_only_add_rules_within_the_set_limit(db) -> None:
    owner = (await tenant(db))["owner"]
    stored = [
        {**term(f"stored_{n:03d}", terms=(f"Kod{n:03d}x",)), "state": "monitor"}
        for n in range(100)
    ]
    for rule in stored:
        rule.pop("examples")
    db.add(
        OrganizationRuleSet(
            organization_id=owner.organization_id, revision=1, rules=stored
        )
    )
    await db.flush()

    exists = await propose(db, owner, {**term(), "id": "stored_000"})
    full = await propose(db, owner, term())

    assert detail(exists)["errors"] == [
        {
            "path": "rules[0].id",
            "code": "RULE_ID_EXISTS",
            "message": "A rule with this id is already in the set; change it with a plan.",
        }
    ]
    assert detail(full)["code"] == "RULE_PROPOSAL_INVALID"
    assert detail(full)["errors"][0]["path"] == "rules"


@pytest.mark.asyncio
async def test_at_most_twenty_open_proposals_and_expired_ones_do_not_count(db) -> None:
    owner = (await tenant(db))["owner"]
    now = datetime.now(timezone.utc)
    for index in range(21):
        db.add(
            PolicyPlan(
                organization_id=owner.organization_id,
                base_version=0,
                changes=[],
                risk="neutral",
                status="draft",
                source="proposal",
                context={},
                created_by=str(owner.id),
                created_by_actor_type="user_jwt",
                # One of them has expired.
                expires_at=now + timedelta(days=-1 if index == 0 else 7),
            )
        )
    await db.flush()

    limited = await propose(db, owner, term())

    assert limited.status_code == 409
    assert detail(limited) == {
        "code": "RULE_PROPOSAL_LIMIT",
        "open": 20,
        "message": "Too many rule proposals wait for an administrator.",
        "hint": "Apply or let the open proposals expire first.",
    }


@pytest.mark.asyncio
async def test_in_file_mode_the_rules_come_back_for_the_file_and_nothing_is_stored(
    db,
) -> None:
    owner = (await tenant(db))["owner"]
    await file_mode(db, owner, "rules")
    plans = await db.scalar(
        select(func.count()).where(PolicyPlan.organization_id == owner.organization_id)
    )

    response = await propose(db, owner, term())

    assert response.status_code == 409
    body = detail(response)
    assert body["code"] == "CONFIG_FILE_MANAGED"
    assert body["validated_rules"] == [
        {
            "id": "project_atlas",
            "name": "Atlas projesi",
            "kind": "term",
            "action": "mask",
            "state": "monitor",
            "scope": body["validated_rules"][0]["scope"],
            "match": body["validated_rules"][0]["match"],
        }
    ]
    assert body["validated_rules"][0]["match"]["terms"] == ["Atlaszeta"]
    assert (
        await db.scalar(
            select(func.count()).where(
                PolicyPlan.organization_id == owner.organization_id
            )
        )
        == plans
    )


@pytest.mark.asyncio
async def test_a_service_account_through_mcp_is_labelled_mcp(db) -> None:
    owner = (await tenant(db))["owner"]
    agent = User(
        id=uuid4(),
        organization_id=owner.organization_id,
        email=f"agent-{uuid4().hex}@example.com",
        role="recommender",
        kind="service",
        is_active=True,
        is_verified=True,
    )
    db.add(agent)
    await db.flush()

    response = await call(
        db,
        agent,
        "POST",
        PROPOSALS,
        json={"sentence": SENTENCE, "rules": [term()]},
        headers={"x-shim-channel": "mcp"},
    )

    assert response.status_code == 201, response.text
    assert response.json()["plan"]["context"]["proposal"]["channel"] == "mcp"


@pytest.mark.asyncio
async def test_a_stored_rule_this_release_cannot_run_still_holds_its_id_and_place(
    db,
) -> None:
    owner = (await tenant(db))["owner"]
    stored = [
        {**term(f"stored_{n:03d}", terms=(f"Kod{n:03d}x",)), "state": "monitor"}
        for n in range(99)
    ]
    for rule in stored:
        rule.pop("examples")
    # A newer build's kind: kept as it is, unusable here.
    stored.append(
        {"id": "future_rule", "kind": "hologram", "action": "mask", "state": "monitor"}
    )
    db.add(
        OrganizationRuleSet(
            organization_id=owner.organization_id, revision=1, rules=stored
        )
    )
    await db.flush()

    exists = await propose(db, owner, {**term(), "id": "future_rule"})
    full = await propose(db, owner, term())

    assert detail(exists)["errors"][0]["code"] == "RULE_ID_EXISTS"
    assert detail(full)["code"] == "RULE_PROPOSAL_INVALID"
    assert detail(full)["errors"][0]["path"] == "rules"


@pytest.mark.asyncio
async def test_a_set_over_its_regex_limit_is_refused_before_each_rule_is_probed(
    db, monkeypatch
) -> None:
    owner = (await tenant(db))["owner"]
    checked: list[int] = []
    checked_set = proposals.checked_set

    def counted(version, rules):
        checked.append(len(rules))
        return checked_set(version, rules)

    monkeypatch.setattr(proposals, "checked_set", counted)
    rules = [
        pattern(
            f"code_{n}",
            regexes=[rf"PRJ{n:02d}{k:02d}-[0-9]{{4}}" for k in range(32)],
        )
        for n in range(20)
    ]

    refused = await propose(db, owner, *rules)

    assert detail(refused)["code"] == "RULE_PROPOSAL_INVALID"
    assert detail(refused)["errors"][0]["path"].startswith("rules")
    # One check of the whole set; no rule's probes ran.
    assert checked == [20]
