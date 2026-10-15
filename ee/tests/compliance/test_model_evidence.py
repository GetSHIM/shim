"""Model evidence documents on seeded rows: every section, the facts, the file and its reads."""

from __future__ import annotations

import asyncio

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from hashlib import sha256
import json
from uuid import uuid4

import pytest
from sqlalchemy import func, select, update

from ee.tests.gateway.test_attempts import _deployment, origins  # noqa: F401
from ee.tests.observability.test_tasks import _request, _tenant
from ee.tests.rules.test_rules_resource import MANAGEMENT, _call
from shim.rules import validate_rule_set
from shim_enterprise.ai_act.audit_writer import write_audit_row
from shim_enterprise.ai_act.bundle import build_audit_bundle
from shim_enterprise.billing.models import RequestLifecycle
from shim_enterprise.compliance.models import ModelEvidenceFile
from shim_enterprise.compliance.services import model_evidence
from shim_enterprise.compliance.services.model_evidence import (
    collect,
    facts_digest,
    routing_section,
    story,
)
from shim_enterprise.compliance.reporting import report_styles
from shim_enterprise.observability.analytics_projection import RequestLog
from shim_enterprise.outbox.models import OutboxEvent
from shim_enterprise.rules.canaries import canary_sides
from shim_enterprise.rules.change_tests import change_test_results
from shim_enterprise.tenants.models import ModelDeployment, User

pytestmark = pytest.mark.usefixtures("origins")
EVIDENCE = f"{MANAGEMENT}/model-evidence"
NOW = datetime.now(timezone.utc).replace(microsecond=0)
START, END = NOW - timedelta(days=2), NOW
PROMPT = "Fatura 4521 için özet çıkar"
ANSWER = "Özet: fatura ödendi"


def _route(rule_id: str = "cheap_start", **match) -> dict:
    return {
        "id": rule_id,
        "name": "Short starts",
        "kind": "route",
        "action": "route",
        "state": "enforced",
        "match": {
            "from": ["strong"],
            "to": "cheap",
            "when": {"max_start_chars": 400},
            **match,
        },
    }


def _routed(
    db,
    key,
    outcome="routed",
    reason="max_start_chars",
    rule_id="cheap_start",
    previous=False,
    language=None,
    decision_values=None,
    **values,
):
    decision = {
        "rule_id": rule_id,
        "state": "enforced" if outcome != "would_route" else "monitor",
        "from": "strong",
        "to": "cheap",
        "reason": reason,
        "conversation_id": f"conv-{values.pop('conversation', 1)}",
        "outcome": outcome,
        **(decision_values or {}),
    }
    if previous:
        decision = {"rule_id": "other", "reason": "fallback", "previous": decision}
    metadata = {"route_decision": decision}
    if language is not None:
        metadata["response_analysis"] = {"language": {"answer": language}}
    request_id = _request(
        db,
        key,
        None,
        model=values.pop("model", "strong"),
        started_at=values.pop("started_at", NOW - timedelta(hours=1)),
        prompt_tokens=1_000,
        completion_tokens=200,
        **metadata,
        **values,
    )
    db.add(
        RequestLog(
            request_id=request_id,
            api_key_id=key.id,
            organization_id=key.organization_id,
            prompt_tokens=1_000,
            completion_tokens=200,
            details={},
        )
    )
    return request_id


async def _priced(db, key, to_price=True):
    await _deployment(
        db,
        key,
        "strong",
        input_price_per_million=Decimal("3.00"),
        output_price_per_million=Decimal("15.00"),
    )
    await _deployment(
        db,
        key,
        "cheap",
        upstream_model="model-the-catalog-does-not-know",
        **(
            {
                "input_price_per_million": Decimal("0.50"),
                "output_price_per_million": Decimal("1.50"),
            }
            if to_price
            else {}
        ),
    )


async def _routing(db, user, rule=None):
    rules = validate_rule_set({"revision": 1, "rules": [rule or _route()]})
    return await routing_section(
        db, user.organization_id, "cheap_start", rules, START, END, [], {}
    )


@pytest.mark.asyncio
async def test_route_repricing_matches_s65_fixture(db) -> None:
    user, key, _ = await _tenant(db)
    await _priced(db, key)
    for index in range(10):
        _routed(db, key, conversation=index)
    _routed(db, key, reason="fallback")
    _routed(db, key, reason="degrade")
    await db.flush()

    section = await _routing(db, user)

    [saving] = section["savings"]
    assert saving["requests"] == 10
    assert (
        saving["cost_at_from_usd"],
        saving["cost_at_to_usd"],
        saving["savings_usd"],
    ) == ("0.0600000000", "0.0080000000", "0.0520000000")
    assert saving["tokens"] == {"prompt": 10_000, "completion": 2_000}
    assert section["decisions"]["routed"] == 12
    assert section["decisions"]["conversations"] == 10


@pytest.mark.asyncio
async def test_an_unpriced_target_is_not_repriced(db) -> None:
    user, key, _ = await _tenant(db)
    await _priced(db, key, to_price=False)
    for _ in range(10):
        _routed(db, key)
    await db.flush()

    [unpriced] = (await _routing(db, user))["savings"]

    assert unpriced["priced"] is False and "savings_usd" not in unpriced


@pytest.mark.asyncio
async def test_an_alias_is_priced_and_served_by_its_price_model_as_s65_does(
    db,
) -> None:
    user, key, _ = await _tenant(db)
    # No deployment prices: strong bills as its price model, cheap as its upstream.
    await _deployment(db, key, "strong", price_model="gpt-4o-mini")
    await _deployment(db, key, "cheap", upstream_model="gpt-4.1-nano")
    for index in range(10):
        _routed(db, key, conversation=index)
    served = _request(
        db, key, None, model="strong", started_at=NOW - timedelta(hours=1)
    )
    await db.flush()
    await db.execute(
        update(RequestLifecycle)
        .where(RequestLifecycle.request_id == served)
        .values(provider_model="gpt-4o-mini")
    )

    [saving] = (await _routing(db, user))["savings"]
    sections = (await _model_selection(db, user))["sections"]

    # 10,000 prompt and 2,000 completion tokens at 0.15/0.60 and 0.10/0.40 per million.
    assert (
        saving["cost_at_from_usd"],
        saving["cost_at_to_usd"],
        saving["savings_usd"],
    ) == ("0.0027000000", "0.0018000000", "0.0009000000")
    assert [
        (model["price_source"], model["input_per_million"])
        for model in sections["models"]
    ] == [("catalog", "0.15"), ("catalog", "0.1")]
    assert [row["model"] for row in sections["live_traffic"]] == ["gpt-4o-mini"]


@pytest.mark.asyncio
async def test_lane_decisions_count_without_repricing_and_previous_decisions_count(
    db,
) -> None:
    user, key, _ = await _tenant(db)
    await _priced(db, key)
    _routed(db, key, outcome=None, reason="long_request")
    _routed(db, key, previous=True)
    _routed(db, key, outcome="would_route")
    await db.flush()

    section = await _routing(db, user)

    by = {
        (item["reason"], item["outcome"]): item["requests"]
        for item in section["decisions"]["by_state_reason_outcome"]
    }
    assert by == {
        ("long_request", None): 1,
        ("max_start_chars", "routed"): 1,
        ("max_start_chars", "would_route"): 1,
    }
    assert [item["requests"] for item in section["savings"]] == [1]
    [potential] = section["potential_savings"]
    assert potential["potential_savings_usd"] == "0.0052000000"


@pytest.mark.asyncio
async def test_served_counts_aliases_and_a_monitor_row_as_served_by_from(db) -> None:
    user, key, _ = await _tenant(db)
    await _priced(db, key)
    strong, cheap = [
        await db.scalar(
            select(ModelDeployment.id).where(
                ModelDeployment.organization_id == user.organization_id,
                ModelDeployment.alias == alias,
            )
        )
        for alias in ("strong", "cheap")
    ]
    # A monitor lane names its lane as `to`; the request stayed on `from`.
    _routed(
        db,
        key,
        outcome=None,
        reason="long_request",
        decision_values={"state": "monitor"},
    )
    # A retargeted request (E63) records deployment ids.
    _routed(
        db,
        key,
        reason="fallback",
        decision_values={"from": str(strong), "to": str(cheap)},
    )
    _routed(db, key)
    await db.flush()

    section = await _routing(db, user)

    assert section["decisions"]["served"] == {"cheap": 2, "strong": 1}


@pytest.mark.asyncio
@pytest.mark.parametrize(("eligible", "adjusted"), [(30, True), (29, False)])
async def test_the_language_adjustment_needs_thirty_answers_per_model(
    db, eligible, adjusted
) -> None:
    user, key, _ = await _tenant(db)
    await _priced(db, key)
    # E46 keys a settled dated snapshot by its price-book entry.
    for alias, upstream in (
        ("strong", "gpt-4o-mini-2024-07-18"),
        ("cheap", "gpt-4.1-nano"),
    ):
        await db.execute(
            update(ModelDeployment)
            .where(
                ModelDeployment.organization_id == user.organization_id,
                ModelDeployment.alias == alias,
            )
            .values(upstream_model=upstream)
        )
    _routed(db, key, language="tr")
    await db.flush()
    ratios = {
        ("gpt-4o-mini", "tr"): (300.0, eligible),
        ("gpt-4.1-nano", "tr"): (200.0, 30),
    }
    rules = validate_rule_set({"revision": 1, "rules": [_route()]})

    section = await routing_section(
        db, user.organization_id, "cheap_start", rules, START, END, [], ratios
    )

    [saving] = section["savings"]
    if adjusted:
        # 200 completion tokens become 300 at strong's own tokens per character.
        assert saving["adjusted_cost_at_from_usd"] == "0.0075000000"
    else:
        assert saving["adjustment_unavailable_reason"] == "not_enough_answers"


@pytest.mark.asyncio
async def test_a_deleted_rule_still_has_numbers(db) -> None:
    user, key, _ = await _tenant(db)
    await _priced(db, key)
    _routed(db, key)
    await db.flush()

    section = await routing_section(
        db, user.organization_id, "cheap_start", None, START, END, [], {}
    )

    assert section["definition"] == "not in the current rule set"
    assert section["decisions"]["routed"] == 1


@pytest.mark.asyncio
async def test_quality_compares_routed_rows_with_the_rest_of_from(db) -> None:
    user, key, _ = await _tenant(db)
    await _priced(db, key)
    _routed(db, key, outcome="routed")
    _request(
        db,
        key,
        None,
        model="strong",
        started_at=NOW - timedelta(hours=1),
        outcome="truncated",
        response_analysis={"schema": {"valid": False}},
    )
    await db.flush()

    quality = (await _routing(db, user))["quality"]

    assert [group["requests"] for group in quality["routed"]] == [1]
    [rest] = quality["not_routed"]
    assert rest["completion_outcomes"]["truncated"] == 1
    assert (rest["schema_invalid_rate"], rest["schema_analysed"]) == (1.0, 1)


async def _model_selection(db, user, **sources):
    return await collect(
        db,
        user.organization_id,
        kind="model_selection",
        title="Llama 4 replaces Llama 3.3",
        note="Decided in the architecture meeting.",
        start=START,
        end=END,
        sources={
            "current": "strong",
            "candidates": ["cheap"],
            "change_tests": [],
            "canaries": [],
            "route_rules": [],
            **sources,
        },
        rule_set=None,
        generated_at=NOW,
        generator_version="shim-gateway/test",
    )


@pytest.mark.asyncio
async def test_model_selection_reuses_the_change_test_and_canary_reads(db) -> None:
    user, key, _ = await _tenant(db)
    await _priced(db, key)
    _request(
        db,
        key,
        None,
        model="strong-upstream",
        started_at=NOW - timedelta(hours=1),
        shadow_rule_id="degisiklik",
        shadow_comparison={
            "primary": {"outcome": "complete"},
            "candidate": {"outcome": "complete"},
            "schema_expected": "none",
        },
    )
    await db.flush()

    facts = await _model_selection(
        db, user, change_tests=["degisiklik"], canaries=["kanarya"]
    )

    sections = facts["sections"]
    expected = await change_test_results(
        db, user.organization_id, "degisiklik", START, END
    )
    assert sections["change_tests"]["degisiklik"] == json.loads(
        json.dumps(expected, default=str)
    )
    assert expected["copies"] == 1
    assert sections["canaries"]["kanarya"] == json.loads(
        json.dumps(
            await canary_sides(db, user.organization_id, "kanarya", START, END),
            default=str,
        )
    )
    assert [model["price_source"] for model in sections["models"]] == [
        "deployment",
        "deployment",
    ]
    assert sections["language_cost"] == model_evidence.NOT_RECORDED
    assert facts["limits"][-1] == "masked_input"


@pytest.mark.asyncio
async def test_the_facts_hash_is_canonical_and_holds_no_content(db) -> None:
    user, key, _ = await _tenant(db)
    await _priced(db, key)
    _routed(db, key)
    await db.flush()

    facts = await _model_selection(db, user)
    shuffled = json.loads(json.dumps(facts, sort_keys=False))
    text = " ".join(
        str(getattr(part, "text", ""))
        for part in story(facts, "management:x", "doc", report_styles())
    )

    assert facts_digest(dict(reversed(list(shuffled.items())))) == facts_digest(facts)
    assert PROMPT not in json.dumps(facts) and ANSWER not in json.dumps(facts)
    assert PROMPT not in text and "What this document does not prove" in text
    assert "management:x" in text


@pytest.mark.asyncio
async def test_create_stores_the_file_and_the_audit_intent_together(db) -> None:
    user, key, _ = await _tenant(db, role="admin")
    await _priced(db, key)
    _routed(db, key)
    await db.flush()

    created = await _call(
        db,
        user,
        "POST",
        EVIDENCE,
        json={
            "kind": "routing",
            "title": "Short starts go to the cheaper model",
            "start": START.isoformat(),
            "end": END.isoformat(),
            "route_rules": ["cheap_start"],
        },
    )

    assert created.status_code == 201, created.text
    body = created.json()
    row = await db.get(ModelEvidenceFile, body["id"])
    assert sha256(row.content).hexdigest() == body["sha256"] == row.sha256
    assert facts_digest(row.facts) == row.facts_sha256
    event = await db.scalar(
        select(OutboxEvent).where(OutboxEvent.aggregate_id == row.audit_event_id)
    )
    assert event.payload["extra"]["sha256"] == row.sha256
    assert event.payload["extra"]["facts_sha256"] == row.facts_sha256
    assert body["anchored"] is False


@pytest.mark.asyncio
async def test_a_slow_collection_stops_at_one_deadline_and_stores_nothing(
    db, monkeypatch
) -> None:
    from shim_enterprise.compliance import model_evidence_api

    user, key, _ = await _tenant(db, role="admin")
    await _priced(db, key)
    await db.flush()
    collect = model_evidence_api.collect

    async def slow(*args, **kwargs):
        # Each statement is bounded; their sum is not.
        await asyncio.sleep(5)
        return await collect(*args, **kwargs)

    monkeypatch.setattr(model_evidence_api, "collect", slow)
    monkeypatch.setattr(model_evidence_api, "COLLECT_SECONDS", 0.2)

    refused = await _call(
        db,
        user,
        "POST",
        EVIDENCE,
        json={
            "kind": "routing",
            "title": "t",
            "start": START.isoformat(),
            "end": END.isoformat(),
            "route_rules": ["cheap_start"],
        },
    )

    assert refused.status_code == 503, refused.text
    assert refused.json()["detail"]["code"] == "QUERY_TIMEOUT"
    assert (
        await db.scalar(
            select(func.count()).where(
                ModelEvidenceFile.organization_id == user.organization_id
            )
        )
        == 0
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        {"start": (NOW - timedelta(days=32)).isoformat()},
        {"end": (NOW + timedelta(hours=1)).isoformat()},
        {"title": ""},
        {"title": "x" * 121},
        {"candidates": []},
        {"candidates": ["a", "b", "c", "d"]},
        {"candidates": ["strong"]},
        {"change_tests": ["Not-An-Id"]},
        {"note": "x" * 2_001},
    ],
)
async def test_create_refuses_out_of_bounds_input(db, change) -> None:
    user, key, _ = await _tenant(db)
    await _priced(db, key)

    refused = await _call(
        db,
        user,
        "POST",
        EVIDENCE,
        json={
            "kind": "model_selection",
            "title": "t",
            "start": START.isoformat(),
            "end": END.isoformat(),
            "current": "strong",
            "candidates": ["cheap"],
            **change,
        },
    )

    assert refused.status_code == 422, refused.text


@pytest.mark.asyncio
async def test_an_unknown_candidate_is_refused(db) -> None:
    user, key, _ = await _tenant(db)
    await _priced(db, key)

    refused = await _call(
        db,
        user,
        "POST",
        EVIDENCE,
        json={
            "kind": "model_selection",
            "title": "t",
            "start": START.isoformat(),
            "end": END.isoformat(),
            "current": "strong",
            "candidates": ["nothing-known"],
        },
    )

    assert refused.status_code == 422, refused.text
    assert refused.json()["detail"]["path"] == "candidates[0]"


@pytest.mark.asyncio
async def test_reads_list_download_and_facts_for_the_tenant_only(db) -> None:
    user, key, _ = await _tenant(db)
    await _priced(db, key)
    created = (
        await _call(
            db,
            user,
            "POST",
            EVIDENCE,
            json={
                "kind": "model_selection",
                "title": "Cheap replaces strong",
                "start": START.isoformat(),
                "end": END.isoformat(),
                "current": "strong",
                "candidates": ["cheap"],
            },
        )
    ).json()
    auditor = User(
        id=uuid4(),
        organization_id=user.organization_id,
        email=f"auditor-{uuid4().hex}@example.com",
        role="auditor",
        is_active=True,
        is_verified=True,
    )
    db.add(auditor)
    stranger, *_ = await _tenant(db)
    await db.flush()

    listed = await _call(db, auditor, "GET", EVIDENCE)
    pdf = await _call(db, auditor, "GET", f"{EVIDENCE}/{created['id']}")
    facts = await _call(db, auditor, "GET", f"{EVIDENCE}/{created['id']}/facts")
    forbidden = await _call(db, auditor, "POST", EVIDENCE, json={})
    hidden = await _call(db, stranger, "GET", f"{EVIDENCE}/{created['id']}")

    assert listed.status_code == 200
    [item] = listed.json()["items"]
    assert "content" not in item and item["anchored"] is False
    assert (
        sha256(pdf.content).hexdigest()
        == created["sha256"]
        == pdf.headers["x-content-sha256"]
    )
    assert (
        facts_digest(facts.json())
        == created["facts_sha256"]
        == facts.headers["x-content-sha256"]
    )
    assert forbidden.status_code == 403
    assert hidden.status_code == 404
    downloads = await db.scalar(
        select(OutboxEvent).where(
            OutboxEvent.payload["endpoint"].astext
            == "tenant.model_evidence_downloaded",
            OutboxEvent.organization_id == user.organization_id,
        )
    )
    assert downloads is not None


@pytest.mark.asyncio
async def test_the_chained_row_anchors_the_file_and_the_bundle_carries_its_hash(
    db,
) -> None:
    user, key, _ = await _tenant(db)
    await _priced(db, key)
    created = (
        await _call(
            db,
            user,
            "POST",
            EVIDENCE,
            json={
                "kind": "model_selection",
                "title": "Cheap replaces strong",
                "start": START.isoformat(),
                "end": END.isoformat(),
                "current": "strong",
                "candidates": ["cheap"],
            },
        )
    ).json()
    event = await db.scalar(
        select(OutboxEvent).where(OutboxEvent.aggregate_id == created["audit_event_id"])
    )
    before = (await _call(db, user, "GET", EVIDENCE)).json()["items"][0]["anchored"]

    # What the outbox's audit handler does with the intent.
    await write_audit_row(dict(event.payload), db)
    after = (await _call(db, user, "GET", EVIDENCE)).json()["items"][0]["anchored"]
    bundle = await build_audit_bundle(
        db, user.organization_id, start=None, end=None, now=datetime.now(timezone.utc)
    )

    assert (before, after) == (False, True)
    [row] = [
        row for row in bundle["rows"] if row["request_id"] == created["audit_event_id"]
    ]
    assert row["extra"]["sha256"] == created["sha256"]
