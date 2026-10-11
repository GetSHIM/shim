from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import func, select, text, update

from shim.rules import Rule
from shim_enterprise.api.enterprise_deps import get_current_user
from shim_enterprise.api.v1.router import management_router
from shim_enterprise.billing.models import RequestLifecycle
from shim_enterprise.core.database import get_db
from shim_enterprise.outbox.models import OutboxEvent
from shim_enterprise.rules import preview
from shim_enterprise.rules.models import (
    OrganizationRuleSet,
    RuleDefinition,
    RulePreview,
)
from shim_enterprise.tenants.models import ApiKey, Organization, User

MANAGEMENT = "/api/v1/management"
NOW = datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc)


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


def _model(**values) -> Rule:
    rule = _rule(**values)
    return Rule.model_validate(
        {**rule, "match": {"label": "TERM", "suffixes": "tr", **rule["match"]}}
    )


class _Frozen(datetime):
    @classmethod
    def now(cls, tz=None):  # type: ignore[override]
        return NOW


async def _tenant(db) -> tuple[User, ApiKey]:
    organization = Organization(
        id=uuid4(), name="Preview", slug=f"preview-{uuid4().hex}", tier="enterprise"
    )
    db.add(organization)
    await db.flush()
    owner = User(
        id=uuid4(),
        organization_id=organization.id,
        email=f"preview-{uuid4().hex}@example.com",
        role="owner",
        is_active=True,
        is_verified=True,
    )
    db.add(owner)
    await db.flush()
    key = ApiKey(
        id=uuid4(),
        organization_id=organization.id,
        user_id=owner.id,
        key_hash=uuid4().hex,
        prefix="sk-shim-pre",
        tier="enterprise",
        is_active=True,
    )
    db.add(key)
    await db.flush()
    return owner, key


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


async def _preview(db, user: User, rule: dict, days: int = 7) -> httpx.Response:
    return await _call(
        db,
        user,
        "POST",
        f"{MANAGEMENT}/rules/preview",
        json={"rule": rule, "window_days": days},
    )


def _row(key: ApiKey, started_at: datetime, model: str = "gpt-5-nano", **metadata):
    return RequestLifecycle(
        request_id=f"req_preview_{uuid4().hex}",
        organization_id=key.organization_id,
        actor_type="api_key",
        api_key_id=key.id,
        source_endpoint="chat.completions",
        status="completed",
        requested_model=model,
        stream=False,
        started_at=started_at,
        lifecycle_metadata=metadata,
    )


def _match(rule_id: str = "falcon", **values) -> list[dict]:
    return [
        {
            "rule_id": rule_id,
            "kind": "term",
            "action": "block",
            "state": "monitor",
            "count": 1,
            **values,
        }
    ]


async def _defined_at(db, organization_id: UUID, rule_id: str = "falcon") -> datetime:
    row = await db.get(
        RuleDefinition, (organization_id, rule_id), populate_existing=True
    )
    return row.defined_at


async def _move_definition(db, organization_id: UUID, when: datetime) -> None:
    await db.execute(
        update(RuleDefinition)
        .where(RuleDefinition.organization_id == organization_id)
        .values(defined_at=when)
    )


def test_the_definition_digest_is_what_the_rule_matches() -> None:
    digest = preview.definition_digest(_model())

    assert digest == preview.definition_digest(
        _model(name="Renamed", action="mask", state="enforced")
    )
    assert digest != preview.definition_digest(_model(scope={"models": ["gpt-5-nano"]}))
    assert digest != preview.definition_digest(
        _model(match={"terms": ["Project Heron"]})
    )
    assert len(digest) == 64 and digest == digest.lower()
    assert preview.preview_digest(_model()) != preview.preview_digest(
        _model(action="mask")
    )
    assert preview.preview_digest(_model()) == preview.preview_digest(
        _model(state="enforced", name="Other")
    )


@pytest.mark.asyncio
async def test_definition_rows_are_kept_reset_backfilled_and_deleted(db) -> None:
    owner, _ = await _tenant(db)
    tenant = owner.organization_id
    earlier = datetime.now(timezone.utc) - timedelta(days=3)
    await _put(db, owner, [_rule()])
    await _move_definition(db, tenant, earlier)

    await _put(db, owner, [_rule(name="Renamed", state="enforced", action="mask")])
    kept = await _defined_at(db, tenant)
    await _put(db, owner, [_rule(match={"terms": ["Project Heron"]})])
    reset = await _defined_at(db, tenant)

    assert kept == earlier
    assert reset > earlier

    # A rule written before definitions were recorded: the set's last write bounds it.
    await db.execute(
        RuleDefinition.__table__.delete().where(
            RuleDefinition.organization_id == tenant
        )
    )
    await db.execute(
        update(OrganizationRuleSet)
        .where(OrganizationRuleSet.organization_id == tenant)
        .values(updated_at=earlier)
    )
    await _put(
        db,
        owner,
        [_rule(match={"terms": ["Project Heron"]}, name="Again"), _rule("heron")],
    )
    backfilled = await _defined_at(db, tenant)
    created = await _defined_at(db, tenant, "heron")
    await _put(db, owner, [_rule("heron")])
    remaining = await db.scalars(
        select(RuleDefinition.rule_id).where(RuleDefinition.organization_id == tenant)
    )

    assert backfilled == earlier
    assert created > earlier
    assert list(remaining) == ["heron"]


@pytest.mark.asyncio
async def test_monitor_history_counts_the_window_after_the_definition(
    db, monkeypatch
) -> None:
    owner, key = await _tenant(db)
    tenant = owner.organization_id
    await _put(db, owner, [_rule()])
    await _move_definition(db, tenant, NOW - timedelta(days=30))
    start = NOW - timedelta(days=7)
    db.add_all(
        [
            _row(key, start - timedelta(seconds=1), rule_matches=_match()),
            _row(key, start, rule_matches=_match()),
            _row(
                key,
                NOW - timedelta(days=1),
                "gpt-5-mini",
                rule_matches=_match(error=True),
            ),
            _row(key, NOW, rule_matches=_match()),
            _row(key, NOW - timedelta(hours=1), rule_matches=_match("heron")),
            _row(
                key,
                NOW - timedelta(hours=2),
                rule_matches=_match("heron"),
                rule_matches_truncated=True,
            ),
        ]
    )
    await db.flush()
    monkeypatch.setattr(preview, "datetime", _Frozen)

    whole = await _preview(db, owner, _rule(state="enforced"))
    await _move_definition(db, tenant, NOW - timedelta(days=2))
    recent = await _preview(db, owner, _rule())

    body = whole.json()
    assert (body["basis"], body["requests"], body["errors"]) == (
        "monitor_history",
        2,
        1,
    )
    assert body["window"]["covered_days"] == 7
    assert body["by_scope"] == {
        "api_keys": [{"id": str(key.id), "requests": 2}],
        "teams": [],
        "models": [
            {"model": "gpt-5-mini", "requests": 1},
            {"model": "gpt-5-nano", "requests": 1},
        ],
        "truncated_rows": 1,
    }
    assert body["note"].startswith("1 requests in the window matched more rules")
    assert body["enforce_on_create"] is False
    assert recent.json()["requests"] == 1
    assert recent.json()["window"]["covered_days"] == 2


@pytest.mark.asyncio
async def test_each_scope_list_holds_the_20_largest(db, monkeypatch) -> None:
    owner, key = await _tenant(db)
    await _put(db, owner, [_rule()])
    await _move_definition(db, owner.organization_id, NOW - timedelta(days=30))
    db.add_all(
        _row(key, NOW - timedelta(hours=1), f"model-{index:02d}", rule_matches=_match())
        for index in range(25)
    )
    db.add(_row(key, NOW - timedelta(hours=2), "model-24", rule_matches=_match()))
    await db.flush()
    monkeypatch.setattr(preview, "datetime", _Frozen)

    models = (await _preview(db, owner, _rule())).json()["by_scope"]["models"]

    assert len(models) == 20
    assert models[0] == {"model": "model-24", "requests": 2}
    assert [item["model"] for item in models[1:3]] == ["model-00", "model-01"]


def test_the_variant_estimator_wins_over_the_kind(monkeypatch) -> None:
    async def kind(*_):
        return None

    async def variant(*_):
        return None

    monkeypatch.setitem(preview.PREVIEW_ESTIMATORS, "route", kind)
    route = Rule(
        id="cheap",
        name="Cheap",
        kind="route",
        action="route",
        state="monitor",
        match={"on": "format_invalid"},
    )

    assert preview.estimator_for(route) is kind
    monkeypatch.setitem(preview.PREVIEW_ESTIMATORS, "route:format_invalid", variant)
    assert preview.estimator_for(route) is variant
    assert preview.estimator_for(route.model_copy(update={"match": {}})) is kind


@pytest.mark.asyncio
async def test_an_estimator_counts_a_new_rule_and_unlocks_it(db, monkeypatch) -> None:
    owner, key = await _tenant(db)
    tenant = owner.organization_id
    seen = []

    async def estimate(session, organization_id, rule, start, end):
        seen.append((organization_id, rule.id, end - start))
        return {
            "requests": 4,
            "by_scope": {
                "api_keys": [{"id": str(key.id), "requests": 4}],
                "teams": [],
                "models": [],
                "truncated_rows": 0,
            },
            "note": None,
        }

    monkeypatch.setitem(preview.PREVIEW_ESTIMATORS, "term", estimate)
    enforced = _rule(state="enforced")

    answered = await _preview(db, owner, enforced)
    stored = await db.scalar(
        select(RulePreview).where(RulePreview.organization_id == tenant)
    )
    put = await _put(db, owner, [enforced])

    body = answered.json()
    assert seen == [(tenant, "falcon", timedelta(days=7))]
    assert (body["basis"], body["requests"], body["errors"]) == ("metadata", 4, 0)
    assert body["window"]["covered_days"] == 7
    assert body["enforce_on_create"] is True
    expires = datetime.fromisoformat(body["preview_expires_at"])
    assert stored.expires_at == expires
    assert expires - datetime.fromisoformat(body["window"]["end"]) == timedelta(
        hours=24
    )
    assert (stored.rule_id, stored.basis, stored.requests, stored.window_days) == (
        "falcon",
        "metadata",
        4,
        7,
    )
    assert put.status_code == 200, put.text
    assert put.json()["rules"][0]["state"] == "enforced"
    audit = await db.scalar(
        select(OutboxEvent).where(
            OutboxEvent.organization_id == tenant,
            OutboxEvent.payload["endpoint"].astext == "tenant.rule_previewed",
        )
    )
    assert audit.payload["extra"] == {
        "subject_id": str(tenant),
        "rule_id": "falcon",
        "kind": "term",
        "basis": "metadata",
        "requests": 4,
        "window_days": 7,
        "enforce_on_create": True,
        "actor_type": "user_jwt",
    }
    assert "Falcon" not in json.dumps(body) + json.dumps(audit.payload)


@pytest.mark.parametrize(
    "put_rule",
    [
        _rule(state="enforced", action="mask"),
        _rule(state="enforced", scope={"models": ["gpt-5-nano"]}),
        _rule(state="enforced", match={"terms": ["Project Heron"]}),
    ],
)
@pytest.mark.asyncio
async def test_a_preview_unlocks_only_the_exact_rule(db, monkeypatch, put_rule) -> None:
    owner, _ = await _tenant(db)

    async def estimate(*_):
        return {"requests": 0, "by_scope": preview._empty_scope(), "note": None}

    monkeypatch.setitem(preview.PREVIEW_ESTIMATORS, "term", estimate)
    await _preview(db, owner, _rule(state="enforced"))

    refused = await _put(db, owner, [put_rule])

    assert refused.json()["detail"]["code"] == "RULE_MUST_START_IN_MONITOR"


@pytest.mark.asyncio
async def test_no_unlock_when_expired_short_of_seven_days_without_basis_or_elsewhere(
    db, monkeypatch
) -> None:
    owner, _ = await _tenant(db)
    other, _ = await _tenant(db)
    enforced = _rule(state="enforced")

    without_basis = await _preview(db, owner, enforced)

    async def estimate(*_):
        return {"requests": 0, "by_scope": preview._empty_scope(), "note": None}

    monkeypatch.setitem(preview.PREVIEW_ESTIMATORS, "term", estimate)
    six_days = await _preview(db, owner, enforced, days=6)
    elsewhere = await _preview(db, other, enforced)
    refused_elsewhere = await _put(db, owner, [enforced])
    await _preview(db, owner, enforced)
    await db.execute(
        update(RulePreview)
        .where(RulePreview.organization_id == owner.organization_id)
        .values(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    )
    expired = await _put(db, owner, [enforced])

    assert without_basis.json()["basis"] == "none"
    assert without_basis.json()["requests"] is None
    assert without_basis.json()["note"] == preview.NO_HISTORY
    assert without_basis.json()["enforce_on_create"] is False
    assert six_days.json()["enforce_on_create"] is False
    assert elsewhere.json()["enforce_on_create"] is True
    for refused in (refused_elsewhere, expired):
        assert refused.json()["detail"]["code"] == "RULE_MUST_START_IN_MONITOR"


@pytest.mark.asyncio
async def test_a_statement_timeout_gives_no_basis_and_keeps_the_transaction(
    db, monkeypatch
) -> None:
    owner, _ = await _tenant(db)

    async def slow(session, *_):
        await session.execute(text("SET LOCAL statement_timeout = '50ms'"))
        await session.execute(text("SELECT pg_sleep(1)"))

    monkeypatch.setitem(preview.PREVIEW_ESTIMATORS, "term", slow)

    answered = await _preview(db, owner, _rule(state="enforced"))

    assert answered.status_code == 200
    assert (answered.json()["basis"], answered.json()["requests"]) == ("none", None)
    assert answered.json()["note"] == "preview took too long; start in monitor"
    # The audit row after the timeout was written in the same transaction.
    assert (
        await db.scalar(
            select(func.count()).where(
                OutboxEvent.organization_id == owner.organization_id,
                OutboxEvent.payload["endpoint"].astext == "tenant.rule_previewed",
            )
        )
        == 1
    )


@pytest.mark.parametrize("days", [0, 32])
@pytest.mark.asyncio
async def test_the_window_is_one_to_31_days(db, days: int) -> None:
    owner, _ = await _tenant(db)

    refused = await _preview(db, owner, _rule(), days=days)

    assert refused.status_code == 422


@pytest.mark.asyncio
async def test_an_invalid_rule_is_refused_as_the_put_refuses_it(db) -> None:
    owner, _ = await _tenant(db)
    short = _rule(match={"terms": ["ab"]})

    previewed = await _preview(db, owner, short)
    put = await _put(db, owner, [short])

    assert previewed.status_code == put.status_code == 422
    assert previewed.json()["detail"] == put.json()["detail"]
