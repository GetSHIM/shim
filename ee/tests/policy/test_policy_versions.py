from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
from uuid import UUID, uuid4

from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import async_sessionmaker

from shim_enterprise.ai_act.models import OversightPolicy
from shim_enterprise.api.enterprise_deps import get_current_user
from shim_enterprise.api.v1 import management
from shim_enterprise.api.v1.router import management_router
from shim_enterprise.billing.models import CostBudget, RequestLifecycle
from shim_enterprise.core.config import settings
from shim_enterprise.core.database import get_db
from shim_enterprise.outbox.models import OutboxEvent
from shim_enterprise.policy.models import PolicyPlan, PolicyVersion
from shim_enterprise.policy.plans import lock_tenant, record_managed_write
from shim_enterprise.policy.resources import REGISTRY
from shim_enterprise.tenants.models import (
    ApiKey,
    ModelDeployment,
    Organization,
    ProviderSecret,
    Team,
    User,
)

POLICY = "/api/v1/management/policy"
_TARGET = {"kind": "webhook", "endpoint": "https://alerts.example.com/hook"}


async def _tenant(db, role: str = "owner") -> User:
    organization = Organization(
        id=uuid4(), name="Policy", slug=f"policy-{uuid4().hex}", tier="enterprise"
    )
    db.add(organization)
    await db.flush()
    user = User(
        id=uuid4(),
        organization_id=organization.id,
        email=f"policy-{uuid4().hex}@example.com",
        role=role,
        is_active=True,
        is_verified=True,
    )
    db.add(user)
    await db.flush()
    return user


def _app(db, user: User) -> FastAPI:
    app = FastAPI()
    app.include_router(management_router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_db] = lambda: db
    return app


async def _call(db, user: User, method: str, path: str, **kwargs) -> httpx.Response:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app(db, user)), base_url="http://test"
    ) as client:
        return await client.request(method, path, **kwargs)


async def _versions(db, organization_id: UUID) -> list[PolicyVersion]:
    return list(
        await db.scalars(
            select(PolicyVersion)
            .where(PolicyVersion.organization_id == organization_id)
            .order_by(PolicyVersion.version)
        )
    )


def _events(db_rows: list[OutboxEvent], action: str) -> list[dict]:
    return [
        row.payload["extra"] for row in db_rows if row.payload["endpoint"] == action
    ]


async def _audit_rows(db, organization_id: UUID) -> list[OutboxEvent]:
    return list(
        await db.scalars(
            select(OutboxEvent)
            .where(
                OutboxEvent.organization_id == organization_id,
                OutboxEvent.event_type == "audit.chain_append_requested",
            )
            .order_by(OutboxEvent.next_attempt_at)
        )
    )


async def _secret(db, organization_id: UUID) -> ProviderSecret:
    secret = ProviderSecret(
        id=uuid4(),
        organization_id=organization_id,
        provider="openai",
        secret_ref="reference-policy",
        secret_backend="fernet",
        secret_version="v2",
        masked_key="masked",
    )
    db.add(secret)
    await db.flush()
    return secret


def _deployment_body(secret_id: UUID, **values) -> dict:
    return {
        "alias": "policy-model",
        "provider": "openai",
        "upstream_model": "policy-upstream",
        "base_url": "https://a.internal/v1",
        "provider_secret_id": str(secret_id),
        "deployment_kind": "internal",
        "declared_version": "v1",
        "owner": "Platform",
        **values,
    }


@pytest.fixture
def origins(monkeypatch):
    monkeypatch.setattr(
        settings, "MODEL_DEPLOYMENT_ALLOWED_ORIGINS", ["https://a.internal"]
    )
    # Budget targets are checked by DNS; these tests never deliver to them.
    monkeypatch.setattr(management, "assert_safe_forward_url", AsyncMock())


@pytest.mark.asyncio
async def test_a_managed_write_records_one_version_and_none_for_no_change(db) -> None:
    owner = await _tenant(db)
    body = {"entity_actions": {"EMAIL_ADDRESS": "monitor"}}

    first = await _call(db, owner, "PUT", "/api/v1/management/settings/pii", json=body)
    again = await _call(db, owner, "PUT", "/api/v1/management/settings/pii", json=body)
    listed = await _call(db, owner, "GET", f"{POLICY}/versions")
    one = await _call(db, owner, "GET", f"{POLICY}/versions/1")

    assert (first.status_code, again.status_code) == (200, 200)
    assert first.json() == again.json()
    [version] = await _versions(db, owner.organization_id)
    assert (version.version, version.source, version.actor_type, version.risk) == (
        1,
        "api",
        "user_jwt",
        "relaxing",
    )
    assert version.created_by == str(owner.id)
    assert version.previous["privacy"]["_"]["entity_actions"] == {}
    assert version.snapshot["privacy"]["_"]["entity_actions"] == {
        "EMAIL_ADDRESS": "monitor"
    }
    assert [item["items"] for item in listed.json()] == [{"privacy": ["_"]}]
    assert one.json()["snapshot"] == version.snapshot
    updates = _events(
        await _audit_rows(db, owner.organization_id), "tenant.privacy_policy_updated"
    )
    assert [event.get("policy_version") for event in updates] == [1, None]


@pytest.mark.asyncio
async def test_every_resource_snapshots_only_its_managed_fields(db, origins) -> None:
    owner = await _tenant(db)
    tenant = owner.organization_id
    secret = await _secret(db, tenant)
    team = await _call(
        db, owner, "POST", "/api/v1/management/teams", json={"name": "risk"}
    )
    deployment = await _call(
        db,
        owner,
        "POST",
        "/api/v1/management/model-deployments",
        json=_deployment_body(
            secret.id, input_price_per_million="0.50", output_price_per_million="1.5"
        ),
    )
    budget = await _call(
        db,
        owner,
        "POST",
        "/api/v1/management/cost/budgets",
        json={"scope_type": "org", "limit_usd": "10", "notify_targets": [_TARGET]},
    )
    oversight = await _call(
        db,
        owner,
        "POST",
        "/api/v1/compliance/oversight/policies",
        json={"name": "review", "trigger": {"pii_detected": True}},
    )
    key = ApiKey(
        id=uuid4(),
        organization_id=tenant,
        user_id=owner.id,
        key_hash=uuid4().hex,
        prefix="sk-shim-pol",
        tier="enterprise",
        is_active=True,
    )
    db.add(key)
    await db.flush()

    state = (await _call(db, owner, "GET", f"{POLICY}/state")).json()

    assert state["version"] == 4
    resources = state["resources"]
    assert set(resources) == set(REGISTRY)
    assert set(resources["privacy"]["_"]) == set(
        management.PrivacySettings.model_fields
    )
    assert resources["teams"][team.json()["id"]] == {
        "name": "risk",
        "daily_request_limit": None,
        "monthly_request_limit": None,
        "monthly_token_limit": None,
    }
    assert resources["api_keys"][str(key.id)] == {
        "allowed_models": None,
        "team_id": None,
    }
    stored = resources["deployments"][deployment.json()["id"]]
    assert set(stored) == set(management.ModelDeploymentInput.model_fields)
    assert (stored["input_price_per_million"], stored["provider_secret_id"]) == (
        "0.5",
        str(secret.id),
    )
    assert resources["budgets"][budget.json()["id"]] == {
        "scope_type": "org",
        "scope_value": None,
        "limit_usd": "10",
        "limit_tokens": None,
        "alert_thresholds": [0.8, 1.0],
        "enabled": True,
    }
    assert resources["oversight_policies"][oversight.json()["id"]]["mode"] == "flag"
    assert "notify_targets" not in json.dumps(state)


@pytest.mark.parametrize(
    ("name", "before", "after", "risk"),
    [
        ("teams", {"daily_request_limit": 5}, {"daily_request_limit": 6}, "relaxing"),
        (
            "teams",
            {"daily_request_limit": 5},
            {"daily_request_limit": None},
            "relaxing",
        ),
        (
            "teams",
            {"daily_request_limit": None},
            {"daily_request_limit": 5},
            "tightening",
        ),
        ("teams", {"daily_request_limit": 5}, {"daily_request_limit": 5}, "neutral"),
        (
            "api_keys",
            {"allowed_models": ["a"]},
            {"allowed_models": ["a", "b"]},
            "relaxing",
        ),
        ("api_keys", {"allowed_models": ["a"]}, {"allowed_models": None}, "relaxing"),
        ("api_keys", {"allowed_models": None}, {"allowed_models": ["a"]}, "tightening"),
        ("api_keys", {"team_id": "t"}, {"team_id": None}, "relaxing"),
        ("api_keys", {"team_id": None}, {"team_id": "t"}, "tightening"),
        (
            "api_keys",
            {"allowed_models": ["a", "b"], "team_id": None},
            {"allowed_models": ["a"], "team_id": None},
            "tightening",
        ),
        (
            "api_keys",
            {"allowed_models": ["a"], "team_id": "t"},
            {"allowed_models": ["b"], "team_id": "t"},
            "relaxing",
        ),
        ("deployments", None, {}, "relaxing"),
        ("deployments", {"enabled": False}, {"enabled": True}, "relaxing"),
        ("deployments", {"base_url": "x"}, {"base_url": "y"}, "relaxing"),
        (
            "deployments",
            {"deployment_kind": "external"},
            {"deployment_kind": "internal"},
            "relaxing",
        ),
        ("deployments", {"enabled": True}, {"enabled": False}, "tightening"),
        (
            "deployments",
            {"deployment_kind": "internal"},
            {"deployment_kind": "external"},
            "tightening",
        ),
        ("deployments", {"owner": "a"}, {"owner": "b"}, "neutral"),
        ("budgets", {}, None, "relaxing"),
        ("budgets", None, {}, "tightening"),
        ("budgets", {"limit_usd": "10"}, {"limit_usd": "20"}, "relaxing"),
        ("budgets", {"limit_usd": "10"}, {"limit_usd": None}, "relaxing"),
        ("budgets", {"enabled": True}, {"enabled": False}, "relaxing"),
        ("budgets", {"limit_usd": "20"}, {"limit_usd": "10"}, "tightening"),
        ("budgets", {"limit_tokens": None}, {"limit_tokens": 10}, "tightening"),
        (
            "budgets",
            {"alert_thresholds": [1.0]},
            {"alert_thresholds": [0.5]},
            "neutral",
        ),
        ("oversight_policies", {"enabled": True}, None, "relaxing"),
        ("oversight_policies", {"enabled": True}, {"enabled": False}, "relaxing"),
        ("oversight_policies", None, {"enabled": True}, "tightening"),
        (
            "oversight_policies",
            {"enabled": True},
            {"enabled": True, "name": "x"},
            "neutral",
        ),
    ],
)
def test_each_resource_classifies_its_rows(name, before, after, risk) -> None:
    defaults = {
        "teams": dict.fromkeys(
            ("daily_request_limit", "monthly_request_limit", "monthly_token_limit")
        ),
        "api_keys": {"allowed_models": None, "team_id": None},
        "deployments": {
            "enabled": True,
            "base_url": "x",
            "deployment_kind": "internal",
            "owner": "a",
        },
        "budgets": {
            "limit_usd": None,
            "limit_tokens": None,
            "enabled": True,
            "alert_thresholds": [1.0],
        },
        "oversight_policies": {"enabled": True, "name": "a"},
    }[name]
    full = [None if side is None else {**defaults, **side} for side in (before, after)]
    assert REGISTRY[name].classify(*full) == risk


@pytest.mark.parametrize(
    ("before", "after", "risk"),
    [
        ({"block_email": True}, {"block_email": False}, "relaxing"),
        ({"block_email": False}, {"block_email": True}, "tightening"),
        ({"placeholder_mode": "random"}, {"placeholder_mode": "stable"}, "relaxing"),
        ({"bulk_threshold": 50}, {"bulk_threshold": None}, "relaxing"),
        ({"bulk_threshold": 50}, {"bulk_threshold": 10}, "tightening"),
        ({"response_scan": "off"}, {"response_scan": "count"}, "tightening"),
        (
            {"entity_actions": {}},
            {"entity_actions": {"SECRET": "block"}},
            "tightening",
        ),
        (
            {"entity_actions": {}},
            {"entity_actions": {"SECRET": "block", "EMAIL_ADDRESS": "monitor"}},
            "relaxing",
        ),
        ({"entity_actions": {}}, {"entity_actions": {}}, "neutral"),
    ],
)
def test_privacy_classifies_by_the_relaxed_list(before, after, risk) -> None:
    defaults = {
        **dict.fromkeys(
            (
                "block_email",
                "block_phone",
                "block_credit_card",
                "block_secrets",
                "block_pii_tr",
            ),
            True,
        ),
        "entity_actions": {},
        "placeholder_mode": "random",
        "bulk_threshold": 50,
        "response_scan": "off",
    }
    assert (
        REGISTRY["privacy"].classify({**defaults, **before}, {**defaults, **after})
        == risk
    )


@pytest.mark.asyncio
async def test_plans_validate_each_change_with_the_routes_messages(db, origins) -> None:
    owner = await _tenant(db)
    team = await _call(
        db, owner, "POST", "/api/v1/management/teams", json={"name": "risk"}
    )

    async def plan(*changes: dict) -> httpx.Response:
        return await _call(
            db, owner, "POST", f"{POLICY}/plans", json={"changes": list(changes)}
        )

    blank = await plan({"resource": "teams", "item": None, "set": {"name": " "}})
    unknown = await plan({"resource": "secrets", "item": None, "set": {}})
    budget_limit = await plan(
        {
            "resource": "budgets",
            "item": None,
            "set": {"scope_type": "org", "limit_usd": "0"},
        }
    )
    targets = await plan(
        {
            "resource": "budgets",
            "item": None,
            "set": {"scope_type": "org", "limit_usd": "5", "notify_targets": [_TARGET]},
        }
    )
    origin = await plan(
        {
            "resource": "deployments",
            "item": None,
            "set": _deployment_body(uuid4(), base_url="https://b.internal/v1"),
        }
    )
    not_deletable = await plan(
        {"resource": "teams", "item": team.json()["id"], "delete": True}
    )
    not_creatable = await plan({"resource": "privacy", "item": None, "set": {}})
    missing = await plan({"resource": "teams", "item": str(uuid4()), "set": {}})
    twice = await plan(
        {"resource": "privacy", "item": "_", "set": {"block_email": False}},
        {"resource": "privacy", "item": "_", "set": {"block_phone": False}},
    )
    unmanaged = await plan(
        {"resource": "api_keys", "item": str(uuid4()), "set": {"cost_center": "x"}}
    )
    both = await plan({"resource": "teams", "item": "x", "set": {}, "delete": True})
    too_many = await plan(
        *({"resource": "privacy", "item": "_", "set": {}} for _ in range(101))
    )
    too_large = await _call(
        db,
        owner,
        "POST",
        f"{POLICY}/plans",
        json={
            "changes": [{"resource": "privacy", "item": "_", "set": {}}],
            "reason": None,
            "padding": "x" * (256 * 1024),
        },
    )

    assert blank.status_code == 422 and "Team name cannot be blank" in blank.text
    assert blank.json()["detail"]["change"] == 0
    assert unknown.status_code == 422 and "Unknown resource" in unknown.text
    assert budget_limit.status_code == 422 and "greater than 0" in budget_limit.text
    assert targets.status_code == 422
    assert origin.status_code == 422
    assert (
        not_deletable.status_code == 422 and "cannot be deleted" in not_deletable.text
    )
    assert (
        not_creatable.status_code == 422 and "cannot be created" in not_creatable.text
    )
    assert missing.status_code == 422 and "Item not found" in missing.text
    assert twice.status_code == 422 and twice.json()["detail"]["change"] == 1
    assert unmanaged.status_code == 422
    assert both.status_code == 422
    assert too_many.status_code == 422
    assert too_large.status_code == 413
    assert (
        await db.scalar(
            select(PolicyPlan.id).where(
                PolicyPlan.organization_id == owner.organization_id
            )
        )
        is None
    )


@pytest.mark.asyncio
async def test_a_plan_shows_its_effect_and_applies_as_one_version(db, origins) -> None:
    owner = await _tenant(db)
    tenant = owner.organization_id
    team = (
        await _call(
            db, owner, "POST", "/api/v1/management/teams", json={"name": "risk"}
        )
    ).json()
    budget = (
        await _call(
            db,
            owner,
            "POST",
            "/api/v1/management/cost/budgets",
            json={"scope_type": "org", "limit_usd": "10", "notify_targets": [_TARGET]},
        )
    ).json()

    created = await _call(
        db,
        owner,
        "POST",
        f"{POLICY}/plans",
        json={
            "reason": "quarterly review",
            "changes": [
                {
                    "resource": "teams",
                    "item": team["id"],
                    "set": {"daily_request_limit": 100},
                },
                {"resource": "teams", "item": None, "set": {"name": "ops"}},
                {"resource": "budgets", "item": budget["id"], "delete": True},
            ],
        },
    )
    plan = created.json()
    applied = await _call(db, owner, "POST", f"{POLICY}/plans/{plan['id']}/apply")
    again = await _call(db, owner, "POST", f"{POLICY}/plans/{plan['id']}/apply")

    assert created.status_code == 201
    assert (plan["status"], plan["risk"], plan["base_version"]) == (
        "draft",
        "relaxing",
        2,
    )
    first, second, third = plan["changes"]
    assert (
        first["before"]["daily_request_limit"],
        first["after"]["daily_request_limit"],
    ) == (
        None,
        100,
    )
    assert (first["risk"], second["risk"], third["risk"]) == (
        "tightening",
        "neutral",
        "relaxing",
    )
    assert second["before"] is None and UUID(second["item"])
    assert third["after"] is None
    assert first["impact"] == {
        "requests": 0,
        "basis": "metadata",
        "window_days": 7,
        "note": None,
    }
    assert applied.status_code == 200
    assert (applied.json()["status"], applied.json()["applied_version"]) == (
        "applied",
        3,
    )
    assert again.status_code == 409
    assert again.json()["detail"] == {
        "code": "PLAN_STATE_CONFLICT",
        "status": "applied",
    }
    version = (await _versions(db, tenant))[-1]
    assert (version.version, version.source, version.plan_id, version.reason) == (
        3,
        "plan",
        UUID(plan["id"]),
        "quarterly review",
    )
    assert set(version.snapshot["teams"]) == {team["id"], second["item"]}
    assert version.snapshot["budgets"] == {budget["id"]: None}
    assert await db.get(Team, UUID(second["item"])) is not None
    assert await db.get(CostBudget, UUID(budget["id"])) is None
    rows = await _audit_rows(db, tenant)
    assert [
        event["policy_version"] for event in _events(rows, "tenant.budget_deleted")
    ] == [3]
    assert _events(rows, "tenant.policy_plan_applied")[0]["resources"] == [
        "budgets",
        "teams",
    ]


@pytest.mark.asyncio
async def test_a_plan_is_stale_after_a_direct_write_and_expires_on_read(db) -> None:
    owner = await _tenant(db)
    team = (
        await _call(
            db, owner, "POST", "/api/v1/management/teams", json={"name": "risk"}
        )
    ).json()
    change = {
        "resource": "teams",
        "item": team["id"],
        "set": {"daily_request_limit": 5},
    }
    stale = (
        await _call(db, owner, "POST", f"{POLICY}/plans", json={"changes": [change]})
    ).json()
    old = (
        await _call(db, owner, "POST", f"{POLICY}/plans", json={"changes": [change]})
    ).json()
    await _call(
        db,
        owner,
        "PUT",
        f"/api/v1/management/teams/{team['id']}",
        json={"name": "risk", "daily_request_limit": 7},
    )
    await db.execute(
        update(PolicyPlan)
        .where(PolicyPlan.id == UUID(old["id"]))
        .values(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    )

    refused = await _call(db, owner, "POST", f"{POLICY}/plans/{stale['id']}/apply")
    expired = await _call(db, owner, "GET", f"{POLICY}/plans/{old['id']}")
    listed = await _call(
        db, owner, "GET", f"{POLICY}/plans", params={"status": "expired"}
    )
    late = await _call(db, owner, "POST", f"{POLICY}/plans/{old['id']}/apply")

    assert refused.status_code == 409
    assert refused.json()["detail"] == {
        "code": "PLAN_STALE",
        "items": [{"resource": "teams", "item": team["id"]}],
    }
    assert (await db.get(Team, UUID(team["id"]))).daily_request_limit == 7
    assert expired.json()["status"] == "expired"
    assert [plan["id"] for plan in listed.json()] == [old["id"]]
    assert late.json()["detail"] == {"code": "PLAN_STATE_CONFLICT", "status": "expired"}


@pytest.mark.asyncio
async def test_restore_puts_back_what_it_can_and_names_the_rest(db, origins) -> None:
    owner = await _tenant(db)
    tenant = owner.organization_id
    secret = await _secret(db, tenant)
    key = ApiKey(
        id=uuid4(),
        organization_id=tenant,
        user_id=owner.id,
        key_hash=uuid4().hex,
        prefix="sk-shim-res",
        tier="enterprise",
        is_active=True,
    )
    db.add(key)
    await db.flush()
    budget = (
        await _call(
            db,
            owner,
            "POST",
            "/api/v1/management/cost/budgets",
            json={"scope_type": "org", "limit_usd": "10", "notify_targets": [_TARGET]},
        )
    ).json()
    await _call(
        db,
        owner,
        "PATCH",
        f"/api/v1/management/api-keys/{key.id}",
        json={"allowed_models": ["gpt-5-mini"]},
    )
    target = len(await _versions(db, tenant))
    applied_plan = (
        await _call(
            db,
            owner,
            "POST",
            f"{POLICY}/plans",
            json={
                "changes": [
                    {
                        "resource": "privacy",
                        "item": "_",
                        "set": {"entity_actions": {"SECRET": "block"}},
                    }
                ]
            },
        )
    ).json()
    await _call(db, owner, "POST", f"{POLICY}/plans/{applied_plan['id']}/apply")
    await _call(
        db, owner, "PUT", "/api/v1/management/settings/pii", json={"block_phone": False}
    )
    await _call(
        db,
        owner,
        "PATCH",
        f"/api/v1/management/api-keys/{key.id}",
        json={"allowed_models": None},
    )
    await _call(db, owner, "DELETE", f"/api/v1/management/cost/budgets/{budget['id']}")
    team = (
        await _call(
            db, owner, "POST", "/api/v1/management/teams", json={"name": "late"}
        )
    ).json()
    deployment = (
        await _call(
            db,
            owner,
            "POST",
            "/api/v1/management/model-deployments",
            json=_deployment_body(secret.id),
        )
    ).json()
    oversight = (
        await _call(
            db,
            owner,
            "POST",
            "/api/v1/compliance/oversight/policies",
            json={"name": "late", "trigger": {"pii_detected": True}},
        )
    ).json()
    key.is_active = False
    await db.flush()
    privacy_before_restore = (
        await _call(db, owner, "GET", "/api/v1/management/settings/pii")
    ).json()

    restored = await _call(
        db,
        owner,
        "POST",
        f"{POLICY}/versions/{target}/restore",
        json={"reason": "undo"},
    )

    body = restored.json()
    assert restored.status_code == 200
    assert body["plan"]["source"] == "restore" and body["plan"]["status"] == "applied"
    assert {(row["resource"], row["reason"]) for row in body["not_restored"]} == {
        ("api_keys", "key_revoked"),
        ("teams", "team_not_deletable"),
        ("budgets", "notify_targets_not_restored"),
    }
    assert body["approximated"] == [
        {
            "resource": "deployments",
            "item": deployment["id"],
            "reason": "deployment_not_deletable",
        }
    ]
    privacy = (await _call(db, owner, "GET", "/api/v1/management/settings/pii")).json()
    assert (
        privacy_before_restore["block_phone"],
        privacy_before_restore["entity_actions"],
    ) == (False, {"SECRET": "block"})
    assert (privacy["block_phone"], privacy["entity_actions"]) == (True, {})
    recreated = await db.get(CostBudget, UUID(budget["id"]))
    assert recreated is not None and recreated.notify_targets == []
    assert recreated.limit_usd == Decimal("10")
    assert (await db.get(ModelDeployment, UUID(deployment["id"]))).enabled is False
    assert await db.get(OversightPolicy, UUID(oversight["id"])) is None
    assert await db.get(Team, UUID(team["id"])) is not None
    assert (await db.get(PolicyPlan, UUID(applied_plan["id"]))).status == "rolled_back"
    version = (await _versions(db, tenant))[-1]
    assert (version.source, version.plan_id) == ("restore", UUID(body["plan"]["id"]))
    rows = await _audit_rows(db, tenant)
    assert (
        _events(rows, "tenant.policy_version_restored")[0]["target_version"] == target
    )


@pytest.mark.asyncio
async def test_undoing_a_tightening_records_the_relaxation(db) -> None:
    owner = await _tenant(db)
    await _call(
        db, owner, "PUT", "/api/v1/management/settings/pii", json={"block_email": False}
    )
    await _call(
        db, owner, "PUT", "/api/v1/management/settings/pii", json={"block_email": True}
    )

    restored = await _call(db, owner, "POST", f"{POLICY}/versions/1/restore", json={})

    assert restored.json()["plan"]["risk"] == "relaxing"
    rows = await _audit_rows(db, owner.organization_id)
    relaxed = _events(rows, "tenant.privacy_protection_relaxed")
    assert [event["relaxed"] for event in relaxed] == [["block_email"], ["block_email"]]
    assert relaxed[-1]["policy_version"] == 3
    nothing = await _call(db, owner, "POST", f"{POLICY}/versions/3/restore", json={})
    assert nothing.json() == {"plan": None, "not_restored": [], "approximated": []}
    assert (
        await _call(db, owner, "POST", f"{POLICY}/versions/9/restore", json={})
    ).status_code == 404


@pytest.mark.asyncio
async def test_impact_counts_the_windows_lifecycle_rows(db, origins) -> None:
    owner = await _tenant(db)
    tenant = owner.organization_id
    secret = await _secret(db, tenant)
    team = (
        await _call(
            db, owner, "POST", "/api/v1/management/teams", json={"name": "risk"}
        )
    ).json()
    deployment = (
        await _call(
            db,
            owner,
            "POST",
            "/api/v1/management/model-deployments",
            json=_deployment_body(secret.id),
        )
    ).json()
    key = ApiKey(
        id=uuid4(),
        organization_id=tenant,
        user_id=owner.id,
        key_hash=uuid4().hex,
        prefix="sk-shim-imp",
        tier="enterprise",
        is_active=True,
    )
    db.add(key)
    await db.flush()
    now = datetime.now(timezone.utc)

    def row(
        started_at: datetime, model: str = "gpt-5-mini", **metadata
    ) -> RequestLifecycle:
        return RequestLifecycle(
            request_id=f"req_policy_{uuid4().hex}",
            organization_id=tenant,
            actor_type="api_key",
            api_key_id=key.id,
            source_endpoint="chat.completions",
            status="completed",
            requested_model=model,
            stream=False,
            started_at=started_at,
            lifecycle_metadata=metadata,
        )

    inside, outside = now - timedelta(days=1), now - timedelta(days=9)
    db.add_all(
        [
            row(inside, pii_entities={"EMAIL_ADDRESS": 1}, team_id=team["id"]),
            row(inside, monitored_entities={"PHONE_NUMBER": 1}, team_id=team["id"]),
            row(inside, model="policy-model", team_id=team["id"]),
            row(inside, model="other", deployment_id=deployment["id"]),
            row(outside, pii_entities={"EMAIL_ADDRESS": 1}, model="policy-model"),
        ]
    )
    await db.flush()

    async def impact(change: dict) -> dict:
        response = await _call(
            db, owner, "POST", f"{POLICY}/plans", json={"changes": [change]}
        )
        return response.json()["changes"][0]["impact"]

    privacy = await impact(
        {
            "resource": "privacy",
            "item": "_",
            "set": {
                "entity_actions": {"EMAIL_ADDRESS": "monitor", "PHONE_NUMBER": "block"}
            },
        }
    )
    await _call(
        db,
        owner,
        "PUT",
        "/api/v1/management/settings/pii",
        json={"entity_actions": {"IP_ADDRESS": "off"}},
    )
    was_off = await impact(
        {
            "resource": "privacy",
            "item": "_",
            "set": {"entity_actions": {"IP_ADDRESS": "mask"}},
        }
    )
    keys = await impact(
        {
            "resource": "api_keys",
            "item": str(key.id),
            "set": {"allowed_models": ["gpt-5-mini"]},
        }
    )
    disable = await impact(
        {"resource": "deployments", "item": deployment["id"], "set": {"enabled": False}}
    )
    daily = await impact(
        {"resource": "teams", "item": team["id"], "set": {"daily_request_limit": 1}}
    )
    oversight = await impact(
        {
            "resource": "oversight_policies",
            "item": None,
            "set": {"name": "x", "trigger": {"pii_detected": True}},
        }
    )

    assert (privacy["requests"], privacy["basis"]) == (2, "metadata")
    assert was_off == {
        "requests": None,
        "basis": "none",
        "window_days": 7,
        "note": "type was off; start with monitor",
    }
    assert keys["requests"] == 2
    assert disable["requests"] == 2
    assert daily["requests"] == 2
    assert oversight["note"] == "review queue runs after the request"
    wide = await _call(
        db,
        owner,
        "POST",
        f"{POLICY}/plans",
        params={"window_days": 10},
        json={
            "changes": [
                {
                    "resource": "deployments",
                    "item": deployment["id"],
                    "set": {"enabled": False},
                }
            ]
        },
    )
    assert wide.json()["changes"][0]["impact"]["requests"] == 3
    assert (
        await _call(
            db,
            owner,
            "POST",
            f"{POLICY}/plans",
            params={"window_days": 32},
            json={"changes": []},
        )
    ).status_code == 422


@pytest.mark.asyncio
async def test_members_cannot_plan_and_auditors_read_versions(db) -> None:
    member = await _tenant(db, role="member")
    auditor = await _tenant(db, role="auditor")

    refused = await _call(
        db,
        member,
        "POST",
        f"{POLICY}/plans",
        json={"changes": [{"resource": "privacy", "item": "_", "set": {}}]},
    )
    read = await _call(db, auditor, "GET", f"{POLICY}/versions")

    assert (refused.status_code, refused.json()["detail"]) == (
        403,
        "Permission required: plans.create",
    )
    assert (read.status_code, read.json()) == (200, [])


@pytest.mark.asyncio
async def test_concurrent_writes_take_consecutive_versions_per_tenant(
    async_engine,
) -> None:
    factory = async_sessionmaker(async_engine, expire_on_commit=False)
    tenants = []
    async with factory() as session:
        for _ in range(2):
            organization = Organization(
                id=uuid4(), name="Concurrent", slug=f"concurrent-{uuid4().hex}"
            )
            session.add(organization)
            await session.flush()
            user = User(
                id=uuid4(),
                organization_id=organization.id,
                email=f"concurrent-{uuid4().hex}@example.com",
                role="owner",
                is_active=True,
                is_verified=True,
            )
            session.add(user)
            tenants.append(user)
        await session.commit()
    privacy = REGISTRY["privacy"]

    async def write(user: User, field: str) -> None:
        async with factory() as session:
            tenant = user.organization_id
            await lock_tenant(session, tenant)
            before = (await privacy.snapshot(session, tenant, None))["_"]
            after = {**before, field: not before[field]}
            async with record_managed_write(
                session, user, tenant, [(privacy, "_", before, after)], source="api"
            ) as version:
                await privacy.apply(
                    session, user, tenant, "_", before, after, policy_version=version
                )
                await asyncio.sleep(0.05)
            await session.commit()

    try:
        await asyncio.gather(
            *(
                write(user, field)
                for user in tenants
                for field in ("block_email", "block_phone", "block_secrets")
            )
        )
        async with factory() as session:
            for user in tenants:
                versions = await session.scalars(
                    select(PolicyVersion.version)
                    .where(PolicyVersion.organization_id == user.organization_id)
                    .order_by(PolicyVersion.version)
                )
                assert list(versions) == [1, 2, 3]
    finally:
        async with factory() as session:
            for user in tenants:
                await session.execute(
                    delete(OutboxEvent).where(
                        OutboxEvent.organization_id == user.organization_id
                    )
                )
                await session.execute(
                    delete(Organization).where(Organization.id == user.organization_id)
                )
            await session.commit()


@pytest.mark.asyncio
async def test_a_privacy_plan_invalidates_the_policy_cache_after_commit(
    db, monkeypatch
) -> None:
    owner = await _tenant(db)
    invalidated: list[tuple[str, bool]] = []

    class Recorder:
        def __init__(self, cache) -> None:
            self.cache = cache

        async def invalidate_pii_config(self, tenant: str) -> None:
            committed = await db.scalar(
                select(PolicyVersion.version).where(
                    PolicyVersion.organization_id == owner.organization_id
                )
            )
            invalidated.append((tenant, committed == 1))

    monkeypatch.setattr(management, "CacheManager", Recorder)
    app = _app(db, owner)
    app.state.cache = object()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        plan = await client.post(
            f"{POLICY}/plans",
            json={
                "changes": [
                    {
                        "resource": "privacy",
                        "item": "_",
                        "set": {"response_scan": "count"},
                    }
                ]
            },
        )
        await client.post(f"{POLICY}/plans/{plan.json()['id']}/apply")

    assert invalidated == [(str(owner.organization_id), True)]
