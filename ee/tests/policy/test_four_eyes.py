from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import shim_enterprise.core.database as database
from shim_enterprise.ai_act.models import OversightPolicy
from shim_enterprise.api.enterprise_deps import get_current_user
from shim_enterprise.api.v1.router import management_router
from shim_enterprise.billing.models import CostBudget
from shim_enterprise.compliance.models import ComplianceForwardTarget
from shim_enterprise.core.config import settings
from shim_enterprise.core.database import get_db
from shim_enterprise.outbox.handlers import (
    COMPLIANCE_DELIVERY,
    POLICY_APPROVAL_REQUESTED,
    _compliance_text,
    announce_policy_approval,
    build_publisher,
)
from shim_enterprise.outbox.models import OutboxEvent
from shim_enterprise.outbox.publisher import OutboxMessage
from shim_enterprise.policy import api as policy_api
from shim_enterprise.policy.models import PolicyPlan, PolicyVersion
from shim_enterprise.policy.resources import REGISTRY
from shim_enterprise.tenants import gateway_settings
from shim_enterprise.tenants.gateway_settings import GatewaySettings, classify_change
from shim_enterprise.tenants.models import (
    ApiKey,
    Organization,
    OrganizationPIIConfig,
    ProviderSecret,
    Team,
    User,
)

MANAGEMENT = "/api/v1/management"
POLICY = f"{MANAGEMENT}/policy"
SETTINGS = f"{MANAGEMENT}/gateway-settings"


async def _organization(db, *roles: str) -> dict[str, User]:
    """Users by name: `owner` first, then `admin`, `admin2`, ... and `service`."""
    organization = Organization(
        id=uuid4(), name="Four eyes", slug=f"four-eyes-{uuid4().hex}", tier="enterprise"
    )
    db.add(organization)
    await db.flush()
    users: dict[str, User] = {}
    for name in ("owner", *roles):
        users[name] = User(
            id=uuid4(),
            organization_id=organization.id,
            email=f"four-eyes-{uuid4().hex}@example.com",
            role="admin" if name != "owner" else "owner",
            kind="service" if name == "service" else "human",
            is_active=True,
            is_verified=True,
        )
        db.add(users[name])
    await db.flush()
    return users


async def _call(db, user: User, method: str, path: str, **kwargs) -> httpx.Response:
    app = FastAPI()
    app.include_router(management_router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_db] = lambda: db
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        return await client.request(method, path, **kwargs)


async def _turn_on(db, owner: User) -> None:
    response = await _call(db, owner, "PATCH", SETTINGS, json={"four_eyes": "relaxing"})
    assert response.status_code == 200, response.text


async def _version_count(db, organization_id: UUID) -> int:
    return int(
        await db.scalar(
            select(func.count()).where(PolicyVersion.organization_id == organization_id)
        )
    )


async def _outbox(db, organization_id: UUID, event_type: str) -> list[OutboxEvent]:
    return list(
        await db.scalars(
            select(OutboxEvent)
            .where(
                OutboxEvent.organization_id == organization_id,
                OutboxEvent.event_type == event_type,
            )
            .order_by(OutboxEvent.next_attempt_at)
        )
    )


async def _audits(db, organization_id: UUID, action: str) -> list[dict]:
    rows = await _outbox(db, organization_id, "audit.chain_append_requested")
    return [row.payload["extra"] for row in rows if row.payload["endpoint"] == action]


async def _plan(db, user: User, *changes: dict) -> dict:
    response = await _call(
        db, user, "POST", f"{POLICY}/plans", json={"changes": changes}
    )
    assert response.status_code == 201, response.text
    return response.json()


def _block_email_off() -> dict:
    return {"resource": "privacy", "item": "_", "set": {"block_email": False}}


async def _block_email(db, organization_id: UUID) -> bool:
    row = await db.scalar(
        select(OrganizationPIIConfig).where(
            OrganizationPIIConfig.organization_id == organization_id
        )
    )
    await db.refresh(row)
    return row.block_email


@pytest.mark.asyncio
async def test_four_eyes_needs_two_active_human_approvers(db) -> None:
    alone = await _organization(db, "service")
    pair = await _organization(db, "admin")

    refused = await _call(
        db, alone["owner"], "PATCH", SETTINGS, json={"four_eyes": "relaxing"}
    )
    planned = await _call(
        db,
        alone["owner"],
        "POST",
        f"{POLICY}/plans",
        json={
            "changes": [
                {
                    "resource": "gateway_settings",
                    "item": "_",
                    "set": {"four_eyes": "relaxing"},
                }
            ]
        },
    )
    pair["admin"].is_active = False
    await db.flush()
    inactive = await _call(
        db, pair["owner"], "PATCH", SETTINGS, json={"four_eyes": "relaxing"}
    )
    pair["admin"].is_active = True
    await db.flush()
    accepted = await _call(
        db, pair["owner"], "PATCH", SETTINGS, json={"four_eyes": "relaxing"}
    )

    unavailable = {
        "code": "FOUR_EYES_UNAVAILABLE",
        "message": "Four eyes needs two active administrators.",
    }
    assert (refused.status_code, refused.json()["detail"]) == (409, unavailable)
    assert planned.status_code == 201
    applied = await _call(
        db, alone["owner"], "POST", f"{POLICY}/plans/{planned.json()['id']}/apply"
    )
    assert (applied.status_code, applied.json()["detail"]) == (409, unavailable)
    assert (inactive.status_code, inactive.json()["detail"]) == (409, unavailable)
    assert accepted.status_code == 200
    assert accepted.json()["settings"]["four_eyes"] == "relaxing"
    assert await _version_count(db, alone["owner"].organization_id) == 0


@pytest.mark.asyncio
async def test_gateway_settings_are_a_managed_resource(db) -> None:
    users = await _organization(db, "admin")
    owner = users["owner"]
    tenant = owner.organization_id

    patched = await _call(db, owner, "PATCH", SETTINGS, json={"four_eyes": "relaxing"})
    state = (await _call(db, owner, "GET", f"{POLICY}/state")).json()
    [version] = list(
        await db.scalars(
            select(PolicyVersion).where(PolicyVersion.organization_id == tenant)
        )
    )
    updated = await _audits(db, tenant, "tenant.gateway_settings_updated")

    assert patched.json()["revision"] == 1
    assert REGISTRY["gateway_settings"].permission == "settings.write"
    assert state["resources"]["gateway_settings"] == {
        "_": {"response_analysis": [], "four_eyes": "relaxing"}
    }
    assert (version.source, version.risk) == ("api", "tightening")
    assert version.previous == {
        "gateway_settings": {"_": {"response_analysis": [], "four_eyes": "off"}}
    }
    assert updated == [
        {
            "subject_id": str(tenant),
            "before": {"four_eyes": "off"},
            "after": {"four_eyes": "relaxing"},
            "policy_version": 1,
            "actor_type": "user_jwt",
        }
    ]


def test_each_gateway_setting_has_a_direction_and_an_unlisted_one_relaxes(
    monkeypatch,
) -> None:
    on, off = GatewaySettings(four_eyes="relaxing"), GatewaySettings()
    measured = GatewaySettings(response_analysis=["shape"])

    assert classify_change(on, off) == ("relaxing", ["four_eyes"])
    assert classify_change(off, on) == ("tightening", [])
    assert classify_change(off, measured) == ("neutral", [])
    assert set(gateway_settings.SETTING_DIRECTIONS) == set(GatewaySettings.model_fields)
    monkeypatch.delitem(gateway_settings.SETTING_DIRECTIONS, "response_analysis")
    assert classify_change(off, measured) == ("relaxing", ["response_analysis"])


@pytest.mark.asyncio
async def test_every_relaxing_direct_write_is_refused_and_writes_nothing(
    db, monkeypatch
) -> None:
    monkeypatch.setattr(
        settings, "MODEL_DEPLOYMENT_ALLOWED_ORIGINS", ["https://a.internal"]
    )
    users = await _organization(db, "admin")
    owner, admin = users["owner"], users["admin"]
    tenant = owner.organization_id
    team = Team(id=uuid4(), organization_id=tenant, name="ops", daily_request_limit=10)
    key = ApiKey(
        id=uuid4(),
        organization_id=tenant,
        user_id=owner.id,
        key_hash=uuid4().hex,
        prefix="sk-shim-eye",
        tier="enterprise",
        is_active=True,
        allowed_models=["gpt-5-nano"],
    )
    budget = CostBudget(
        id=uuid4(), organization_id=tenant, scope_type="org", limit_usd=10
    )
    policy = OversightPolicy(
        id=uuid4(),
        organization_id=tenant,
        name="review",
        enabled=True,
        trigger={"pii_detected": True},
    )
    secret = ProviderSecret(
        id=uuid4(),
        organization_id=tenant,
        provider="openai",
        secret_ref="reference-eyes",
        secret_backend="fernet",
        secret_version="v2",
        masked_key="masked",
    )
    db.add_all([team, key, budget, policy, secret])
    await db.flush()
    await _turn_on(db, owner)
    versions = await _version_count(db, tenant)

    writes = [
        ("PUT", f"{MANAGEMENT}/settings/pii", {"block_email": False}),
        ("PATCH", SETTINGS, {"four_eyes": "off"}),
        ("PUT", f"{MANAGEMENT}/teams/{team.id}", {"name": "ops"}),
        ("PATCH", f"{MANAGEMENT}/api-keys/{key.id}", {"allowed_models": None}),
        ("DELETE", f"{MANAGEMENT}/cost/budgets/{budget.id}", None),
        (
            "PATCH",
            f"/api/v1/compliance/oversight/policies/{policy.id}",
            {"enabled": False},
        ),
    ]
    refused = [
        await _call(db, admin, method, path, json=body) for method, path, body in writes
    ]
    created = await _call(
        db,
        admin,
        "POST",
        f"{MANAGEMENT}/model-deployments",
        json={
            "alias": "eyes-model",
            "provider": "openai",
            "upstream_model": "eyes-upstream",
            "base_url": "https://a.internal/v1",
            "provider_secret_id": str(secret.id),
            "deployment_kind": "internal",
            "declared_version": "v1",
            "owner": "Platform",
        },
    )

    assert [response.status_code for response in refused] == [409] * len(writes)
    assert [response.json()["detail"]["relaxed"] for response in refused] == [
        ["privacy._.block_email"],
        ["gateway_settings._.four_eyes"],
        [f"teams.{team.id}.daily_request_limit"],
        [f"api_keys.{key.id}.allowed_models"],
        [f"budgets.{budget.id}"],
        [f"oversight_policies.{policy.id}.enabled"],
    ]
    assert {response.json()["detail"]["code"] for response in refused} == {
        "CHANGE_REQUIRES_APPROVAL"
    }
    assert created.status_code == 409
    [deployment] = created.json()["detail"]["relaxed"]
    assert deployment.startswith("deployments.")
    assert await _version_count(db, tenant) == versions
    await db.refresh(team)
    await db.refresh(key)
    await db.refresh(budget)
    await db.refresh(policy)
    assert team.daily_request_limit == 10
    assert key.allowed_models == ["gpt-5-nano"]
    assert (budget.limit_usd, policy.enabled) == (10, True)
    assert await _block_email(db, tenant) is True


@pytest.mark.asyncio
async def test_raising_a_budget_limit_directly_is_refused(db) -> None:
    users = await _organization(db, "admin")
    budget_id = uuid4()
    db.add(
        CostBudget(
            id=budget_id,
            organization_id=users["owner"].organization_id,
            scope_type="org",
            limit_usd=10,
        )
    )
    await db.flush()
    await _turn_on(db, users["owner"])

    # The budget route rolls its session back on any error, so this test asserts
    # only the answer: the shared test session loses its rows with it.
    refused = await _call(
        db,
        users["admin"],
        "PATCH",
        f"{MANAGEMENT}/cost/budgets/{budget_id}",
        json={"limit_usd": "20"},
    )

    assert refused.status_code == 409
    assert refused.json()["detail"]["relaxed"] == [f"budgets.{budget_id}.limit_usd"]


@pytest.mark.asyncio
async def test_tightening_and_neutral_direct_writes_pass(db) -> None:
    users = await _organization(db, "admin")
    await _turn_on(db, users["owner"])

    tightened = await _call(
        db,
        users["admin"],
        "PUT",
        f"{MANAGEMENT}/settings/pii",
        json={"entity_actions": {"SECRET": "block"}},
    )
    neutral = await _call(
        db, users["admin"], "PATCH", SETTINGS, json={"response_analysis": ["shape"]}
    )

    assert tightened.status_code == 200
    assert tightened.json()["entity_actions"] == {"SECRET": "block"}
    assert neutral.status_code == 200


@pytest.mark.asyncio
async def test_a_relaxing_plan_waits_for_a_second_human_administrator(db) -> None:
    users = await _organization(db, "admin", "admin2", "service")
    owner, admin, admin2 = users["owner"], users["admin"], users["admin2"]
    tenant = owner.organization_id
    await _turn_on(db, owner)
    plan = await _plan(db, admin, _block_email_off())

    submitted = await _call(db, owner, "POST", f"{POLICY}/plans/{plan['id']}/apply")
    again = await _call(db, owner, "POST", f"{POLICY}/plans/{plan['id']}/apply")
    by_creator = await _call(
        db, admin, "POST", f"{POLICY}/plans/{plan['id']}/approve", json={}
    )
    by_submitter = await _call(
        db, owner, "POST", f"{POLICY}/plans/{plan['id']}/approve", json={}
    )
    by_service = await _call(
        db, users["service"], "POST", f"{POLICY}/plans/{plan['id']}/approve", json={}
    )
    pending = await _block_email(db, tenant)
    approved = await _call(
        db,
        admin2,
        "POST",
        f"{POLICY}/plans/{plan['id']}/approve",
        json={"note": "checked with the data officer"},
    )

    assert submitted.status_code == 202
    body = submitted.json()
    assert (body["status"], body["submitted_by"]) == ("pending_approval", str(owner.id))
    submitted_at = datetime.fromisoformat(body["submitted_at"])
    assert datetime.fromisoformat(body["expires_at"]) == submitted_at + timedelta(
        hours=72
    )
    assert again.json()["detail"] == {
        "code": "PLAN_STATE_CONFLICT",
        "status": "pending_approval",
    }
    for refused in (by_creator, by_submitter, by_service):
        assert refused.status_code == 403
        assert refused.json()["detail"] == {"code": "APPROVER_NOT_ELIGIBLE"}
    assert pending is True
    assert approved.status_code == 200, approved.text
    result = approved.json()
    assert (result["status"], result["approved_by"], result["applied_by"]) == (
        "applied",
        str(admin2.id),
        str(admin2.id),
    )
    assert result["context"] == {"decision_note": "checked with the data officer"}
    assert await _block_email(db, tenant) is False
    latest = await db.scalar(
        select(PolicyVersion)
        .where(PolicyVersion.organization_id == tenant)
        .order_by(PolicyVersion.version.desc())
        .limit(1)
    )
    assert (latest.source, str(latest.plan_id)) == ("plan", plan["id"])
    expected = {"plan_id": plan["id"], "risk": "relaxing", "resources": ["privacy"]}
    for action, actor in (
        ("tenant.policy_plan_submitted", "user_jwt"),
        ("tenant.policy_plan_approved", "user_jwt"),
    ):
        [event] = await _audits(db, tenant, action)
        assert event == {"subject_id": plan["id"], **expected, "actor_type": actor}
    [intent] = await _outbox(db, tenant, POLICY_APPROVAL_REQUESTED)
    assert intent.idempotency_key == f"policy_approval:{plan['id']}"
    assert intent.payload == {
        "organization_id": str(tenant),
        **expected,
        "submitted_by": str(owner.id),
    }


@pytest.mark.asyncio
async def test_tightening_plans_apply_at_once_under_four_eyes(db) -> None:
    users = await _organization(db, "admin")
    await _turn_on(db, users["owner"])
    plan = await _plan(
        db,
        users["admin"],
        {
            "resource": "privacy",
            "item": "_",
            "set": {"entity_actions": {"SECRET": "block"}},
        },
    )

    applied = await _call(
        db, users["admin"], "POST", f"{POLICY}/plans/{plan['id']}/apply"
    )

    assert (applied.status_code, applied.json()["status"]) == (200, "applied")


@pytest.mark.asyncio
async def test_approving_a_stale_plan_is_refused_and_it_stays_pending(db) -> None:
    users = await _organization(db, "admin")
    owner, admin = users["owner"], users["admin"]
    await _turn_on(db, owner)
    plan = await _plan(db, admin, _block_email_off())
    await _call(db, admin, "POST", f"{POLICY}/plans/{plan['id']}/apply")
    moved = await _call(
        db,
        owner,
        "PUT",
        f"{MANAGEMENT}/settings/pii",
        json={"entity_actions": {"SECRET": "block"}},
    )

    stale = await _call(
        db, owner, "POST", f"{POLICY}/plans/{plan['id']}/approve", json={}
    )
    stored = await db.get(PolicyPlan, UUID(plan["id"]), populate_existing=True)

    assert moved.status_code == 200
    assert stale.status_code == 409
    assert stale.json()["detail"] == {
        "code": "PLAN_STALE",
        "items": [{"resource": "privacy", "item": "_"}],
    }
    assert (stored.status, stored.approved_by) == ("pending_approval", None)


@pytest.mark.asyncio
async def test_a_rejected_plan_changes_nothing(db) -> None:
    users = await _organization(db, "admin")
    owner, admin = users["owner"], users["admin"]
    tenant = owner.organization_id
    await _turn_on(db, owner)
    plan = await _plan(db, admin, _block_email_off())
    await _call(db, admin, "POST", f"{POLICY}/plans/{plan['id']}/apply")

    by_submitter = await _call(
        db, admin, "POST", f"{POLICY}/plans/{plan['id']}/reject", json={}
    )
    rejected = await _call(
        db, owner, "POST", f"{POLICY}/plans/{plan['id']}/reject", json={"note": "no"}
    )
    approve_after = await _call(
        db, owner, "POST", f"{POLICY}/plans/{plan['id']}/approve", json={}
    )
    long_note = await _call(
        db,
        owner,
        "POST",
        f"{POLICY}/plans/{plan['id']}/reject",
        json={"note": "x" * 501},
    )

    assert by_submitter.json()["detail"] == {"code": "APPROVER_NOT_ELIGIBLE"}
    assert (rejected.status_code, rejected.json()["status"]) == (200, "rejected")
    assert approve_after.json()["detail"] == {
        "code": "PLAN_STATE_CONFLICT",
        "status": "rejected",
    }
    assert long_note.status_code == 422
    assert await _block_email(db, tenant) is True
    [event] = await _audits(db, tenant, "tenant.policy_plan_rejected")
    assert event == {
        "subject_id": plan["id"],
        "plan_id": plan["id"],
        "risk": "relaxing",
        "resources": ["privacy"],
        "actor_type": "user_jwt",
    }


@pytest.mark.asyncio
async def test_a_pending_plan_expires_72_hours_after_submission(
    db, monkeypatch
) -> None:
    users = await _organization(db, "admin")
    owner, admin = users["owner"], users["admin"]
    await _turn_on(db, owner)
    plan = await _plan(db, admin, _block_email_off())
    await _call(db, admin, "POST", f"{POLICY}/plans/{plan['id']}/apply")
    real = datetime

    class _Later(datetime):
        @classmethod
        def now(cls, tz=None):  # type: ignore[override]
            return real.now(tz) + timedelta(hours=72, seconds=1)

    monkeypatch.setattr(policy_api, "datetime", _Later)

    read = await _call(db, owner, "GET", f"{POLICY}/plans/{plan['id']}")
    approved = await _call(
        db, owner, "POST", f"{POLICY}/plans/{plan['id']}/approve", json={}
    )

    assert read.json()["status"] == "expired"
    assert approved.json()["detail"] == {
        "code": "PLAN_STATE_CONFLICT",
        "status": "expired",
    }


@pytest.mark.asyncio
async def test_a_relaxing_restore_waits_for_approval_and_finishes_on_it(db) -> None:
    users = await _organization(db, "admin")
    owner, admin = users["owner"], users["admin"]
    tenant = owner.organization_id
    await _call(
        db, owner, "PUT", f"{MANAGEMENT}/settings/pii", json={"block_email": False}
    )
    await _call(
        db, owner, "PUT", f"{MANAGEMENT}/settings/pii", json={"block_email": True}
    )
    await _turn_on(db, owner)

    restore = await _call(
        db, admin, "POST", f"{POLICY}/versions/1/restore", json={"reason": "undo"}
    )
    plan_id = restore.json()["plan"]["id"]
    waiting = await _block_email(db, tenant)
    approved = await _call(
        db, owner, "POST", f"{POLICY}/plans/{plan_id}/approve", json={}
    )

    assert restore.status_code == 202
    assert restore.json()["plan"]["status"] == "pending_approval"
    assert waiting is True
    assert (approved.status_code, approved.json()["status"]) == (200, "applied")
    assert await _block_email(db, tenant) is False
    [restored] = await _audits(db, tenant, "tenant.policy_version_restored")
    assert restored["target_version"] == 1
    assert restored["policy_version"] == approved.json()["applied_version"]


@pytest.mark.asyncio
async def test_an_owner_left_alone_may_turn_four_eyes_off_directly(db) -> None:
    users = await _organization(db, "admin")
    owner, admin = users["owner"], users["admin"]
    tenant = owner.organization_id
    db.add(
        ComplianceForwardTarget(
            organization_id=tenant,
            kind="slack",
            endpoint_origin="https://hooks.slack.com",
            secret_ref="fernet:v2:eyes",
            secret_backend="fernet",
            secret_version="v2",
            enabled=True,
        )
    )
    await db.flush()
    await _turn_on(db, owner)

    with_two = await _call(db, owner, "PATCH", SETTINGS, json={"four_eyes": "off"})
    admin.is_active = False
    await db.flush()
    alone = await _call(db, owner, "PATCH", SETTINGS, json={"four_eyes": "off"})

    assert with_two.status_code == 409
    assert alone.status_code == 200
    assert alone.json()["settings"]["four_eyes"] == "off"
    [override] = await _audits(db, tenant, "tenant.four_eyes_single_admin_override")
    assert override == {
        "subject_id": str(tenant),
        "policy_version": 2,
        "actor_type": "user_jwt",
    }
    assert await _audits(db, tenant, "tenant.gateway_protection_relaxed") == [
        {
            "subject_id": str(tenant),
            "relaxed": ["four_eyes"],
            "policy_version": 2,
            "actor_type": "user_jwt",
        }
    ]
    [delivery] = await _outbox(db, tenant, COMPLIANCE_DELIVERY)
    assert delivery.payload["body"]["kind"] == "gateway_protection_relaxed"
    assert delivery.payload["body"]["fields"] == ["four_eyes"]
    assert _compliance_text(delivery.payload["body"]).startswith(
        "shim gateway protection turned off: four_eyes"
    )


@pytest.mark.asyncio
async def test_an_administrator_left_alone_may_not_override(db) -> None:
    users = await _organization(db, "admin", "admin2")
    await _turn_on(db, users["owner"])
    users["admin2"].is_active = False
    await db.flush()

    refused = await _call(
        db, users["admin"], "PATCH", SETTINGS, json={"four_eyes": "off"}
    )

    assert refused.json()["detail"]["code"] == "CHANGE_REQUIRES_APPROVAL"


@pytest.mark.parametrize("targets", [0, 2])
@pytest.mark.asyncio
async def test_the_approval_request_reaches_every_enabled_forward_target(
    db, monkeypatch, targets: int
) -> None:
    users = await _organization(db)
    tenant = users["owner"].organization_id
    db.add_all(
        ComplianceForwardTarget(
            organization_id=tenant,
            kind="slack",
            endpoint_origin="https://hooks.slack.com",
            secret_ref=f"fernet:v2:{index}",
            secret_backend="fernet",
            secret_version="v2",
            enabled=True,
        )
        for index in range(targets)
    )
    await db.flush()
    monkeypatch.setattr(
        database,
        "AsyncSessionLocal",
        async_sessionmaker(
            await db.connection(),
            class_=AsyncSession,
            expire_on_commit=False,
            join_transaction_mode="create_savepoint",
        ),
    )
    plan_id = str(uuid4())
    message = OutboxMessage(
        id=uuid4(),
        organization_id=tenant,
        event_type=POLICY_APPROVAL_REQUESTED,
        aggregate_type="policy_plan",
        aggregate_id=plan_id,
        idempotency_key=f"policy_approval:{plan_id}",
        payload={
            "organization_id": str(tenant),
            "plan_id": plan_id,
            "risk": "relaxing",
            "resources": ["privacy"],
            "submitted_by": str(users["owner"].id),
        },
        attempt_count=0,
        created_at=datetime.now(timezone.utc),
    )

    await build_publisher().publish(message)
    # A retried handler appends nothing twice.
    await announce_policy_approval(message)

    body = {
        "source": "shim",
        "event_type": "tenant_policy",
        "kind": "policy_approval_requested",
        "plan_id": plan_id,
        "risk": "relaxing",
        "resources": ["privacy"],
        "submitted_by": str(users["owner"].id),
        "review": f"/api/v1/management/policy/plans/{plan_id}",
    }
    deliveries = await _outbox(db, tenant, COMPLIANCE_DELIVERY)
    assert len(deliveries) == targets
    for delivery in deliveries:
        assert delivery.idempotency_key.endswith(f":policy_approval:{plan_id}")
        assert delivery.payload["body"] == body
    assert _compliance_text(body) == (
        f"shim policy plan {plan_id} loosens privacy and waits for a second "
        f"administrator: /api/v1/management/policy/plans/{plan_id}"
    )


def _forward_target(tenant: UUID, *, enabled: bool = True) -> ComplianceForwardTarget:
    return ComplianceForwardTarget(
        id=uuid4(),
        organization_id=tenant,
        kind="slack",
        endpoint_origin="https://hooks.slack.com",
        secret_ref=f"fernet:v2:{uuid4().hex}",
        secret_backend="fernet",
        secret_version="v2",
        enabled=enabled,
    )


def _rule(state: str) -> dict:
    return {
        "id": "falcon",
        "name": "Project names",
        "kind": "term",
        "action": "block",
        "state": state,
        "match": {"terms": ["Project Falcon"]},
    }


async def _put_rules(db, user: User, rules: list[dict]) -> httpx.Response:
    current = await _call(db, user, "GET", f"{MANAGEMENT}/rules")
    return await _call(
        db,
        user,
        "PUT",
        f"{MANAGEMENT}/rules",
        json={"revision": current.json()["revision"], "rules": rules},
    )


@pytest.mark.asyncio
async def test_no_one_approves_a_plan_of_a_service_account_they_created_or_rotated(
    db,
) -> None:
    users = await _organization(db, "rotator", "admin")
    owner, rotator, admin = users["owner"], users["rotator"], users["admin"]
    rotator.role = "owner"
    await db.flush()
    await _turn_on(db, owner)
    created = await _call(
        db,
        owner,
        "POST",
        f"{MANAGEMENT}/service-accounts",
        json={"name": "ci", "role": "admin", "expires_in_days": 30},
    )
    robot = await db.get(User, UUID(created.json()["id"]))
    rotated = await _call(
        db, rotator, "POST", f"{MANAGEMENT}/service-accounts/{robot.id}/rotate"
    )
    plan = await _plan(db, robot, _block_email_off())

    submitted = await _call(db, robot, "POST", f"{POLICY}/plans/{plan['id']}/apply")
    refused = [
        await _call(db, user, "POST", f"{POLICY}/plans/{plan['id']}/approve", json={})
        for user in (owner, rotator)
    ]
    approved = await _call(
        db, admin, "POST", f"{POLICY}/plans/{plan['id']}/approve", json={}
    )

    assert (created.status_code, rotated.status_code) == (201, 200)
    assert submitted.status_code == 202
    assert [response.status_code for response in refused] == [403, 403]
    assert {response.json()["detail"]["code"] for response in refused} == {
        "APPROVER_NOT_ELIGIBLE"
    }
    assert (approved.status_code, approved.json()["status"]) == (200, "applied")


@pytest.mark.asyncio
async def test_under_four_eyes_the_second_approver_is_neither_demoted_nor_removed(
    db,
) -> None:
    users = await _organization(db, "admin")
    owner, admin = users["owner"], users["admin"]
    await _turn_on(db, owner)
    member = f"{MANAGEMENT}/team/members/{admin.id}"

    refused = [
        await _call(db, owner, "PATCH", member, json={"role": "member"}),
        await _call(db, owner, "PATCH", member, json={"role": "auditor"}),
        await _call(db, owner, "DELETE", member),
    ]
    promoted = await _call(db, owner, "PATCH", member, json={"role": "owner"})
    third = User(
        id=uuid4(),
        organization_id=owner.organization_id,
        email=f"four-eyes-{uuid4().hex}@example.com",
        role="admin",
        kind="human",
        is_active=True,
        is_verified=True,
    )
    db.add(third)
    await db.flush()
    demoted = await _call(db, owner, "PATCH", member, json={"role": "member"})
    last = await _call(db, owner, "DELETE", f"{MANAGEMENT}/team/members/{third.id}")

    assert [response.status_code for response in refused] == [409] * 3
    assert {response.json()["detail"]["code"] for response in refused} == {
        "FOUR_EYES_UNAVAILABLE"
    }
    assert (promoted.status_code, demoted.status_code) == (200, 200)
    assert last.json()["detail"]["code"] == "FOUR_EYES_UNAVAILABLE"
    await db.refresh(third)
    assert third.is_active is True


@pytest.mark.asyncio
async def test_moving_a_key_to_another_team_relaxes(db) -> None:
    users = await _organization(db, "admin")
    owner, admin = users["owner"], users["admin"]
    tenant = owner.organization_id
    limited = Team(id=uuid4(), organization_id=tenant, name="limited")
    other = Team(id=uuid4(), organization_id=tenant, name="other")
    key = ApiKey(
        id=uuid4(),
        organization_id=tenant,
        user_id=admin.id,
        key_hash=uuid4().hex,
        prefix="sk-shim-mv",
        tier="enterprise",
        is_active=True,
        team_id=limited.id,
    )
    db.add_all([limited, other])
    await db.flush()
    db.add(key)
    await db.flush()
    await _turn_on(db, owner)

    moved = await _call(
        db,
        admin,
        "PATCH",
        f"{MANAGEMENT}/api-keys/{key.id}",
        json={"team_id": str(other.id)},
    )

    assert moved.status_code == 409
    assert moved.json()["detail"]["relaxed"] == [f"api_keys.{key.id}.team_id"]
    await db.refresh(key)
    assert key.team_id == limited.id


_DEPLOYMENT = {
    "alias": "a",
    "provider": "openai",
    "upstream_model": "m",
    "base_url": "https://a.internal/v1",
    "provider_secret_id": str(uuid4()),
    "timeout_seconds": 60,
    "deployment_kind": "internal",
    "declared_version": "v1",
    "owner": "Platform",
    "enabled": True,
    "input_price_per_million": None,
    "output_price_per_million": None,
    "context_window": None,
}
_OVERSIGHT = {
    "name": "review",
    "enabled": True,
    "mode": "async_review",
    "trigger": {"pii_detected": True, "models": ["a"]},
    "ttl_seconds": 600,
    "default_on_timeout": "deny",
}
_TEAM = {
    "name": "a",
    "daily_request_limit": 1,
    "monthly_request_limit": None,
    "monthly_token_limit": None,
}
_BUDGET = {
    "scope_type": "org",
    "scope_value": None,
    "limit_usd": "10",
    "limit_tokens": None,
    "alert_thresholds": [0.8, 1.0],
    "enabled": True,
    "notify_targets": [{"kind": "slack", "endpoint_origin": "https://h", "id": "a"}],
}


@pytest.mark.parametrize(
    ("resource", "before", "change", "risk"),
    [
        ("deployments", _DEPLOYMENT, {"alias": "b"}, "relaxing"),
        ("deployments", _DEPLOYMENT, {"upstream_model": "n"}, "relaxing"),
        ("deployments", _DEPLOYMENT, {"provider_secret_id": str(uuid4())}, "relaxing"),
        ("deployments", _DEPLOYMENT, {"owner": "Security"}, "neutral"),
        ("deployments", _DEPLOYMENT, {"enabled": False}, "tightening"),
        (
            "oversight_policies",
            _OVERSIGHT,
            {"trigger": {"pii_detected": True}},
            "relaxing",
        ),
        ("oversight_policies", _OVERSIGHT, {"default_on_timeout": "allow"}, "relaxing"),
        ("oversight_policies", _OVERSIGHT, {"name": "renamed"}, "neutral"),
        ("budgets", _BUDGET, {"alert_thresholds": [1.0]}, "relaxing"),
        ("budgets", _BUDGET, {"alert_thresholds": [0.5, 0.8, 1.0]}, "tightening"),
        ("budgets", _BUDGET, {"notify_targets": []}, "relaxing"),
        ("teams", _TEAM, {"name": "b"}, "neutral"),
        ("teams", _TEAM, {"daily_request_limit": 2}, "relaxing"),
        ("teams", _TEAM, {"monthly_request_limit": 5}, "tightening"),
        ("teams", {**_TEAM, "added_later": 1}, {"added_later": 2}, "relaxing"),
    ],
)
def test_a_field_change_not_listed_as_neutral_or_tightening_relaxes(
    resource: str, before: dict, change: dict, risk: str
) -> None:
    assert REGISTRY[resource].classify(before, {**before, **change}) == risk


@pytest.mark.asyncio
async def test_replacing_budget_alert_targets_is_versioned_and_relaxes(
    db, monkeypatch
) -> None:
    async def safe(_url: str) -> None:
        return None

    monkeypatch.setattr(
        "shim_enterprise.api.v1.management.assert_safe_forward_url", safe
    )
    users = await _organization(db, "admin")
    owner, admin = users["owner"], users["admin"]
    created = await _call(
        db,
        admin,
        "POST",
        f"{MANAGEMENT}/cost/budgets",
        json={
            "scope_type": "org",
            "limit_usd": "10",
            "notify_targets": [
                {"kind": "slack", "endpoint": "https://hooks.slack.com/services/a"}
            ],
        },
    )
    assert created.status_code == 200, created.text
    budget = created.json()["id"]
    state = await _call(db, admin, "GET", f"{POLICY}/state")
    await _turn_on(db, owner)

    replaced = await _call(
        db,
        admin,
        "PATCH",
        f"{MANAGEMENT}/cost/budgets/{budget}",
        json={
            "notify_targets": [
                {"kind": "slack", "endpoint": "https://hooks.slack.com/services/b"}
            ]
        },
    )

    [target] = state.json()["resources"]["budgets"][budget]["notify_targets"]
    assert target["endpoint_origin"] == "https://hooks.slack.com"
    assert "secret_ref" not in target
    assert replaced.status_code == 409
    assert replaced.json()["detail"]["relaxed"] == [f"budgets.{budget}.notify_targets"]


@pytest.mark.asyncio
async def test_direct_routes_that_loosen_protection_ask_for_a_plan(db) -> None:
    users = await _organization(db, "admin")
    owner, admin = users["owner"], users["admin"]
    tenant = owner.organization_id
    target = _forward_target(tenant)
    db.add(target)
    (await db.get(Organization, tenant)).allow_customer_provider_keys = False
    await db.flush()
    assert (await _put_rules(db, admin, [_rule("monitor")])).status_code == 200
    assert (await _put_rules(db, admin, [_rule("enforced")])).status_code == 200
    await _turn_on(db, owner)
    keys = await db.scalar(select(func.count()).where(ApiKey.organization_id == tenant))
    forward = f"/api/v1/compliance/forward-targets/{target.id}"

    refused = [
        await _put_rules(db, admin, []),
        await _call(
            db,
            admin,
            "PUT",
            f"{MANAGEMENT}/settings/provider-keys",
            json={"allow_customer_provider_keys": True},
        ),
        await _call(db, admin, "PATCH", forward, json={"enabled": False}),
        await _call(db, admin, "PATCH", forward, json={"min_severity": "critical"}),
        await _call(db, admin, "DELETE", forward),
        await _call(db, admin, "POST", f"{MANAGEMENT}/api-keys", json={"name": "open"}),
    ]

    assert [response.status_code for response in refused] == [409] * len(refused)
    assert {response.json()["detail"]["code"] for response in refused} == {
        "CHANGE_REQUIRES_APPROVAL"
    }
    rules = await _call(db, admin, "GET", f"{MANAGEMENT}/rules")
    assert [rule["state"] for rule in rules.json()["rules"]] == ["enforced"]
    organization = await db.get(Organization, tenant)
    await db.refresh(organization)
    await db.refresh(target)
    assert organization.allow_customer_provider_keys is False
    assert (target.enabled, target.min_severity) == (True, "high")
    assert (
        await db.scalar(select(func.count()).where(ApiKey.organization_id == tenant))
        == keys
    )


@pytest.mark.asyncio
async def test_direct_routes_that_tighten_pass_under_four_eyes(db) -> None:
    users = await _organization(db, "admin")
    owner, admin = users["owner"], users["admin"]
    tenant = owner.organization_id
    target = _forward_target(tenant, enabled=False)
    db.add(target)
    await db.flush()
    assert (await _put_rules(db, admin, [_rule("monitor")])).status_code == 200
    await _turn_on(db, owner)
    forward = f"/api/v1/compliance/forward-targets/{target.id}"

    passed = [
        await _put_rules(db, admin, [_rule("enforced")]),
        await _call(
            db,
            admin,
            "PUT",
            f"{MANAGEMENT}/settings/provider-keys",
            json={"allow_customer_provider_keys": False},
        ),
        await _call(db, admin, "PATCH", forward, json={"enabled": True}),
        await _call(
            db,
            admin,
            "POST",
            f"{MANAGEMENT}/api-keys",
            json={"name": "limited", "allowed_models": ["gpt-5-nano"]},
        ),
    ]

    assert [response.status_code for response in passed] == [200] * len(passed)


@pytest.mark.asyncio
async def test_direct_routes_that_loosen_protection_pass_with_four_eyes_off(
    db,
) -> None:
    users = await _organization(db, "admin")
    admin = users["admin"]
    target = _forward_target(admin.organization_id)
    db.add(target)
    (
        await db.get(Organization, admin.organization_id)
    ).allow_customer_provider_keys = False
    await db.flush()
    await _put_rules(db, admin, [_rule("monitor")])
    await _put_rules(db, admin, [_rule("enforced")])
    forward = f"/api/v1/compliance/forward-targets/{target.id}"

    passed = [
        await _put_rules(db, admin, []),
        await _call(
            db,
            admin,
            "PUT",
            f"{MANAGEMENT}/settings/provider-keys",
            json={"allow_customer_provider_keys": True},
        ),
        await _call(db, admin, "PATCH", forward, json={"enabled": False}),
        await _call(db, admin, "POST", f"{MANAGEMENT}/api-keys", json={"name": "open"}),
        await _call(db, admin, "DELETE", forward),
    ]

    assert [response.status_code for response in passed] == [200, 200, 200, 200, 204]


@pytest.mark.asyncio
async def test_rules_provider_keys_and_forward_targets_travel_as_plans(db) -> None:
    users = await _organization(db, "admin")
    owner, admin = users["owner"], users["admin"]
    tenant = owner.organization_id
    disabled, deleted = _forward_target(tenant), _forward_target(tenant)
    db.add_all([disabled, deleted])
    (await db.get(Organization, tenant)).allow_customer_provider_keys = False
    await db.flush()
    await _put_rules(db, admin, [_rule("monitor")])
    await _put_rules(db, admin, [_rule("enforced")])
    await _turn_on(db, owner)
    plan = await _plan(
        db,
        admin,
        {"resource": "rules", "item": "_", "set": {"rules": []}},
        {
            "resource": "provider_keys",
            "item": "_",
            "set": {"allow_customer_provider_keys": True},
        },
        {
            "resource": "forward_targets",
            "item": str(disabled.id),
            "set": {"enabled": False},
        },
        {"resource": "forward_targets", "item": str(deleted.id), "delete": True},
    )

    submitted = await _call(db, admin, "POST", f"{POLICY}/plans/{plan['id']}/apply")
    approved = await _call(
        db, owner, "POST", f"{POLICY}/plans/{plan['id']}/approve", json={}
    )

    assert plan["risk"] == "relaxing"
    assert {change["risk"] for change in plan["changes"]} == {"relaxing"}
    assert submitted.status_code == 202
    assert (approved.status_code, approved.json()["status"]) == (200, "applied")
    rules = await _call(db, admin, "GET", f"{MANAGEMENT}/rules")
    assert (rules.json()["rules"], rules.json()["revision"]) == ([], 3)
    organization = await db.get(Organization, tenant)
    await db.refresh(organization)
    await db.refresh(disabled)
    assert organization.allow_customer_provider_keys is True
    assert disabled.enabled is False
    assert await db.get(ComplianceForwardTarget, deleted.id) is None
