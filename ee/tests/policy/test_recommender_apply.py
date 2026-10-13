from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.api.enterprise_deps import get_current_user
from shim_enterprise.api.v1.router import management_router
from shim_enterprise.billing.models import RequestLifecycle
from shim_enterprise.core.database import get_db
from shim_enterprise.outbox.models import OutboxEvent
from shim_enterprise.policy import allowlist
from shim_enterprise.policy.allowlist import AllowlistEntry
from shim_enterprise.policy.models import PolicyPlan, PolicyVersion
from shim_enterprise.tenants.models import Organization, User

POLICY = "/api/v1/management/policy"
PII = "/api/v1/management/settings/pii"
MASK_EMAIL = AllowlistEntry(
    id="test.mask_email",
    resource="privacy",
    fields=frozenset({"entity_actions"}),
    accepts=lambda before, after: (
        after["entity_actions"].get("EMAIL_ADDRESS") in {"mask", "block"}
    ),
    max_impact_requests=0,
)
TIGHTEN = {
    "changes": [
        {
            "resource": "privacy",
            "item": "_",
            "set": {"entity_actions": {"EMAIL_ADDRESS": "mask"}},
        }
    ]
}


async def _tenant(db) -> dict[str, User]:
    organization = Organization(
        id=uuid4(), name="Agent", slug=f"agent-{uuid4().hex}", tier="enterprise"
    )
    db.add(organization)
    await db.flush()
    users = {
        name: User(
            id=uuid4(),
            organization_id=organization.id,
            email=f"agent-{uuid4().hex}@example.com",
            role=role,
            kind=kind,
            is_active=True,
            is_verified=True,
        )
        for name, role, kind in (
            ("owner", "owner", "human"),
            ("admin", "admin", "human"),
            ("agent", "recommender", "service"),
        )
    }
    db.add_all(users.values())
    await db.flush()
    return users


async def _call(db, user: User, method: str, path: str, **kwargs) -> httpx.Response:
    connection = await db.connection()

    async def request_session():
        # Its own savepoint per request, so a refused one rolls back as in production.
        async with AsyncSession(
            bind=connection,
            join_transaction_mode="create_savepoint",
            expire_on_commit=False,
        ) as session:
            yield session

    app = FastAPI()
    app.include_router(management_router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_db] = request_session
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        return await client.request(method, path, **kwargs)


async def _monitoring_email(db, users) -> None:
    response = await _call(
        db,
        users["owner"],
        "PUT",
        PII,
        json={"entity_actions": {"EMAIL_ADDRESS": "monitor"}},
    )
    assert response.status_code == 200, response.text


async def _audits(db, organization_id: UUID, action: str) -> list[dict]:
    events = await db.scalars(
        select(OutboxEvent).where(
            OutboxEvent.organization_id == organization_id,
            OutboxEvent.event_type == "audit.chain_append_requested",
        )
    )
    return [
        event.payload["extra"]
        for event in events
        if event.payload["endpoint"] == action
    ]


async def _count(db, model, organization_id: UUID) -> int:
    return int(
        await db.scalar(
            select(func.count()).where(model.organization_id == organization_id)
        )
    )


@pytest.mark.asyncio
async def test_a_recommender_proposes_but_the_empty_allowlist_applies_nothing(
    db,
) -> None:
    users = await _tenant(db)
    agent, owner = users["agent"], users["owner"]
    tenant = owner.organization_id
    await _monitoring_email(db, users)
    created = await _call(db, agent, "POST", f"{POLICY}/plans", json=TIGHTEN)
    assert created.status_code == 201, created.text
    plan = created.json()
    versions = await _count(db, PolicyVersion, tenant)

    refused = await _call(db, agent, "POST", f"{POLICY}/plans/{plan['id']}/apply")
    approve = await _call(
        db, agent, "POST", f"{POLICY}/plans/{plan['id']}/approve", json={}
    )
    stored = await db.get(PolicyPlan, UUID(plan["id"]), populate_existing=True)
    versions_after_refusal = await _count(db, PolicyVersion, tenant)
    by_owner = await _call(db, owner, "POST", f"{POLICY}/plans/{plan['id']}/apply")

    assert plan["risk"] == "tightening"
    assert refused.status_code == 403
    assert refused.json()["detail"] == {
        "code": "PLAN_NOT_ALLOWLISTED",
        "changes": [
            {
                "index": 0,
                "resource": "privacy",
                "item": "_",
                "reason": "not_allowlisted",
            }
        ],
        "message": "This plan needs a person to apply it.",
        "hint": "Ask an administrator to apply it, or create a plan whose changes "
        "only tighten or cheapen.",
    }
    assert stored.status == "draft"
    assert versions_after_refusal == versions
    assert approve.status_code == 403
    [audit] = await _audits(db, tenant, "tenant.policy_plan_apply_refused")
    assert audit == {
        "subject_id": plan["id"],
        "plan_id": plan["id"],
        "risk": "tightening",
        "reasons": ["not_allowlisted"],
        "actor_type": "service",
        "actor_role": "recommender",
    }
    [created_audit] = await _audits(db, tenant, "tenant.policy_plan_created")
    assert (created_audit["actor_type"], created_audit["actor_role"]) == (
        "service",
        "recommender",
    )
    assert by_owner.status_code == 200, by_owner.text
    [applied] = await _audits(db, tenant, "tenant.policy_plan_applied")
    assert applied["actor_type"] == "user_jwt" and "actor_role" not in applied


@pytest.mark.asyncio
async def test_an_allowlisted_plan_applies_and_the_impact_is_measured_at_apply(
    db, monkeypatch
) -> None:
    monkeypatch.setattr(allowlist, "ALLOWLIST", (MASK_EMAIL,))
    users = await _tenant(db)
    agent = users["agent"]
    tenant = agent.organization_id
    await _monitoring_email(db, users)
    first = (await _call(db, agent, "POST", f"{POLICY}/plans", json=TIGHTEN)).json()

    applied = await _call(db, agent, "POST", f"{POLICY}/plans/{first['id']}/apply")
    version = await db.scalar(
        select(PolicyVersion)
        .where(PolicyVersion.organization_id == tenant)
        .order_by(PolicyVersion.version.desc())
    )
    assert applied.status_code == 200, applied.text
    assert (version.actor_type, version.created_by) == ("service", str(agent.id))

    await _monitoring_email(db, users)
    second = (await _call(db, agent, "POST", f"{POLICY}/plans", json=TIGHTEN)).json()
    # A request with an e-mail arrives after the plan was made.
    db.add(
        RequestLifecycle(
            request_id=f"req_agent_{uuid4().hex}",
            organization_id=tenant,
            actor_type="internal",
            source_endpoint="chat.completions",
            status="completed",
            requested_model="gpt-5-mini",
            stream=False,
            started_at=datetime.now(timezone.utc) - timedelta(minutes=5),
            lifecycle_metadata={"monitored_entities": {"EMAIL_ADDRESS": 1}},
        )
    )
    await db.flush()
    too_large = await _call(db, agent, "POST", f"{POLICY}/plans/{second['id']}/apply")

    assert second["changes"][0]["impact"]["requests"] == 0
    assert too_large.status_code == 403
    assert too_large.json()["detail"]["changes"][0]["reason"] == "impact_too_large"


@pytest.mark.asyncio
async def test_a_restore_by_a_recommender_passes_the_same_check(
    db, monkeypatch
) -> None:
    users = await _tenant(db)
    agent, owner = users["agent"], users["owner"]
    tenant = owner.organization_id
    await _monitoring_email(db, users)
    masked = await _call(
        db, owner, "PUT", PII, json={"entity_actions": {"EMAIL_ADDRESS": "mask"}}
    )
    assert masked.status_code == 200
    loosen = await _call(
        db, owner, "PUT", PII, json={"entity_actions": {"EMAIL_ADDRESS": "monitor"}}
    )
    assert loosen.status_code == 200
    target = await db.scalar(
        select(func.max(PolicyVersion.version)).where(
            PolicyVersion.organization_id == tenant
        )
    )
    plans = await _count(db, PolicyPlan, tenant)

    refused = await _call(
        db, agent, "POST", f"{POLICY}/versions/{target - 1}/restore", json={}
    )
    no_plan = await _count(db, PolicyPlan, tenant)
    monkeypatch.setattr(allowlist, "ALLOWLIST", (MASK_EMAIL,))
    restored = await _call(
        db, agent, "POST", f"{POLICY}/versions/{target - 1}/restore", json={}
    )
    read = await _call(db, agent, "GET", f"{POLICY}/versions")

    assert refused.status_code == 403
    assert refused.json()["detail"]["code"] == "PLAN_NOT_ALLOWLISTED"
    assert no_plan == plans
    assert restored.status_code == 200, restored.text
    assert restored.json()["plan"]["source"] == "restore"
    assert read.status_code == 200
    [audit] = await _audits(db, tenant, "tenant.policy_plan_apply_refused")
    assert audit["plan_id"] is None


@pytest.mark.asyncio
async def test_only_a_person_applies_a_rule_proposal(db) -> None:
    from ee.tests.rules.test_proposals import PROPOSALS, SENTENCE, term

    users = await _tenant(db)
    owner, admin, agent = users["owner"], users["admin"], users["agent"]
    service_admin = User(
        id=uuid4(),
        organization_id=owner.organization_id,
        email=f"agent-{uuid4().hex}@example.com",
        role="admin",
        kind="service",
        is_active=True,
        is_verified=True,
    )
    db.add(service_admin)
    await db.flush()
    four_eyes = await _call(
        db,
        owner,
        "PATCH",
        "/api/v1/management/gateway-settings",
        json={"four_eyes": "relaxing"},
    )
    assert four_eyes.status_code == 200, four_eyes.text
    proposed = await _call(
        db, agent, "POST", PROPOSALS, json={"sentence": SENTENCE, "rules": [term()]}
    )
    plan_id = proposed.json()["plan"]["id"]

    by_agent = await _call(db, agent, "POST", f"{POLICY}/plans/{plan_id}/apply")
    by_service = await _call(
        db, service_admin, "POST", f"{POLICY}/plans/{plan_id}/apply"
    )
    by_admin = await _call(db, admin, "POST", f"{POLICY}/plans/{plan_id}/apply")
    rules = await _call(db, owner, "GET", "/api/v1/management/rules")

    assert proposed.status_code == 201, proposed.text
    reasons = {change["reason"] for change in by_agent.json()["detail"]["changes"]}
    assert by_agent.status_code == 403 and "proposal_needs_human" in reasons
    assert (by_service.status_code, by_service.json()["detail"]["code"]) == (
        403,
        "PROPOSAL_NEEDS_HUMAN",
    )
    # Adding monitor rules loosens nothing, so four eyes does not hold it.
    assert by_admin.status_code == 200, by_admin.text
    assert by_admin.json()["status"] == "applied"
    assert [(rule["id"], rule["state"]) for rule in rules.json()["rules"]] == [
        ("project_atlas", "monitor")
    ]
