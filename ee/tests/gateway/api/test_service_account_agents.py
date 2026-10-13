from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from uuid import UUID, uuid4

from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI, HTTPException
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.ai_act.models import AIActAuditLog
from shim_enterprise.api.enterprise_deps import get_current_user
from shim_enterprise.api.v1 import management
from shim_enterprise.api.v1.router import management_router
from shim_enterprise.billing.models import RequestLifecycle, UsageLedger
from shim_enterprise.core.database import get_db
from shim_enterprise.gateway.pipeline.quota_reservation import AccountingPolicyLoader
from shim_enterprise.mcp import api as mcp_api
from shim_enterprise.policy.models import PolicyPlan, PolicyRemediation, PolicyVersion
from shim_enterprise.tenants.models import (
    Organization,
    Team,
    TeamMembership,
    User,
)
from shim_enterprise.tenants.plans import activate_organization_plan
from shim_enterprise.tenants.service import authenticate_api_key

ACCOUNTS = "/api/v1/management/service-accounts"
MODELS = ["gpt-5-mini"]


async def _tenant(db) -> dict[str, User]:
    organization = Organization(
        id=uuid4(), name="Agents", slug=f"agents-{uuid4().hex}", tier="enterprise"
    )
    db.add(organization)
    await db.flush()
    await activate_organization_plan(db, organization.id, "enterprise")
    people = {
        name: User(
            id=uuid4(),
            organization_id=organization.id,
            email=f"agents-{uuid4().hex}@example.com",
            role=role,
            is_active=True,
            is_verified=True,
        )
        for name, role in (("owner", "owner"), ("admin", "admin"), ("member", "member"))
    }
    db.add_all(people.values())
    await db.flush()
    return people


async def _account(db, owner: User, role: str = "recommender") -> tuple[User, str]:
    created = await management.members.create_service_account(
        management.members.ServiceAccountInput(
            name=f"agent-{role}", role=role, expires_in_days=1
        ),
        owner,
        db,
    )
    account = await db.get(User, created.id)
    assert account is not None
    return account, created.plaintext


async def _call(db, user: User | None, method: str, path: str, **kwargs):
    connection = await db.connection()

    async def request_session():
        async with AsyncSession(
            bind=connection,
            join_transaction_mode="create_savepoint",
            expire_on_commit=False,
        ) as session:
            yield session

    app = FastAPI()
    app.include_router(management_router, prefix="/api/v1")
    if user is not None:
        app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_db] = request_session
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        return await client.request(method, path, **kwargs)


async def _issue(db, owner: User, account: User, **body) -> httpx.Response:
    return await _call(
        db,
        owner,
        "POST",
        f"{ACCOUNTS}/{account.id}/gateway-keys",
        json={"name": "agent", "allowed_models": MODELS, "expires_in_days": 30, **body},
    )


@pytest.mark.asyncio
async def test_an_owner_issues_the_agent_a_key_it_cannot_mint(db, audit_events) -> None:
    people = await _tenant(db)
    owner = people["owner"]
    account, _ = await _account(db, owner)
    team = Team(id=uuid4(), organization_id=owner.organization_id, name="agents")
    db.add(team)
    await db.flush()

    first = await _issue(db, owner, account, team_id=str(team.id))
    second = await _issue(db, owner, account, team_id=str(team.id))
    third = await _issue(db, owner, account)
    no_models = await _issue(db, owner, account, allowed_models=[])
    own = await _call(
        db, account, "POST", "/api/v1/management/api-keys", json={"name": "x"}
    )

    assert first.status_code == 201, first.text
    key = first.json()
    assert key["plaintext"].startswith("sk-shim-")
    assert (key["user_id"], key["team_id"], key["allowed_models"]) == (
        str(account.id),
        str(team.id),
        MODELS,
    )
    assert datetime.fromisoformat(key["expires_at"]) > datetime.now(
        timezone.utc
    ) + timedelta(days=29)
    memberships = list(
        await db.scalars(
            select(TeamMembership).where(TeamMembership.user_id == account.id)
        )
    )
    assert [(m.team_id, m.role, m.source) for m in memberships] == [
        (team.id, "member", "local")
    ]
    assert second.status_code == 201
    assert (third.status_code, third.json()["detail"]["code"]) == (
        409,
        "AGENT_KEY_LIMIT",
    )
    assert no_models.status_code == 422
    assert own.status_code == 403
    authenticated = await authenticate_api_key(db, key["plaintext"])
    assert authenticated is not None and authenticated.user_id == account.id
    issued = [
        event["extra"]
        for event in await audit_events(owner.organization_id)
        if event["endpoint"] == "tenant.agent_gateway_key_issued"
    ]
    assert issued[0] == {
        "subject_id": str(account.id),
        "account_id": str(account.id),
        "api_key_id": key["id"],
        "team_id": str(team.id),
        "models": 1,
        "actor_type": "user_jwt",
    }
    assert len(issued) == 2


@pytest.mark.asyncio
async def test_only_a_recommender_of_this_tenant_gets_a_key_from_an_owner(db) -> None:
    people = await _tenant(db)
    owner = people["owner"]
    admin_account, _ = await _account(db, owner, "admin")
    agent, _ = await _account(db, owner)
    other = await _tenant(db)

    admin_key = await _issue(db, owner, admin_account)
    foreign = await _issue(db, other["owner"], agent)
    by_admin = await _issue(db, people["admin"], agent)
    by_member = await _issue(db, people["member"], agent)

    assert (admin_key.status_code, admin_key.json()["detail"]["code"]) == (
        409,
        "ACCOUNT_CANNOT_HOLD_KEYS",
    )
    assert foreign.status_code == 404
    assert by_admin.status_code == 403
    assert by_member.status_code == 403


@pytest.mark.asyncio
async def test_freeze_stops_every_key_and_unfreeze_restores_them(
    db, monkeypatch
) -> None:
    connection = await db.connection()
    # The MCP endpoint opens its own session to authenticate the service key.
    monkeypatch.setattr(
        mcp_api,
        "AsyncSessionLocal",
        lambda: AsyncSession(
            bind=connection,
            join_transaction_mode="create_savepoint",
            expire_on_commit=False,
        ),
    )
    people = await _tenant(db)
    owner = people["owner"]
    agent, management_key = await _account(db, owner)
    gateway_key = (await _issue(db, owner, agent)).json()["plaintext"]

    frozen = await _call(db, owner, "POST", f"{ACCOUNTS}/{agent.id}/freeze")
    listed = await _call(db, owner, "GET", ACCOUNTS)
    await db.refresh(agent)
    gateway_frozen = await authenticate_api_key(db, gateway_key)
    mcp_frozen = await _call(
        db,
        None,
        "POST",
        "/api/v1/mcp",
        headers={"authorization": f"Bearer {management_key}"},
        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
    )
    thawed = await _call(db, owner, "POST", f"{ACCOUNTS}/{agent.id}/unfreeze")
    await db.refresh(agent)
    gateway_thawed = await authenticate_api_key(db, gateway_key)
    mcp_thawed = await _call(
        db,
        None,
        "POST",
        "/api/v1/mcp",
        headers={"authorization": f"Bearer {management_key}"},
        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
    )

    assert (frozen.status_code, frozen.json()) == (
        200,
        {"id": str(agent.id), "active": False},
    )
    assert [(a["id"], a["active"]) for a in listed.json()] == [(str(agent.id), False)]
    assert gateway_frozen is None
    assert mcp_frozen.status_code == 401
    assert thawed.json()["active"] is True
    assert gateway_thawed is not None
    assert mcp_thawed.status_code == 200


@pytest.mark.asyncio
async def test_a_deleted_account_cannot_be_unfrozen(db) -> None:
    people = await _tenant(db)
    owner = people["owner"]
    agent, _ = await _account(db, owner)
    deleted = await _call(db, owner, "DELETE", f"{ACCOUNTS}/{agent.id}")

    unfrozen = await _call(db, owner, "POST", f"{ACCOUNTS}/{agent.id}/unfreeze")
    frozen = await _call(db, owner, "POST", f"{ACCOUNTS}/{agent.id}/freeze")

    assert deleted.status_code == 204
    assert (unfrozen.status_code, unfrozen.json()["detail"]["code"]) == (
        409,
        "SERVICE_ACCOUNT_DELETED",
    )
    assert frozen.status_code == 404


@pytest.mark.asyncio
async def test_the_activity_view_counts_only_this_accounts_window(db) -> None:
    people = await _tenant(db)
    owner = people["owner"]
    tenant = owner.organization_id
    agent, _ = await _account(db, owner)
    key = (await _issue(db, owner, agent)).json()
    now = datetime.now(timezone.utc)
    for index, (status, hours_ago) in enumerate(
        (("completed", 1), ("completed", 2), ("provider_error", 3), ("completed", 30))
    ):
        request_id = f"req_agent_{uuid4().hex}"
        db.add(
            RequestLifecycle(
                request_id=request_id,
                organization_id=tenant,
                actor_type="api_key",
                api_key_id=UUID(key["id"]),
                source_endpoint="chat.completions",
                status=status,
                requested_model="gpt-5-mini" if index else "gpt-5-nano",
                stream=False,
                started_at=now - timedelta(hours=hours_ago),
            )
        )
        await db.flush()
        ledger = {
            "request_id": request_id,
            "organization_id": tenant,
            "api_key_id": UUID(key["id"]),
            "requested_model": "gpt-5-mini",
            "provider": "openai",
            "provider_model": "gpt-5-mini",
            "cost_usd": Decimal("0.10"),
            "created_at": now - timedelta(hours=hours_ago),
        }
        reservation = uuid4()
        db.add_all(
            [
                UsageLedger(
                    id=reservation,
                    event_type="spend_reservation",
                    idempotency_key=f"{request_id}:spend:reservation",
                    **ledger,
                ),
                UsageLedger(
                    event_type="spend_settlement",
                    idempotency_key=f"{request_id}:spend:settlement",
                    reservation_event_id=reservation,
                    **ledger,
                ),
            ]
        )
    for status, hours_ago in (("draft", 1), ("applied", 2), ("draft", 30)):
        db.add(
            PolicyPlan(
                organization_id=tenant,
                base_version=0,
                changes=[],
                risk="tightening",
                status=status,
                source="mcp",
                created_by=str(agent.id),
                created_by_actor_type="service",
                created_at=now - timedelta(hours=hours_ago),
                expires_at=now + timedelta(days=1),
            )
        )
    for version, hours_ago in ((7, 1), (8, 30)):
        db.add(
            PolicyVersion(
                organization_id=tenant,
                version=version,
                snapshot={},
                previous={},
                source="mcp",
                risk="tightening",
                created_by=str(agent.id),
                actor_type="service",
                created_at=now - timedelta(hours=hours_ago),
            )
        )
    db.add(
        PolicyRemediation(
            organization_id=tenant,
            actor_type="service",
            actor_id=str(agent.id),
            items=[],
            status="watching",
        )
    )
    db.add(
        AIActAuditLog(
            organization_id=tenant,
            seq=1,
            event_type="management_action",
            actor=str(agent.id),
            endpoint="tenant.policy_plan_apply_refused",
            prev_hash="0" * 64,
            row_hash=uuid4().hex * 2,
            created_at=now - timedelta(hours=1),
        )
    )
    other = await _tenant(db)
    other_agent, _ = await _account(db, other["owner"])
    db.add(
        PolicyRemediation(
            organization_id=other["owner"].organization_id,
            actor_type="service",
            actor_id=str(other_agent.id),
            items=[],
            status="kept",
        )
    )
    await db.flush()
    auditor = User(
        id=uuid4(),
        organization_id=tenant,
        email=f"auditor-{uuid4().hex}@example.com",
        role="auditor",
        is_active=True,
        is_verified=True,
    )
    db.add(auditor)
    await db.flush()

    read = await _call(
        db, auditor, "GET", f"{ACCOUNTS}/{agent.id}/activity", params={"hours": 24}
    )
    foreign = await _call(db, auditor, "GET", f"{ACCOUNTS}/{other_agent.id}/activity")
    refused = [
        (
            await _call(
                db,
                auditor,
                "GET",
                f"{ACCOUNTS}/{agent.id}/activity",
                params={"hours": hours},
            )
        ).status_code
        for hours in (0, 721)
    ]
    by_member = await _call(
        db, people["member"], "GET", f"{ACCOUNTS}/{agent.id}/activity"
    )

    assert read.status_code == 200, read.text
    body = read.json()
    assert body["account"]["active"] is True
    assert [k["id"] for k in body["gateway_keys"]] == [key["id"]]
    assert body["model_usage"] == {
        "requests": 3,
        "failed": 1,
        "cost_usd": "0.30000000",
        "by_model": [
            {"model": "gpt-5-mini", "requests": 2},
            {"model": "gpt-5-nano", "requests": 1},
        ],
    }
    assert body["management"] == {
        "plans_by_status": {"draft": 1, "applied": 1},
        "versions": [7],
        "remediations_by_status": {"watching": 1},
        "refused_applies": 1,
    }
    assert foreign.status_code == 404
    assert refused == [422, 422]
    assert by_member.status_code == 403


@pytest.mark.asyncio
async def test_the_agents_key_passes_the_reservation_through_its_team(db) -> None:
    people = await _tenant(db)
    owner = people["owner"]
    agent, _ = await _account(db, owner)
    team = Team(
        id=uuid4(),
        organization_id=owner.organization_id,
        name="agents",
        daily_request_limit=5,
    )
    db.add(team)
    await db.flush()
    key = (await _issue(db, owner, agent, team_id=str(team.id))).json()
    prepared = SimpleNamespace(
        tenant_id=owner.organization_id, api_key_id=UUID(key["id"]), model=MODELS[0]
    )

    policy = await AccountingPolicyLoader().quota(db, prepared)
    await db.execute(delete(TeamMembership).where(TeamMembership.user_id == agent.id))
    with pytest.raises(HTTPException) as outside:
        await AccountingPolicyLoader().quota(db, prepared)

    assert policy.team_policy is not None
    assert policy.team_policy.daily_request_limit == 5
    assert outside.value.status_code == 403
