"""Team boundaries use real PostgreSQL authorization and reservation transactions."""

import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import async_sessionmaker

from shim_enterprise.api.enterprise_deps import get_current_user
from shim_enterprise.api.v1 import management
from shim_enterprise.billing.ledger import (
    DurableAccountingRepository,
    FinalizationCommand,
    QuotaLimitExceeded,
    QuotaPolicySnapshot,
    QuotaReservationCommand,
    TerminalAction,
)
from shim_enterprise.billing.models import (
    QuotaPeriodUsage,
    RequestLifecycle,
    UsageLedger,
)
from shim_enterprise.core.database import get_db
from shim_enterprise.gateway.pipeline.quota_reservation import AccountingPolicyLoader
from shim_enterprise.outbox.models import OutboxEvent
from shim_enterprise.tenants.models import (
    ApiKey,
    Organization,
    Team,
    TeamMembership,
    User,
)
from shim_enterprise.tenants.service import authenticate_api_key, create_api_key
from shim_enterprise.tenants.teams import synchronize_oidc_teams


@pytest.mark.asyncio
async def test_team_admin_isolation_auditor_and_immediate_rotation(
    db, test_user_with_org
):
    owner = test_user_with_org
    owner.role = "owner"
    admin = User(
        id=uuid4(),
        organization_id=owner.organization_id,
        email=f"admin-{uuid4()}@example.com",
        role="member",
        is_active=True,
        is_verified=True,
    )
    auditor = User(
        id=uuid4(),
        organization_id=owner.organization_id,
        email=f"audit-{uuid4()}@example.com",
        role="auditor",
        is_active=True,
        is_verified=True,
    )
    first = Team(id=uuid4(), organization_id=owner.organization_id, name="First")
    second = Team(id=uuid4(), organization_id=owner.organization_id, name="Second")
    db.add_all([admin, auditor, first, second])
    await db.flush()
    db.add(
        TeamMembership(
            organization_id=owner.organization_id,
            team_id=first.id,
            user_id=admin.id,
            role="team_admin",
        )
    )
    await db.flush()
    plaintext, key = await create_api_key(
        db,
        user_id=owner.id,
        name="Team key",
        team="historical-label",
        team_id=first.id,
        allowed_models=["internal-model"],
    )
    _, other = await create_api_key(
        db, user_id=owner.id, name="Other team", team_id=second.id
    )

    app = FastAPI()
    app.include_router(management.router)
    current = admin
    app.dependency_overrides[get_current_user] = lambda: current
    app.dependency_overrides[get_db] = lambda: db
    async with AsyncClient(
        transport=ASGITransport(app), base_url="http://test"
    ) as client:
        assert (await client.delete(f"/api-keys/{other.id}")).status_code == 404
        assert (
            await client.put(
                f"/teams/{second.id}/members/{admin.id}", json={"role": "member"}
            )
        ).status_code == 404
        assert (
            await client.put(f"/teams/{first.id}", json={"name": "Edited"})
        ).status_code == 403
        assert (
            await client.put(
                f"/teams/{first.id}/members/{owner.id}", json={"role": "team_admin"}
            )
        ).status_code == 403
        rotated = await client.post(f"/api-keys/{key.id}/rotate")
        assert rotated.status_code == 200, rotated.text
        payload = rotated.json()
        assert payload["id"] == str(key.id)
        assert payload["allowed_models"] == ["internal-model"]
        assert payload["team"] == "historical-label"
        assert payload["team_id"] == str(first.id)
        assert await authenticate_api_key(db, plaintext) is None
        assert (await authenticate_api_key(db, payload["plaintext"])).id == key.id
        assert "plaintext" not in (await client.get("/api-keys")).json()[0]
        current = auditor
        assert (
            await client.post("/api-keys", json={"name": "forbidden"})
        ).status_code == 403
        assert (await client.post(f"/api-keys/{key.id}/rotate")).status_code == 403
        assert (
            await client.put(
                f"/teams/{first.id}/members/{owner.id}", json={"role": "member"}
            )
        ).status_code == 403
        assert (await client.get("/teams")).status_code == 200

    event = await db.scalar(
        select(OutboxEvent).where(OutboxEvent.organization_id == owner.organization_id)
    )
    assert event.payload["endpoint"] == "tenant.api_key_rotated"
    assert payload["plaintext"] not in str(event.payload)


@pytest.mark.asyncio
async def test_team_mapping_never_grants_cross_tenant_and_revokes_only_oidc(
    db, test_user_with_org
):
    user = test_user_with_org
    teams = [
        Team(id=uuid4(), organization_id=user.organization_id, name=f"Team {i}")
        for i in range(2)
    ]
    db.add_all(teams)
    await db.flush()
    db.add(
        TeamMembership(
            organization_id=user.organization_id,
            team_id=teams[0].id,
            user_id=user.id,
            role="member",
            source="local",
        )
    )
    await db.flush()
    mapping = {
        "local": {"team_id": str(teams[0].id), "role": "team_admin"},
        "mapped": {"team_id": str(teams[1].id), "role": "team_admin"},
    }
    await synchronize_oidc_teams(db, user, ["local", "mapped"], mapping)
    memberships = list(
        (
            await db.scalars(
                select(TeamMembership).where(TeamMembership.user_id == user.id)
            )
        ).all()
    )
    assert {(row.source, row.role) for row in memberships} == {
        ("local", "member"),
        ("oidc", "team_admin"),
    }
    await synchronize_oidc_teams(db, user, [], mapping)
    remaining = list(
        (
            await db.scalars(
                select(TeamMembership).where(TeamMembership.user_id == user.id)
            )
        ).all()
    )
    assert len(remaining) == 1 and remaining[0].source == "local"
    with pytest.raises(ValueError, match="organization"):
        await synchronize_oidc_teams(
            db,
            user,
            ["outside"],
            {"outside": {"team_id": str(uuid4()), "role": "member"}},
        )


@pytest.mark.asyncio
async def test_model_and_membership_denial_precedes_quota(db, test_user_with_org):
    user = test_user_with_org
    team = Team(id=uuid4(), organization_id=user.organization_id, name="Restricted")
    db.add(team)
    await db.flush()
    _, key = await create_api_key(
        db,
        user_id=user.id,
        name="Restricted",
        team_id=team.id,
        allowed_models=["internal"],
    )
    prepared = SimpleNamespace(
        tenant_id=user.organization_id, api_key_id=key.id, model="external"
    )
    with pytest.raises(HTTPException) as model_error:
        await AccountingPolicyLoader().quota(db, prepared)
    assert model_error.value.status_code == 403
    assert model_error.value.detail["code"] == "MODEL_NOT_ALLOWED"
    prepared.model = "internal"
    with pytest.raises(HTTPException, match="team member"):
        await AccountingPolicyLoader().quota(db, prepared)
    assert (
        await db.scalar(
            select(QuotaPeriodUsage.id).where(
                QuotaPeriodUsage.organization_id == user.organization_id
            )
        )
        is None
    )


@pytest.mark.asyncio
async def test_concurrent_team_quota_reserves_and_refunds_all_scopes(async_engine):
    factory = async_sessionmaker(async_engine, expire_on_commit=False)
    organization_id, user_id, team_id = uuid4(), uuid4(), uuid4()
    async with factory.begin() as session:
        session.add(
            Organization(
                id=organization_id,
                name="Quota race",
                slug=f"quota-race-{organization_id}",
            )
        )
        await session.flush()
        session.add(
            User(
                id=user_id,
                organization_id=organization_id,
                email=f"quota-race-{user_id}@example.com",
                role="owner",
                is_active=True,
                is_verified=True,
            )
        )
        session.add(
            Team(
                id=team_id,
                organization_id=organization_id,
                name="Concurrent",
                monthly_request_limit=3,
                monthly_token_limit=30,
            )
        )
        await session.flush()
        keys = [
            (
                await create_api_key(
                    session, user_id=user_id, name=f"key {i}", team_id=team_id
                )
            )[1].id
            for i in range(8)
        ]

    repository = DurableAccountingRepository()

    async def reserve(key_id):
        now = datetime.now(timezone.utc)
        request_id = f"req_team_{uuid4().hex}"
        async with factory() as session:
            policy = await AccountingPolicyLoader().quota(
                session,
                SimpleNamespace(
                    tenant_id=organization_id, api_key_id=key_id, model="internal"
                ),
            )
            # This key's limit is stricter than the team limit, and both count.
            policy = QuotaPolicySnapshot(
                version=policy.version,
                daily_request_limit=None,
                monthly_request_limit=1,
                monthly_token_limit=10,
                team_id=team_id,
                team_policy=policy.team_policy,
            )
            try:
                result = await repository.reserve_quota(
                    session,
                    QuotaReservationCommand(
                        tenant_id=organization_id,
                        api_key_id=key_id,
                        request_id=request_id,
                        requested_model="internal",
                        source_endpoint="chat.completions",
                        started_at=now,
                        reconciliation_due_at=now + timedelta(minutes=2),
                        estimated_input_tokens=2,
                        maximum_output_tokens=8,
                        policy=policy,
                    ),
                )
                await session.commit()
                return request_id, result
            except QuotaLimitExceeded:
                await session.rollback()
                return None

    try:
        results = await asyncio.gather(*(reserve(key) for key in keys))
        admitted = [result for result in results if result is not None]
        assert len(admitted) == 3
        assert all(len(result.period_allocations) == 2 for _, result in admitted)
        used_key = keys[next(index for index, result in enumerate(results) if result)]
        assert await reserve(used_key) is None
        async with factory.begin() as session:
            await repository.finalize(
                session,
                FinalizationCommand(
                    tenant_id=organization_id,
                    request_id=admitted[0][0],
                    quota_action=TerminalAction.REFUND,
                    lifecycle_status="failed",
                    terminal_error_code="REQUEST_ABORTED",
                    completed_at=datetime.now(timezone.utc),
                ),
            )
        assert await reserve(used_key) is not None
        async with factory() as session:
            counter = await session.scalar(
                select(QuotaPeriodUsage).where(QuotaPeriodUsage.team_id == team_id)
            )
            assert counter.reserved_requests == 3 and counter.reserved_tokens == 30
    finally:
        async with factory.begin() as session:
            for model in (
                OutboxEvent,
                UsageLedger,
                RequestLifecycle,
                QuotaPeriodUsage,
                ApiKey,
                TeamMembership,
                Team,
                User,
            ):
                await session.execute(
                    delete(model).where(model.organization_id == organization_id)
                )
            await session.execute(
                delete(Organization).where(Organization.id == organization_id)
            )
