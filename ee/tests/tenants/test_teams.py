"""Team boundaries use real PostgreSQL authorization and reservation transactions."""

import asyncio
import csv
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import io
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
from shim_enterprise.observability.analytics_projection import RequestLog
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
async def test_removing_organization_caps_preserves_active_accounting(db, test_api_key):
    repository = DurableAccountingRepository()
    now = datetime.now(timezone.utc)
    organization_id = test_api_key.organization_id
    common = dict(
        tenant_id=organization_id,
        api_key_id=test_api_key.id,
        requested_model="internal",
        source_endpoint="chat.completions",
        started_at=now,
        reconciliation_due_at=now + timedelta(minutes=2),
        estimated_input_tokens=2,
        maximum_output_tokens=8,
    )
    capped_request = f"req_capped_{uuid4().hex}"
    uncapped_request = f"req_uncapped_{uuid4().hex}"
    await repository.reserve_quota(
        db,
        QuotaReservationCommand(
            **common,
            request_id=capped_request,
            policy=QuotaPolicySnapshot(
                "capped",
                None,
                None,
                None,
                organization_policy=QuotaPolicySnapshot("organization", None, 1, 10),
            ),
        ),
    )
    await repository.reserve_quota(
        db,
        QuotaReservationCommand(
            **common,
            request_id=uncapped_request,
            policy=QuotaPolicySnapshot("uncapped", None, None, None),
        ),
    )
    for request_id in (uncapped_request, capped_request):
        await repository.finalize(
            db,
            FinalizationCommand(
                tenant_id=organization_id,
                request_id=request_id,
                quota_action=TerminalAction.REFUND,
                lifecycle_status="failed",
            ),
        )
    counters = (
        await db.scalars(
            select(QuotaPeriodUsage)
            .where(QuotaPeriodUsage.organization_id == organization_id)
            .execution_options(populate_existing=True)
        )
    ).all()
    assert len(counters) == 2
    assert all(
        (
            row.reserved_requests,
            row.reserved_tokens,
            row.settled_requests,
            row.settled_tokens,
        )
        == (0, 0, 0, 0)
        for row in counters
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
        async with factory.begin() as session:
            settled = await repository.finalize(
                session,
                FinalizationCommand(
                    tenant_id=organization_id,
                    request_id=admitted[1][0],
                    quota_action=TerminalAction.SETTLE,
                    prompt_tokens=2,
                    completion_tokens=3,
                    lifecycle_status="completed",
                    completed_at=datetime.now(timezone.utc),
                ),
            )
            replay = await repository.finalize(
                session,
                FinalizationCommand(
                    tenant_id=organization_id,
                    request_id=admitted[1][0],
                    quota_action=TerminalAction.SETTLE,
                    prompt_tokens=2,
                    completion_tokens=3,
                    lifecycle_status="completed",
                ),
            )
            assert replay.replayed and replay.quota_event_id == settled.quota_event_id
        async with factory() as session:
            counter = await session.scalar(
                select(QuotaPeriodUsage).where(QuotaPeriodUsage.team_id == team_id)
            )
            assert (counter.reserved_requests, counter.settled_requests) == (2, 1)
            assert (counter.reserved_tokens, counter.settled_tokens) == (20, 5)
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


@pytest.mark.asyncio
async def test_organization_quota_shares_existing_usage_across_new_keys(async_engine):
    factory = async_sessionmaker(async_engine, expire_on_commit=False)
    organization_id, user_id = uuid4(), uuid4()
    repository = DurableAccountingRepository()
    async with factory.begin() as session:
        session.add(
            Organization(
                id=organization_id,
                name="Organization quota",
                slug=f"organization-quota-{organization_id}",
            )
        )
        session.add(
            User(
                id=user_id,
                organization_id=organization_id,
                email=f"organization-quota-{user_id}@example.com",
                role="owner",
                is_active=True,
                is_verified=True,
            )
        )
        await session.flush()
        _, legacy_key = await create_api_key(session, user_id=user_id, name="legacy")
        started_at = datetime.now(timezone.utc)
        legacy_request = f"req_legacy_{uuid4().hex}"
        await repository.reserve_quota(
            session,
            QuotaReservationCommand(
                tenant_id=organization_id,
                api_key_id=legacy_key.id,
                request_id=legacy_request,
                requested_model="internal",
                source_endpoint="chat.completions",
                started_at=started_at,
                reconciliation_due_at=started_at + timedelta(minutes=2),
                estimated_input_tokens=2,
                maximum_output_tokens=8,
                policy=QuotaPolicySnapshot("legacy", None, None, None),
            ),
        )
        await repository.finalize(
            session,
            FinalizationCommand(
                tenant_id=organization_id,
                request_id=legacy_request,
                quota_action=TerminalAction.SETTLE,
                prompt_tokens=2,
                completion_tokens=3,
                lifecycle_status="completed",
            ),
        )
        legacy_active_request = f"req_legacy_active_{uuid4().hex}"
        await repository.reserve_quota(
            session,
            QuotaReservationCommand(
                tenant_id=organization_id,
                api_key_id=legacy_key.id,
                request_id=legacy_active_request,
                requested_model="internal",
                source_endpoint="chat.completions",
                started_at=started_at,
                reconciliation_due_at=started_at + timedelta(minutes=2),
                estimated_input_tokens=2,
                maximum_output_tokens=8,
                policy=QuotaPolicySnapshot("legacy", None, None, None),
            ),
        )

    async with factory.begin() as session:
        organization = await session.get(Organization, organization_id)
        assert organization is not None
        organization.quota_monthly_request_limit = 4
        organization.quota_monthly_token_limit = 35
        organization.billing_revision += 1
        _, first_new_key = await create_api_key(
            session, user_id=user_id, name="first new"
        )
        _, second_new_key = await create_api_key(
            session, user_id=user_id, name="second new"
        )

    async def reserve(api_key_id):
        request_id = f"req_organization_{uuid4().hex}"
        now = datetime.now(timezone.utc)
        async with factory() as session:
            policy = await AccountingPolicyLoader().quota(
                session,
                SimpleNamespace(
                    tenant_id=organization_id,
                    api_key_id=api_key_id,
                    model="internal",
                ),
            )
            try:
                await repository.reserve_quota(
                    session,
                    QuotaReservationCommand(
                        tenant_id=organization_id,
                        api_key_id=api_key_id,
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
                return request_id
            except QuotaLimitExceeded:
                await session.rollback()
                return None

    try:
        first, second = await asyncio.gather(
            reserve(first_new_key.id), reserve(second_new_key.id)
        )
        assert first is not None and second is not None
        assert await reserve(legacy_key.id) is None

        async with factory.begin() as session:
            counter = await session.scalar(
                select(QuotaPeriodUsage).where(
                    QuotaPeriodUsage.organization_id == organization_id,
                    QuotaPeriodUsage.api_key_id.is_(None),
                    QuotaPeriodUsage.team_id.is_(None),
                )
            )
            assert counter is not None
            assert (counter.reserved_requests, counter.settled_requests) == (3, 1)
            assert (counter.reserved_tokens, counter.settled_tokens) == (30, 5)
            await repository.finalize(
                session,
                FinalizationCommand(
                    tenant_id=organization_id,
                    request_id=legacy_active_request,
                    quota_action=TerminalAction.SETTLE,
                    prompt_tokens=2,
                    completion_tokens=3,
                    lifecycle_status="completed",
                ),
            )
            await repository.finalize(
                session,
                FinalizationCommand(
                    tenant_id=organization_id,
                    request_id=first,
                    quota_action=TerminalAction.REFUND,
                    lifecycle_status="failed",
                    terminal_error_code="REQUEST_ABORTED",
                ),
            )
            await repository.finalize(
                session,
                FinalizationCommand(
                    tenant_id=organization_id,
                    request_id=second,
                    quota_action=TerminalAction.SETTLE,
                    prompt_tokens=2,
                    completion_tokens=4,
                    lifecycle_status="completed",
                ),
            )

        replacement = await reserve(legacy_key.id)
        assert replacement is not None
        async with factory.begin() as session:
            await repository.finalize(
                session,
                FinalizationCommand(
                    tenant_id=organization_id,
                    request_id=replacement,
                    quota_action=TerminalAction.SETTLE,
                    prompt_tokens=2,
                    completion_tokens=5,
                    lifecycle_status="completed",
                ),
            )
            counter = await session.scalar(
                select(QuotaPeriodUsage).where(
                    QuotaPeriodUsage.organization_id == organization_id,
                    QuotaPeriodUsage.api_key_id.is_(None),
                    QuotaPeriodUsage.team_id.is_(None),
                )
            )
            assert counter is not None
            assert (counter.reserved_requests, counter.settled_requests) == (0, 4)
            assert (counter.reserved_tokens, counter.settled_tokens) == (0, 23)
        assert await reserve(legacy_key.id) is None
    finally:
        async with factory.begin() as session:
            for model in (
                OutboxEvent,
                UsageLedger,
                RequestLifecycle,
                QuotaPeriodUsage,
                ApiKey,
                User,
            ):
                await session.execute(
                    delete(model).where(model.organization_id == organization_id)
                )
            await session.execute(
                delete(Organization).where(Organization.id == organization_id)
            )


@pytest.mark.asyncio
async def test_member_reads_requests_of_own_and_administered_team_keys(
    db, test_user_with_org
):
    owner = test_user_with_org
    owner.role = "owner"
    member = User(
        id=uuid4(),
        organization_id=owner.organization_id,
        email=f"reader-{uuid4()}@example.com",
        role="member",
        is_active=True,
        is_verified=True,
    )
    administered_team = Team(
        id=uuid4(), organization_id=owner.organization_id, name="Administered"
    )
    other_team = Team(id=uuid4(), organization_id=owner.organization_id, name="Other")
    db.add_all([member, administered_team, other_team])
    await db.flush()
    db.add_all(
        [
            TeamMembership(
                organization_id=owner.organization_id,
                team_id=administered_team.id,
                user_id=member.id,
                role="team_admin",
            ),
            # Belonging to a team without administering it does not open its keys.
            TeamMembership(
                organization_id=owner.organization_id,
                team_id=other_team.id,
                user_id=member.id,
                role="member",
            ),
        ]
    )
    await db.flush()
    keys = {
        "own": (await create_api_key(db, user_id=member.id, name="own"))[1],
        "administered": (
            await create_api_key(
                db, user_id=owner.id, name="administered", team_id=administered_team.id
            )
        )[1],
        "other team": (
            await create_api_key(
                db, user_id=owner.id, name="other", team_id=other_team.id
            )
        )[1],
        "owner": (await create_api_key(db, user_id=owner.id, name="owner"))[1],
    }
    now = datetime.now(timezone.utc)
    requests = {name: [f"req_scope_{uuid4().hex}" for _ in range(2)] for name in keys}
    db.add_all(
        RequestLog(
            request_id=request_id,
            api_key_id=keys[name].id,
            organization_id=owner.organization_id,
            timestamp=now - timedelta(seconds=index),
        )
        for name, request_ids in requests.items()
        for index, request_id in enumerate(request_ids)
    )
    await db.flush()

    app = FastAPI()
    app.include_router(management.router)
    current = member
    app.dependency_overrides[get_current_user] = lambda: current
    app.dependency_overrides[get_db] = lambda: db
    async with AsyncClient(
        transport=ASGITransport(app), base_url="http://test"
    ) as client:
        first = (await client.get("/requests", params={"limit": 3})).json()
        second = (
            await client.get("/requests", params={"limit": 3, "offset": 3})
        ).json()
        # Two exports on one pooled connection: the second used to bind the
        # cached rows statement against the count query's unnamed statement.
        exports = [await client.get("/requests/export") for _ in range(2)]
        current = owner
        everything = (await client.get("/requests", params={"limit": 200})).json()

    readable = {*requests["own"], *requests["administered"]}
    assert (first["total"], second["total"]) == (4, 4)
    assert first["summary"]["requests"] == 4
    assert [len(first["items"]), len(second["items"])] == [3, 1]
    assert {item["request_id"] for item in first["items"] + second["items"]} == readable
    for exported in exports:
        assert exported.status_code == 200
        assert {
            row["request_id"]
            for row in csv.DictReader(io.StringIO(exported.content.decode("utf-8-sig")))
        } == readable
    assert everything["total"] == 8


@pytest.mark.asyncio
async def test_member_list_is_for_organization_readers_and_team_admins(
    db, test_user_with_org
):
    owner = test_user_with_org
    owner.role = "owner"
    other_org = Organization(id=uuid4(), name="Other", slug=f"other-{uuid4().hex}")
    db.add(other_org)
    await db.flush()

    def person(organization_id, role):
        return User(
            id=uuid4(),
            organization_id=organization_id,
            email=f"{role}-{uuid4()}@example.com",
            role=role,
            is_active=True,
            is_verified=True,
        )

    users = {role: person(owner.organization_id, role) for role in ("admin", "auditor")}
    users |= {
        name: person(owner.organization_id, "member")
        for name in ("member", "team member", "team admin")
    }
    outsider = person(other_org.id, "member")
    team = Team(id=uuid4(), organization_id=owner.organization_id, name="Team")
    other_team = Team(id=uuid4(), organization_id=other_org.id, name="Team")
    db.add_all([*users.values(), outsider, team, other_team])
    await db.flush()
    db.add_all(
        [
            TeamMembership(
                organization_id=owner.organization_id,
                team_id=team.id,
                user_id=users["team member"].id,
                role="member",
            ),
            TeamMembership(
                organization_id=owner.organization_id,
                team_id=team.id,
                user_id=users["team admin"].id,
                role="team_admin",
            ),
            TeamMembership(
                organization_id=other_org.id,
                team_id=other_team.id,
                user_id=outsider.id,
                role="team_admin",
            ),
        ]
    )
    await db.flush()

    app = FastAPI()
    app.include_router(management.router)
    current = owner
    app.dependency_overrides[get_current_user] = lambda: current
    app.dependency_overrides[get_db] = lambda: db
    statuses, listed = {}, {}
    async with AsyncClient(
        transport=ASGITransport(app), base_url="http://test"
    ) as client:
        for name, current in {"owner": owner, **users, "outsider": outsider}.items():
            response = await client.get("/team/members")
            statuses[name] = response.status_code
            if response.status_code == 200:
                listed[name] = response.json()

    assert statuses == {
        "owner": 200,
        "admin": 200,
        "auditor": 200,
        "member": 403,
        "team member": 403,
        "team admin": 200,
        "outsider": 200,
    }
    organization = {owner.email, *(user.email for user in users.values())}
    emails = {name: {row["email"] for row in rows} for name, rows in listed.items()}
    assert emails["owner"] == emails["admin"] == emails["auditor"] == organization
    # Team admins see who is in the organization, not their e-mail addresses.
    assert emails["team admin"] == emails["outsider"] == {None}
    assert {row["id"] for row in listed["team admin"]} == {
        str(person.id) for person in (owner, *users.values())
    }
    assert [row["id"] for row in listed["outsider"]] == [str(outsider.id)]


@pytest.mark.asyncio
async def test_team_breakdown_rows_carry_the_tenant_team_name(
    db, test_api_key, monkeypatch
):
    organization_id = test_api_key.organization_id
    other_org = Organization(id=uuid4(), name="Other", slug=f"other-{uuid4().hex}")
    db.add(other_org)
    await db.flush()
    team = Team(id=uuid4(), organization_id=organization_id, name="Payments")
    foreign = Team(id=uuid4(), organization_id=other_org.id, name="Foreign")
    db.add_all([team, foreign])
    await db.flush()
    at = datetime.now(timezone.utc) - timedelta(minutes=5)
    for team_id in (str(team.id), str(foreign.id), None):
        request_id = f"req_label_{uuid4().hex}"
        db.add(
            RequestLifecycle(
                request_id=request_id,
                organization_id=organization_id,
                actor_type="api_key",
                api_key_id=test_api_key.id,
                user_id=None,
                source_endpoint="chat.completions",
                status="completed",
                provider="openai",
                provider_model="gpt-5-mini",
                requested_model="gpt-5-mini",
                stream=False,
                started_at=at,
                completed_at=at,
                reconciled_at=at,
                lifecycle_metadata={} if team_id is None else {"team_id": team_id},
            )
        )
        reservation = UsageLedger(
            request_id=request_id,
            organization_id=organization_id,
            api_key_id=test_api_key.id,
            requested_model="gpt-5-mini",
            provider="openai",
            provider_model="gpt-5-mini",
            event_type="spend_reservation",
            idempotency_key=f"{request_id}:spend:reservation",
            cost_usd=Decimal("0.01"),
        )
        db.add(reservation)
        await db.flush()
        db.add(
            UsageLedger(
                request_id=request_id,
                organization_id=organization_id,
                api_key_id=test_api_key.id,
                requested_model="gpt-5-mini",
                provider="openai",
                provider_model="gpt-5-mini",
                event_type="spend_settlement",
                idempotency_key=f"{request_id}:spend:settlement",
                reservation_event_id=reservation.id,
                cost_usd=Decimal("0.01"),
            )
        )
    await db.flush()

    pdf_rows = []

    def evidence_table(rows, headers):
        pdf_rows.extend(rows)
        return real_evidence_table(rows, headers)

    real_evidence_table = management.evidence_table
    monkeypatch.setattr(management, "evidence_table", evidence_table)
    owner = await db.get(User, test_api_key.user_id)
    owner.role = "owner"
    app = FastAPI()
    app.include_router(management.router)
    app.dependency_overrides[get_current_user] = lambda: owner
    app.dependency_overrides[get_db] = lambda: db
    query = {"group_by": "team_id"}
    async with AsyncClient(
        transport=ASGITransport(app), base_url="http://test"
    ) as client:
        rows = (await client.get("/billing/breakdown", params=query)).json()["rows"]
        team.name = "Payments EU"
        await db.flush()
        renamed = (await client.get("/billing/breakdown", params=query)).json()
        exported = await client.get("/billing/export", params=query)
        pdf = await client.get("/billing/export", params=query | {"format": "pdf"})
        by_model = (await client.get("/billing/breakdown")).json()["rows"]

    assert {row["key"]: row["label"] for row in rows} == {
        str(team.id): "Payments",
        str(foreign.id): None,
        "unassigned": None,
    }
    assert {row["key"]: row["label"] for row in renamed["rows"]}[
        str(team.id)
    ] == "Payments EU"
    reader = csv.reader(io.StringIO(exported.content.decode("utf-8-sig")))
    header, *lines = list(reader)
    assert header[-1] == "label"
    assert {line[0]: line[-1] for line in lines} == {
        str(team.id): "Payments EU",
        str(foreign.id): "",
        "unassigned": "",
    }
    assert pdf.status_code == 200
    assert {row[0] for row in pdf_rows} == {
        "Payments EU",
        str(foreign.id),
        "unassigned",
    }
    assert [row["label"] for row in by_model] == [None]


@pytest.mark.asyncio
async def test_only_organization_admins_change_the_customer_provider_key_policy(
    db, test_user_with_org
):
    owner = test_user_with_org
    owner.role = "owner"
    users = {
        role: User(
            id=uuid4(),
            organization_id=owner.organization_id,
            email=f"{role}-{uuid4()}@example.com",
            role=role,
            is_active=True,
            is_verified=True,
        )
        for role in ("admin", "member", "auditor")
    }
    db.add_all(users.values())
    await db.flush()
    path = "/settings/provider-keys"

    app = FastAPI()
    app.include_router(management.router)
    current = users["member"]
    app.dependency_overrides[get_current_user] = lambda: current
    app.dependency_overrides[get_db] = lambda: db
    async with AsyncClient(
        transport=ASGITransport(app), base_url="http://test"
    ) as client:
        read = await client.get(path)
        refused = {"allow_customer_provider_keys": False}
        denied = {}
        for role in ("member", "auditor"):
            current = users[role]
            denied[role] = (await client.put(path, json=refused)).status_code
        current = users["admin"]
        changed = await client.put(path, json=refused)
        current = owner
        reread = await client.get(path)

    assert read.status_code == 200
    assert read.json() == {"allow_customer_provider_keys": True}
    assert denied == {"member": 403, "auditor": 403}
    assert changed.status_code == 200, changed.text
    assert changed.json() == reread.json() == refused
    organization = await db.get(Organization, owner.organization_id)
    assert organization.allow_customer_provider_keys is False
    events = (
        await db.scalars(
            select(OutboxEvent).where(
                OutboxEvent.organization_id == owner.organization_id
            )
        )
    ).all()
    assert [(event.payload["actor"], event.payload["extra"]) for event in events] == [
        (
            str(users["admin"].id),
            {
                "subject_id": str(owner.organization_id),
                "actor_type": "user_jwt",
                "before": {"allow_customer_provider_keys": True},
                "after": {"allow_customer_provider_keys": False},
            },
        )
    ]
    assert events[0].payload["endpoint"] == "tenant.provider_key_policy_updated"
