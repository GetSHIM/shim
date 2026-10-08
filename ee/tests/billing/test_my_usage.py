from datetime import datetime, timedelta, timezone
from decimal import Decimal
from uuid import uuid4

import pytest
from fastapi import HTTPException

from shim.gateway.contracts.ids import TenantId
from shim_enterprise.api.v1 import management
from shim_enterprise.billing.models import RequestLifecycle, UsageLedger
from shim_enterprise.billing.read_models import BillingReadModels
from shim_enterprise.tenants.models import (
    ApiKey,
    Organization,
    Team,
    TeamMembership,
    User,
)


async def _tenant(db) -> Organization:
    organization = Organization(id=uuid4(), name="Usage", slug=f"usage-{uuid4()}")
    db.add(organization)
    await db.flush()
    return organization


async def _user(db, organization: Organization, role: str = "member") -> User:
    user = User(
        id=uuid4(),
        organization_id=organization.id,
        email=f"usage-{uuid4().hex}@example.com",
        role=role,
        is_active=True,
        is_verified=True,
    )
    db.add(user)
    await db.flush()
    return user


async def _key(db, owner: User, team: Team | None = None) -> ApiKey:
    key = ApiKey(
        id=uuid4(),
        organization_id=owner.organization_id,
        user_id=owner.id,
        team_id=team.id if team else None,
        key_hash=uuid4().hex,
        prefix=f"sk-shim-{uuid4().hex[:8]}",
        name=f"key-{uuid4().hex[:6]}",
        tier="free",
        is_active=True,
    )
    db.add(key)
    await db.flush()
    return key


async def _settle(
    db, key: ApiKey, *, tokens: int, cost: str, unpriced: bool = False
) -> None:
    request_id = f"req_usage_{uuid4().hex}"
    now = datetime.now(timezone.utc)
    common = {
        "request_id": request_id,
        "organization_id": key.organization_id,
        "api_key_id": key.id,
        "requested_model": "gpt-5-mini",
        "created_at": now,
    }
    db.add(
        RequestLifecycle(
            request_id=request_id,
            organization_id=key.organization_id,
            actor_type="api_key",
            api_key_id=key.id,
            source_endpoint="chat.completions",
            status="completed",
            provider="openai",
            provider_model="gpt-5-mini",
            requested_model="gpt-5-mini",
            stream=False,
            started_at=now,
            completed_at=now,
            reconciled_at=now,
            lifecycle_metadata={},
        )
    )
    quota = UsageLedger(
        **common,
        event_type="quota_reservation",
        idempotency_key=f"{request_id}:quota:reservation",
    )
    spend = UsageLedger(
        **common,
        provider="openai",
        provider_model="gpt-5-mini",
        event_type="spend_reservation",
        idempotency_key=f"{request_id}:spend:reservation",
        cost_usd=Decimal(cost),
    )
    db.add_all([quota, spend])
    await db.flush()
    db.add_all(
        [
            UsageLedger(
                **common,
                event_type="quota_settlement",
                idempotency_key=f"{request_id}:quota:settlement",
                reservation_event_id=quota.id,
                request_count=1,
                prompt_tokens=tokens,
                completion_tokens=1,
                total_tokens=tokens + 1,
            ),
            UsageLedger(
                **common,
                provider="openai",
                provider_model="gpt-5-mini",
                event_type="spend_settlement",
                idempotency_key=f"{request_id}:spend:settlement",
                reservation_event_id=spend.id,
                cost_usd=Decimal(cost),
                event_metadata=(
                    {"pricing": {"pricing_resolution": "unknown"}} if unpriced else {}
                ),
            ),
        ]
    )
    await db.flush()


async def _mine(db, user: User) -> management.MyUsageView:
    return await management.my_usage(None, None, user, db)


@pytest.mark.asyncio
async def test_usage_mine_covers_own_and_administered_keys_only(db) -> None:
    organization = await _tenant(db)
    owner = await _user(db, organization, "owner")
    member = await _user(db, organization)
    team_admin = await _user(db, organization)
    keyless = await _user(db, organization)
    other = await _user(db, organization)
    team = Team(organization_id=organization.id, name="risk")
    db.add(team)
    await db.flush()
    db.add(
        TeamMembership(
            organization_id=organization.id,
            team_id=team.id,
            user_id=team_admin.id,
            role="team_admin",
        )
    )
    member_key = await _key(db, member, team)
    owner_key = await _key(db, owner)
    other_key = await _key(db, other)
    for _ in range(3):
        await _settle(db, member_key, tokens=10, cost="0.25")
    for key in (owner_key, owner_key, other_key):
        await _settle(db, key, tokens=7, cost="0.5")

    member_usage = await _mine(db, member)
    assert member_usage.totals.model_dump() == {
        "requests": 3,
        "input_tokens": 30,
        "output_tokens": 3,
        "cost_usd": Decimal("0.75"),
        "cost_complete": True,
        "unpriced_requests": 0,
    }
    assert [
        (row.api_key_id, row.name, row.prefix, row.requests)
        for row in member_usage.by_api_key
    ] == [(member_key.id, member_key.name, member_key.prefix, 3)]
    assert [(row.model, row.requests) for row in member_usage.by_model] == [
        ("gpt-5-mini", 3)
    ]
    assert [(day.date, day.requests) for day in member_usage.daily] == [
        (datetime.now(timezone.utc).date(), 3)
    ]
    assert (await _mine(db, team_admin)).totals == member_usage.totals
    owner_usage = await _mine(db, owner)
    assert owner_usage.totals.requests == 2
    assert [row.api_key_id for row in owner_usage.by_api_key] == [owner_key.id]
    nothing = await _mine(db, keyless)
    assert nothing.totals.model_dump() == {
        "requests": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "cost_usd": Decimal("0"),
        "cost_complete": True,
        "unpriced_requests": 0,
    }
    assert (nothing.daily, nothing.by_model, nothing.by_api_key) == ([], [], [])


@pytest.mark.asyncio
async def test_usage_mine_follows_billing_cost_semantics(db) -> None:
    organization = await _tenant(db)
    owner = await _user(db, organization, "owner")
    priced, unpriced = await _key(db, owner), await _key(db, owner)
    await _settle(db, priced, tokens=10, cost="0.25")
    await _settle(db, unpriced, tokens=5, cost="0", unpriced=True)

    usage = await _mine(db, owner)
    billing = await BillingReadModels().breakdown(
        db,
        tenant_id=TenantId(organization.id),
        start_at=usage.period.start,
        end_at=usage.period.end,
        group_by="model",
        limit=None,
    )

    assert (usage.totals.cost_usd, usage.totals.cost_complete) == (None, False)
    assert usage.totals.unpriced_requests == 1
    assert [
        (row.requests, row.input_tokens, row.output_tokens, row.unpriced_requests)
        for row in usage.by_model
    ] == [
        (r.request_count, r.prompt_tokens, r.completion_tokens, r.unpriced_requests)
        for r in billing
    ]
    by_key = {
        row.api_key_id: (row.cost_usd, row.cost_complete) for row in usage.by_api_key
    }
    assert by_key == {
        priced.id: (Decimal("0.25"), True),
        unpriced.id: (None, False),
    }
    assert [(day.cost_usd, day.cost_complete) for day in usage.daily] == [(None, False)]


@pytest.mark.asyncio
async def test_usage_mine_window_defaults_to_this_month_and_is_bounded(db) -> None:
    organization = await _tenant(db)
    member = await _user(db, organization)
    now = datetime.now(timezone.utc)

    usage = await _mine(db, member)

    assert usage.period.start == now.replace(
        day=1, hour=0, minute=0, second=0, microsecond=0
    )
    assert usage.period.end >= now
    for start, end in (
        (now, now - timedelta(seconds=1)),
        (now - timedelta(days=31, seconds=1), now),
    ):
        with pytest.raises(HTTPException) as refused:
            await management.my_usage(start, end, member, db)
        assert refused.value.status_code == 422
    assert (
        await management.my_usage(now - timedelta(days=31), now, member, db)
    ).totals.requests == 0
