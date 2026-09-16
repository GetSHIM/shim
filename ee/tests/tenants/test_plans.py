from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.dialects import postgresql

from shim_enterprise.api.v1 import management
from shim_enterprise.billing.models import QuotaPeriodUsage, UsageLedger
from shim_enterprise.tenants.models import (
    BillingWebhookReceipt,
    Organization,
    OrganizationPIIConfig,
    User,
)
from shim_enterprise.tenants.plans import (
    OrganizationPlan,
    _plan,
    activate_organization_plan,
    configure_organization_quota,
    create_organization_plan,
)
from shim_enterprise.tenants.service import (
    authenticate_api_key,
    create_api_key,
    ensure_privacy_defaults,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("target_tier", ["free", "managed", "agency", "enterprise"])
async def test_operator_transition_preserves_access_accounting_and_history(
    db, test_org, test_user_with_org, target_tier: str
) -> None:
    plaintext, api_key = await create_api_key(
        db, user_id=test_user_with_org.id, name="Existing key"
    )
    _, revoked_key = await create_api_key(
        db, user_id=test_user_with_org.id, name="Revoked key"
    )
    revoked_key.is_active = False
    test_org.tier = api_key.tier = "managed"
    test_org.billing_status = "active"
    test_org.billing_source = "lemonsqueezy"
    legacy = {
        "external_customer_id": f"customer-{uuid4()}",
        "external_subscription_id": f"subscription-{uuid4()}",
        "billing_variant_id": "legacy-variant",
        "current_period_end": datetime(2026, 9, 1, tzinfo=timezone.utc),
        "cancel_at_period_end": True,
        "customer_portal_url": "https://example.test/historical-portal",
    }
    for name, value in legacy.items():
        setattr(test_org, name, value)
    receipt = BillingWebhookReceipt(
        organization_id=test_org.id,
        payload_digest=uuid4().hex,
        event_name="subscription_created",
        external_subscription_id=test_org.external_subscription_id,
        event_at=datetime.now(timezone.utc),
    )
    ledger = UsageLedger(
        organization_id=test_org.id,
        api_key_id=api_key.id,
        request_id=f"test-{uuid4()}",
        requested_model="gpt-4o-mini",
        event_type="adjustment_credit",
        idempotency_key=f"test-{uuid4()}",
        cost_usd=Decimal("1.25"),
    )
    quota = QuotaPeriodUsage(
        organization_id=test_org.id,
        api_key_id=api_key.id,
        period_type="monthly",
        period_start=date(2026, 9, 1),
        period_end=date(2026, 10, 1),
        settled_requests=7,
        settled_tokens=900,
        reserved_requests=1,
        reserved_tokens=100,
    )
    other_org = Organization(name="Other tenant", slug=f"other-{uuid4()}")
    db.add_all([receipt, ledger, quota, other_org])
    await db.flush()

    await activate_organization_plan(db, test_org.id, target_tier)
    await db.commit()
    for row in (test_org, api_key, revoked_key, receipt, ledger, quota, other_org):
        await db.refresh(row)

    assert test_org.tier == api_key.tier == target_tier
    assert test_org.billing_status == ("free" if target_tier == "free" else "active")
    assert test_org.billing_source == "operator"
    assert await authenticate_api_key(db, plaintext) is api_key
    assert revoked_key.is_active is False and revoked_key.tier == "free"
    assert other_org.tier == "free"
    assert {name: getattr(test_org, name) for name in legacy} == legacy
    assert receipt.external_subscription_id == legacy["external_subscription_id"]
    assert ledger.cost_usd == Decimal("1.25")
    assert (quota.settled_requests, quota.settled_tokens) == (7, 900)
    assert (quota.reserved_requests, quota.reserved_tokens) == (1, 100)
    _, new_key = await create_api_key(db, user_id=test_user_with_org.id, name="New key")
    assert new_key.tier == target_tier
    view = await management.get_subscription(test_user_with_org, db)
    assert view.plan == target_tier
    assert set(view.model_dump()) == {"plan", "status", "source", "entitlements"}


@pytest.mark.asyncio
async def test_new_customer_provisioning_and_invalid_plan(db, test_org) -> None:
    with pytest.raises(ValueError, match="Unknown tier"):
        await activate_organization_plan(db, test_org.id, "missing-tier")
    assert test_org.tier == "free"
    with pytest.raises(ValueError, match="Organization not found"):
        await activate_organization_plan(db, uuid4(), "enterprise")
    with pytest.raises(ValueError, match="Organization name"):
        await create_organization_plan(db, " ", "enterprise")

    created = await create_organization_plan(db, " Pilot bank ", "enterprise")
    await db.commit()
    assert created.name == "Pilot bank" and created.tier == "enterprise"
    assert created.billing_source == "operator"
    assert (
        await db.scalar(select(User.id).where(User.organization_id == created.id))
        is None
    )
    assert (
        await db.scalar(
            select(OrganizationPIIConfig.id).where(
                OrganizationPIIConfig.organization_id == created.id
            )
        )
        is not None
    )
    other = await create_organization_plan(db, "Pilot bank", "free")
    assert other.id != created.id
    assert created.tier == "enterprise"


@pytest.mark.asyncio
async def test_invite_acceptance_moves_only_an_empty_verified_bootstrap(
    db,
    test_org,
    test_user_with_org,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    test_user_with_org.role = "owner"
    await activate_organization_plan(db, test_org.id, "agency")
    target_id = uuid4()
    temporary_org = Organization(
        id=uuid4(),
        name="Temporary",
        slug=f"temporary-{target_id}",
    )
    invited = User(
        id=target_id,
        organization_id=temporary_org.id,
        email=f"invited-{target_id}@example.com",
        role="owner",
        is_active=True,
        is_verified=True,
    )
    db.add_all([temporary_org, invited])
    await db.flush()
    await ensure_privacy_defaults(db, temporary_org.id)
    monkeypatch.setattr(management, "_audit", AsyncMock())

    created = await management.create_team_invite(
        management.TeamInviteInput(email=invited.email, role="member"),
        test_user_with_org,
        db,
    )
    receipt = BillingWebhookReceipt(
        organization_id=temporary_org.id,
        payload_digest=uuid4().hex,
        event_name="subscription_created",
        event_at=datetime.now(timezone.utc),
    )
    db.add(receipt)
    await db.flush()
    with pytest.raises(management.HTTPException, match="Leave or empty"):
        await management.accept_team_invite(
            management.AcceptTeamInvite(token=created.token),
            invited,
            db,
        )
    assert await db.get(Organization, temporary_org.id) is not None
    await db.delete(receipt)
    await db.flush()

    accepted = await management.accept_team_invite(
        management.AcceptTeamInvite(token=created.token),
        invited,
        db,
    )

    assert accepted.organization_id == test_org.id
    assert accepted.role == "member"
    assert await db.get(Organization, temporary_org.id) is None
    with pytest.raises(management.HTTPException, match="invalid or expired"):
        await management.accept_team_invite(
            management.AcceptTeamInvite(token=created.token),
            invited,
            db,
        )


@pytest.mark.asyncio
async def test_invite_acceptance_locks_destination_before_revalidating_invite(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_id = uuid4()
    destination_id = uuid4()
    user = SimpleNamespace(
        id=uuid4(),
        organization_id=source_id,
        email="invited@example.com",
        is_verified=True,
    )
    invite = SimpleNamespace(
        id=uuid4(),
        organization_id=destination_id,
        email=user.email,
        role="member",
        accepted_at=None,
        revoked_at=None,
        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
    )
    session = SimpleNamespace(
        scalar=AsyncMock(return_value=destination_id),
        execute=AsyncMock(
            side_effect=[
                SimpleNamespace(),
                SimpleNamespace(scalar_one_or_none=lambda: invite),
            ]
        ),
        commit=AsyncMock(),
        refresh=AsyncMock(),
    )
    move = AsyncMock(return_value=user)
    monkeypatch.setattr(management, "_require_entitlement", AsyncMock())
    monkeypatch.setattr(management, "move_user_from_bootstrap", move)
    monkeypatch.setattr(management, "_audit", AsyncMock())

    accepted = await management.accept_team_invite(
        management.AcceptTeamInvite(token="x" * 32),
        user,
        session,
    )

    statements = [call.args[0] for call in session.execute.await_args_list]
    assert "FOR UPDATE OF organizations" in str(
        statements[0].compile(dialect=postgresql.dialect())
    )
    assert "FOR UPDATE OF organization_invites" in str(
        statements[1].compile(dialect=postgresql.dialect())
    )
    assert accepted is user
    move.assert_awaited_once_with(
        session,
        user_id=user.id,
        source_organization_id=source_id,
        destination_organization_id=destination_id,
        role="member",
    )


@pytest.mark.asyncio
async def test_last_owner_cannot_be_removed(db, test_org, test_user_with_org) -> None:
    test_user_with_org.role = "owner"
    with pytest.raises(management.HTTPException, match="needs an owner"):
        await management._protect_last_owner(db, test_org.id)


@pytest.mark.asyncio
async def test_free_plan_cannot_add_team_members(
    db,
    test_user_with_org,
) -> None:
    test_user_with_org.role = "owner"
    with pytest.raises(management.HTTPException, match="Plan upgrade"):
        await management.create_team_invite(
            management.TeamInviteInput(email="new-member@example.com"),
            test_user_with_org,
            db,
        )


def test_organization_plan_maps_organization_columns_in_field_order() -> None:
    organization = SimpleNamespace(
        id=uuid4(),
        tier="agency",
        billing_source="operator",
        billing_status="active",
        external_customer_id="customer-1",
        external_subscription_id="subscription-1",
        current_period_end=datetime(2026, 9, 1, tzinfo=timezone.utc),
        cancel_at_period_end=True,
        billing_revision=7,
    )

    assert _plan(organization) == OrganizationPlan(
        organization_id=organization.id,
        tier="agency",
        source="operator",
        status="active",
        customer_id="customer-1",
        subscription_id="subscription-1",
        current_period_end=organization.current_period_end,
        cancel_at_period_end=True,
        revision=7,
    )


def _organization(organization_id: UUID, **overrides) -> SimpleNamespace:
    fields: dict[str, object] = {
        "id": organization_id,
        "tier": "free",
        "quota_monthly_request_limit": None,
        "quota_monthly_token_limit": None,
    }
    fields.update(overrides)
    return SimpleNamespace(**fields)


def _tier(request_limit: int, token_limit: int) -> SimpleNamespace:
    return SimpleNamespace(
        monthly_request_limit=request_limit, monthly_token_limit=token_limit
    )


def _session_get(
    organization: SimpleNamespace | None = None,
    tiers: list[SimpleNamespace] | None = None,
) -> AsyncMock:
    """Answer ``session.get`` by what is fetched, not by call order."""
    pending_tiers = list(tiers or [])

    async def get(model, *_args, **_kwargs):
        if model is Organization:
            return organization
        return pending_tiers.pop(0)

    return AsyncMock(side_effect=get)


@pytest.mark.asyncio
async def test_quota_configuration_keeps_its_errors_for_missing_rows() -> None:
    organization_id = uuid4()
    session = SimpleNamespace(
        get=AsyncMock(
            side_effect=[
                None,
                _organization(organization_id, tier="gone"),
                None,
            ]
        ),
        scalar=AsyncMock(),
        flush=AsyncMock(),
    )

    with pytest.raises(ValueError, match="Organization not found"):
        await configure_organization_quota(session, organization_id)
    with pytest.raises(ValueError, match="Organization tier does not exist"):
        await configure_organization_quota(session, organization_id)

    session.scalar.assert_not_awaited()
    session.flush.assert_not_awaited()


@pytest.mark.asyncio
async def test_quota_configuration_skips_the_row_lock_in_the_steady_state() -> None:
    organization_id = uuid4()
    session = SimpleNamespace(
        get=_session_get(
            organization=_organization(
                organization_id,
                quota_monthly_request_limit=1000,
                quota_monthly_token_limit=1_000_000,
            ),
            tiers=[_tier(1000, 1_000_000)],
        ),
        scalar=AsyncMock(),
        flush=AsyncMock(),
    )

    await configure_organization_quota(session, organization_id)

    session.scalar.assert_not_awaited()
    session.flush.assert_not_awaited()


@pytest.mark.asyncio
async def test_quota_configuration_locks_and_rereads_the_tier_on_drift() -> None:
    organization_id = uuid4()
    locked = _organization(organization_id, tier="agency")
    session = SimpleNamespace(
        get=_session_get(
            organization=_organization(organization_id, tier="managed"),
            tiers=[_tier(5000, 5_000_000), _tier(50000, 50_000_000)],
        ),
        scalar=AsyncMock(return_value=locked),
        flush=AsyncMock(),
    )

    await configure_organization_quota(session, organization_id)

    statement = session.scalar.await_args_list[0].args[0]
    assert "FOR UPDATE OF organizations" in str(
        statement.compile(dialect=postgresql.dialect())
    )
    assert session.get.await_args_list[-1].kwargs == {"populate_existing": True}
    assert (locked.quota_monthly_request_limit, locked.quota_monthly_token_limit) == (
        50000,
        50_000_000,
    )
    session.flush.assert_awaited_once()
