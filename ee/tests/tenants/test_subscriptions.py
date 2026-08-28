from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import pytest
from sqlalchemy.dialects import postgresql

from shim_enterprise.api.v1 import management
from shim_enterprise.tenants import subscriptions
from shim_enterprise.tenants.models import BillingWebhookReceipt, Organization, User
from shim_enterprise.tenants.service import create_api_key, ensure_privacy_defaults
from shim_enterprise.tenants.subscriptions import (
    checkout_urls,
    process_lemonsqueezy_webhook,
    set_organization_tier,
    verify_lemonsqueezy_signature,
)


def _event(
    organization_id,
    user_id,
    *,
    event_name: str,
    status: str,
    updated_at: str,
    variant_id: str = "managed-variant",
) -> bytes:
    return json.dumps(
        {
            "meta": {
                "event_name": event_name,
                "custom_data": {
                    "organization_id": str(organization_id),
                    "user_id": str(user_id),
                    "checkout_signature": subscriptions._checkout_signature(
                        organization_id,
                        user_id,
                    ),
                },
            },
            "data": {
                "id": "subscription-123",
                "attributes": {
                    "customer_id": "customer-123",
                    "variant_id": variant_id,
                    "status": status,
                    "updated_at": updated_at,
                    "renews_at": "2026-09-01T00:00:00Z",
                    "urls": {
                        "customer_portal": (
                            "https://app.lemonsqueezy.com/my-orders/example"
                        )
                    },
                },
            },
        },
        separators=(",", ":"),
    ).encode()


def test_webhook_signature_is_timing_safe() -> None:
    payload = b"signed"
    secret = "test-signing-secret"
    signature = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

    assert verify_lemonsqueezy_signature(payload, signature, secret)
    assert not verify_lemonsqueezy_signature(payload, "invalid", secret)


@pytest.mark.asyncio
async def test_plan_changes_propagate_and_webhooks_are_ordered(
    db,
    test_org,
    test_user_with_org,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    test_user_with_org.role = "owner"
    monkeypatch.setattr(
        "shim_enterprise.tenants.subscriptions.settings.LEMON_SQUEEZY_SOLO_PRO_MONTHLY_VARIANT_ID",
        "managed-variant",
    )
    monkeypatch.setattr(
        "shim_enterprise.tenants.subscriptions.settings.LEMON_SQUEEZY_AGENCY_YEARLY_VARIANT_ID",
        "agency-variant",
    )
    plaintext, api_key = await create_api_key(
        db,
        user_id=test_user_with_org.id,
        name="Inherited plan",
    )
    assert plaintext.startswith("sk-shim-")
    assert api_key.tier == "free"

    created = _event(
        test_org.id,
        test_user_with_org.id,
        event_name="subscription_created",
        status="active",
        updated_at="2026-08-01T12:00:00Z",
    )
    assert await process_lemonsqueezy_webhook(db, created) == "processed"
    assert await process_lemonsqueezy_webhook(db, created) == "duplicate"
    await db.refresh(test_org)
    await db.refresh(api_key)
    assert test_org.tier == "managed"
    assert api_key.tier == "managed"

    agency = _event(
        test_org.id,
        test_user_with_org.id,
        event_name="subscription_updated",
        status="active",
        updated_at="2026-08-01T13:00:00Z",
        variant_id="agency-variant",
    )
    assert await process_lemonsqueezy_webhook(db, agency) == "processed"
    await db.refresh(test_org)
    await db.refresh(api_key)
    assert test_org.tier == "agency"
    assert api_key.tier == "agency"

    expired = _event(
        test_org.id,
        test_user_with_org.id,
        event_name="subscription_expired",
        status="expired",
        updated_at="2026-08-02T12:00:00Z",
    )
    assert await process_lemonsqueezy_webhook(db, expired) == "processed"
    stale_active = _event(
        test_org.id,
        test_user_with_org.id,
        event_name="subscription_updated",
        status="active",
        updated_at="2026-08-01T14:00:00Z",
    )
    assert await process_lemonsqueezy_webhook(db, stale_active) == "stale"
    await db.refresh(test_org)
    await db.refresh(api_key)
    assert test_org.tier == "free"
    assert api_key.tier == "free"


@pytest.mark.asyncio
async def test_checkout_identity_cannot_be_redirected_to_another_tenant(
    db,
    test_org,
    test_user_with_org,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    test_user_with_org.role = "owner"
    victim = Organization(
        id=uuid4(),
        name="Victim",
        slug=f"victim-{uuid4().hex}",
    )
    db.add(victim)
    await db.flush()
    monkeypatch.setattr(
        "shim_enterprise.tenants.subscriptions.settings.LEMON_SQUEEZY_SOLO_PRO_MONTHLY_CHECKOUT_URL",
        "https://getshim.lemonsqueezy.com/buy/solo",
    )
    monkeypatch.setattr(
        "shim_enterprise.tenants.subscriptions.settings.LEMON_SQUEEZY_SOLO_PRO_MONTHLY_VARIANT_ID",
        "managed-variant",
    )
    url = checkout_urls(test_org.id, test_user_with_org.id)["managed"]["monthly"]
    custom_data = {
        key.removeprefix("checkout[custom][").removesuffix("]"): values[-1]
        for key, values in parse_qs(urlsplit(url).query).items()
        if key.startswith("checkout[custom][")
    }

    forged = json.loads(
        _event(
            test_org.id,
            test_user_with_org.id,
            event_name="subscription_created",
            status="active",
            updated_at="2026-08-01T12:00:00Z",
        )
    )
    forged["meta"]["custom_data"] = {
        **custom_data,
        "organization_id": str(victim.id),
    }
    forged_body = json.dumps(forged, separators=(",", ":")).encode()

    with pytest.raises(ValueError, match="Invalid checkout identity"):
        await process_lemonsqueezy_webhook(db, forged_body)
    assert victim.tier == "free"

    valid = json.loads(
        _event(
            test_org.id,
            test_user_with_org.id,
            event_name="subscription_created",
            status="active",
            updated_at="2026-08-01T12:00:00Z",
        )
    )
    valid["meta"]["custom_data"] = custom_data
    valid_body = json.dumps(valid, separators=(",", ":")).encode()

    assert await process_lemonsqueezy_webhook(db, valid_body) == "processed"
    await db.refresh(test_org)
    assert test_org.tier == "managed"

    mismatched = json.loads(valid_body)
    mismatched["meta"]["event_name"] = "subscription_updated"
    mismatched["meta"]["custom_data"]["organization_id"] = str(victim.id)
    mismatched["data"]["attributes"]["updated_at"] = "2026-08-01T13:00:00Z"
    with pytest.raises(ValueError, match="Subscription identity mismatch"):
        await process_lemonsqueezy_webhook(
            db,
            json.dumps(mismatched, separators=(",", ":")).encode(),
        )

    established = json.loads(valid_body)
    established["meta"].pop("custom_data")
    established["meta"]["event_name"] = "subscription_updated"
    established["data"]["attributes"]["updated_at"] = "2026-08-01T13:00:00Z"
    assert (
        await process_lemonsqueezy_webhook(
            db,
            json.dumps(established, separators=(",", ":")).encode(),
        )
        == "processed"
    )
    assert victim.tier == "free"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("role", "is_active"),
    [("member", True), ("owner", False)],
)
async def test_new_checkout_requires_an_active_owner(
    db,
    test_org,
    test_user_with_org,
    role: str,
    is_active: bool,
) -> None:
    test_user_with_org.role = role
    test_user_with_org.is_active = is_active
    await db.flush()
    meta = {
        "custom_data": {
            "organization_id": str(test_org.id),
            "user_id": str(test_user_with_org.id),
            "checkout_signature": subscriptions._checkout_signature(
                test_org.id,
                test_user_with_org.id,
            ),
        }
    }

    with pytest.raises(LookupError, match="Organization not found"):
        await subscriptions._webhook_organization(db, meta, "new-subscription")


@pytest.mark.asyncio
async def test_operator_plan_is_inherited_by_new_keys(
    db,
    test_org,
    test_user_with_org,
) -> None:
    await set_organization_tier(
        db,
        test_org,
        "managed",
        status="active",
        source="operator",
    )
    _, api_key = await create_api_key(
        db,
        user_id=test_user_with_org.id,
        name="Managed",
    )
    assert api_key.tier == "managed"


def test_checkout_urls_include_cadence_and_tenant_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization_id = uuid4()
    user_id = uuid4()
    for name in (
        "LEMON_SQUEEZY_SOLO_PRO_MONTHLY_CHECKOUT_URL",
        "LEMON_SQUEEZY_SOLO_PRO_YEARLY_CHECKOUT_URL",
        "LEMON_SQUEEZY_AGENCY_MONTHLY_CHECKOUT_URL",
        "LEMON_SQUEEZY_AGENCY_YEARLY_CHECKOUT_URL",
    ):
        monkeypatch.setattr(
            f"shim_enterprise.tenants.subscriptions.settings.{name}", None
        )
    assert checkout_urls(organization_id, user_id) == {}
    monkeypatch.setattr(
        "shim_enterprise.tenants.subscriptions.settings.LEMON_SQUEEZY_SOLO_PRO_MONTHLY_CHECKOUT_URL",
        "https://getshim.lemonsqueezy.com/buy/solo?discount=launch",
    )
    monkeypatch.setattr(
        "shim_enterprise.tenants.subscriptions.settings.LEMON_SQUEEZY_AGENCY_YEARLY_CHECKOUT_URL",
        "https://getshim.lemonsqueezy.com/buy/agency-yearly",
    )

    urls = checkout_urls(organization_id, user_id)

    assert set(urls) == {"managed", "agency"}
    assert set(urls["managed"]) == {"monthly"}
    assert "discount=launch" in urls["managed"]["monthly"]
    identity = f"lemonsqueezy-checkout:v1:{organization_id}:{user_id}".encode()
    expected_signature = hmac.new(
        subscriptions.settings.SECRET_KEY.encode(),
        identity,
        hashlib.sha256,
    ).hexdigest()
    for plan_urls in urls.values():
        for url in plan_urls.values():
            custom = parse_qs(urlsplit(url).query)
            assert custom["checkout[custom][organization_id]"] == [str(organization_id)]
            assert custom["checkout[custom][user_id]"] == [str(user_id)]
            assert custom["checkout[custom][checkout_signature]"] == [
                expected_signature
            ]


@pytest.mark.asyncio
async def test_only_free_owners_receive_checkout_links(
    db,
    test_org,
    test_user_with_org,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    test_user_with_org.role = "owner"
    configured = {"managed": {"monthly": "https://store.example.test/solo"}}
    monkeypatch.setattr(management, "checkout_urls", lambda *_: configured)

    free = await management.get_subscription(test_user_with_org, db)
    assert free.checkout_urls == configured

    await set_organization_tier(
        db,
        test_org,
        "managed",
        status="active",
        source="lemonsqueezy",
    )
    paid = await management.get_subscription(test_user_with_org, db)
    assert paid.checkout_urls == {}


@pytest.mark.asyncio
async def test_invite_acceptance_moves_only_an_empty_verified_bootstrap(
    db,
    test_org,
    test_user_with_org,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    test_user_with_org.role = "owner"
    await set_organization_tier(
        db,
        test_org,
        "agency",
        status="active",
        source="operator",
    )
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
