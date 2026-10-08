from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from starlette.requests import Request

import shim_enterprise.api.enterprise_deps as enterprise_deps
from shim_enterprise.api.v1 import management
from shim_enterprise.tenants.audit import record_management_action
from shim_enterprise.tenants.models import (
    ApiKey,
    Organization,
    ServiceAccountCredential,
    Team,
    User,
)
from shim_enterprise.tenants.plans import activate_organization_plan
from shim_enterprise.tenants.service import _digest_api_key, authenticate_api_key

MANAGEMENT = "/api/v1/management/api-keys"


def _request(method: str = "GET", path: str = MANAGEMENT) -> Request:
    return Request({"type": "http", "method": method, "path": path, "headers": []})


def _bearer(token: str) -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


async def _owner(session) -> User:
    organization = Organization(id=uuid4(), name="Bank", slug=f"svc-{uuid4().hex}")
    owner = User(
        id=uuid4(),
        organization_id=organization.id,
        email=f"svc-owner-{uuid4().hex}@example.com",
        role="owner",
        is_active=True,
        is_verified=True,
    )
    session.add_all([organization, owner])
    await session.flush()
    await activate_organization_plan(session, organization.id, "enterprise")
    return owner


async def _create(session, owner: User, role: str = "admin", days: int = 30):
    created = await management.create_service_account(
        management.ServiceAccountInput(
            name=f"ci-{role}", role=role, expires_in_days=days
        ),
        owner,
        session,
    )
    return created, await session.get(User, created.id)


async def _resolve(session, token: str, method: str = "GET", path: str = MANAGEMENT):
    return await enterprise_deps.get_current_user(
        _request(method, path), _bearer(token), session
    )


async def _refused(session, token: str) -> HTTPException:
    with pytest.raises(HTTPException) as refused:
        await _resolve(session, token)
    return refused.value


@pytest.mark.asyncio
async def test_a_service_key_authenticates_as_its_service_user(db) -> None:
    owner = await _owner(db)
    created, account = await _create(db, owner)

    resolved = await _resolve(db, created.plaintext)

    assert resolved.id == account.id
    assert (resolved.kind, resolved.role, resolved.is_verified) == (
        "service",
        "admin",
        True,
    )
    assert account.email == f"{account.id}@service-accounts.getshim.tech"
    assert created.plaintext.startswith("sk-shim-svc-")
    assert len(created.plaintext) == len("sk-shim-svc-") + 64
    assert created.prefix == created.plaintext[:20]
    assert created.expires_at - datetime.now(timezone.utc) > timedelta(days=29)


@pytest.mark.parametrize(
    "failure", ["revoked", "expired", "deactivated", "unknown", "malformed"]
)
@pytest.mark.asyncio
async def test_every_failed_service_key_gets_the_same_401(db, failure: str) -> None:
    owner = await _owner(db)
    created, account = await _create(db, owner)
    token = created.plaintext
    if failure == "revoked":
        await management.rotate_service_account(account.id, owner, db)
    elif failure == "expired":
        await db.execute(
            update(ServiceAccountCredential)
            .where(ServiceAccountCredential.user_id == account.id)
            .values(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
        )
    elif failure == "deactivated":
        account.is_active = False
        await db.flush()
    elif failure == "unknown":
        token = "sk-shim-svc-" + "0" * 64
    else:
        token = "sk-shim-svc-"

    refused = await _refused(db, token)

    assert refused.status_code == 401
    assert refused.detail == "Invalid API Key"
    assert refused.headers == {
        "WWW-Authenticate": "Bearer",
        "X-Shim-Error-Code": "INVALID_API_KEY",
    }


@pytest.mark.asyncio
async def test_gateway_keys_and_service_keys_stay_on_their_own_side(
    db, test_api_key, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner = await _owner(db)
    created, account = await _create(db, owner)
    monkeypatch.setattr(
        enterprise_deps.jwt_verifier, "verify", AsyncMock(return_value=None)
    )

    with pytest.raises(HTTPException) as gateway_key:
        await _resolve(db, "sk-shim-architecture-test")
    assert gateway_key.value.status_code == 401
    # Even a gateway-key row with the service key's digest does not authenticate it.
    db.add(
        ApiKey(
            user_id=account.id,
            organization_id=account.organization_id,
            key_hash=_digest_api_key(created.plaintext),
            prefix="sk-shim-svc-0000",
            name="digest collision",
            tier="enterprise",
            is_active=True,
        )
    )
    await db.flush()
    assert await authenticate_api_key(db, created.plaintext) is None


@pytest.mark.asyncio
async def test_last_use_is_written_at_most_once_a_minute(db) -> None:
    owner = await _owner(db)
    created, account = await _create(db, owner)

    async def last_used() -> datetime | None:
        return await db.scalar(
            select(ServiceAccountCredential.last_used_at)
            .where(ServiceAccountCredential.user_id == account.id)
            .execution_options(populate_existing=True)
        )

    await _resolve(db, created.plaintext)
    first = await last_used()
    await _resolve(db, created.plaintext)
    assert first is not None and await last_used() == first
    stale = datetime.now(timezone.utc) - timedelta(minutes=2)
    await db.execute(
        update(ServiceAccountCredential)
        .where(ServiceAccountCredential.user_id == account.id)
        .values(last_used_at=stale)
    )
    await _resolve(db, created.plaintext)
    assert await last_used() > stale


@pytest.mark.asyncio
async def test_service_accounts_cannot_take_human_powers(db) -> None:
    owner = await _owner(db)
    created, admin = await _create(db, owner)
    auditor_created, auditor = await _create(db, owner, "auditor")

    with pytest.raises(HTTPException) as manage:
        await enterprise_deps.get_org_owner(admin)
    assert manage.value.status_code == 403
    for call in (
        management.update_team_member(
            admin.id, management.TeamRolePatch(role="owner"), owner, db
        ),
        management.remove_team_member(admin.id, owner, db),
    ):
        with pytest.raises(HTTPException) as hidden:
            await call
        assert hidden.value.status_code == 404
    with pytest.raises(HTTPException) as listing:
        await management.list_service_accounts(admin, db)
    assert listing.value.status_code == 403
    members = await management.list_team_members(owner, db)
    assert {member.id for member in members} == {owner.id}
    with pytest.raises(HTTPException) as read_only:
        await _resolve(
            db, auditor_created.plaintext, "PUT", "/api/v1/management/settings/pii"
        )
    assert read_only.value.status_code == 403
    assert (await _resolve(db, auditor_created.plaintext)).id == auditor.id

    key = await management.create_api_key(
        management.ApiKeyInput(name="pipeline"), admin, db
    )
    assert (await db.get(ApiKey, key.id)).user_id == admin.id


@pytest.mark.asyncio
async def test_oidc_mode_takes_service_keys_without_origin_but_never_on_invites(
    db, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner = await _owner(db)
    created, account = await _create(db, owner)
    monkeypatch.setattr(enterprise_deps.settings, "AUTH_MODE", "oidc")

    assert (await _resolve(db, created.plaintext, "POST")).id == account.id
    with pytest.raises(HTTPException) as invites:
        await _resolve(db, created.plaintext, "POST", "/api/v1/management/team/invites")
    assert invites.value.status_code == 403


@pytest.mark.asyncio
async def test_a_service_account_cannot_accept_an_invitation(db) -> None:
    owner = await _owner(db)
    _, account = await _create(db, owner)
    other = await _owner(db)
    invite = await management.create_team_invite(
        management.TeamInviteInput(email=account.email, role="admin"), other, db
    )

    with pytest.raises(HTTPException) as refused:
        await management.accept_team_invite(
            management.AcceptTeamInvite(token=invite.token), account, db
        )

    assert refused.value.status_code == 403
    assert refused.value.detail == "Service accounts cannot accept invitations"


@pytest.mark.asyncio
async def test_service_account_lifecycle_is_audited_with_its_actor_type(
    db, audit_events
) -> None:
    owner = await _owner(db)
    created, account = await _create(db, owner)
    await management.create_api_key(
        management.ApiKeyInput(name="pipeline"), account, db
    )

    listed = await management.list_service_accounts(owner, db)
    assert [item.model_dump() for item in listed] == [
        created.model_dump(exclude={"plaintext"})
    ]
    assert "plaintext" not in listed[0].model_dump()
    rotated = await management.rotate_service_account(account.id, owner, db)
    assert rotated.expires_at == created.expires_at
    assert rotated.prefix != created.prefix
    assert (await _refused(db, created.plaintext)).status_code == 401
    assert (await _resolve(db, rotated.plaintext)).id == account.id
    await management.delete_service_account(account.id, owner, db)
    assert (await _refused(db, rotated.plaintext)).status_code == 401
    assert await management.list_service_accounts(owner, db) == []
    assert not (await db.get(User, account.id)).is_active
    with pytest.raises(HTTPException) as gone:
        await management.rotate_service_account(account.id, owner, db)
    assert gone.value.status_code == 404

    events = await audit_events(owner.organization_id)
    actions = [
        (event["endpoint"], event["actor"], event["extra"]["actor_type"])
        for event in events
        if event["endpoint"].startswith(("tenant.service_account", "tenant.api_key"))
    ]
    assert actions == [
        ("tenant.service_account_created", str(owner.id), "user_jwt"),
        ("tenant.api_key_created", str(account.id), "service"),
        ("tenant.service_account_rotated", str(owner.id), "user_jwt"),
        ("tenant.service_account_deleted", str(owner.id), "user_jwt"),
    ]
    created_event = next(
        event
        for event in events
        if event["endpoint"] == "tenant.service_account_created"
    )
    assert created_event["extra"]["after"] == {
        "name": "ci-admin",
        "role": "admin",
        "expires_at": created.expires_at.isoformat(),
    }
    assert created.plaintext not in str(events)


@pytest.mark.asyncio
async def test_an_expired_service_account_cannot_be_rotated(db) -> None:
    owner = await _owner(db)
    _, account = await _create(db, owner)
    await db.execute(
        update(ServiceAccountCredential)
        .where(ServiceAccountCredential.user_id == account.id)
        .values(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    )

    with pytest.raises(HTTPException) as refused:
        await management.rotate_service_account(account.id, owner, db)

    assert refused.value.status_code == 409
    assert "create a new service account" in refused.value.detail
    assert (
        await db.scalar(
            select(func.count(ServiceAccountCredential.id)).where(
                ServiceAccountCredential.user_id == account.id,
                ServiceAccountCredential.revoked_at.is_(None),
            )
        )
        == 1
    )


@pytest.mark.asyncio
async def test_an_admin_service_account_cannot_change_memberships_or_invite(
    db,
) -> None:
    owner = await _owner(db)
    _, admin = await _create(db, owner)
    member = User(
        id=uuid4(),
        organization_id=owner.organization_id,
        email=f"svc-member-{uuid4().hex}@example.com",
        role="member",
        is_active=True,
        is_verified=True,
    )
    team = Team(organization_id=owner.organization_id, name="platform")
    db.add_all([member, team])
    await db.flush()
    await management.set_membership(
        team.id, member.id, management.MembershipInput(), owner, db
    )

    for call in (
        management.set_membership(
            team.id, member.id, management.MembershipInput(role="team_admin"), admin, db
        ),
        management.remove_membership(team.id, member.id, admin, db),
        management.remove_team_member(member.id, admin, db),
        management.create_team_invite(
            management.TeamInviteInput(email="new@example.com", role="member"),
            admin,
            db,
        ),
    ):
        with pytest.raises(HTTPException) as refused:
            await call
        assert refused.value.status_code == 403
    assert (await db.get(User, member.id)).is_active


@pytest.mark.asyncio
async def test_details_cannot_overwrite_the_audit_actor_type(db, audit_events) -> None:
    owner = await _owner(db)
    _, account = await _create(db, owner)

    await record_management_action(
        db, account, "tenant.test", "subject", details={"actor_type": "user_jwt"}
    )

    assert (await audit_events(owner.organization_id))[-1]["extra"][
        "actor_type"
    ] == "service"


@pytest.mark.asyncio
async def test_the_database_refuses_a_service_owner(db) -> None:
    owner = await _owner(db)
    _, account = await _create(db, owner)

    with pytest.raises(IntegrityError, match="ck_users_service_role"):
        async with db.begin_nested():
            await db.execute(
                update(User).where(User.id == account.id).values(role="owner")
            )
    with pytest.raises(IntegrityError, match="ck_users_kind"):
        async with db.begin_nested():
            await db.execute(update(User).where(User.id == owner.id).values(kind="bot"))
