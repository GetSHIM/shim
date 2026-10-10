from __future__ import annotations

import hashlib
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import ValidationError
from sqlalchemy import select, text, update

from ee.tests.gateway.api.test_permission_matrix import (
    dependency_calls,
    management_routes,
)
from shim_enterprise.api import enterprise_deps
from shim_enterprise.api.enterprise_deps import (
    get_current_user,
    get_invite_user,
    get_org_admin,
    get_org_owner,
    get_org_reader,
)
from shim_enterprise.api.v1 import management
from shim_enterprise.application import create_enterprise_app
from shim_enterprise.core.database import get_db
from shim_enterprise.gateway.pipeline.quota_reservation import AccountingPolicyLoader
from shim_enterprise.tenants.models import (
    ApiKey,
    Organization,
    OrganizationRole,
    Team,
    TeamMembership,
    User,
)
from shim_enterprise.tenants.permissions import (
    ANY_USER_ROUTES,
    BUILTIN_ROLE_PERMISSIONS,
    KEY_OWNER_ROLES,
    PERMISSIONS,
    RESERVED_PERMISSIONS,
    effective_permissions,
    user_permissions,
)
from shim_enterprise.tenants.service import authenticate_api_key

# The R1 table of internal PRD E31, column by column.
_TABLE = {
    "settings.read": "owner admin member auditor",
    "settings.write": "owner admin",
    "rules.read": "owner admin auditor",
    "rules.write": "owner admin",
    "deployments.read": "owner admin auditor",
    "deployments.manage": "owner admin",
    "providers.manage": "owner admin",
    "budgets.manage": "owner admin",
    "teams.manage": "owner admin",
    "keys.own": "owner admin member",
    "keys.manage": "owner admin",
    "members.read": "owner admin auditor",
    "members.manage": "owner admin",
    "roles.manage": "owner",
    "usage.read": "owner admin auditor",
    "audit.read": "owner admin auditor",
    "compliance.manage": "owner admin",
    "findings.read": "owner admin auditor",
    "findings.manage": "owner admin",
    "plans.create": "owner admin",
    "plans.apply": "owner admin",
    "plans.approve": "owner admin",
    "requests.approve": "owner admin",
    "content.read": "owner admin",
    "config.manage": "owner",
}
_GUARDS = {get_org_admin, get_org_reader, get_org_owner}


def test_built_in_roles_hold_exactly_the_table() -> None:
    assert set(_TABLE) == PERMISSIONS
    for role, granted in BUILTIN_ROLE_PERMISSIONS.items():
        assert granted == {
            permission for permission, roles in _TABLE.items() if role in roles.split()
        }
    assert KEY_OWNER_ROLES == {"owner", "admin", "member"}


def test_an_unknown_role_has_no_permission_and_a_custom_role_replaces_the_set() -> None:
    unknown = User(role="recommender", custom_role_id=None)
    assert effective_permissions(unknown, None) == frozenset()
    member = User(role="member", custom_role_id=uuid4())
    role = OrganizationRole(permissions=["usage.read", "content.read", "made.up"])
    assert effective_permissions(member, role) == {"usage.read"}
    assert effective_permissions(member, None) == frozenset()


@pytest.mark.parametrize("permission", sorted(RESERVED_PERMISSIONS) + ["made.up"])
def test_a_custom_role_cannot_carry_a_reserved_or_unknown_permission(
    permission: str,
) -> None:
    with pytest.raises(ValidationError, match=permission):
        management.CustomRoleInput(
            slug="viewer", name="Viewer", permissions=[permission]
        )


def test_keys_manage_stays_with_owners_and_admins() -> None:
    with pytest.raises(ValidationError, match="keys.manage"):
        management.CustomRoleInput(
            slug="keys", name="Keys", permissions=["keys.own", "keys.manage"]
        )
    stored = OrganizationRole(permissions=["keys.own", "keys.manage"])

    assert effective_permissions(
        User(role="member", custom_role_id=uuid4()), stored
    ) == {"keys.own"}
    assert {
        role
        for role, granted in BUILTIN_ROLE_PERMISSIONS.items()
        if "keys.manage" in granted
    } == {"owner", "admin"}


@pytest.mark.parametrize("slug", ["owner", "a", "Viewer", "1viewer", "v" * 33])
def test_a_custom_role_slug_is_short_lowercase_and_not_built_in(slug: str) -> None:
    with pytest.raises(ValidationError):
        management.CustomRoleInput(slug=slug, name="Viewer", permissions=[])


def unguarded_routes(app: FastAPI) -> list[str]:
    unguarded = []
    for method, path, route in management_routes(app.routes):
        calls = dependency_calls(route)
        authenticated = calls & {get_current_user, get_invite_user}
        guarded = calls & _GUARDS or any(
            getattr(call, "__qualname__", "") == "require.<locals>.guard"
            for call in calls
        )
        if authenticated and not guarded and (method, path) not in ANY_USER_ROUTES:
            unguarded.append(f"{method} {path}")
    return unguarded


def test_every_management_route_asks_for_a_permission_or_is_listed() -> None:
    app = create_enterprise_app()
    assert unguarded_routes(app) == []

    @app.get("/api/v1/management/unguarded-fixture")
    async def fixture(user: User = Depends(get_current_user)) -> None:
        return None

    assert unguarded_routes(app) == ["GET /api/v1/management/unguarded-fixture"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("user", "path", "allowed"),
    [
        (
            SimpleNamespace(role="recommender", custom_role_id=None),
            "/api/v1/management/teams",
            False,
        ),
        (
            SimpleNamespace(role="auditor", custom_role_id=None),
            "/api/v1/compliance/reports/kvkk",
            True,
        ),
        (
            SimpleNamespace(role="member", custom_role_id=None),
            "/api/v1/management/api-keys",
            True,
        ),
    ],
)
async def test_a_role_without_a_write_permission_is_refused_every_write(
    monkeypatch, user, path, allowed
) -> None:
    user.is_active = True
    monkeypatch.setattr(
        enterprise_deps, "get_invite_user", AsyncMock(return_value=user)
    )
    request = Request({"type": "http", "method": "POST", "path": path, "headers": []})
    if allowed:
        assert await get_current_user(request, None, None) is user
        return
    with pytest.raises(HTTPException) as refused:
        await get_current_user(request, None, None)
    assert (refused.value.status_code, refused.value.detail) == (
        403,
        "Auditor access is read-only",
    )


async def _organization(db, tier: str = "enterprise") -> Organization:
    organization = Organization(
        id=uuid4(), name="Roles", slug=f"roles-{uuid4().hex}", tier=tier
    )
    db.add(organization)
    await db.flush()
    return organization


async def _user(db, organization: Organization, role: str, **values) -> User:
    user = User(
        id=uuid4(),
        organization_id=organization.id,
        email=f"roles-{role}-{uuid4().hex}@example.com",
        role=role,
        is_active=True,
        is_verified=True,
        **values,
    )
    db.add(user)
    await db.flush()
    return user


async def _key(db, owner: User) -> str:
    plaintext = f"sk-shim-roles-{uuid4().hex}"
    db.add(
        ApiKey(
            id=uuid4(),
            organization_id=owner.organization_id,
            user_id=owner.id,
            key_hash=hashlib.sha256(plaintext.encode()).hexdigest(),
            prefix=plaintext[:12],
            tier="enterprise",
            is_active=True,
        )
    )
    await db.flush()
    return plaintext


async def _signed_in(
    db, monkeypatch, caller: User, method: str, path: str, **kwargs
) -> httpx.Response:
    monkeypatch.setattr(
        enterprise_deps, "get_invite_user", AsyncMock(return_value=caller)
    )
    app = FastAPI()
    app.include_router(management.router, prefix="/api/v1/management")
    app.dependency_overrides[get_db] = lambda: db
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        return await client.request(method, f"/api/v1/management{path}", **kwargs)


@pytest.mark.asyncio
async def test_a_read_only_custom_role_keeps_its_own_and_team_scoped_writes(
    db, monkeypatch
) -> None:
    organization = await _organization(db)
    empty, reader, keys = (
        OrganizationRole(
            organization_id=organization.id, slug=slug, name=slug, permissions=granted
        )
        for slug, granted in (
            ("empty", []),
            ("reader", ["usage.read"]),
            ("reader-keys", ["usage.read", "keys.own"]),
        )
    )
    team = Team(id=uuid4(), organization_id=organization.id, name="platform")
    db.add_all([empty, reader, keys, team])
    await db.flush()
    nobody = await _user(db, organization, "member", custom_role_id=empty.id)
    team_admin = await _user(db, organization, "member", custom_role_id=reader.id)
    key_holder = await _user(db, organization, "member", custom_role_id=keys.id)
    teammate = await _user(db, organization, "member")
    db.add(
        TeamMembership(
            organization_id=organization.id,
            team_id=team.id,
            user_id=team_admin.id,
            role="team_admin",
        )
    )
    await db.flush()
    await _key(db, team_admin)
    await _key(db, key_holder)
    owned = {
        holder: await db.scalar(select(ApiKey.id).where(ApiKey.user_id == holder.id))
        for holder in (team_admin, key_holder)
    }

    async def call(caller: User, method: str, path: str, **kwargs) -> httpx.Response:
        return await _signed_in(db, monkeypatch, caller, method, path, **kwargs)

    settings = await call(nobody, "PUT", "/settings/pii", json={})
    key = await call(nobody, "POST", "/api-keys", json={"name": "k"})
    profile = await call(nobody, "PUT", "/auth/me", json={"full_name": "Nobody"})
    added = await call(
        team_admin,
        "PUT",
        f"/teams/{team.id}/members/{teammate.id}",
        json={"role": "member"},
    )
    removed = await call(
        team_admin, "DELETE", f"/teams/{team.id}/members/{teammate.id}"
    )
    refused_rotation = await call(
        team_admin, "POST", f"/api-keys/{owned[team_admin]}/rotate"
    )
    rotated = await call(key_holder, "POST", f"/api-keys/{owned[key_holder]}/rotate")

    for refused in (settings, key):
        assert (refused.status_code, refused.json()["detail"]) == (
            403,
            "Auditor access is read-only",
        )
    assert profile.status_code == 200 and profile.json()["full_name"] == "Nobody"
    assert (added.status_code, removed.status_code) == (200, 204)
    assert (refused_rotation.status_code, refused_rotation.json()["detail"]) == (
        403,
        "Organization admin required",
    )
    assert rotated.status_code == 200


@pytest.mark.asyncio
async def test_only_key_owner_roles_authenticate_a_gateway_key(db) -> None:
    organization = await _organization(db)
    await db.execute(text("ALTER TABLE users DROP CONSTRAINT ck_users_role"))
    keys = {
        role: await _key(db, await _user(db, organization, role))
        for role in ("owner", "admin", "member", "auditor", "recommender")
    }

    for role, plaintext in keys.items():
        authenticated = await authenticate_api_key(db, plaintext)
        assert (authenticated is not None) == (role in KEY_OWNER_ROLES), role
        key_id = await db.scalar(
            select(ApiKey.id).where(
                ApiKey.key_hash == hashlib.sha256(plaintext.encode()).hexdigest()
            )
        )
        prepared = SimpleNamespace(
            tenant_id=organization.id, api_key_id=key_id, model="gpt-5-mini"
        )
        if role in KEY_OWNER_ROLES:
            assert await AccountingPolicyLoader().quota(db, prepared) is not None
            continue
        with pytest.raises(HTTPException) as refused:
            await AccountingPolicyLoader().quota(db, prepared)
        assert refused.value.status_code == 401, role


def _app(db, caller: User) -> FastAPI:
    app = FastAPI()
    app.include_router(management.router, prefix="/api/v1/management")
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: caller
    return app


async def _call(db, caller: User, method: str, path: str, **kwargs) -> httpx.Response:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app(db, caller)), base_url="http://test"
    ) as client:
        return await client.request(method, f"/api/v1/management{path}", **kwargs)


@pytest.mark.asyncio
async def test_owners_create_change_and_delete_custom_roles(db, audit_events) -> None:
    organization = await _organization(db)
    owner = await _user(db, organization, "owner")
    admin = await _user(db, organization, "admin")
    body = {"slug": "billing-viewer", "name": "Billing", "permissions": ["usage.read"]}

    refused = await _call(db, admin, "POST", "/roles", json=body)
    created = await _call(db, owner, "POST", "/roles", json=body)
    duplicate = await _call(db, owner, "POST", "/roles", json=body)
    reserved = await _call(
        db, owner, "POST", "/roles", json={**body, "permissions": ["content.read"]}
    )
    role_id = created.json()["id"]
    updated = await _call(
        db,
        owner,
        "PUT",
        f"/roles/{role_id}",
        json={**body, "permissions": ["usage.read", "findings.read"]},
    )
    listed = await _call(db, owner, "GET", "/roles")
    deleted = await _call(db, owner, "DELETE", f"/roles/{role_id}")
    missing = await _call(db, owner, "DELETE", f"/roles/{role_id}")

    assert (refused.status_code, refused.json()["detail"]) == (
        403,
        "Permission required: roles.manage",
    )
    assert created.status_code == 201
    assert created.json()["permissions"] == ["usage.read"]
    assert created.json()["created_by"] == str(owner.id)
    assert duplicate.status_code == 409
    assert reserved.status_code == 422 and "content.read" in reserved.text
    assert updated.json()["permissions"] == ["findings.read", "usage.read"]
    assert [item["slug"] for item in listed.json()] == ["billing-viewer"]
    assert (deleted.status_code, missing.status_code) == (204, 404)
    events = {
        event["endpoint"]: event["extra"]
        for event in await audit_events(organization.id)
        if event["endpoint"].startswith("tenant.custom_role")
    }
    assert events["tenant.custom_role_updated"]["before"] == {
        "permissions": ["usage.read"]
    }
    assert events["tenant.custom_role_updated"]["after"] == {
        "permissions": ["findings.read", "usage.read"]
    }
    assert set(events) == {
        "tenant.custom_role_created",
        "tenant.custom_role_updated",
        "tenant.custom_role_deleted",
    }


@pytest.mark.asyncio
async def test_custom_roles_need_team_access_and_stop_at_twenty(db) -> None:
    free = await _organization(db, tier="free")
    free_owner = await _user(db, free, "owner")
    organization = await _organization(db)
    owner = await _user(db, organization, "owner")

    upgrade = await _call(db, free_owner, "GET", "/roles")
    for number in range(20):
        response = await _call(
            db,
            owner,
            "POST",
            "/roles",
            json={"slug": f"role-{number}", "name": "R", "permissions": []},
        )
        assert response.status_code == 201
    beyond = await _call(
        db,
        owner,
        "POST",
        "/roles",
        json={"slug": "role-x", "name": "R", "permissions": []},
    )

    assert upgrade.status_code == 403
    assert upgrade.json()["detail"]["code"] == "PLAN_UPGRADE_REQUIRED"
    assert beyond.status_code == 409


@pytest.mark.asyncio
async def test_a_member_holds_a_custom_role_by_the_assignment_rules(
    db, audit_events
) -> None:
    organization = await _organization(db)
    owner = await _user(db, organization, "owner")
    member = await _user(db, organization, "member")
    holder = await _user(db, organization, "member")
    await _key(db, holder)
    viewer = OrganizationRole(
        organization_id=organization.id,
        slug="viewer",
        name="Viewer",
        permissions=["usage.read"],
    )
    db.add(viewer)
    await db.flush()

    def patch(user: User, **body) -> dict:
        return {"json": body, "path": f"/team/members/{user.id}", "method": "PATCH"}

    wrong_role = await _call(
        db, owner, **patch(member, role="admin", custom_role_id=str(viewer.id))
    )
    unknown = await _call(
        db, owner, **patch(member, role="member", custom_role_id=str(uuid4()))
    )
    holder_refused = await _call(
        db, owner, **patch(holder, role="member", custom_role_id=str(viewer.id))
    )
    assigned = await _call(
        db, owner, **patch(member, role="member", custom_role_id=str(viewer.id))
    )
    in_use = await _call(db, owner, "DELETE", f"/roles/{viewer.id}")
    me = await _call(db, member, "GET", "/auth/me")
    overview = await _call(db, member, "GET", "/overview")
    kept = await _call(db, owner, **patch(member, role="member"))
    cleared = await _call(db, owner, **patch(member, role="auditor"))

    assert wrong_role.status_code == 422
    assert unknown.status_code == 404
    assert holder_refused.status_code == 409
    assert holder_refused.json()["detail"] == {
        "code": "ROLE_HOLDERS_HAVE_KEYS",
        "users": 1,
    }
    assert assigned.json()["custom_role"] == "viewer"
    assert in_use.status_code == 409
    assert me.json()["custom_role"] == "viewer"
    assert me.json()["permissions"] == ["usage.read"]
    assert overview.status_code == 200
    assert kept.json()["custom_role"] == "viewer"
    assert cleared.json()["custom_role"] is None
    changes = [
        (event["extra"]["before"], event["extra"]["after"])
        for event in await audit_events(organization.id)
        if event["endpoint"] == "tenant.member_custom_role_changed"
    ]
    assert changes == [(None, "viewer"), ("viewer", None)]


@pytest.mark.asyncio
async def test_a_removed_member_no_longer_holds_their_custom_role(db) -> None:
    organization = await _organization(db)
    owner = await _user(db, organization, "owner")
    role = OrganizationRole(
        organization_id=organization.id, slug="viewer", name="Viewer"
    )
    db.add(role)
    await db.flush()
    holder = await _user(db, organization, "member", custom_role_id=role.id)

    removed = await _call(db, owner, "DELETE", f"/team/members/{holder.id}")
    deleted = await _call(db, owner, "DELETE", f"/roles/{role.id}")

    assert (removed.status_code, deleted.status_code) == (204, 204)
    assert (holder.is_active, holder.custom_role_id) == (False, None)


@pytest.mark.asyncio
async def test_a_role_cannot_lose_keys_own_while_its_holders_have_keys(db) -> None:
    organization = await _organization(db)
    owner = await _user(db, organization, "owner")
    role = OrganizationRole(
        organization_id=organization.id,
        slug="key-holder",
        name="Keys",
        permissions=["keys.own"],
    )
    db.add(role)
    await db.flush()
    holder = await _user(db, organization, "member", custom_role_id=role.id)
    await _key(db, holder)

    refused = await _call(
        db,
        owner,
        "PUT",
        f"/roles/{role.id}",
        json={"slug": "key-holder", "name": "Keys", "permissions": ["usage.read"]},
    )

    assert refused.status_code == 409
    assert refused.json()["detail"] == {"code": "ROLE_HOLDERS_HAVE_KEYS", "users": 1}


@pytest.mark.asyncio
async def test_a_custom_role_without_keys_own_cannot_create_a_key(db) -> None:
    organization = await _organization(db)
    role = OrganizationRole(
        organization_id=organization.id,
        slug="reader",
        name="Reader",
        permissions=["usage.read", "budgets.manage"],
    )
    db.add(role)
    await db.flush()
    holder = await _user(db, organization, "member", custom_role_id=role.id)

    created = await _call(db, holder, "POST", "/api-keys", json={"name": "k"})
    budgets = await _call(db, holder, "GET", "/cost/budgets")
    privacy = await _call(db, holder, "PUT", "/settings/pii", json={})

    assert (created.status_code, created.json()["detail"]) == (
        403,
        "Organization admin required",
    )
    assert budgets.status_code == 200
    assert (privacy.status_code, privacy.json()["detail"]) == (
        403,
        "Organization admin required",
    )


@pytest.mark.asyncio
async def test_a_key_is_created_only_while_its_owner_holds_keys_own_under_the_lock(
    db,
) -> None:
    organization = await _organization(db)
    keys, reader = (
        OrganizationRole(
            organization_id=organization.id, slug=slug, name=slug, permissions=granted
        )
        for slug, granted in (("keys", ["keys.own"]), ("reader", ["usage.read"]))
    )
    db.add_all([keys, reader])
    await db.flush()
    demoted = await _user(db, organization, "member", custom_role_id=keys.id)
    reassigned = await _user(db, organization, "member", custom_role_id=keys.id)
    for holder in (demoted, reassigned):
        assert "keys.own" in await user_permissions(db, holder)
    # Role changes that commit between the route guard and the tenant lock.
    await db.execute(
        update(OrganizationRole)
        .where(OrganizationRole.id == keys.id)
        .values(permissions=["usage.read"])
        .execution_options(synchronize_session=False)
    )
    await db.execute(
        update(User)
        .where(User.id == reassigned.id)
        .values(custom_role_id=reader.id)
        .execution_options(synchronize_session=False)
    )

    for holder in (demoted, reassigned):
        with pytest.raises(HTTPException) as refused:
            await management.create_api_key(
                management.ApiKeyInput(name="k"), holder, db
            )
        assert (refused.value.status_code, refused.value.detail) == (
            403,
            "Organization admin required",
        )
    assert (
        await db.scalar(
            select(ApiKey.id).where(ApiKey.user_id.in_([demoted.id, reassigned.id]))
        )
        is None
    )


@pytest.mark.asyncio
async def test_a_team_key_is_created_only_for_an_owner_the_gateway_accepts(db) -> None:
    organization = await _organization(db)
    team = Team(id=uuid4(), organization_id=organization.id, name="platform")
    role = OrganizationRole(
        organization_id=organization.id,
        slug="key-admin",
        name="Keys",
        permissions=["keys.own", "keys.manage", "usage.read"],
    )
    db.add_all([team, role])
    await db.flush()
    outsider = await _user(db, organization, "member", custom_role_id=role.id)
    admin = await _user(db, organization, "admin")
    body = {"json": {"name": "k", "team_id": str(team.id)}}

    refused = await _call(db, outsider, "POST", "/api-keys", **body)
    created = await _call(db, admin, "POST", "/api-keys", **body)

    assert (refused.status_code, refused.json()["detail"]) == (
        403,
        "API-key owner is not a member of this team",
    )
    assert created.status_code == 200
    prepared = SimpleNamespace(
        tenant_id=organization.id,
        api_key_id=UUID(created.json()["id"]),
        model="gpt-5-mini",
    )
    assert await AccountingPolicyLoader().quota(db, prepared) is not None


@pytest.mark.asyncio
async def test_a_custom_role_with_members_read_sees_the_member_list(
    db,
) -> None:
    organization = await _organization(db)
    role = OrganizationRole(
        organization_id=organization.id,
        slug="directory",
        name="Directory",
        permissions=["members.read"],
    )
    db.add(role)
    await db.flush()
    reader = await _user(db, organization, "member", custom_role_id=role.id)
    plain = await _user(db, organization, "member")

    listed = await _call(db, reader, "GET", "/team/members")
    refused = await _call(db, plain, "GET", "/team/members")

    assert {row["email"] for row in listed.json()} == {reader.email, plain.email}
    assert {row["custom_role"] for row in listed.json()} == {"directory", None}
    assert refused.status_code == 403
