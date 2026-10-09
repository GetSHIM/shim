from __future__ import annotations

import hashlib
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import httpx
import pytest
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.routing import APIRoute
from pydantic import ValidationError
from sqlalchemy import select, text

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


@pytest.mark.parametrize("slug", ["owner", "a", "Viewer", "1viewer", "v" * 33])
def test_a_custom_role_slug_is_short_lowercase_and_not_built_in(slug: str) -> None:
    with pytest.raises(ValidationError):
        management.CustomRoleInput(slug=slug, name="Viewer", permissions=[])


def _routes(routes) -> list[tuple[str, str, APIRoute]]:
    found = []
    for route in routes:
        if type(route).__name__ == "_IncludedRouter":
            found += _routes(route.effective_candidates())
        elif type(route).__name__ == "_EffectiveRouteContext":
            if isinstance(route.original_route, APIRoute):
                found += [
                    (method, route.path, route.original_route)
                    for method in route.original_route.methods
                ]
        elif isinstance(route, APIRoute):
            found += [(method, route.path, route) for method in route.methods]
    return [item for item in found if item[1].startswith("/api/v1/")]


def _unguarded(app: FastAPI) -> list[str]:
    unguarded = []
    for method, path, route in _routes(app.routes):
        calls, pending = set(), list(route.dependant.dependencies)
        while pending:
            dependency = pending.pop()
            calls.add(dependency.call)
            pending += dependency.dependencies
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
    assert _unguarded(app) == []
    listed = {(method, path) for method, path, _ in _routes(app.routes)}
    assert set(ANY_USER_ROUTES) <= listed

    @app.get("/api/v1/management/unguarded-fixture")
    async def fixture(user: User = Depends(get_current_user)) -> None:
        return None

    assert _unguarded(app) == ["GET /api/v1/management/unguarded-fixture"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("user", "path", "allowed"),
    [
        (SimpleNamespace(role="recommender"), "/api/v1/management/teams", False),
        (SimpleNamespace(role="auditor"), "/api/v1/compliance/reports/kvkk", True),
        (SimpleNamespace(role="member"), "/api/v1/management/api-keys", True),
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


@pytest.mark.asyncio
async def test_an_empty_custom_role_is_refused_every_write(db, monkeypatch) -> None:
    organization = await _organization(db)
    role = OrganizationRole(organization_id=organization.id, slug="empty", name="E")
    db.add(role)
    await db.flush()
    holder = await _user(db, organization, "member", custom_role_id=role.id)
    monkeypatch.setattr(
        enterprise_deps, "get_invite_user", AsyncMock(return_value=holder)
    )
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/management/api-keys",
            "headers": [],
        }
    )

    with pytest.raises(HTTPException) as refused:
        await get_current_user(request, None, db)

    assert refused.value.detail == "Auditor access is read-only"
    assert await user_permissions(db, holder) == frozenset()


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
