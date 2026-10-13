from __future__ import annotations

import re
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute

from ee.tests.gateway.api.test_permission_matrix import management_routes
from shim_enterprise.api.enterprise_deps import get_current_user
from shim_enterprise.api.v1.router import management_router
from shim_enterprise.core.database import get_db
from shim_enterprise.mcp.tools import TOOLS
from shim_enterprise.tenants.models import Organization, OrganizationRole, User

# What a caller needs besides the tool's own permission for its route to pass.
_ALSO = {
    "create_plan": {"settings.write"},
    "list_plans": {"deployments.read", "rules.read", "settings.read", "usage.read"},
    "get_plan": {"deployments.read", "rules.read", "settings.read", "usage.read"},
    "restore_version": {"plans.create"},
}
_BODIES = {
    "create_plan": {
        "changes": [{"resource": "privacy", "item": "_", "set": {"block_email": False}}]
    },
    "restore_version": {},
    "propose_rules": {"sentence": "x", "rules": []},
}
_NEVER = re.compile(
    r"/content|/providers|/api-keys|/team/|/roles|/service-accounts|/config/|/export"
    r"|/request-archive|/approvals"
)


def _app() -> FastAPI:
    app = FastAPI()
    app.include_router(management_router, prefix="/api/v1")
    return app


def _route(tool) -> APIRoute:
    for method, path, route in management_routes(_app().routes):
        if method == tool.method and path == tool.path:
            return route
    raise AssertionError(f"{tool.name} names no route")


def test_tool_names_are_unique_and_tools_never_reach_the_closed_areas() -> None:
    names = [tool.name for tool in TOOLS]

    assert len(names) == len(set(names)) == 17
    assert all(re.fullmatch(r"^[a-z][a-z0-9_]{1,47}$", name) for name in names)
    assert not [tool.path for tool in TOOLS if _NEVER.search(tool.path)]
    # No tool changes a finding's status or writes a setting directly.
    assert {(tool.method, tool.path) for tool in TOOLS if tool.method != "GET"} == {
        ("POST", "/api/v1/management/findings/{finding_id}/plan"),
        ("POST", "/api/v1/management/policy/plans"),
        ("POST", "/api/v1/management/policy/plans/{plan_id}/apply"),
        ("POST", "/api/v1/management/policy/versions/{version}/restore"),
        ("POST", "/api/v1/management/rules/proposals"),
    }


@pytest.mark.parametrize("tool", TOOLS, ids=[tool.name for tool in TOOLS])
def test_every_argument_is_a_parameter_of_the_route(tool) -> None:
    dependant = _route(tool).dependant
    parameters = {
        param.alias for param in (*dependant.path_params, *dependant.query_params)
    }
    fields = set(tool.arguments.model_fields)

    assert fields - {"body"} <= parameters, tool.name
    assert ("body" in fields) == bool(dependant.body_params), tool.name
    for name in re.findall(r"{(\w+)}", tool.path):
        assert name in fields, tool.name


async def _caller(db, permissions: set[str]) -> User:
    organization = Organization(
        id=uuid4(), name="Tools", slug=f"tools-{uuid4().hex}", tier="enterprise"
    )
    db.add(organization)
    await db.flush()
    role = OrganizationRole(
        organization_id=organization.id,
        slug=f"r-{uuid4().hex[:8]}",
        name="Tool caller",
        permissions=sorted(permissions),
    )
    db.add(role)
    await db.flush()
    user = User(
        id=uuid4(),
        organization_id=organization.id,
        email=f"tools-{uuid4().hex}@example.com",
        role="member",
        custom_role_id=role.id,
        is_active=True,
        is_verified=True,
    )
    db.add(user)
    await db.flush()
    return user


async def _status(db, user: User, tool) -> int:
    app = _app()
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_db] = lambda: db
    values = {"finding_id": uuid4(), "plan_id": uuid4(), "version": 0}
    path = tool.path.format(**values)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.request(tool.method, path, json=_BODIES.get(tool.name))
    return response.status_code


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", TOOLS, ids=[tool.name for tool in TOOLS])
async def test_the_route_decides_with_the_permissions_the_tool_is_listed_for(
    db, tool
) -> None:
    extra = _ALSO.get(tool.name, set())
    without = await _status(db, await _caller(db, extra), tool)
    holding = [
        await _status(db, await _caller(db, {permission} | extra), tool)
        for permission in tool.permissions_any
    ]

    if tool.name == "list_requests":
        # Open to any signed-in user, scoped to the keys it owns: usage.read widens it.
        assert (without, holding) == (200, [200])
        return
    assert without == 403, tool.name
    assert 403 not in holding, (tool.name, holding)
