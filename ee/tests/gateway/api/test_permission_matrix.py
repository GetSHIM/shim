"""Who is refused on every management route, pinned across the permission map."""

from __future__ import annotations

import json
from pathlib import Path
import re
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi import Depends, Request
from fastapi.routing import APIRoute
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.api import enterprise_deps
from shim_enterprise.api.enterprise_deps import get_current_user, get_invite_user
from shim_enterprise.application import create_enterprise_app
from shim_enterprise.core.database import get_db
from shim_enterprise.tenants.models import Organization, Team, TeamMembership, User

IDENTITIES = (
    "owner",
    "admin",
    "member",
    "auditor",
    "team_admin",
    "service_admin",
    "service_auditor",
)
EXPECTED = Path(__file__).with_name("permission_matrix.json")
_PATH_VALUES = {"period": "2026-09", "control_id": "A.2.2"}


def management_routes(routes) -> list[tuple[str, str, APIRoute]]:
    found = []
    for route in routes:
        if type(route).__name__ == "_IncludedRouter":
            found += [
                (method, path, item)
                for method, path, item in management_routes(
                    route.effective_candidates()
                )
            ]
        elif type(route).__name__ == "_EffectiveRouteContext":
            original = route.original_route
            if isinstance(original, APIRoute) and route.path.startswith("/api/v1/"):
                found += [(method, route.path, original) for method in original.methods]
        elif isinstance(route, APIRoute) and route.path.startswith("/api/v1/"):
            found += [(method, route.path, route) for method in route.methods]
    return sorted(found, key=lambda item: (item[1], item[0]))


def dependency_calls(route: APIRoute) -> set[object]:
    calls: set[object] = set()
    pending = list(route.dependant.dependencies)
    while pending:
        dependency = pending.pop()
        calls.add(dependency.call)
        pending += dependency.dependencies
    return calls


def _outcome(response: httpx.Response) -> str:
    if response.status_code != 403:
        return str(response.status_code)
    detail = response.json().get("detail")
    return f"403 {json.dumps(detail, sort_keys=True) if isinstance(detail, dict) else detail}"


async def _identities(session: AsyncSession) -> dict[str, UUID]:
    organization = Organization(
        id=uuid4(), name="Matrix", slug=f"matrix-{uuid4().hex}", tier="enterprise"
    )
    session.add(organization)
    await session.flush()
    users = {
        name: User(
            id=uuid4(),
            organization_id=organization.id,
            email=f"matrix-{name.replace('_', '-')}-{uuid4().hex}@example.com",
            role=role,
            kind=kind,
            is_active=True,
            is_verified=True,
        )
        for name, role, kind in (
            ("owner", "owner", "human"),
            ("admin", "admin", "human"),
            ("member", "member", "human"),
            ("auditor", "auditor", "human"),
            ("team_admin", "member", "human"),
            ("service_admin", "admin", "service"),
            ("service_auditor", "auditor", "service"),
        )
    }
    session.add_all(users.values())
    team = Team(id=uuid4(), organization_id=organization.id, name="matrix")
    session.add(team)
    await session.flush()
    session.add(
        TeamMembership(
            organization_id=organization.id,
            team_id=team.id,
            user_id=users["team_admin"].id,
            role="team_admin",
        )
    )
    await session.flush()
    return {name: user.id for name, user in users.items()}


async def observed_matrix(db, monkeypatch) -> dict[str, dict[str, str]]:
    connection = await db.connection()

    def request_session() -> AsyncSession:
        # Savepoints keep the fixture's rolled-back transaction across commits and rollbacks.
        return AsyncSession(
            bind=connection,
            join_transaction_mode="create_savepoint",
            expire_on_commit=False,
        )

    async with request_session() as session:
        ids = await _identities(session)
        await session.commit()

    async def identity(request, bearer=None, session=None) -> User:
        user = await session.get(User, ids[request.headers["x-matrix-identity"]])
        assert user is not None
        return user

    async def override_db():
        async with request_session() as session:
            yield session

    monkeypatch.setattr(enterprise_deps, "get_invite_user", identity)
    app = create_enterprise_app()
    app.dependency_overrides[get_db] = override_db

    async def invite_user(request: Request, session: AsyncSession = Depends(get_db)):
        return await identity(request, None, session)

    app.dependency_overrides[get_invite_user] = invite_user
    observed: dict[str, dict[str, str]] = {}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://matrix.test",
    ) as client:
        for method, path, route in management_routes(app.routes):
            calls = dependency_calls(route)
            if not calls & {get_current_user, get_invite_user}:
                continue
            url = re.sub(
                r"\{(\w+)\}",
                lambda match: _PATH_VALUES.get(match.group(1), str(uuid4())),
                path,
            )
            observed[f"{method} {path}"] = {
                name: _outcome(
                    await client.request(
                        method,
                        url,
                        headers={"x-matrix-identity": name},
                        json={} if method in {"POST", "PUT", "PATCH"} else None,
                    )
                )
                for name in IDENTITIES
            }
    return observed


@pytest.mark.asyncio
async def test_every_management_route_refuses_the_same_identities(
    db, monkeypatch
) -> None:
    observed = await observed_matrix(db, monkeypatch)
    assert observed == json.loads(EXPECTED.read_text())
