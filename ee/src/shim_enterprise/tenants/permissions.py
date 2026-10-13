"""Positive management permissions: built-in role sets and tenant custom roles."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Literal, get_args

from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.tenants.models import OrganizationRole, User

Permission = Literal[
    "settings.read",
    "settings.write",
    "rules.read",
    "rules.write",
    "deployments.read",
    "deployments.manage",
    "providers.manage",
    "budgets.manage",
    "teams.manage",
    "keys.own",
    "keys.manage",
    "members.read",
    "members.manage",
    "roles.manage",
    "usage.read",
    "audit.read",
    "compliance.manage",
    "findings.read",
    "findings.manage",
    "incidents.read",
    "incidents.manage",
    "plans.create",
    "plans.apply",
    "plans.apply_allowlisted",
    "plans.approve",
    "requests.approve",
    "content.read",
    "config.manage",
]

PERMISSIONS: frozenset[Permission] = frozenset(get_args(Permission))
READ_PERMISSIONS: frozenset[Permission] = frozenset(
    {
        "settings.read",
        "rules.read",
        "deployments.read",
        "members.read",
        "usage.read",
        "audit.read",
        "findings.read",
        "incidents.read",
    }
)
RESERVED_PERMISSIONS: frozenset[Permission] = frozenset(
    {
        # The gateway lets only owners and admins hold keys on any team.
        "keys.manage",
        "roles.manage",
        "config.manage",
        "content.read",
        "plans.approve",
        "requests.approve",
    }
)
# Owners and admins apply any plan (plans.apply); the allowlisted limit is for agents.
_HUMAN_ADMIN = PERMISSIONS - {"plans.apply_allowlisted"}
BUILTIN_ROLE_PERMISSIONS: Mapping[str, frozenset[Permission]] = {
    "owner": _HUMAN_ADMIN,
    "admin": _HUMAN_ADMIN - {"roles.manage", "config.manage"},
    "member": frozenset({"settings.read", "keys.own"}),
    "auditor": READ_PERMISSIONS,
    # Service accounts only (ck_users_service_role): an agent reads and proposes,
    # and applies only plans whose every change is on the allowlist.
    "recommender": frozenset(
        {
            "settings.read",
            "rules.read",
            "deployments.read",
            "findings.read",
            "usage.read",
            "plans.create",
            "plans.apply_allowlisted",
        }
    ),
}
KEY_OWNER_ROLES = frozenset(
    role for role, granted in BUILTIN_ROLE_PERMISSIONS.items() if "keys.own" in granted
)

# Routes any signed-in user may call; each scopes its result to the caller in its query.
ANY_USER_ROUTES: tuple[tuple[str, str], ...] = (
    ("GET", "/api/v1/management/auth/me"),
    ("PUT", "/api/v1/management/auth/me"),
    ("GET", "/api/v1/management/subscription"),
    ("GET", "/api/v1/management/tier-info"),
    ("GET", "/api/v1/management/team/members"),
    ("GET", "/api/v1/management/teams"),
    ("GET", "/api/v1/management/teams/{team_id}/members"),
    ("PUT", "/api/v1/management/teams/{team_id}/members/{member_id}"),
    ("DELETE", "/api/v1/management/teams/{team_id}/members/{member_id}"),
    ("GET", "/api/v1/management/api-keys"),
    ("POST", "/api/v1/management/api-keys/{api_key_id}/rotate"),
    ("PATCH", "/api/v1/management/api-keys/{api_key_id}"),
    ("DELETE", "/api/v1/management/api-keys/{api_key_id}"),
    ("GET", "/api/v1/management/requests"),
    ("GET", "/api/v1/management/requests/export"),
    ("GET", "/api/v1/management/tasks"),
    # Authorization per tool, in the dispatched route.
    ("POST", "/api/v1/mcp"),
    ("GET", "/api/v1/management/request-archive/openings"),
    ("POST", "/api/v1/management/team/invites/accept"),
    ("GET", "/api/v1/management/usage/mine"),
    # Cloud only: every member reads the plan; managing it is checked as owner.
    ("GET", "/api/v1/management/cloud-billing"),
)


def effective_permissions(
    user: User, custom_role: OrganizationRole | None
) -> frozenset[Permission]:
    if user.custom_role_id is not None:
        if custom_role is None:
            return frozenset()
        return (PERMISSIONS & set(custom_role.permissions)) - RESERVED_PERMISSIONS
    return BUILTIN_ROLE_PERMISSIONS.get(user.role, frozenset())


async def user_permissions(
    session: AsyncSession, user: User, *, reload: bool = False
) -> frozenset[Permission]:
    """`reload` re-reads the user and role, for a check repeated under the tenant lock."""
    if reload:
        await session.refresh(user, ["role", "custom_role_id"])
    if user.custom_role_id is None:
        return BUILTIN_ROLE_PERMISSIONS.get(user.role, frozenset())
    # The identity map makes this one read per request session.
    role = await session.get(
        OrganizationRole, user.custom_role_id, populate_existing=reload
    )
    if role is not None and role.organization_id != user.organization_id:
        role = None
    return effective_permissions(user, role)
