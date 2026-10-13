"""A version on every managed write, under the tenant lock and in the caller's transaction."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterable, Sequence
from contextlib import asynccontextmanager
from contextvars import ContextVar
from typing import TYPE_CHECKING, Any, Literal, TypedDict
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from shim.gateway.contracts.ids import TenantId
from shim_enterprise.compliance.services.forwarder import ComplianceForwarderService
from shim_enterprise.config_file import FILE_MANAGEABLE
from shim_enterprise.policy.models import PolicyVersion, Risk, Source
from shim_enterprise.tenants.audit import record_management_action
from shim_enterprise.tenants.gateway_settings import stored_settings
from shim_enterprise.tenants.models import (
    Organization,
    OrganizationGatewaySettings,
    ServiceAccountCredential,
    User,
)
from shim_enterprise.tenants.permissions import BUILTIN_ROLE_PERMISSIONS

if TYPE_CHECKING:
    from shim_enterprise.policy.resources import ManagedResource

State = dict[str, Any]


class Impact(TypedDict):
    requests: int | None
    basis: Literal["metadata", "monitor_history", "none"]
    window_days: int
    note: str | None


Change = tuple["ManagedResource", str, State | None, State | None]

# The source of the managed write in progress, for the one check that differs by
# source: a restore may re-create an enforced rule without a preview.
WRITE_SOURCE: ContextVar[Source] = ContextVar("policy_write_source", default="api")


def no_impact(window_days: int, note: str | None = None) -> Impact:
    return {"requests": None, "basis": "none", "window_days": window_days, "note": note}


def combine_risk(risks: Iterable[Risk]) -> Risk:
    found = set(risks)
    for risk in ("relaxing", "tightening"):
        if risk in found:
            return risk
    return "neutral"


def actor_type(actor: User | None) -> Literal["user_jwt", "service", "system"]:
    if actor is None or actor.kind == "system":
        return "system"
    return "service" if actor.kind == "service" else "user_jwt"


def actor_id(actor: User | None) -> str | None:
    return None if actor is None or actor.kind == "system" else str(actor.id)


def system_actor(organization_id: UUID) -> User:
    """shim itself, applying an allowlisted change: never stored, holds an admin's rights.

    Resources check the actor they are given; under the allowlist that check is
    the allowlist, so they get this actor while the version names who applied.
    """
    return User(
        id=None,
        organization_id=organization_id,
        email="system@shim.internal",
        role="admin",
        kind="system",
        is_active=True,
        is_verified=True,
    )


def version_detail(version: int | None) -> dict[str, int]:
    return {"policy_version": version} if version is not None else {}


async def lock_tenant(session: AsyncSession, organization_id: UUID) -> None:
    # The lock team, key and member administration already take.
    await session.execute(
        select(Organization.id)
        .where(Organization.id == organization_id)
        .with_for_update(of=Organization)
    )


async def lock_at_version(
    session: AsyncSession, organization_id: UUID, version: int
) -> None:
    """The tenant lock for work planned without it (every request of the tenant waits
    on the lock); 409 when a policy write landed after `version` was read."""
    await lock_tenant(session, organization_id)
    latest = await current_version(session, organization_id)
    if latest != version:
        raise HTTPException(
            status_code=409,
            detail={"code": "POLICY_VERSION_CHANGED", "version": latest},
        )


async def current_version(session: AsyncSession, organization_id: UUID) -> int:
    return int(
        await session.scalar(
            select(func.max(PolicyVersion.version)).where(
                PolicyVersion.organization_id == organization_id
            )
        )
        or 0
    )


async def state_at(
    session: AsyncSession, organization_id: UUID, version: int
) -> dict[str, dict[str, State | None]]:
    """Each versioned item's state at `version`; items never versioned are left out."""
    targets: dict[str, dict[str, State | None]] = {}
    for row in await session.scalars(
        select(PolicyVersion)
        .where(PolicyVersion.organization_id == organization_id)
        .order_by(PolicyVersion.version)
    ):
        for name, items in row.snapshot.items():
            known = targets.setdefault(name, {})
            for item, state in items.items():
                # At or before the target its latest state wins; after it, the
                # state before the first later change is the state it had then.
                if row.version <= version:
                    known[item] = state
                elif item not in known:
                    known[item] = row.previous[name][item]
    return targets


# Custom roles never grant plans.approve and hang only off the member role, so
# built-in roles are the approvers.
_APPROVER_ROLES = [
    role
    for role, granted in BUILTIN_ROLE_PERMISSIONS.items()
    if "plans.approve" in granted
]


async def four_eyes_on(session: AsyncSession, organization_id: UUID) -> bool:
    stored = await session.scalar(
        select(OrganizationGatewaySettings.settings).where(
            OrganizationGatewaySettings.organization_id == organization_id
        )
    )
    return stored is not None and stored_settings(stored).four_eyes == "relaxing"


async def count_approvers(session: AsyncSession, organization_id: UUID) -> int:
    return int(
        await session.scalar(
            select(func.count()).where(
                User.organization_id == organization_id,
                User.is_active.is_(True),
                User.kind == "human",
                User.role.in_(_APPROVER_ROLES),
            )
        )
        or 0
    )


async def key_holders(
    session: AsyncSession, organization_id: UUID, user_ids: set[UUID]
) -> set[UUID]:
    """The users, and whoever created or rotated their service-account key."""
    if not user_ids:
        return set()
    creators = await session.scalars(
        select(ServiceAccountCredential.created_by).where(
            ServiceAccountCredential.organization_id == organization_id,
            ServiceAccountCredential.user_id.in_(user_ids),
        )
    )
    return user_ids | set(creators)


async def require_two_approvers(
    session: AsyncSession, organization_id: UUID, *, losing: int = 0
) -> None:
    if await count_approvers(session, organization_id) - losing < 2:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "FOUR_EYES_UNAVAILABLE",
                "message": "Four eyes needs two active administrators.",
            },
        )


async def keep_two_approvers(
    session: AsyncSession, member: User, organization_id: UUID, role: str | None
) -> None:
    """Under four eyes, refuse to demote (`role`) or remove (None) the second approver."""
    if (
        member.kind == "human"
        and member.role in _APPROVER_ROLES
        and role not in _APPROVER_ROLES
        and await four_eyes_on(session, organization_id)
    ):
        await require_two_approvers(session, organization_id, losing=1)


def relaxed_fields(changes: Sequence[Change]) -> list[str]:
    """`resource.item.field` of each relaxing field, `resource.item` for a create or delete."""
    relaxed: list[str] = []
    for resource, item, before, after in changes:
        if resource.classify(before, after) != "relaxing":
            continue
        prefix = f"{resource.name}.{item}"
        if before is None or after is None:
            relaxed.append(prefix)
            continue
        fields = [
            f"{prefix}.{field}"
            for field in after
            if before.get(field) != after[field]
            and resource.classify(before, {**before, field: after[field]}) == "relaxing"
        ]
        relaxed += fields or [prefix]
    return relaxed


async def _refuse_unapproved(
    session: AsyncSession,
    actor: User | None,
    organization_id: UUID,
    changes: Sequence[Change],
    version: int,
) -> None:
    relaxed = relaxed_fields(changes)
    if not relaxed or not await four_eyes_on(session, organization_id):
        return
    if (
        relaxed == ["gateway_settings._.four_eyes"]
        and actor is not None
        and actor.role == "owner"
        and await count_approvers(session, organization_id) < 2
    ):
        # Single-admin lockout: nobody could approve turning four eyes off.
        event_id = await record_management_action(
            session,
            actor,
            "tenant.four_eyes_single_admin_override",
            str(organization_id),
            details={"policy_version": version},
        )
        await ComplianceForwarderService().send_privacy_protection_relaxed(
            session,
            TenantId(organization_id),
            fields=["four_eyes"],
            actor=str(actor.id),
            actor_email=actor.email,
            event_id=event_id,
            kind="gateway_protection_relaxed",
        )
        return
    raise approval_required(relaxed)


async def refuse_file_managed(
    session: AsyncSession,
    organization_id: UUID,
    resources: Iterable[str],
    source: Source,
) -> None:
    """409 for a write from anywhere but the signed file to a resource it manages."""
    touched = set(resources) & set(FILE_MANAGEABLE)
    if source == "file" or not touched:
        return
    # Here, not at the top: config_file.models registers a policy resource.
    from shim_enterprise.config_file.models import file_managed

    managed = sorted(touched & set(await file_managed(session, organization_id)))
    if managed:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "CONFIG_FILE_MANAGED",
                "resource": managed[0],
                "message": f"This tenant manages {managed[0]} from a signed "
                "configuration file.",
                "hint": "Change the file, sign it and push it; or switch the tenant "
                "back to api mode.",
            },
        )


def approval_required(relaxed: list[str]) -> HTTPException:
    return HTTPException(
        status_code=409,
        detail={
            "code": "CHANGE_REQUIRES_APPROVAL",
            "relaxed": relaxed,
            "message": "This change loosens protection. Create a plan and ask a "
            "second administrator to approve it.",
        },
    )


@asynccontextmanager
async def record_managed_write(
    session: AsyncSession,
    actor: User | None,
    organization_id: UUID,
    changes: Sequence[Change],
    *,
    source: Source,
    plan_id: UUID | None = None,
    reason: str | None = None,
) -> AsyncIterator[int | None]:
    """Yield the version the writes inside belong to, or None when nothing changes.

    The caller took the tenant lock before reading each change's before-state.
    """
    await lock_tenant(session, organization_id)
    await refuse_file_managed(
        session, organization_id, (change[0].name for change in changes), source
    )
    changed = [change for change in changes if change[2] != change[3]]
    if not changed:
        yield None
        return
    version = await current_version(session, organization_id) + 1
    if plan_id is None:
        await _refuse_unapproved(session, actor, organization_id, changed, version)
    token = WRITE_SOURCE.set(source)
    try:
        yield version
    finally:
        WRITE_SOURCE.reset(token)
    await session.flush()
    snapshot: dict[str, State] = {}
    previous: dict[str, State] = {}
    items: dict[ManagedResource, list[str]] = {}
    for resource, item, before, _ in changed:
        items.setdefault(resource, []).append(item)
        previous.setdefault(resource.name, {})[item] = before
    # One read per resource: a rule set PUT can change a hundred items.
    for resource, names in items.items():
        current = await resource.snapshot(session, organization_id, names)
        for item in names:
            snapshot.setdefault(resource.name, {})[item] = current.get(item)
    session.add(
        PolicyVersion(
            organization_id=organization_id,
            version=version,
            snapshot=snapshot,
            previous=previous,
            source=source,
            plan_id=plan_id,
            risk=combine_risk(
                resource.classify(before, after)
                for resource, _, before, after in changed
            ),
            created_by=actor_id(actor),
            actor_type=actor_type(actor),
            reason=reason,
        )
    )
    await session.flush()
