"""A version on every managed write, under the tenant lock and in the caller's transaction."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterable, Sequence
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any, Literal, TypedDict
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from shim.gateway.contracts.ids import TenantId
from shim_enterprise.compliance.services.forwarder import ComplianceForwarderService
from shim_enterprise.policy.models import PolicyVersion, Risk, Source
from shim_enterprise.tenants.audit import record_management_action
from shim_enterprise.tenants.gateway_settings import stored_settings
from shim_enterprise.tenants.models import (
    Organization,
    OrganizationGatewaySettings,
    User,
)
from shim_enterprise.tenants.permissions import BUILTIN_ROLE_PERMISSIONS

if TYPE_CHECKING:
    from shim_enterprise.policy.resources import ManagedResource

State = dict[str, Any]


class Impact(TypedDict):
    requests: int | None
    basis: Literal["metadata", "none"]
    window_days: int
    note: str | None


Change = tuple["ManagedResource", str, State | None, State | None]


def no_impact(window_days: int, note: str | None = None) -> Impact:
    return {"requests": None, "basis": "none", "window_days": window_days, "note": note}


def combine_risk(risks: Iterable[Risk]) -> Risk:
    found = set(risks)
    for risk in ("relaxing", "tightening"):
        if risk in found:
            return risk
    return "neutral"


def actor_type(actor: User | None) -> Literal["user_jwt", "service", "system"]:
    if actor is None:
        return "system"
    return "service" if actor.kind == "service" else "user_jwt"


def version_detail(version: int | None) -> dict[str, int]:
    return {"policy_version": version} if version is not None else {}


async def lock_tenant(session: AsyncSession, organization_id: UUID) -> None:
    # The lock team, key and member administration already take.
    await session.execute(
        select(Organization.id)
        .where(Organization.id == organization_id)
        .with_for_update(of=Organization)
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


# Custom roles never grant plans.approve, so built-in roles are the approvers.
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
                User.custom_role_id.is_(None),
                User.role.in_(_APPROVER_ROLES),
            )
        )
        or 0
    )


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
        )
        return
    raise HTTPException(
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
    changed = [change for change in changes if change[2] != change[3]]
    if not changed:
        yield None
        return
    version = await current_version(session, organization_id) + 1
    if plan_id is None:
        await _refuse_unapproved(session, actor, organization_id, changed, version)
    yield version
    await session.flush()
    snapshot: dict[str, State] = {}
    previous: dict[str, State] = {}
    for resource, item, before, _ in changed:
        current = await resource.snapshot(session, organization_id, [item])
        snapshot.setdefault(resource.name, {})[item] = current.get(item)
        previous.setdefault(resource.name, {})[item] = before
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
            created_by=str(actor.id) if actor is not None else None,
            actor_type=actor_type(actor),
            reason=reason,
        )
    )
    await session.flush()
