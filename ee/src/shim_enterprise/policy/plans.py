"""A version on every managed write, under the tenant lock and in the caller's transaction."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterable, Sequence
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any, Literal, TypedDict
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.policy.models import PolicyVersion, Risk, Source
from shim_enterprise.tenants.models import Organization, User

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
