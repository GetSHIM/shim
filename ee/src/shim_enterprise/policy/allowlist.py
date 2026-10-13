"""The changes an agent may apply by itself: those that tighten or cheapen.

E56 fills `ALLOWLIST`; while it is empty a recommender proposes and never applies.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
import re
from dataclasses import dataclass
from typing import Any, Literal, get_args
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.policy.resources import REGISTRY

RefusalReason = Literal[
    "create_or_delete",
    "not_allowlisted",
    "extra_fields",
    "wrong_direction",
    "impact_unknown",
    "impact_too_large",
    "plan_not_tightening",
    "proposal_needs_human",
]
REFUSAL_REASONS = get_args(RefusalReason)
_ENTRY_ID = re.compile(r"^[a-z][a-z0-9_.]{0,63}$")


@dataclass(frozen=True)
class AllowlistEntry:
    id: str
    resource: str
    # The item fields this entry may change.
    fields: frozenset[str]
    # Before and after of the item: true when every changed field moves the allowed way.
    accepts: Callable[[dict[str, Any], dict[str, Any]], bool]
    # The largest impact.requests the change may have; None leaves it unbounded.
    max_impact_requests: int | None = None
    min_window_days: int = 7
    action_kind: str | None = None

    def __post_init__(self) -> None:
        if not _ENTRY_ID.fullmatch(self.id) or self.resource not in REGISTRY:
            raise ValueError(f"allowlist entry {self.id!r} names no known resource")


@dataclass(frozen=True)
class PlanRefusal:
    index: int | None
    resource: str | None
    item: str | None
    reason: RefusalReason


ALLOWLIST: tuple[AllowlistEntry, ...] = ()


async def _refusal(
    session: AsyncSession,
    organization_id: UUID,
    entry: AllowlistEntry,
    change: dict[str, Any],
) -> RefusalReason | None:
    before, after = change["before"], change["after"]
    changed = {
        field for field in {*before, *after} if before.get(field) != after.get(field)
    }
    if changed - entry.fields:
        return "extra_fields"
    if not entry.accepts(before, after):
        return "wrong_direction"
    if entry.max_impact_requests is None:
        return None
    # Recomputed now: the figure stored on the plan may be days old.
    impact = await REGISTRY[entry.resource].impact(
        session,
        organization_id,
        change["item"],
        before,
        after,
        entry.min_window_days,
    )
    if impact["requests"] is None:
        return "impact_unknown"
    return (
        "impact_too_large" if impact["requests"] > entry.max_impact_requests else None
    )


async def check_plan(
    session: AsyncSession,
    organization_id: UUID,
    changes: Sequence[dict[str, Any]],
    *,
    risk: str,
    source: str,
) -> list[PlanRefusal]:
    """Why a plan's changes need a person; empty when every change is allowlisted."""
    refusals: list[PlanRefusal] = []
    if risk != "tightening":
        refusals.append(PlanRefusal(None, None, None, "plan_not_tightening"))
    if source == "proposal":
        refusals.append(PlanRefusal(None, None, None, "proposal_needs_human"))
    for index, change in enumerate(changes):
        resource, item = change["resource"], change["item"]
        if change["before"] is None or change["after"] is None:
            refusals.append(PlanRefusal(index, resource, item, "create_or_delete"))
            continue
        # Accepted when any entry accepts; otherwise the first entry's reason.
        reasons: list[RefusalReason] = []
        for entry in (entry for entry in ALLOWLIST if entry.resource == resource):
            reason = await _refusal(session, organization_id, entry, change)
            if reason is None:
                break
            reasons.append(reason)
        else:
            refusals.append(
                PlanRefusal(
                    index, resource, item, reasons[0] if reasons else "not_allowlisted"
                )
            )
    return refusals
