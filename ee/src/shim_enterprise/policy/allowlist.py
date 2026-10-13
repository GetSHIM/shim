"""The changes shim or an agent may apply unattended: those that tighten or cheapen.

Every entry touches one existing item, changes nothing in a request's content, and
is undone by setting the item back. Nothing here writes `rules` or
`gateway_settings`: no unattended change can create, enforce or widen a rule.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping, Sequence
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Literal, get_args
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from shim.gateway.contracts.ids import TenantId
from shim.privacy.policies import PII_CONFIG_DEFAULTS, effective_entity_actions
from shim_enterprise.gateway.pipeline.audit_intent import resolve_audit_policy
from shim_enterprise.observability.enterprise_metrics import REMEDIATIONS_TOTAL
from shim_enterprise.outbox.handlers import REMEDIATION_CHANGED
from shim_enterprise.outbox.publisher import OutboxWriter
from shim_enterprise.policy.models import PolicyPlan, PolicyRemediation
from shim_enterprise.policy.plans import system_actor
from shim_enterprise.policy.resources import REGISTRY
from shim_enterprise.tenants.audit import record_management_action
from shim_enterprise.tenants.gateway_settings import stored_settings
from shim_enterprise.tenants.models import (
    Organization,
    OrganizationGatewaySettings,
    TierDefinition,
    User,
)

RefusalReason = Literal[
    "create_or_delete",
    "not_allowlisted",
    "extra_fields",
    "wrong_direction",
    "impact_unknown",
    "impact_too_large",
    "plan_not_tightening",
    "proposal_needs_human",
    "too_many_changes",
    "proof_unavailable",
]
REFUSAL_REASONS = get_args(RefusalReason)
MAX_UNATTENDED_CHANGES = 5
_ENTRY_ID = re.compile(r"^[a-z][a-z0-9_.]{0,63}$")


@dataclass(frozen=True)
class Proof:
    """What must not rise after the change: refusals of these verdicts, over a window."""

    metric: Literal["refusals"]
    verdict_ids: tuple[str, ...]
    scope: Literal["tenant", "key", "team"]
    window_hours: int


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
    proof: Proof | None = None

    def __post_init__(self) -> None:
        if not _ENTRY_ID.fullmatch(self.id) or self.resource not in REGISTRY:
            raise ValueError(f"allowlist entry {self.id!r} names no known resource")


@dataclass(frozen=True)
class PlanRefusal:
    index: int | None
    resource: str | None
    item: str | None
    reason: RefusalReason


@dataclass(frozen=True)
class PlanCheck:
    refusals: list[PlanRefusal]
    # The entry that accepted each change, by change index.
    entries: dict[int, AllowlistEntry] = field(default_factory=dict)


def _changed(before: Mapping[str, Any], after: Mapping[str, Any]) -> set[str]:
    return {name for name in {*before, *after} if before.get(name) != after.get(name)}


def _disables(before: dict[str, Any], after: dict[str, Any]) -> bool:
    return before.get("enabled") is True and after.get("enabled") is False


def _narrows_models(before: dict[str, Any], after: dict[str, Any]) -> bool:
    old, new = before.get("allowed_models"), after.get("allowed_models")
    return bool(new) and (old is None or set(new) < set(old))


def _lowers(old: Any, new: Any) -> bool:
    return new is not None and (old is None or Decimal(str(new)) < Decimal(str(old)))


def _lowers_team_limits(before: dict[str, Any], after: dict[str, Any]) -> bool:
    return all(
        _lowers(before.get(name), after.get(name)) for name in _changed(before, after)
    )


def _lowers_budget(before: dict[str, Any], after: dict[str, Any]) -> bool:
    for name in _changed(before, after):
        if name == "enabled":
            if not (before[name] is False and after[name] is True):
                return False
        elif before.get(name) is None or not _lowers(before.get(name), after.get(name)):
            return False
    return True


def _actions(state: Mapping[str, Any]) -> Mapping[str, str]:
    return effective_entity_actions(
        {name: state[name] for name in PII_CONFIG_DEFAULTS if name in state},
        state.get("entity_actions") or {},
    )


def _starts_counting(before: dict[str, Any], after: dict[str, Any]) -> bool:
    old, new = _actions(before), _actions(after)
    moved = [kind for kind in new if new[kind] != old.get(kind)]
    return bool(moved) and all(
        old.get(kind) == "off" and new[kind] == "monitor" for kind in moved
    )


ALLOWLIST: tuple[AllowlistEntry, ...] = (
    AllowlistEntry(
        id="deployment.disable",
        resource="deployments",
        fields=frozenset({"enabled"}),
        accepts=_disables,
        max_impact_requests=0,
        action_kind="deployment.disable",
        proof=Proof("refusals", ("deployment.registry",), "tenant", 24),
    ),
    AllowlistEntry(
        id="api_key.narrow_models",
        resource="api_keys",
        fields=frozenset({"allowed_models"}),
        accepts=_narrows_models,
        max_impact_requests=0,
        proof=Proof("refusals", ("access.key_models", "api_key.access"), "key", 24),
    ),
    AllowlistEntry(
        id="team.lower_limit",
        resource="teams",
        fields=frozenset(
            {"daily_request_limit", "monthly_request_limit", "monthly_token_limit"}
        ),
        accepts=_lowers_team_limits,
        max_impact_requests=0,
        proof=Proof("refusals", ("quota.requests_and_tokens",), "team", 24),
    ),
    AllowlistEntry(
        id="budget.lower",
        resource="budgets",
        fields=frozenset({"limit_usd", "limit_tokens", "enabled"}),
        # Budgets only notify: nothing to bound and nothing they can break.
        accepts=_lowers_budget,
    ),
    AllowlistEntry(
        id="privacy.start_counting",
        resource="privacy",
        fields=frozenset({"entity_actions"}),
        # Counting leaves content untouched.
        accepts=_starts_counting,
    ),
)


async def tenant_audit_mode(session: AsyncSession, organization_id: UUID) -> str:
    """The tenant's audit mode; `off` means refusals leave no row to measure."""
    tier = await session.scalar(
        select(Organization.tier).where(Organization.id == organization_id)
    )
    features = await session.scalar(
        select(TierDefinition.features).where(TierDefinition.slug == tier)
    )
    return resolve_audit_policy(
        None if features is None else {"features": dict(features)}
    ).mode


async def _refusal(
    session: AsyncSession,
    organization_id: UUID,
    entry: AllowlistEntry,
    change: dict[str, Any],
    audit_mode: Callable[[], Awaitable[str]],
) -> RefusalReason | None:
    before, after = change["before"], change["after"]
    if _changed(before, after) - entry.fields:
        return "extra_fields"
    if not entry.accepts(before, after):
        return "wrong_direction"
    if entry.proof is not None and await audit_mode() == "off":
        return "proof_unavailable"
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
) -> PlanCheck:
    """Why a plan's changes need a person, and the entry that accepted each change."""
    mode: list[str] = []

    async def audit_mode() -> str:
        if not mode:
            mode.append(await tenant_audit_mode(session, organization_id))
        return mode[0]

    check = PlanCheck([])
    if risk != "tightening":
        check.refusals.append(PlanRefusal(None, None, None, "plan_not_tightening"))
    if source == "proposal":
        check.refusals.append(PlanRefusal(None, None, None, "proposal_needs_human"))
    if len(changes) > MAX_UNATTENDED_CHANGES:
        check.refusals.append(PlanRefusal(None, None, None, "too_many_changes"))
    for index, change in enumerate(changes):
        resource, item = change["resource"], change["item"]
        if change["before"] is None or change["after"] is None:
            check.refusals.append(
                PlanRefusal(index, resource, item, "create_or_delete")
            )
            continue
        # Accepted when any entry accepts; otherwise the first entry's reason.
        reasons: list[RefusalReason] = []
        for entry in (entry for entry in ALLOWLIST if entry.resource == resource):
            reason = await _refusal(session, organization_id, entry, change, audit_mode)
            if reason is None:
                check.entries[index] = entry
                break
            reasons.append(reason)
        else:
            check.refusals.append(
                PlanRefusal(
                    index, resource, item, reasons[0] if reasons else "not_allowlisted"
                )
            )
    return check


MAX_REMEDIATIONS_PER_DAY = 20


@dataclass(eq=False)
class Unattended(Exception):
    """Why an unattended apply cannot run: paused, over the daily limit, or not listed."""

    status: int
    code: str
    hint: str
    refusals: tuple[PlanRefusal, ...] = ()


async def admit_unattended(
    session: AsyncSession,
    organization_id: UUID,
    changes: Sequence[dict[str, Any]],
    *,
    risk: str,
    source: str,
) -> PlanCheck:
    """The one gate for the executor and for agents: pause, daily limit, allowlist."""
    stored = await session.scalar(
        select(OrganizationGatewaySettings.settings).where(
            OrganizationGatewaySettings.organization_id == organization_id
        )
    )
    if stored is not None and stored_settings(stored).auto_remediation_paused:
        raise Unattended(
            409,
            "AUTO_REMEDIATION_PAUSED",
            "An administrator paused automatic changes in the gateway settings.",
        )
    recent = await session.scalar(
        select(func.count()).where(
            PolicyRemediation.organization_id == organization_id,
            PolicyRemediation.status != "skipped",
            PolicyRemediation.created_at
            > datetime.now(timezone.utc) - timedelta(days=1),
        )
    )
    if (recent or 0) >= MAX_REMEDIATIONS_PER_DAY:
        raise Unattended(
            429,
            "REMEDIATION_LIMIT",
            "Too many unattended changes in 24 hours; a person can apply this plan.",
        )
    check = await check_plan(
        session, organization_id, changes, risk=risk, source=source
    )
    if check.refusals:
        raise Unattended(
            403,
            "PLAN_NOT_ALLOWLISTED",
            "Ask an administrator to apply it, or create a plan whose changes only "
            "tighten or cheapen.",
            tuple(check.refusals),
        )
    return check


async def notify_remediation(
    session: AsyncSession,
    row: PolicyRemediation,
    phase: str,
    version: int | None,
    *,
    actor: User | None = None,
) -> None:
    """Outbox intent for the tenant's forward targets, an audit row and the counter.

    The audit row names `actor` (the person who undoes) or the row's own actor.
    """
    entries = sorted({item["entry"] for item in row.items})
    resources = sorted({item["resource"] for item in row.items})
    details = {
        "remediation_id": str(row.id),
        "entries": entries,
        "resources": resources,
        "policy_version": version,
        "reasons": row.result.get("reasons", []),
    }
    if actor is None:
        actor = (
            system_actor(row.organization_id)
            if row.actor_type == "system"
            else await session.get(User, UUID(str(row.actor_id)))
        )
    assert actor is not None
    await record_management_action(
        session, actor, f"tenant.remediation_{phase}", str(row.id), details=details
    )
    if phase != "skipped":
        # Ids and names only, never a before or after value.
        await OutboxWriter().append(
            session,
            organization_id=TenantId(row.organization_id),
            values={
                "event_type": REMEDIATION_CHANGED,
                "aggregate_type": "remediation",
                "aggregate_id": str(row.id),
                "idempotency_key": f"remediation:{row.id}:{phase}",
                "payload": {
                    "organization_id": str(row.organization_id),
                    "remediation_id": str(row.id),
                    "phase": phase,
                    "entries": entries,
                    "resources": resources,
                    "policy_version": version,
                    "actor_type": row.actor_type,
                },
                "status": "pending",
                "next_attempt_at": datetime.now(timezone.utc),
            },
        )
    # A skipped finding has no accepted change, so no entry: it counts under "none".
    for entry in entries or ["none"]:
        REMEDIATIONS_TOTAL.labels(entry=entry, phase=phase).inc()


async def open_remediation(
    session: AsyncSession,
    actor: User,
    plan: PolicyPlan,
    check: PlanCheck,
    *,
    finding_id: UUID | None = None,
) -> PolicyRemediation:
    """Watch an applied unattended plan, or keep it at once when nothing can be measured."""
    now = datetime.now(timezone.utc)
    items, hours = [], []
    for index, change in enumerate(plan.changes):
        proof = check.entries[index].proof
        items.append(
            {
                "resource": change["resource"],
                "item": change["item"],
                "entry": check.entries[index].id,
                "before": change["before"],
                "after": change["after"],
                "proof": None if proof is None else asdict(proof),
            }
        )
        if proof is not None:
            hours.append(proof.window_hours)
    row = PolicyRemediation(
        id=uuid4(),
        organization_id=plan.organization_id,
        finding_id=finding_id,
        plan_id=plan.id,
        applied_version=plan.applied_version,
        actor_type="system" if actor.kind == "system" else "service",
        actor_id=None if actor.kind == "system" else str(actor.id),
        items=items,
        status="watching" if hours else "kept",
        window_start=now if hours else None,
        window_end=now + timedelta(hours=max(hours)) if hours else None,
        closed_at=None if hours else now,
        result={},
    )
    session.add(row)
    await session.flush()
    await notify_remediation(session, row, "applied", plan.applied_version)
    if not hours:
        await notify_remediation(session, row, "kept", plan.applied_version)
    return row
