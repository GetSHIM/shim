"""shim's own fixes: apply an allowlisted plan for an `auto` finding, watch it, undo it.

The executor runs in the reconciliation worker after each findings pass. Every fix
is a plan applied through the shared apply as the system actor; the window that
follows counts refusals of the fix's verdicts against the window before, and a
rise sets the items back. A person sees every row and can undo it.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field
from sqlalchemy import exists, func, or_, select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.ai_act.models import AIActAuditLog
from shim_enterprise.api.enterprise_deps import require
from shim_enterprise.core.config import settings
from shim_enterprise.core.database import QUERY_CANCELED, bound_statements, get_db
from shim_enterprise.findings.api import finding_changes
from shim_enterprise.findings.models import Finding
from shim_enterprise.findings.service import (
    RULES,
    STATUS_IDS,
    STATUS_RESOLVED,
    finding_ladder,
)
from shim_enterprise.policy.allowlist import (
    ALLOWLIST,
    PlanCheck,
    Unattended,
    admit_unattended,
    mark_undone,
    notify_remediation,
)
from shim_enterprise.policy.api import (
    _after_commit,
    _apply_plan,
    new_plan,
    planned_change,
)
from shim_enterprise.policy.models import PolicyRemediation, RemediationStatus
from shim_enterprise.policy.plans import combine_risk, lock_tenant, system_actor
from shim_enterprise.policy.resources import REGISTRY
from shim_enterprise.tenants.models import ApiKey, Organization, User

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/management/remediations", tags=["remediations"])

# Open findings the executor takes up in one pass of one tenant.
MAX_PER_PASS = 5
_OPEN = (STATUS_IDS["new"], STATUS_IDS["in_progress"])


async def _skip(
    session: AsyncSession,
    organization_id: UUID,
    finding_id: UUID,
    reasons: Sequence[str],
) -> None:
    """Record why a finding's fix did not run; the unique index stops any retry.

    A refusal that passes (the day's limit, a pause, nothing to measure yet) writes
    no row, so the next pass tries again."""
    if set(reasons) <= _TRANSIENT:
        return
    row = PolicyRemediation(
        id=uuid4(),
        organization_id=organization_id,
        finding_id=finding_id,
        actor_type="system",
        items=[],
        status="skipped",
        closed_at=datetime.now(timezone.utc),
        result={"reasons": sorted(set(reasons))},
    )
    session.add(row)
    await session.flush()
    await notify_remediation(session, row, "skipped", None)


_TRANSIENT = {"REMEDIATION_LIMIT", "AUTO_REMEDIATION_PAUSED", "proof_unavailable"}


def _error_code(error: HTTPException) -> str:
    detail = error.detail
    if isinstance(detail, dict) and isinstance(detail.get("code"), str):
        return detail["code"]
    return f"http_{error.status_code}"


@dataclass
class _Fix:
    finding: Finding
    changes: list[dict[str, Any]]
    check: PlanCheck | None
    reasons: list[str]


async def _planned_fixes(session: AsyncSession, organization_id: UUID) -> list[_Fix]:
    """Up to MAX_PER_PASS open `auto` findings with no row yet, each planned and
    checked against the allowlist, or the reasons it cannot run."""
    ladder = await finding_ladder(session, organization_id)
    kinds = {entry.action_kind for entry in ALLOWLIST if entry.action_kind}
    rules = [
        rule_id
        for rule_id, mode in ladder.modes.items()
        if mode == "auto" and rule_id in RULES and RULES[rule_id].ACTION_KIND in kinds
    ]
    if ladder.paused or not rules:
        return []
    findings = await session.scalars(
        select(Finding)
        .where(
            Finding.organization_id == organization_id,
            Finding.rule_id.in_(rules),
            Finding.status_id.in_(_OPEN),
            ~exists().where(
                PolicyRemediation.organization_id == organization_id,
                PolicyRemediation.finding_id == Finding.id,
            ),
        )
        .order_by(Finding.first_seen_at, Finding.id)
        .limit(MAX_PER_PASS)
    )
    actor = system_actor(organization_id)
    fixes = []
    for finding in findings.all():
        try:
            changes = await finding_changes(session, actor, finding)
            check = await admit_unattended(
                session,
                organization_id,
                changes,
                risk=combine_risk(change["risk"] for change in changes),
                source="auto",
                agent=False,
            )
            fixes.append(_Fix(finding, changes, check, []))
        except Unattended as refused:
            reasons: list[str] = [refusal.reason for refusal in refused.refusals]
            fixes.append(_Fix(finding, [], None, reasons or [refused.code]))
        except HTTPException as error:
            fixes.append(_Fix(finding, [], None, [_error_code(error)]))
    return fixes


async def _remediate(session: AsyncSession, fix: _Fix) -> None:
    finding, organization_id = fix.finding, fix.finding.organization_id
    actor = system_actor(organization_id)
    assert fix.check is not None
    try:
        async with session.begin_nested():
            plan = await new_plan(
                session,
                actor,
                organization_id,
                fix.changes,
                source="auto",
                reason=f"finding:{finding.id}",
            )
            # Its stale check stops a fix whose item changed since it was planned.
            await _apply_plan(
                session, actor, plan, admitted=fix.check, finding_id=finding.id
            )
    except HTTPException as error:
        await _skip(session, organization_id, finding.id, [_error_code(error)])
        return
    finding.status_id = STATUS_IDS["in_progress"]
    finding.evidence = {
        **finding.evidence,
        "policy_versions": [
            *(finding.evidence.get("policy_versions") or []),
            plan.applied_version,
        ],
    }


def _refusals(
    organization_id: UUID, item: dict[str, Any], start: datetime, end: datetime
) -> Any:
    """Requests refused with one of the proof's verdicts in [start, end)."""
    proof = item["proof"]
    statement = select(func.count()).where(
        AIActAuditLog.organization_id == organization_id,
        AIActAuditLog.event_type == "ai_request",
        AIActAuditLog.created_at >= start,
        AIActAuditLog.created_at < end,
        or_(
            *(
                AIActAuditLog.policy_verdicts.contains(
                    [{"rule_id": verdict, "outcome": "deny"}]
                )
                for verdict in proof["verdict_ids"]
            )
        ),
    )
    if proof["scope"] == "key":
        return statement.where(AIActAuditLog.api_key_id == UUID(item["item"]))
    if proof["scope"] == "team":
        return statement.where(
            AIActAuditLog.api_key_id.in_(
                select(ApiKey.id).where(
                    ApiKey.organization_id == organization_id,
                    ApiKey.team_id == UUID(item["item"]),
                )
            )
        )
    return statement


async def _restore_changes(
    session: AsyncSession, row: PolicyRemediation
) -> list[dict[str, Any]] | None:
    """Every item set back to `before` in the fields the fix changed.

    None when an item is no longer what the fix left: a person decides then.
    """
    changes = []
    for item in row.items:
        current = (
            await REGISTRY[item["resource"]].snapshot(
                session, row.organization_id, [item["item"]]
            )
        ).get(item["item"])
        if current is None or current != item["after"]:
            return None
        before = item["before"]
        changed = {
            name
            for name in {*before, *current}
            if before.get(name) != current.get(name)
        }
        changes.append(
            await planned_change(
                session,
                row.organization_id,
                item["resource"],
                item["item"],
                current,
                {**current, **{name: before.get(name) for name in changed}},
                7,
            )
        )
    return changes


async def _measure(
    session: AsyncSession, row: PolicyRemediation
) -> tuple[dict[str, Any], bool]:
    assert row.window_start is not None and row.window_end is not None
    previous = row.window_start - (row.window_end - row.window_start)
    measured, risen = {}, False
    for index, item in enumerate(row.items):
        if item["proof"] is None:
            continue
        after = await session.scalar(
            _refusals(row.organization_id, item, row.window_start, row.window_end)
        )
        baseline = await session.scalar(
            _refusals(row.organization_id, item, previous, row.window_start)
        )
        measured[str(index)] = {"baseline": baseline, "measured": after}
        risen |= (after or 0) > (baseline or 0)
    return measured, risen


@dataclass
class _Closing:
    row: PolicyRemediation
    measured: dict[str, Any]
    risen: bool
    # The undo when risen; None when an item changed since the fix.
    changes: list[dict[str, Any]] | None


async def _measured(
    session: AsyncSession, organization_id: UUID, now: datetime
) -> list[_Closing]:
    """Each watching row whose window closed, measured, with its undo planned."""
    due = await session.scalars(
        select(PolicyRemediation)
        .where(
            PolicyRemediation.organization_id == organization_id,
            PolicyRemediation.status == "watching",
            PolicyRemediation.window_end
            <= now - timedelta(seconds=settings.REMEDIATION_WINDOW_GRACE_SECONDS),
        )
        .order_by(PolicyRemediation.window_end, PolicyRemediation.id)
    )
    closing = []
    for row in due.all():
        try:
            async with session.begin_nested():
                measured, risen = await _measure(session, row)
                changes = await _restore_changes(session, row) if risen else []
        except DBAPIError as error:
            if getattr(error.orig, "pgcode", None) != QUERY_CANCELED:
                raise
            # Too slow this pass: the row stays watching for the next one.
            logger.warning("Remediation window measurement timed out")
            continue
        closing.append(_Closing(row, measured, risen, changes))
    return closing


async def _close(session: AsyncSession, closing: _Closing, now: datetime) -> None:
    row = closing.row
    await session.refresh(row)
    if row.status != "watching":
        # A person undid it since it was measured.
        return
    row.result = {**row.result, "items": closing.measured}
    finding = (
        None if row.finding_id is None else await session.get(Finding, row.finding_id)
    )
    if not closing.risen:
        row.status, row.closed_at = "kept", now
        if finding is not None and finding.status_id in _OPEN:
            finding.status_id = STATUS_RESOLVED
            finding.resolved_at, finding.resolved_by = now, "system"
        await notify_remediation(session, row, "kept", row.applied_version)
        return
    reason = "item_changed"
    if closing.changes is not None:
        actor = system_actor(row.organization_id)
        try:
            async with session.begin_nested():
                plan = await new_plan(
                    session,
                    actor,
                    row.organization_id,
                    closing.changes,
                    source="auto",
                    reason=f"remediation:{row.id}:restore",
                )
                # The automatic undo is the one relaxing plan four eyes does not
                # hold (`_apply_plan`); its stale check stops it if an item changed.
                await _apply_plan(session, actor, plan)
        except HTTPException as error:
            # Refused by the item itself (a deployment that no longer validates):
            # this row only, never the tenant's whole pass.
            reason = _error_code(error)
        else:
            row.status, row.closed_at = "restored", now
            row.restore_plan_id, row.restored_version = plan.id, plan.applied_version
            if finding is not None and finding.status_id in _OPEN:
                finding.status_id = STATUS_IDS["new"]
            await notify_remediation(session, row, "restored", plan.applied_version)
            return
    row.status, row.closed_at = "restore_skipped", now
    row.result = {**row.result, "reason": reason}
    await notify_remediation(session, row, "restore_skipped", None)


async def run_remediations(
    session_factory: Callable[[], Any], *, now: datetime
) -> None:
    """Close due windows, then fix `auto` findings, one transaction per organization.

    Measuring and planning read history, so they run before the tenant lock, which
    every request of the tenant waits on; only the writes run under it."""
    async with session_factory() as session:
        tenant_ids = (
            await session.scalars(
                select(Organization.id).where(Organization.archived_at.is_(None))
            )
        ).all()
    for tenant_id in tenant_ids:
        async with session_factory() as session:
            try:
                await bound_statements(session)
                closing = await _measured(session, tenant_id, now)
                fixes = await _planned_fixes(session, tenant_id)
                await lock_tenant(session, tenant_id)
                for due in closing:
                    await _close(session, due, now)
                for fix in fixes:
                    if fix.check is None:
                        await _skip(session, tenant_id, fix.finding.id, fix.reasons)
                    else:
                        await _remediate(session, fix)
                await session.commit()
            except Exception as exc:
                await session.rollback()
                logger.error(
                    "Remediation pass failed organization_id=%s type=%s",
                    tenant_id,
                    type(exc).__name__,
                )


class RemediationView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    finding_id: UUID | None
    plan_id: UUID | None
    applied_version: int | None
    actor_type: Literal["system", "service"]
    actor_id: str | None
    items: list[dict[str, Any]] = Field(
        description="Per change: resource, item, entry, before, after and proof."
    )
    status: RemediationStatus
    window_start: datetime | None
    window_end: datetime | None
    result: dict[str, Any] = Field(
        description="Per measured item its baseline and measured refusals; the "
        "reasons of a skipped row; the reason of a restore_skipped one."
    )
    restore_plan_id: UUID | None
    restored_version: int | None
    created_at: datetime
    closed_at: datetime | None


class UndoInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str | None = Field(default=None, max_length=500)


_read = require("findings.read", "audit.read")


async def _owned(
    session: AsyncSession, user: User, remediation_id: UUID, *, lock: bool = False
) -> PolicyRemediation:
    statement = select(PolicyRemediation).where(
        PolicyRemediation.organization_id == user.organization_id,
        PolicyRemediation.id == remediation_id,
    )
    row = await session.scalar(
        statement.with_for_update().execution_options(populate_existing=True)
        if lock
        else statement
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Remediation not found")
    return row


@router.get("", response_model=list[RemediationView])
async def list_remediations(
    status: RemediationStatus | None = None,
    limit: int = Query(default=50, ge=1, le=100),
    before: AwareDatetime | None = Query(
        default=None, description="Rows created before this time; the next page."
    ),
    user: User = Depends(_read),
    session: AsyncSession = Depends(get_db),
) -> Sequence[PolicyRemediation]:
    statement = select(PolicyRemediation).where(
        PolicyRemediation.organization_id == user.organization_id
    )
    if status is not None:
        statement = statement.where(PolicyRemediation.status == status)
    if before is not None:
        statement = statement.where(PolicyRemediation.created_at < before)
    return (
        await session.scalars(
            statement.order_by(
                PolicyRemediation.created_at.desc(), PolicyRemediation.id.desc()
            ).limit(limit)
        )
    ).all()


@router.get("/{remediation_id}", response_model=RemediationView)
async def get_remediation(
    remediation_id: UUID,
    user: User = Depends(_read),
    session: AsyncSession = Depends(get_db),
) -> PolicyRemediation:
    return await _owned(session, user, remediation_id)


@router.post(
    "/{remediation_id}/undo",
    response_model=RemediationView,
    responses={202: {"description": "The undo waits for a second approver."}},
)
async def undo_remediation(
    remediation_id: UUID,
    payload: UndoInput,
    request: Request,
    response: Response,
    user: User = Depends(require("plans.apply")),
    session: AsyncSession = Depends(get_db),
) -> PolicyRemediation:
    if user.kind != "human":
        raise HTTPException(
            status_code=403,
            detail={
                "code": "UNDO_NEEDS_HUMAN",
                "message": "A person undoes an automatic change.",
            },
        )
    organization_id = user.organization_id
    assert organization_id is not None
    # Planned before the tenant lock (impact reads history); the plan's stale
    # check guards the items under it.
    changes = await _restore_changes(
        session, await _owned(session, user, remediation_id)
    )
    await lock_tenant(session, organization_id)
    row = await _owned(session, user, remediation_id, lock=True)
    if row.status not in ("watching", "kept"):
        raise HTTPException(
            status_code=409,
            detail={"code": "REMEDIATION_STATE_CONFLICT", "status": row.status},
        )
    if changes is None:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "PLAN_STALE",
                "message": "An item changed since the automatic change; "
                "change it from its own page.",
            },
        )
    plan = await new_plan(
        session, user, organization_id, changes, source="restore", reason=payload.reason
    )
    cleanups = await _apply_plan(session, user, plan)
    row.restore_plan_id = plan.id
    # A plan four eyes holds leaves the row as it is until its approval (`approve_plan`).
    if cleanups is not None:
        await mark_undone(session, row, plan.applied_version, user)
    await session.commit()
    await session.refresh(row)
    if cleanups is None:
        response.status_code = 202
    else:
        await _after_commit(request, plan, cleanups)
    return row
