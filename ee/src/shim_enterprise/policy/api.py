"""Plans, versions and restore of the managed policy resources."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, cast
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from shim.gateway.contracts.ids import TenantId
from shim_enterprise.api.enterprise_deps import require
from shim_enterprise.config_file.models import file_managed
from shim_enterprise.core.database import get_db
from shim_enterprise.outbox.handlers import POLICY_APPROVAL_REQUESTED
from shim_enterprise.policy.allowlist import (
    PlanCheck,
    Unattended,
    admit_unattended,
    mark_undone,
    open_remediation,
    unattended_gate,
)
from shim_enterprise.outbox.publisher import OutboxWriter
from shim_enterprise.policy.models import (
    PlanStatus,
    PolicyPlan,
    PolicyRemediation,
    PolicyVersion,
)
from shim_enterprise.policy.plans import (
    Impact,
    Risk,
    Source,
    State,
    actor_id,
    actor_type,
    combine_risk,
    current_version,
    four_eyes_on,
    key_holders,
    lock_at_version,
    lock_tenant,
    record_managed_write,
    refuse_file_managed,
    state_at,
    system_actor,
)
from shim_enterprise.policy.resources import REGISTRY, ManagedResource, PostCommit
from shim_enterprise.tenants.audit import record_management_action as _audit
from shim_enterprise.tenants.models import User
from shim_enterprise.tenants.permissions import user_permissions

router = APIRouter(prefix="/management/policy", tags=["policy"])

_PLAN_LIFETIME = timedelta(days=7)
_APPROVAL_LIFETIME = timedelta(hours=72)
_MAX_PLAN_BYTES = 256 * 1024
_MAX_CHANGES = 100
# A recommender chooses a version to restore without reading the audit log.
_VERSION_READS = require(
    "audit.read", "plans.create", legacy_detail="Permission required: audit.read"
)
# Applying asks for plans.apply, or for the allowlisted limit an agent holds.
_APPLY = require(
    "plans.apply",
    "plans.apply_allowlisted",
    legacy_detail="Permission required: plans.apply",
)
_NOT_ALLOWLISTED: dict[int | str, dict[str, Any]] = {
    403: {
        "description": "PLAN_NOT_ALLOWLISTED: a caller limited to allowlisted plans "
        "asked for a change that needs a person; `changes` lists each refusal."
    }
}
_MAX_VERSION = 2_147_483_647
# What /state, one version's states and plans' changes show besides audit.read.
_STATE_READS = ("deployments.read", "rules.read", "settings.read", "usage.read")
# A plan written by these sources keeps its source on the version it applies.
_OWN_SOURCES = {"mcp", "file", "auto", "import", "proposal", "restore"}


class ChangeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resource: str
    item: str | None = None
    set: dict[str, Any] | None = None
    delete: bool = False

    @model_validator(mode="after")
    def one_action(self) -> ChangeInput:
        if self.delete == (self.set is not None):
            raise ValueError("A change either sets fields or deletes the item")
        if self.delete and self.item is None:
            raise ValueError("Deleting needs the item")
        return self


class PlanInput(BaseModel):
    changes: list[ChangeInput] = Field(min_length=1, max_length=_MAX_CHANGES)
    reason: str | None = Field(default=None, max_length=500)


class DecisionInput(BaseModel):
    note: str | None = Field(default=None, max_length=500)


class PlanView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    status: PlanStatus
    source: str
    risk: Risk
    reason: str | None
    base_version: int
    changes: list[dict[str, Any]]
    context: dict[str, Any]
    created_by: str | None
    created_by_actor_type: str
    created_at: datetime
    submitted_by: str | None
    submitted_at: datetime | None
    approved_by: str | None
    approved_at: datetime | None
    applied_by: str | None
    applied_at: datetime | None
    applied_version: int | None
    expires_at: datetime


class VersionSummary(BaseModel):
    version: int
    created_at: datetime
    source: str
    created_by: str | None
    actor_type: str
    risk: Risk
    plan_id: UUID | None
    reason: str | None
    items: dict[str, list[str]] = Field(
        description="The items this version changed, by resource."
    )


class VersionView(VersionSummary):
    snapshot: dict[str, dict[str, State | None]]
    previous: dict[str, dict[str, State | None]]


class PolicyStateView(BaseModel):
    version: int
    resources: dict[str, dict[str, State]]


class RestoreInput(BaseModel):
    reason: str | None = Field(default=None, max_length=500)
    expected_version: int | None = Field(
        default=None,
        ge=0,
        le=_MAX_VERSION,
        description="The current version the caller read; 409 when it moved since.",
    )


class Unrestored(BaseModel):
    resource: str
    item: str
    reason: str


class RestoreView(BaseModel):
    plan: PlanView | None
    not_restored: list[Unrestored]
    approximated: list[Unrestored]


def _tenant(user: User) -> UUID:
    if user.organization_id is None:
        raise HTTPException(status_code=403, detail="Authenticated user has no tenant")
    return user.organization_id


def _summary(row: PolicyVersion) -> dict[str, Any]:
    return {
        "version": row.version,
        "created_at": row.created_at,
        "source": row.source,
        "created_by": row.created_by,
        "actor_type": row.actor_type,
        "risk": row.risk,
        "plan_id": row.plan_id,
        "reason": row.reason,
        "items": {name: sorted(items) for name, items in row.snapshot.items()},
    }


async def authorize_change(
    session: AsyncSession, actor: User, resource: ManagedResource
) -> None:
    if actor.kind == "system":
        # shim's executor applies only what the allowlist already admitted.
        return
    granted = await user_permissions(session, actor)
    # An agent proposes anything; what it may apply is the allowlist, checked at apply.
    if resource.permission not in granted and not _allowlisted_only(granted):
        raise HTTPException(
            status_code=403, detail=f"Permission required: {resource.permission}"
        )


def plan_source(request: Request, actor: User) -> Literal["api", "mcp"]:
    """`mcp` for a service account calling through the MCP server; a label, never an authority."""
    if actor.kind == "service" and request.headers.get("x-shim-channel") == "mcp":
        return "mcp"
    return "api"


def _allowlisted_only(granted: frozenset[str]) -> bool:
    return "plans.apply_allowlisted" in granted and "plans.apply" not in granted


async def _admit_agent(
    session: AsyncSession,
    actor: User,
    organization_id: UUID,
    changes: list[dict[str, Any]],
    *,
    risk: str,
    source: str,
    plan_id: UUID | None,
) -> PlanCheck:
    """The unattended gate for an agent; a refusal is audited and committed first.

    It recomputes impact, so it runs before the tenant lock."""
    try:
        return await admit_unattended(
            session, organization_id, changes, risk=risk, source=source, agent=True
        )
    except Unattended as refused:
        if refused.code != "PLAN_NOT_ALLOWLISTED":
            raise HTTPException(
                status_code=refused.status,
                detail={"code": refused.code, "hint": refused.hint},
            ) from None
        await _audit(
            session,
            actor,
            "tenant.policy_plan_apply_refused",
            str(plan_id or organization_id),
            details={
                "plan_id": str(plan_id) if plan_id is not None else None,
                "risk": risk,
                "reasons": sorted({refusal.reason for refusal in refused.refusals}),
            },
        )
        await session.commit()
        raise HTTPException(
            status_code=403,
            detail={
                "code": "PLAN_NOT_ALLOWLISTED",
                "changes": [asdict(refusal) for refusal in refused.refusals],
                "message": "This plan needs a person to apply it.",
                "hint": refused.hint,
            },
        ) from None


async def _require_state_reads(session: AsyncSession, user: User) -> None:
    granted = await user_permissions(session, user)
    missing = [permission for permission in _STATE_READS if permission not in granted]
    if missing:
        raise HTTPException(
            status_code=403, detail=f"Permission required: {' and '.join(missing)}"
        )


async def _expire_overdue(
    session: AsyncSession, organization_id: UUID, *where: Any
) -> None:
    await session.execute(
        update(PolicyPlan)
        .where(
            PolicyPlan.organization_id == organization_id,
            PolicyPlan.status.in_(("draft", "pending_approval")),
            PolicyPlan.expires_at <= datetime.now(timezone.utc),
            *where,
        )
        .values(status="expired")
    )
    await session.commit()


async def planned_change(
    session: AsyncSession,
    organization_id: UUID,
    resource_name: str,
    item: str,
    before: State | None,
    after: State | None,
    window_days: int,
    impact: Impact | None = None,
) -> dict[str, Any]:
    resource = REGISTRY[resource_name]
    if impact is None:
        impact = await resource.impact(
            session, organization_id, item, before, after, window_days
        )
    return {
        "resource": resource_name,
        "item": item,
        "before": before,
        "after": after,
        "risk": resource.classify(before, after),
        "impact": impact,
    }


async def new_plan(
    session: AsyncSession,
    actor: User,
    organization_id: UUID,
    changes: list[dict[str, Any]],
    *,
    source: Literal["api", "restore", "import", "file", "mcp", "proposal", "auto"],
    reason: str | None,
    context: dict[str, Any] | None = None,
) -> PolicyPlan:
    await refuse_file_managed(
        session, organization_id, (change["resource"] for change in changes), source
    )
    plan = PolicyPlan(
        id=uuid4(),
        organization_id=organization_id,
        base_version=await current_version(session, organization_id),
        changes=changes,
        risk=combine_risk(change["risk"] for change in changes),
        status="draft",
        source=source,
        reason=reason,
        context=context or {},
        created_by=actor_id(actor),
        created_by_actor_type=actor_type(actor),
        expires_at=datetime.now(timezone.utc) + _PLAN_LIFETIME,
    )
    session.add(plan)
    await session.flush()
    await _audit(
        session,
        actor,
        "tenant.policy_plan_created",
        str(plan.id),
        details={
            "plan_id": str(plan.id),
            "risk": plan.risk,
            "resources": sorted({change["resource"] for change in changes}),
        },
    )
    return plan


async def _apply_plan(
    session: AsyncSession,
    actor: User,
    plan: PolicyPlan,
    *,
    status: str = "draft",
    admitted: PlanCheck | None = None,
    finding_id: UUID | None = None,
) -> list[PostCommit] | None:
    """The cleanups to run after commit, or None when the plan went for approval.

    `admitted` is the executor's own pass through the unattended gate; an agent
    limited to allowlisted plans passes it here. Either way the applied plan is
    watched as a remediation.
    """
    organization_id = plan.organization_id
    if plan.status != status:
        raise HTTPException(
            status_code=409,
            detail={"code": "PLAN_STATE_CONFLICT", "status": plan.status},
        )
    stale, changes = [], []
    for change in plan.changes:
        resource = REGISTRY[change["resource"]]
        # The one who applies may hold less than the one who planned.
        await authorize_change(session, actor, resource)
        current = await resource.snapshot(session, organization_id, [change["item"]])
        if current.get(change["item"]) != change["before"]:
            stale.append({"resource": change["resource"], "item": change["item"]})
        changes.append((resource, change["item"], change["before"], change["after"]))
    if stale:
        raise HTTPException(
            status_code=409, detail={"code": "PLAN_STALE", "items": stale}
        )
    if admitted is not None:
        # Admitted before the lock; a pause or the day's limit since then still holds.
        try:
            await unattended_gate(
                session, organization_id, agent=actor.kind != "system"
            )
        except Unattended as refused:
            raise HTTPException(
                status_code=refused.status,
                detail={"code": refused.code, "hint": refused.hint},
            ) from None
    elif actor.kind != "system":
        if _allowlisted_only(await user_permissions(session, actor)):
            # Allowlisted plans tighten by construction, so four eyes never holds one.
            admitted = await _admit_agent(
                session,
                actor,
                organization_id,
                plan.changes,
                risk=plan.risk,
                source=plan.source,
                plan_id=plan.id,
            )
    if plan.source == "proposal" and actor.kind != "human":
        # Rules an agent proposed are turned on by a person, whatever the account's role.
        raise HTTPException(
            status_code=403,
            detail={
                "code": "PROPOSAL_NEEDS_HUMAN",
                "message": "A rule proposal is applied by a person.",
                "hint": "An administrator applies rule proposals from the plan page.",
            },
        )
    # An automatic undo returns items to the state a person set, and the stale check
    # above stops it when anything else changed; four eyes does not hold it.
    automatic_undo = plan.source == "auto" and (plan.reason or "").startswith(
        "remediation:"
    )
    if (
        plan.status == "draft"
        and plan.risk == "relaxing"
        and not automatic_undo
        and await four_eyes_on(session, organization_id)
    ):
        await _submit(session, actor, plan)
        return None
    cleanups: list[PostCommit] = []
    async with record_managed_write(
        session,
        actor,
        organization_id,
        changes,
        source=cast(Source, plan.source) if plan.source in _OWN_SOURCES else "plan",
        plan_id=plan.id,
        reason=plan.reason,
    ) as version:
        # Under the allowlist the entry is the authority; resources check the actor
        # they get, so they act as shim while the version names who applied.
        authority = actor if admitted is None else system_actor(organization_id)
        for resource, item, before, after in changes:
            cleanup = await resource.apply(
                session,
                authority,
                organization_id,
                item,
                before,
                after,
                policy_version=version,
            )
            if cleanup is not None:
                cleanups.append(cleanup)
    plan.status = "applied"
    plan.applied_by = actor_id(actor)
    plan.applied_at = datetime.now(timezone.utc)
    plan.applied_version = version
    await _audit(
        session,
        actor,
        "tenant.policy_plan_applied",
        str(plan.id),
        details={
            "plan_id": str(plan.id),
            "risk": plan.risk,
            "resources": sorted({change["resource"] for change in plan.changes}),
            "policy_version": version,
        },
    )
    if admitted is not None:
        await open_remediation(session, actor, plan, admitted, finding_id=finding_id)
    return cleanups


def _plan_details(plan: PolicyPlan) -> dict[str, Any]:
    return {
        "plan_id": str(plan.id),
        "risk": plan.risk,
        "resources": sorted({change["resource"] for change in plan.changes}),
    }


async def _submit(session: AsyncSession, actor: User, plan: PolicyPlan) -> None:
    now = datetime.now(timezone.utc)
    plan.status = "pending_approval"
    plan.submitted_by = str(actor.id)
    plan.submitted_at = now
    plan.expires_at = now + _APPROVAL_LIFETIME
    details = _plan_details(plan)
    await OutboxWriter().append(
        session,
        organization_id=TenantId(plan.organization_id),
        values={
            "event_type": POLICY_APPROVAL_REQUESTED,
            "aggregate_type": "policy_plan",
            "aggregate_id": str(plan.id),
            "idempotency_key": f"policy_approval:{plan.id}",
            # Ids and resource names only, never a setting value.
            "payload": {
                "organization_id": str(plan.organization_id),
                **details,
                "submitted_by": str(actor.id),
            },
            "status": "pending",
            "next_attempt_at": now,
        },
    )
    await _audit(
        session, actor, "tenant.policy_plan_submitted", str(plan.id), details=details
    )


async def _after_commit(
    request: Request, plan: PolicyPlan, cleanups: list[PostCommit]
) -> None:
    for name in sorted({change["resource"] for change in plan.changes}):
        if hook := getattr(REGISTRY[name], "after_commit", None):
            await hook(request, plan.organization_id)
    for cleanup in cleanups:
        await cleanup()


async def _owned_plan(
    session: AsyncSession, organization_id: UUID, plan_id: UUID, *, lock: bool = False
) -> PolicyPlan:
    statement = select(PolicyPlan).where(
        PolicyPlan.organization_id == organization_id, PolicyPlan.id == plan_id
    )
    plan = await session.scalar(
        statement.with_for_update().execution_options(populate_existing=True)
        if lock
        else statement
    )
    if plan is None:
        raise HTTPException(status_code=404, detail="Plan not found")
    return plan


@router.post("/plans", response_model=PlanView, status_code=201)
async def create_plan(
    payload: PlanInput,
    request: Request,
    window_days: int = Query(default=7, ge=1, le=31),
    user: User = Depends(require("plans.create")),
    session: AsyncSession = Depends(get_db),
) -> PolicyPlan:
    if len(await request.body()) > _MAX_PLAN_BYTES:
        raise HTTPException(status_code=413, detail="A plan body is at most 256 KB")
    organization_id = _tenant(user)
    # An agent's change is validated as shim would apply it; applying it is the
    # allowlist's decision, or a person's.
    authority = (
        system_actor(organization_id)
        if _allowlisted_only(await user_permissions(session, user))
        else user
    )
    changes, seen = [], set()
    for index, change in enumerate(payload.changes):
        resource = REGISTRY.get(change.resource)
        if resource is None:
            raise HTTPException(
                status_code=422,
                detail={
                    "change": index,
                    "errors": f"Unknown resource {change.resource}",
                },
            )
        await authorize_change(session, user, resource)
        if change.item is None and not resource.creatable:
            raise HTTPException(
                status_code=422,
                detail={
                    "change": index,
                    "errors": f"{resource.name} cannot be created",
                },
            )
        if change.delete and not resource.deletable:
            raise HTTPException(
                status_code=422,
                detail={
                    "change": index,
                    "errors": f"{resource.name} cannot be deleted",
                },
            )
        if change.item is not None:
            item = change.item
        elif new_item := getattr(resource, "new_item", None):
            # A resource whose items the caller names, as a rule id.
            item = new_item(change.set or {})
        else:
            item = str(uuid4())
        before = None
        if change.item is not None:
            before = (await resource.snapshot(session, organization_id, [item])).get(
                item
            )
            if before is None:
                raise HTTPException(
                    status_code=422,
                    detail={"change": index, "errors": "Item not found"},
                )
        if (resource.name, item) in seen:
            raise HTTPException(
                status_code=422,
                detail={"change": index, "errors": "An item is changed once per plan"},
            )
        seen.add((resource.name, item))
        try:
            after = (
                None
                if change.delete
                else await resource.validate(
                    session, authority, change.item, before, change.set or {}
                )
            )
        except HTTPException as exc:
            # A change that names something the tenant lacks cannot be processed.
            raise HTTPException(
                status_code=422 if exc.status_code == 404 else exc.status_code,
                detail={"change": index, "errors": exc.detail},
            ) from None
        if after == before:
            raise HTTPException(
                status_code=422,
                detail={"change": index, "errors": "The change sets nothing new"},
            )
        changes.append(
            await planned_change(
                session,
                organization_id,
                resource.name,
                item,
                before,
                after,
                window_days,
            )
        )
    plan = await new_plan(
        session,
        user,
        organization_id,
        changes,
        source=plan_source(request, user),
        reason=payload.reason,
    )
    await session.commit()
    return plan


@router.get("/plans", response_model=list[PlanView])
async def list_plans(
    status: PlanStatus | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    user: User = Depends(require("plans.create", "audit.read")),
    session: AsyncSession = Depends(get_db),
) -> list[PolicyPlan]:
    await _require_state_reads(session, user)
    organization_id = _tenant(user)
    await _expire_overdue(session, organization_id)
    statement = select(PolicyPlan).where(PolicyPlan.organization_id == organization_id)
    if status is not None:
        statement = statement.where(PolicyPlan.status == status)
    return list(
        await session.scalars(
            statement.order_by(PolicyPlan.created_at.desc()).limit(limit)
        )
    )


@router.get("/plans/{plan_id}", response_model=PlanView)
async def get_plan(
    plan_id: UUID,
    user: User = Depends(require("plans.create", "audit.read")),
    session: AsyncSession = Depends(get_db),
) -> PolicyPlan:
    await _require_state_reads(session, user)
    organization_id = _tenant(user)
    await _expire_overdue(session, organization_id, PolicyPlan.id == plan_id)
    return await _owned_plan(session, organization_id, plan_id)


@router.post(
    "/plans/{plan_id}/apply",
    response_model=PlanView,
    responses={
        202: {"model": PlanView, "description": "Waiting for approval"},
        **_NOT_ALLOWLISTED,
    },
)
async def apply_plan(
    plan_id: UUID,
    request: Request,
    response: Response,
    user: User = Depends(_APPLY),
    session: AsyncSession = Depends(get_db),
) -> PolicyPlan:
    organization_id = _tenant(user)
    await _expire_overdue(session, organization_id, PolicyPlan.id == plan_id)
    admitted = None
    plan = await _owned_plan(session, organization_id, plan_id)
    if plan.status == "draft" and _allowlisted_only(
        await user_permissions(session, user)
    ):
        admitted = await _admit_agent(
            session,
            user,
            organization_id,
            plan.changes,
            risk=plan.risk,
            source=plan.source,
            plan_id=plan.id,
        )
    await lock_tenant(session, organization_id)
    plan = await _owned_plan(session, organization_id, plan_id, lock=True)
    cleanups = await _apply_plan(session, user, plan, admitted=admitted)
    await session.commit()
    if cleanups is None:
        response.status_code = 202
    else:
        await _after_commit(request, plan, cleanups)
    return plan


async def _pending_for(session: AsyncSession, user: User, plan_id: UUID) -> PolicyPlan:
    organization_id = _tenant(user)
    await _expire_overdue(session, organization_id, PolicyPlan.id == plan_id)
    await lock_tenant(session, organization_id)
    plan = await _owned_plan(session, organization_id, plan_id, lock=True)
    if plan.status != "pending_approval":
        raise HTTPException(
            status_code=409,
            detail={"code": "PLAN_STATE_CONFLICT", "status": plan.status},
        )
    # Who signed a file's loosening change, or registered its key, cannot approve it.
    authors = {
        UUID(author)
        for author in (
            plan.created_by,
            plan.submitted_by,
            plan.context.get("signer_user_id"),
            plan.context.get("registered_by"),
        )
        if author
    }
    if user.kind != "human" or user.id in await key_holders(
        session, organization_id, authors
    ):
        raise HTTPException(status_code=403, detail={"code": "APPROVER_NOT_ELIGIBLE"})
    return plan


def _keep_note(plan: PolicyPlan, note: str | None) -> None:
    if note is not None:
        plan.context = {**plan.context, "decision_note": note}


@router.post("/plans/{plan_id}/approve", response_model=PlanView)
async def approve_plan(
    plan_id: UUID,
    payload: DecisionInput,
    request: Request,
    user: User = Depends(require("plans.approve")),
    session: AsyncSession = Depends(get_db),
) -> PolicyPlan:
    plan = await _pending_for(session, user, plan_id)
    plan.approved_by = str(user.id)
    plan.approved_at = datetime.now(timezone.utc)
    _keep_note(plan, payload.note)
    cleanups = await _apply_plan(session, user, plan, status="pending_approval")
    assert cleanups is not None
    if plan.source == "restore" and "target_version" in plan.context:
        await _finish_restore(session, user, plan, plan.context["target_version"])
    # A person's undo of an automatic change that waited for this approval.
    undone = await session.scalar(
        select(PolicyRemediation)
        .where(
            PolicyRemediation.organization_id == plan.organization_id,
            PolicyRemediation.restore_plan_id == plan.id,
            PolicyRemediation.status.in_(("watching", "kept")),
        )
        .with_for_update()
    )
    if undone is not None:
        await mark_undone(session, undone, plan.applied_version, user)
    await _audit(
        session,
        user,
        "tenant.policy_plan_approved",
        str(plan.id),
        details=_plan_details(plan),
    )
    await session.commit()
    await _after_commit(request, plan, cleanups)
    return plan


@router.post("/plans/{plan_id}/reject", response_model=PlanView)
async def reject_plan(
    plan_id: UUID,
    payload: DecisionInput,
    user: User = Depends(require("plans.approve")),
    session: AsyncSession = Depends(get_db),
) -> PolicyPlan:
    plan = await _pending_for(session, user, plan_id)
    plan.status = "rejected"
    _keep_note(plan, payload.note)
    await _audit(
        session,
        user,
        "tenant.policy_plan_rejected",
        str(plan.id),
        details=_plan_details(plan),
    )
    await session.commit()
    return plan


@router.get("/versions", response_model=list[VersionSummary])
async def list_versions(
    limit: int = Query(default=50, ge=1, le=200),
    before: int | None = Query(default=None, ge=1, le=_MAX_VERSION),
    user: User = Depends(_VERSION_READS),
    session: AsyncSession = Depends(get_db),
) -> list[dict[str, Any]]:
    statement = select(PolicyVersion).where(
        PolicyVersion.organization_id == _tenant(user)
    )
    if before is not None:
        statement = statement.where(PolicyVersion.version < before)
    rows = await session.scalars(
        statement.order_by(PolicyVersion.version.desc()).limit(limit)
    )
    return [_summary(row) for row in rows]


@router.get("/versions/{version}", response_model=VersionView)
async def get_version(
    version: int = Path(ge=0, le=_MAX_VERSION),
    user: User = Depends(_VERSION_READS),
    session: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    await _require_state_reads(session, user)
    row = await session.scalar(
        select(PolicyVersion).where(
            PolicyVersion.organization_id == _tenant(user),
            PolicyVersion.version == version,
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Policy version not found")
    return {**_summary(row), "snapshot": row.snapshot, "previous": row.previous}


@router.get("/state", response_model=PolicyStateView)
async def policy_state(
    user: User = Depends(_VERSION_READS),
    session: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    await _require_state_reads(session, user)
    organization_id = _tenant(user)
    resources = {
        name: await resource.snapshot(session, organization_id, None)
        for name, resource in REGISTRY.items()
    }
    version = await current_version(session, organization_id)
    await session.commit()
    return {"version": version, "resources": resources}


async def _finish_restore(
    session: AsyncSession, user: User, plan: PolicyPlan, version: int
) -> None:
    await session.execute(
        update(PolicyPlan)
        .where(
            PolicyPlan.organization_id == plan.organization_id,
            PolicyPlan.status == "applied",
            # What applied after the restore was planned stays; it was not undone.
            PolicyPlan.applied_version > version,
            PolicyPlan.applied_version <= plan.base_version,
        )
        .values(status="rolled_back")
    )
    await _audit(
        session,
        user,
        "tenant.policy_version_restored",
        str(plan.id),
        details={
            "target_version": version,
            "plan_id": str(plan.id),
            "policy_version": plan.applied_version,
        },
    )


@router.post(
    "/versions/{version}/restore",
    response_model=RestoreView,
    responses={
        202: {"model": RestoreView, "description": "Waiting for approval"},
        **_NOT_ALLOWLISTED,
    },
)
async def restore_version(
    payload: RestoreInput,
    request: Request,
    response: Response,
    version: int = Path(ge=0, le=_MAX_VERSION),
    user: User = Depends(require("plans.create")),
    _: User = Depends(_APPLY),
    session: AsyncSession = Depends(get_db),
) -> RestoreView:
    organization_id = _tenant(user)
    latest = await current_version(session, organization_id)
    if not 0 <= version <= latest:
        raise HTTPException(status_code=404, detail="Policy version not found")
    if payload.expected_version not in {None, latest}:
        raise HTTPException(
            status_code=409,
            detail={"code": "POLICY_VERSION_CHANGED", "version": latest},
        )
    targets = await state_at(session, organization_id, version)
    changes: list[dict[str, Any]] = []
    not_restored: list[Unrestored] = []
    approximated: list[Unrestored] = []
    managed = await file_managed(session, organization_id)
    authority = (
        system_actor(organization_id)
        if _allowlisted_only(await user_permissions(session, user))
        else user
    )
    for name, items in targets.items():
        resource = REGISTRY.get(name)
        if resource is None:
            continue
        current = await resource.snapshot(session, organization_id, list(items))
        if name in managed:
            not_restored += [
                Unrestored(resource=name, item=item, reason="file_managed")
                for item, target in items.items()
                if target != current.get(item)
            ]
            continue
        for item, target in items.items():
            now = current.get(item)
            if name == "budgets" and target is not None:
                # Alert destinations are secrets a restore cannot bring back.
                kept = [] if now is None else now["notify_targets"]
                if target.get("notify_targets") != kept:
                    not_restored.append(
                        Unrestored(
                            resource=name,
                            item=item,
                            reason="notify_targets_not_restored",
                        )
                    )
                    target = {**target, "notify_targets": kept}
            if target == now:
                continue
            if now is None and not resource.creatable:
                gone = {
                    "record_sets": "record_set_deleted",
                    "forward_targets": "forward_target_deleted",
                }.get(name, "key_revoked")
                not_restored.append(Unrestored(resource=name, item=item, reason=gone))
                continue
            if target is None and now is not None and not resource.deletable:
                if name == "teams":
                    not_restored.append(
                        Unrestored(
                            resource=name, item=item, reason="team_not_deletable"
                        )
                    )
                    continue
                # A deployment cannot be deleted; disabling it comes closest.
                if not now["enabled"]:
                    continue
                target = {**now, "enabled": False}
                approximated.append(
                    Unrestored(
                        resource=name, item=item, reason="deployment_not_deletable"
                    )
                )
            await authorize_change(session, user, resource)
            try:
                if target is not None:
                    # What the item's own route would refuse is skipped, not fatal.
                    await resource.validate(
                        session,
                        authority,
                        item,
                        now,
                        {
                            key: value
                            for key, value in target.items()
                            if now is None or now.get(key) != value
                        },
                    )
            except HTTPException as exc:
                if exc.status_code == 403:
                    raise
                reason = exc.detail if isinstance(exc.detail, str) else "invalid"
                not_restored.append(Unrestored(resource=name, item=item, reason=reason))
                continue
            changes.append(
                await planned_change(
                    session, organization_id, name, item, now, target, 7
                )
            )
    if len(changes) > _MAX_CHANGES:
        raise HTTPException(
            status_code=422, detail=f"A plan holds at most {_MAX_CHANGES} changes"
        )
    plan = None
    admitted: PlanCheck | None = None
    cleanups: list[PostCommit] | None = []
    if changes and _allowlisted_only(await user_permissions(session, user)):
        # A refused restore creates no plan.
        admitted = await _admit_agent(
            session,
            user,
            organization_id,
            changes,
            risk=combine_risk(change["risk"] for change in changes),
            source="restore",
            plan_id=None,
        )
    # Planned without the tenant lock: impact reads history.
    await lock_at_version(session, organization_id, latest)
    if changes:
        plan = await new_plan(
            session,
            user,
            organization_id,
            changes,
            source="restore",
            reason=payload.reason,
        )
        cleanups = await _apply_plan(session, user, plan, admitted=admitted)
        if cleanups is None:
            # The rest of the restore runs when the plan is approved.
            plan.context = {"target_version": version}
        else:
            await _finish_restore(session, user, plan, version)
    await session.commit()
    if cleanups is None:
        response.status_code = 202
    elif plan is not None:
        await _after_commit(request, plan, cleanups)
    return RestoreView(
        plan=None if plan is None else PlanView.model_validate(plan),
        not_restored=not_restored,
        approximated=approximated,
    )
