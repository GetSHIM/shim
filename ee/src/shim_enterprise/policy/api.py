"""Plans, versions and restore of the managed policy resources."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Literal, cast
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.api.enterprise_deps import require
from shim_enterprise.core.database import get_db
from shim_enterprise.policy.models import PlanStatus, PolicyPlan, PolicyVersion
from shim_enterprise.policy.plans import (
    Impact,
    Risk,
    Source,
    State,
    actor_type,
    combine_risk,
    current_version,
    lock_tenant,
    record_managed_write,
)
from shim_enterprise.policy.resources import REGISTRY, PostCommit
from shim_enterprise.tenants.audit import record_management_action as _audit
from shim_enterprise.tenants.models import User

router = APIRouter(prefix="/management/policy", tags=["policy"])

_PLAN_LIFETIME = timedelta(days=7)
_MAX_PLAN_BYTES = 256 * 1024
# A plan written by these sources keeps its source on the version it applies.
_OWN_SOURCES = {"mcp", "file", "auto", "import", "proposal", "restore"}
_NOT_DELETABLE = {
    "teams": "team_not_deletable",
    "deployments": "deployment_not_deletable",
}


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
    changes: list[ChangeInput] = Field(min_length=1, max_length=100)
    reason: str | None = Field(default=None, max_length=500)


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


def _expired(plan: PolicyPlan) -> bool:
    if plan.status in {"draft", "pending_approval"} and plan.expires_at <= datetime.now(
        timezone.utc
    ):
        plan.status = "expired"
        return True
    return False


async def _change(
    session: AsyncSession,
    organization_id: UUID,
    resource_name: str,
    item: str,
    before: State | None,
    after: State | None,
    window_days: int,
) -> dict[str, Any]:
    resource = REGISTRY[resource_name]
    impact: Impact = await resource.impact(
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


async def _new_plan(
    session: AsyncSession,
    actor: User,
    organization_id: UUID,
    changes: list[dict[str, Any]],
    *,
    source: Literal["api", "restore"],
    reason: str | None,
) -> PolicyPlan:
    plan = PolicyPlan(
        id=uuid4(),
        organization_id=organization_id,
        base_version=await current_version(session, organization_id),
        changes=changes,
        risk=combine_risk(change["risk"] for change in changes),
        status="draft",
        source=source,
        reason=reason,
        context={},
        created_by=str(actor.id),
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
    session: AsyncSession, actor: User, plan: PolicyPlan
) -> list[PostCommit]:
    organization_id = plan.organization_id
    if plan.status != "draft":
        raise HTTPException(
            status_code=409,
            detail={"code": "PLAN_STATE_CONFLICT", "status": plan.status},
        )
    stale, changes = [], []
    for change in plan.changes:
        resource = REGISTRY[change["resource"]]
        current = await resource.snapshot(session, organization_id, [change["item"]])
        if current.get(change["item"]) != change["before"]:
            stale.append({"resource": change["resource"], "item": change["item"]})
        changes.append((resource, change["item"], change["before"], change["after"]))
    if stale:
        raise HTTPException(
            status_code=409, detail={"code": "PLAN_STALE", "items": stale}
        )
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
        for resource, item, before, after in changes:
            cleanup = await resource.apply(
                session,
                actor,
                organization_id,
                item,
                before,
                after,
                policy_version=version,
            )
            if cleanup is not None:
                cleanups.append(cleanup)
    plan.status = "applied"
    plan.applied_by = str(actor.id)
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
    return cleanups


async def _after_commit(
    request: Request, plan: PolicyPlan, cleanups: list[PostCommit]
) -> None:
    for name in sorted({change["resource"] for change in plan.changes}):
        await REGISTRY[name].after_commit(request, plan.organization_id)
    for cleanup in cleanups:
        await cleanup()


async def _owned_plan(
    session: AsyncSession, organization_id: UUID, plan_id: UUID, *, lock: bool = False
) -> PolicyPlan:
    statement = select(PolicyPlan).where(
        PolicyPlan.organization_id == organization_id, PolicyPlan.id == plan_id
    )
    plan = await session.scalar(statement.with_for_update() if lock else statement)
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
        item = change.item or str(uuid4())
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
                else resource.validate(change.item, before, change.set or {})
            )
        except HTTPException as exc:
            raise HTTPException(
                status_code=exc.status_code,
                detail={"change": index, "errors": exc.detail},
            ) from None
        changes.append(
            await _change(
                session,
                organization_id,
                resource.name,
                item,
                before,
                after,
                window_days,
            )
        )
    plan = await _new_plan(
        session, user, organization_id, changes, source="api", reason=payload.reason
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
    organization_id = _tenant(user)
    await session.execute(
        update(PolicyPlan)
        .where(
            PolicyPlan.organization_id == organization_id,
            PolicyPlan.status.in_(("draft", "pending_approval")),
            PolicyPlan.expires_at <= datetime.now(timezone.utc),
        )
        .values(status="expired")
    )
    await session.commit()
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
    plan = await _owned_plan(session, _tenant(user), plan_id)
    if _expired(plan):
        await session.commit()
    return plan


@router.post("/plans/{plan_id}/apply", response_model=PlanView)
async def apply_plan(
    plan_id: UUID,
    request: Request,
    user: User = Depends(require("plans.apply")),
    session: AsyncSession = Depends(get_db),
) -> PolicyPlan:
    organization_id = _tenant(user)
    await lock_tenant(session, organization_id)
    plan = await _owned_plan(session, organization_id, plan_id, lock=True)
    if _expired(plan):
        await session.commit()
    cleanups = await _apply_plan(session, user, plan)
    await session.commit()
    await _after_commit(request, plan, cleanups)
    return plan


@router.get("/versions", response_model=list[VersionSummary])
async def list_versions(
    limit: int = Query(default=50, ge=1, le=200),
    before: int | None = Query(default=None, ge=1),
    user: User = Depends(require("audit.read")),
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
    version: int,
    user: User = Depends(require("audit.read")),
    session: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
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
    user: User = Depends(require("audit.read")),
    session: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    organization_id = _tenant(user)
    resources = {
        name: await resource.snapshot(session, organization_id, None)
        for name, resource in REGISTRY.items()
    }
    version = await current_version(session, organization_id)
    await session.commit()
    return {"version": version, "resources": resources}


@router.post("/versions/{version}/restore", response_model=RestoreView)
async def restore_version(
    version: int,
    payload: RestoreInput,
    request: Request,
    user: User = Depends(require("plans.create")),
    _: User = Depends(require("plans.apply")),
    session: AsyncSession = Depends(get_db),
) -> RestoreView:
    organization_id = _tenant(user)
    await lock_tenant(session, organization_id)
    if not 0 <= version <= await current_version(session, organization_id):
        raise HTTPException(status_code=404, detail="Policy version not found")
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
    changes: list[dict[str, Any]] = []
    not_restored: list[Unrestored] = []
    approximated: list[Unrestored] = []
    for name, items in targets.items():
        resource = REGISTRY.get(name)
        if resource is None:
            continue
        current = await resource.snapshot(session, organization_id, list(items))
        for item, target in items.items():
            now = current.get(item)
            if target == now:
                continue
            if now is None and not resource.creatable:
                not_restored.append(
                    Unrestored(resource=name, item=item, reason="key_revoked")
                )
                continue
            if target is None and now is not None and not resource.deletable:
                reason = _NOT_DELETABLE[name]
                if name != "deployments":
                    not_restored.append(
                        Unrestored(resource=name, item=item, reason=reason)
                    )
                    continue
                target = {**now, "enabled": False}
                if target == now:
                    continue
                approximated.append(Unrestored(resource=name, item=item, reason=reason))
            if now is None and name == "budgets":
                not_restored.append(
                    Unrestored(
                        resource=name, item=item, reason="notify_targets_not_restored"
                    )
                )
            changes.append(
                await _change(session, organization_id, name, item, now, target, 7)
            )
    plan = None
    cleanups: list[PostCommit] = []
    if changes:
        plan = await _new_plan(
            session,
            user,
            organization_id,
            changes,
            source="restore",
            reason=payload.reason,
        )
        cleanups = await _apply_plan(session, user, plan)
        await session.execute(
            update(PolicyPlan)
            .where(
                PolicyPlan.organization_id == organization_id,
                PolicyPlan.status == "applied",
                PolicyPlan.applied_version > version,
                PolicyPlan.id != plan.id,
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
    await session.commit()
    if plan is not None:
        await _after_commit(request, plan, cleanups)
    return RestoreView(
        plan=None if plan is None else PlanView.model_validate(plan),
        not_restored=not_restored,
        approximated=approximated,
    )
