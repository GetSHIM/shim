"""Turn a finding's suggested action into a policy plan."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.api.enterprise_deps import require
from shim_enterprise.core.database import get_db
from shim_enterprise.findings.models import Finding
from shim_enterprise.findings.service import STATUS_IDS
from shim_enterprise.policy.api import (
    PlanView,
    authorize_change,
    new_plan,
    plan_source,
    planned_change,
)
from shim_enterprise.policy.models import PolicyPlan
from shim_enterprise.policy.resources import REGISTRY
from shim_enterprise.tenants.models import User

router = APIRouter(prefix="/management/findings", tags=["findings"])

_OPEN = (STATUS_IDS["new"], STATUS_IDS["in_progress"])


async def finding_changes(
    session: AsyncSession, actor: User, finding: Finding
) -> list[dict[str, Any]]:
    """The planned changes that make an open finding's suggested action."""
    tenant_id = finding.organization_id
    action = finding.remediation.get("action")
    if finding.status_id not in _OPEN:
        raise HTTPException(status_code=409, detail="The finding is not open")
    if action is None:
        raise HTTPException(status_code=409, detail="The finding suggests no action")
    # deployment.disable is the one action kind so far; anything else stored (a newer
    # build's kind, a broken row) is refused, never guessed.
    item = action.get("params", {}).get("deployment_id")
    if action.get("kind") != "deployment.disable" or not isinstance(item, str):
        raise HTTPException(
            status_code=409, detail="This build cannot plan the finding's action"
        )
    deployments = REGISTRY["deployments"]
    await authorize_change(session, actor, deployments)
    before = (await deployments.snapshot(session, tenant_id, [item])).get(item)
    if before is None:
        raise HTTPException(status_code=422, detail="Item not found")
    after = await deployments.validate(session, actor, item, before, {"enabled": False})
    if after == before:
        raise HTTPException(status_code=422, detail="The change sets nothing new")
    return [
        await planned_change(session, tenant_id, "deployments", item, before, after, 7)
    ]


@router.post("/{finding_id}/plan", response_model=PlanView, status_code=201)
async def plan_from_finding(
    finding_id: UUID,
    request: Request,
    user: User = Depends(require("plans.create")),
    session: AsyncSession = Depends(get_db),
) -> PolicyPlan:
    tenant_id = user.organization_id
    finding = await session.scalar(
        select(Finding).where(
            Finding.organization_id == tenant_id, Finding.id == finding_id
        )
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    plan = await new_plan(
        session,
        user,
        tenant_id,
        await finding_changes(session, user, finding),
        source=plan_source(request, user),
        reason=f"finding:{finding.id}",
    )
    await session.commit()
    return plan
