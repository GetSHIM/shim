"""Turn a finding's suggested action into a policy plan."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.api.enterprise_deps import require
from shim_enterprise.core.database import get_db
from shim_enterprise.findings.models import Finding
from shim_enterprise.findings.service import STATUS_IDS
from shim_enterprise.policy.api import PlanView, new_plan, planned_change
from shim_enterprise.policy.models import PolicyPlan
from shim_enterprise.policy.resources import REGISTRY
from shim_enterprise.tenants.models import User
from shim_enterprise.tenants.permissions import user_permissions

router = APIRouter(prefix="/management/findings", tags=["findings"])

_OPEN = (STATUS_IDS["new"], STATUS_IDS["in_progress"])


@router.post("/{finding_id}/plan", response_model=PlanView, status_code=201)
async def plan_from_finding(
    finding_id: UUID,
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
    action = finding.remediation.get("action")
    if finding.status_id not in _OPEN:
        raise HTTPException(status_code=409, detail="The finding is not open")
    if action is None:
        raise HTTPException(status_code=409, detail="The finding suggests no action")
    # deployment.disable is the one action kind so far.
    deployments = REGISTRY["deployments"]
    if deployments.permission not in await user_permissions(session, user):
        raise HTTPException(
            status_code=403, detail=f"Permission required: {deployments.permission}"
        )
    item = action["params"]["deployment_id"]
    before = (await deployments.snapshot(session, tenant_id, [item])).get(item)
    if before is None:
        raise HTTPException(status_code=422, detail="Item not found")
    after = await deployments.validate(session, user, item, before, {"enabled": False})
    if after == before:
        raise HTTPException(status_code=422, detail="The change sets nothing new")
    plan = await new_plan(
        session,
        user,
        tenant_id,
        [
            await planned_change(
                session, tenant_id, "deployments", item, before, after, 7
            )
        ],
        source="api",
        reason=f"finding:{finding.id}",
    )
    await session.commit()
    return plan
