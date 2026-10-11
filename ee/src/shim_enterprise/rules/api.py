"""Preview a rule before enforcing it, and import AIUC rule files as a plan."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.api.enterprise_deps import require
from shim_enterprise.api.v1.management import bounded_body
from shim_enterprise.core.database import get_db
from shim_enterprise.policy.api import PlanView, new_plan, planned_change
from shim_enterprise.policy.plans import current_version, lock_tenant
from shim_enterprise.policy.resources import REGISTRY
from shim_enterprise.rules.aiuc import AiucPolicy, map_policy
from shim_enterprise.rules.models import OrganizationRuleSet, RulePreview
from shim_enterprise.rules.preview import (
    PREVIEW_LIFETIME,
    RULE_PREVIEW_DEFAULT_DAYS,
    preview_digest,
    preview_rule,
    stored_rules,
)
from shim_enterprise.tenants.audit import record_management_action as _audit
from shim_enterprise.tenants.models import User
from shim_enterprise.tenants.permissions import user_permissions

router = APIRouter(prefix="/management/rules", tags=["rules"])


class PreviewInput(BaseModel):
    rule: dict[str, Any] = Field(description="A rule as in PUT /rules.")
    window_days: int = Field(default=RULE_PREVIEW_DEFAULT_DAYS, ge=1, le=31)


class IdCount(BaseModel):
    id: str
    requests: int


class ModelCount(BaseModel):
    model: str
    requests: int


class ByScopeView(BaseModel):
    api_keys: list[IdCount]
    teams: list[IdCount]
    models: list[ModelCount]
    truncated_rows: int


class PreviewWindow(BaseModel):
    start: datetime
    end: datetime
    days: int
    covered_days: int


class RulePreviewView(BaseModel):
    rule_id: str
    basis: Literal["metadata", "monitor_history", "none"]
    requests: int | None
    errors: int | None
    window: PreviewWindow
    by_scope: ByScopeView
    note: str | None
    enforce_on_create: bool
    preview_expires_at: datetime | None


class ImportView(BaseModel):
    plan: PlanView | None
    report: dict[str, Any]


@router.post("/preview", response_model=RulePreviewView)
async def preview(
    payload: PreviewInput,
    user: User = Depends(require("rules.write")),
    session: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    tenant_id = user.organization_id
    rule, answer = await preview_rule(
        session, tenant_id, payload.rule, payload.window_days
    )
    if answer["enforce_on_create"]:
        now = answer["window"]["end"]
        await session.execute(
            delete(RulePreview).where(
                RulePreview.organization_id == tenant_id, RulePreview.expires_at <= now
            )
        )
        answer["preview_expires_at"] = now + PREVIEW_LIFETIME
        session.add(
            RulePreview(
                organization_id=tenant_id,
                rule_id=rule.id,
                preview_digest=preview_digest(rule),
                basis=answer["basis"],
                requests=answer["requests"],
                window_days=payload.window_days,
                window_start=answer["window"]["start"],
                window_end=answer["window"]["end"],
                expires_at=answer["preview_expires_at"],
                created_by=str(user.id),
            )
        )
    await _audit(
        session,
        user,
        "tenant.rule_previewed",
        str(tenant_id),
        details={
            "rule_id": rule.id,
            "kind": rule.kind,
            "basis": answer["basis"],
            "requests": answer["requests"],
            "window_days": payload.window_days,
            "enforce_on_create": answer["enforce_on_create"],
        },
    )
    await session.commit()
    return answer


async def import_aiuc(
    payload: AiucPolicy,
    response: Response,
    user: User = Depends(require("plans.create")),
    session: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    granted = await user_permissions(session, user)
    if "rules.write" not in granted:
        raise HTTPException(status_code=403, detail="Permission required: rules.write")
    tenant_id = user.organization_id
    # Planned without the tenant lock (each change reads history); a policy write
    # in between is caught under the lock below.
    version = await current_version(session, tenant_id)
    stored = stored_rules(await session.get(OrganizationRuleSet, tenant_id))
    privacy = (await REGISTRY["privacy"].snapshot(session, tenant_id, None))["_"]
    rule_changes, privacy_after, report = map_policy(payload, stored, privacy)
    if privacy_after is not None and "settings.write" not in granted:
        raise HTTPException(
            status_code=403, detail="Permission required: settings.write"
        )
    changes = [
        await planned_change(session, tenant_id, "rules", rule_id, before, after, 7)
        for rule_id, before, after in rule_changes
    ]
    if privacy_after is not None:
        changes.append(
            await planned_change(
                session, tenant_id, "privacy", "_", privacy, privacy_after, 7
            )
        )
    await lock_tenant(session, tenant_id)
    latest = await current_version(session, tenant_id)
    if latest != version:
        raise HTTPException(
            status_code=409,
            detail={"code": "POLICY_VERSION_CHANGED", "version": latest},
        )
    plan = None
    if changes:
        plan = await new_plan(
            session,
            user,
            tenant_id,
            changes,
            source="import",
            reason="AIUC rule import",
        )
        plan.context = report
    else:
        response.status_code = 200
    await _audit(
        session,
        user,
        "tenant.rules_imported",
        str(tenant_id),
        details={
            "plan_id": None if plan is None else str(plan.id),
            "mapped": len(report["mapped"]),
            "not_mapped": len(report["not_mapped"]),
            "source_revision": report["source_revision"],
        },
    )
    await session.commit()
    return {"plan": plan, "report": report}


router.add_api_route(
    "/import/aiuc",
    import_aiuc,
    methods=["POST"],
    response_model=ImportView,
    status_code=201,
    responses={200: {"model": ImportView, "description": "Nothing would change"}},
    route_class_override=bounded_body(
        256 * 1024, "An AIUC rule file is at most 256 KB."
    ),
)
