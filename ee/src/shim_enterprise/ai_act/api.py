"""Authenticated tenant API for audit evidence and asynchronous oversight."""

from __future__ import annotations

import asyncio
from datetime import date, datetime, timedelta, timezone
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.ai_act.anchor import write_anchor
from shim_enterprise.ai_act.bundle import build_audit_bundle
from shim_enterprise.ai_act.models import (
    AIActAuditLog,
    OversightPolicy,
    OversightRequest,
)
from shim_enterprise.ai_act.overview import build_overview, empty_overview
from shim_enterprise.ai_act.oversight import (
    OversightStateError,
    decide,
    expire_pending,
    run_oversight_evaluation,
    validate_trigger,
)
from shim_enterprise.ai_act.report import FRAMEWORK_ORDER, generate_audit_report
from shim_enterprise.ai_act.schemas import (
    AnchorResult,
    AuditLogPage,
    AuditLogRead,
    AuditReportRequest,
    MonthlyEvidenceRead,
    OversightDecision,
    OversightPolicyCreate,
    OversightPolicyRead,
    OversightPolicyUpdate,
    OversightRequestRead,
    OverviewResponse,
    VerifyResult,
)
from shim_enterprise.ai_act.verify import (
    AuditVerificationLimitExceeded,
    verify_anchors,
    verify_chain,
)
from shim_enterprise.api.enterprise_deps import get_org_admin, get_org_reader
from shim_enterprise.compliance.models import MonthlyEvidenceFile
from shim_enterprise.core.config import settings
from shim_enterprise.core.database import get_db
from shim_enterprise.tenants.audit import change_details, export_details
from shim_enterprise.tenants.audit import record_management_action as _audit
from shim_enterprise.tenants.models import Organization, User


router = APIRouter(prefix="/compliance", tags=["ai-act-control-plane"])
_FRAMEWORKS = frozenset(FRAMEWORK_ORDER)
_MAX_SYNC_WINDOW = timedelta(days=31)
_REPORT_RESPONSES: dict[int | str, dict[str, Any]] = {
    200: {
        "description": "PDF or CSV report attachment.",
        "content": {
            "application/pdf": {"schema": {"type": "string", "format": "binary"}},
            "text/csv": {"schema": {"type": "string", "format": "binary"}},
        },
        "headers": {
            "Content-Disposition": {
                "description": "Attachment disposition and filename.",
                "schema": {"type": "string"},
            }
        },
    }
}


async def _tenant_for_write(session: AsyncSession, user: User) -> UUID:
    if user.organization_id is None:
        raise HTTPException(
            status_code=403,
            detail="A tenant membership is required.",
        )
    try:
        tenant = await session.get(Organization, user.organization_id)
        if tenant is None:
            raise ValueError("user references an unavailable tenant")
        await session.commit()
    except Exception:
        await session.rollback()
        raise HTTPException(
            status_code=503,
            detail="Tenant state is unavailable.",
        ) from None
    return tenant.id


def _validate_sync_window(start: datetime | None, end: datetime | None) -> None:
    if start is None or end is None:
        return
    if start > end:
        raise HTTPException(status_code=422, detail="start must not be after end")
    if end - start > _MAX_SYNC_WINDOW:
        raise HTTPException(
            status_code=422,
            detail="synchronous operations are limited to 31 days",
        )


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _validate_policy_trigger(trigger: dict[str, object]) -> None:
    try:
        validate_trigger(trigger)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None


def _policy_facts(policy: OversightPolicy) -> dict[str, Any]:
    return {
        "name": policy.name,
        "enabled": policy.enabled,
        "mode": policy.mode,
        "trigger": policy.trigger,
        "ttl_seconds": policy.ttl_seconds,
        "default_on_timeout": policy.default_on_timeout,
    }


async def _tenant_policy(
    session: AsyncSession,
    tenant_id: UUID,
    policy_id: UUID,
) -> OversightPolicy:
    policy = (
        await session.execute(
            select(OversightPolicy).where(
                OversightPolicy.organization_id == tenant_id,
                OversightPolicy.id == policy_id,
            )
        )
    ).scalar_one_or_none()
    if policy is None:
        raise HTTPException(status_code=404, detail="Oversight policy not found.")
    return policy


@router.get("/overview", response_model=OverviewResponse)
async def compliance_overview(
    start: datetime | None = Query(default=None),
    end: datetime | None = Query(default=None),
    current_user: User = Depends(get_org_reader),
    session: AsyncSession = Depends(get_db),
) -> OverviewResponse:
    if start is not None and end is not None and start > end:
        raise HTTPException(status_code=422, detail="start must not be after end")
    if current_user.organization_id is None:
        return OverviewResponse.model_validate(empty_overview())
    projection = await build_overview(
        session,
        current_user.organization_id,
        start,
        end,
    )
    return OverviewResponse.model_validate(projection)


@router.get("/audit/logs", response_model=AuditLogPage)
async def list_audit_logs(
    request_id: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    start: datetime | None = Query(default=None),
    end: datetime | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_org_reader),
    session: AsyncSession = Depends(get_db),
) -> AuditLogPage:
    if start is not None and end is not None and start > end:
        raise HTTPException(status_code=422, detail="start must not be after end")
    tenant_id = current_user.organization_id
    if tenant_id is None:
        return AuditLogPage(items=[], total=0, limit=limit, offset=offset)
    statement = select(AIActAuditLog).where(AIActAuditLog.organization_id == tenant_id)
    filters = (
        (AIActAuditLog.request_id == request_id) if request_id else None,
        (AIActAuditLog.event_type == event_type) if event_type else None,
        (AIActAuditLog.created_at >= start) if start else None,
        (AIActAuditLog.created_at <= end) if end else None,
    )
    for condition in filters:
        if condition is not None:
            statement = statement.where(condition)
    total = int(
        await session.scalar(select(func.count()).select_from(statement.subquery()))
        or 0
    )
    rows = (
        await session.execute(
            statement.order_by(AIActAuditLog.seq.desc()).limit(limit).offset(offset)
        )
    ).scalars()
    return AuditLogPage(
        items=[AuditLogRead.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/audit/bundle",
    response_class=JSONResponse,
    responses={
        200: {"description": "A `shim.audit.bundle` v1 evidence file."},
        404: {"description": "No audit rows in the requested window."},
        422: {"description": "Window rejected or above the synchronous limits."},
    },
)
async def export_audit_bundle(
    start: datetime | None = Query(default=None),
    end: datetime | None = Query(default=None),
    current_user: User = Depends(get_org_reader),
    session: AsyncSession = Depends(get_db),
) -> JSONResponse:
    start = _aware(start) if start is not None else None
    end = _aware(end) if end is not None else None
    if start is not None and end is not None and start > end:
        raise HTTPException(status_code=422, detail="start must not be after end")
    tenant_id = current_user.organization_id
    bundle = None
    if tenant_id is not None:
        try:
            bundle = await build_audit_bundle(
                session, tenant_id, start=start, end=end, now=datetime.now(timezone.utc)
            )
        except AuditVerificationLimitExceeded as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
    if bundle is None:
        raise HTTPException(
            status_code=404, detail="No audit rows in the requested window."
        )
    # The event reaches the chain through the outbox, after this export was read.
    await _audit(
        session,
        current_user,
        "compliance.audit_bundle_exported",
        str(tenant_id),
        details=export_details(start, end, rows=bundle["row_count"]),
    )
    await session.commit()
    # Rendering tens of megabytes of JSON stays off the event loop.
    return await asyncio.to_thread(
        JSONResponse,
        bundle,
        headers={
            "Content-Disposition": (
                f'attachment; filename="shim-audit-bundle-{tenant_id}.json"'
            )
        },
    )


@router.get("/evidence/monthly", response_model=list[MonthlyEvidenceRead])
async def list_monthly_evidence(
    current_user: User = Depends(get_org_reader),
    session: AsyncSession = Depends(get_db),
) -> list[MonthlyEvidenceRead]:
    # The listing never loads the files themselves.
    rows = await session.execute(
        select(
            MonthlyEvidenceFile.period,
            MonthlyEvidenceFile.kind,
            MonthlyEvidenceFile.format,
            MonthlyEvidenceFile.size_bytes,
            MonthlyEvidenceFile.sha256,
            MonthlyEvidenceFile.generated_at,
        )
        .where(MonthlyEvidenceFile.organization_id == current_user.organization_id)
        .order_by(MonthlyEvidenceFile.period.desc(), MonthlyEvidenceFile.kind)
    )
    return [MonthlyEvidenceRead.model_validate(row) for row in rows]


@router.get(
    "/evidence/monthly/{period}",
    response_class=Response,
    responses={
        200: {"content": {"application/pdf": {}}, "description": "The PDF."},
        404: {"description": "No file of this kind for this period."},
    },
)
async def download_monthly_evidence(
    period: str = Path(pattern=r"^[0-9]{4}-(0[1-9]|1[0-2])$"),
    kind: Literal["monthly", "monthly_partial"] = Query(default="monthly"),
    current_user: User = Depends(get_org_reader),
    session: AsyncSession = Depends(get_db),
) -> Response:
    stored = await session.scalar(
        select(MonthlyEvidenceFile).where(
            MonthlyEvidenceFile.organization_id == current_user.organization_id,
            MonthlyEvidenceFile.kind == kind,
            MonthlyEvidenceFile.period == period,
        )
    )
    if stored is None:
        raise HTTPException(status_code=404, detail="No evidence file for this period")
    await _audit(
        session,
        current_user,
        "tenant.evidence_downloaded",
        str(stored.id),
        details={"kind": kind, "period": period, "sha256": stored.sha256},
    )
    await session.commit()
    return Response(
        stored.content,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="shim-evidence-{kind}-{period}.pdf"'
            ),
            "X-Content-SHA256": stored.sha256,
        },
    )


@router.post("/audit/verify", response_model=VerifyResult)
async def verify_audit_chain(
    start: datetime | None = Query(default=None, alias="from"),
    end: datetime | None = Query(default=None, alias="to"),
    current_user: User = Depends(get_org_reader),
    session: AsyncSession = Depends(get_db),
) -> VerifyResult:
    start = _aware(start) if start is not None else None
    end = _aware(end) if end is not None else None
    _validate_sync_window(start, end)
    tenant_id = await _tenant_for_write(session, current_user)
    try:
        chain = await verify_chain(session, tenant_id, start=start, end=end)
        anchors = await verify_anchors(
            session,
            tenant_id,
            start=start,
            end=end,
        )
    except AuditVerificationLimitExceeded as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    ok = bool(chain["ok"] and anchors["ok"])
    await _audit(
        session,
        current_user,
        "compliance.audit_verified",
        str(tenant_id),
        details=export_details(start, end, rows=chain["rows_checked"], ok=ok),
    )
    await session.commit()
    return VerifyResult.model_validate(
        {
            "ok": ok,
            "chain_start": chain["chain_start"],
            "rows_checked": chain["rows_checked"],
            "first_break": chain["first_break"],
            "last_verified_seq": chain["last_verified_seq"],
            "anchors_checked": anchors["anchors_checked"],
            "anchor_mismatches": anchors["mismatches"],
        }
    )


@router.post(
    "/reports/audit",
    response_class=Response,
    responses=_REPORT_RESPONSES,
)
async def generate_audit_report_endpoint(
    payload: AuditReportRequest,
    current_user: User = Depends(get_org_reader),
    session: AsyncSession = Depends(get_db),
) -> Response:
    requested = list(dict.fromkeys(payload.frameworks))
    if not requested or any(item not in _FRAMEWORKS for item in requested):
        raise HTTPException(
            status_code=422,
            detail="frameworks contain an unsupported value",
        )
    end = _aware(payload.end or datetime.now(timezone.utc))
    start = _aware(payload.start or end - timedelta(days=30))
    _validate_sync_window(start, end)
    tenant_id = await _tenant_for_write(session, current_user)
    try:
        content, media_type, filename = await generate_audit_report(
            session,
            org_id=tenant_id,
            frameworks=requested,
            start=start,
            end=end,
            connector_id=payload.connector_id,
            fmt=payload.format,
        )
    except AuditVerificationLimitExceeded as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    await _audit(
        session,
        current_user,
        "compliance.audit_report_generated",
        str(tenant_id),
        details=export_details(
            start,
            end,
            frameworks=requested,
            format=payload.format,
            connector_id=(
                str(payload.connector_id) if payload.connector_id is not None else None
            ),
        ),
    )
    await session.commit()
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post(
    "/oversight/policies",
    response_model=OversightPolicyRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_oversight_policy(
    payload: OversightPolicyCreate,
    current_user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
) -> OversightPolicyRead:
    _validate_policy_trigger(payload.trigger)
    tenant_id = await _tenant_for_write(session, current_user)
    policy = OversightPolicy(
        organization_id=tenant_id,
        name=payload.name,
        enabled=payload.enabled,
        mode="flag",
        trigger=payload.trigger,
        ttl_seconds=payload.ttl_seconds or settings.OVERSIGHT_DEFAULT_TTL_SECONDS,
        default_on_timeout=payload.default_on_timeout,
    )
    session.add(policy)
    await session.flush()
    await _audit(
        session,
        current_user,
        "compliance.oversight_policy_created",
        str(policy.id),
        details=change_details(None, _policy_facts(policy)),
    )
    await session.commit()
    await session.refresh(policy)
    return OversightPolicyRead.model_validate(policy)


@router.get("/oversight/policies", response_model=list[OversightPolicyRead])
async def list_oversight_policies(
    current_user: User = Depends(get_org_reader),
    session: AsyncSession = Depends(get_db),
) -> list[OversightPolicyRead]:
    if current_user.organization_id is None:
        return []
    rows = (
        await session.execute(
            select(OversightPolicy)
            .where(OversightPolicy.organization_id == current_user.organization_id)
            .order_by(OversightPolicy.created_at.desc())
        )
    ).scalars()
    return [OversightPolicyRead.model_validate(row) for row in rows]


@router.patch(
    "/oversight/policies/{policy_id}",
    response_model=OversightPolicyRead,
)
async def update_oversight_policy(
    policy_id: UUID,
    payload: OversightPolicyUpdate,
    current_user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
) -> OversightPolicyRead:
    tenant_id = current_user.organization_id
    if tenant_id is None:
        raise HTTPException(status_code=404, detail="Oversight policy not found.")
    policy = await _tenant_policy(session, tenant_id, policy_id)
    updates = payload.model_dump(exclude_unset=True, exclude_none=True)
    if "trigger" in updates:
        _validate_policy_trigger(updates["trigger"])
    before = _policy_facts(policy)
    for field, value in updates.items():
        setattr(policy, field, value)
    await _audit(
        session,
        current_user,
        "compliance.oversight_policy_updated",
        str(policy.id),
        details=change_details(before, _policy_facts(policy)),
    )
    await session.commit()
    await session.refresh(policy)
    return OversightPolicyRead.model_validate(policy)


@router.delete(
    "/oversight/policies/{policy_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_oversight_policy(
    policy_id: UUID,
    current_user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
) -> Response:
    tenant_id = current_user.organization_id
    if tenant_id is None:
        raise HTTPException(status_code=404, detail="Oversight policy not found.")
    policy = await _tenant_policy(session, tenant_id, policy_id)
    await _audit(
        session,
        current_user,
        "compliance.oversight_policy_deleted",
        str(policy.id),
        details=change_details(_policy_facts(policy), None),
    )
    await session.delete(policy)
    await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/oversight", response_model=list[OversightRequestRead])
async def list_oversight_requests(
    status_filter: Literal["pending", "approved", "rejected", "expired"] | None = Query(
        default=None,
        alias="status",
    ),
    limit: int = Query(default=100, ge=1, le=500),
    current_user: User = Depends(get_org_reader),
    session: AsyncSession = Depends(get_db),
) -> list[OversightRequestRead]:
    tenant_id = current_user.organization_id
    if tenant_id is None:
        return []
    statement = select(OversightRequest).where(
        OversightRequest.organization_id == tenant_id
    )
    if status_filter is not None:
        statement = statement.where(OversightRequest.status == status_filter)
    rows = (
        await session.execute(
            statement.order_by(OversightRequest.created_at.desc()).limit(limit)
        )
    ).scalars()
    return [OversightRequestRead.model_validate(row) for row in rows]


@router.post(
    "/oversight/{request_id}/decision",
    response_model=OversightRequestRead,
)
async def decide_oversight_request(
    request_id: UUID,
    payload: OversightDecision,
    current_user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
) -> OversightRequestRead:
    tenant_id = await _tenant_for_write(session, current_user)
    try:
        request = await decide(
            session,
            request_id,
            tenant_id,
            decision=payload.decision,
            note=payload.note,
            approver=str(current_user.id),
        )
    except OversightStateError as exc:
        code = 404 if "not found" in str(exc) else 409
        raise HTTPException(
            status_code=code,
            detail=(
                "Oversight request not found."
                if code == 404
                else "Oversight request is no longer pending."
            ),
        ) from None
    await session.commit()
    await session.refresh(request)
    return OversightRequestRead.model_validate(request)


@router.post("/oversight/evaluate")
async def trigger_oversight_evaluation(
    current_user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
) -> dict[str, int]:
    tenant_id = await _tenant_for_write(session, current_user)
    created = await run_oversight_evaluation(session, org_id=tenant_id)
    expired = await expire_pending(session, org_id=tenant_id)
    await _audit(
        session,
        current_user,
        "compliance.oversight_evaluated",
        str(tenant_id),
        details={**created, **expired},
    )
    await session.commit()
    return {**created, **expired}


@router.post("/audit/anchor", response_model=AnchorResult)
async def trigger_anchor(
    anchor_date: date | None = Query(default=None),
    current_user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
) -> AnchorResult:
    today = datetime.now(timezone.utc).date()
    target = anchor_date or today - timedelta(days=1)
    if target >= today:
        raise HTTPException(
            status_code=422,
            detail="anchor_date must be before today",
        )
    tenant_id = await _tenant_for_write(session, current_user)
    anchor = await write_anchor(session, tenant_id, target)
    await _audit(
        session,
        current_user,
        "compliance.audit_anchored",
        str(tenant_id),
        details={
            "anchor_date": target.isoformat(),
            "row_count": anchor.row_count if anchor is not None else 0,
        },
    )
    await session.commit()
    if anchor is None:
        return AnchorResult(
            anchor_date=target.isoformat(),
            root_hash=None,
            row_count=0,
        )
    return AnchorResult(
        anchor_date=anchor.anchor_date.isoformat(),
        root_hash=anchor.root_hash,
        row_count=anchor.row_count,
        external_ref=anchor.external_ref,
    )
