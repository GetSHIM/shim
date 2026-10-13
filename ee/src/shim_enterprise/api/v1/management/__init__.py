"""JWT-authenticated tenant management API."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError

from shim_enterprise.api.enterprise_deps import ADMIN_REQUIRED, READER_REQUIRED, require
from shim.findings import Finding as FindingV1
from shim_enterprise.core.database import get_db
from shim_enterprise.findings.models import Finding
from shim_enterprise.findings.service import (
    RULES as FINDING_RULES,
    RULE_VERSION,
    RULE_VERSIONS,
    STATUS_IDS,
    STATUS_RESOLVED,
    effective_mode,
    finding_from_row,
    finding_modes,
    ocsf_detection_finding,
    rule_doc,
)
from shim_enterprise.tenants.audit import (
    change_details,
    record_management_action as _audit,
)
from shim_enterprise.tenants.gateway_settings import FindingMode
from shim_enterprise.tenants.models import User
from shim_enterprise.api.v1.management import (
    members,
    teams,
    api_keys,
    providers,
    configuration,
    record_sets,
    budgets,
    analytics,
    archive,
    activity,
    usage,
    deployments,
)
from shim_enterprise.api.v1.management._common import (
    _MAX_SYNC_REQUEST_EXPORT_ROWS,
    _tenant_id,
)


router = APIRouter()


# Finding v1's status, or the workflow state v0.3.0 used, in the filter and the PATCH alike.
FindingStatus = Literal[
    "open", "dismissed", "resolved", "new", "in_progress", "suppressed"
]
_FINDING_STATUS_IDS: dict[str, tuple[int, ...]] = {
    "open": (STATUS_IDS["new"], STATUS_IDS["in_progress"]),
    "dismissed": (STATUS_IDS["suppressed"],),
    **{name: (status_id,) for name, status_id in STATUS_IDS.items()},
}
_FINDING_STATUSES = {value: name for name, value in STATUS_IDS.items()}


class FindingPage(BaseModel):
    items: list[FindingV1]
    total: int
    limit: int
    offset: int


class FindingPatch(BaseModel):
    status: FindingStatus


def _finding_filters(
    user: User,
    status_filter: FindingStatus | None,
    rule_id: str | None,
    severity_id: int | None,
) -> list[Any]:
    filters = [Finding.organization_id == _tenant_id(user)]
    if status_filter is not None:
        filters.append(Finding.status_id.in_(_FINDING_STATUS_IDS[status_filter]))
    if rule_id is not None:
        filters.append(Finding.rule_id == rule_id)
    if severity_id is not None:
        filters.append(Finding.severity_id == severity_id)
    return filters


@router.get("/findings", response_model=FindingPage)
async def list_findings(
    status_filter: FindingStatus | None = Query(default=None, alias="status"),
    rule_id: str | None = Query(default=None, min_length=1, max_length=64),
    severity_id: int | None = Query(default=None, ge=1, le=5),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    user: User = Depends(require("findings.read", legacy_detail=READER_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> FindingPage:
    filters = _finding_filters(user, status_filter, rule_id, severity_id)
    total = await session.scalar(select(func.count(Finding.id)).where(*filters))
    rows = await session.scalars(
        select(Finding)
        .where(*filters)
        .order_by(Finding.last_seen_at.desc(), Finding.id)
        .limit(limit)
        .offset(offset)
    )
    return FindingPage(
        items=[finding_from_row(row) for row in rows],
        total=total or 0,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/findings/export",
    response_class=Response,
    responses={
        200: {
            "content": {"application/x-ndjson": {}},
            "description": "One OCSF Detection Finding per line.",
        }
    },
)
async def export_findings(
    status_filter: FindingStatus | None = Query(default=None, alias="status"),
    rule_id: str | None = Query(default=None, min_length=1, max_length=64),
    severity_id: int | None = Query(default=None, ge=1, le=5),
    user: User = Depends(require("findings.read", legacy_detail=READER_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> Response:
    rows = (
        await session.scalars(
            select(Finding)
            .where(*_finding_filters(user, status_filter, rule_id, severity_id))
            .order_by(Finding.last_seen_at.desc(), Finding.id)
            .limit(_MAX_SYNC_REQUEST_EXPORT_ROWS + 1)
        )
    ).all()
    if len(rows) > _MAX_SYNC_REQUEST_EXPORT_ROWS:
        raise HTTPException(
            status_code=422,
            detail=(
                "synchronous finding exports are limited to "
                f"{_MAX_SYNC_REQUEST_EXPORT_ROWS} rows"
            ),
        )
    body = "".join(
        json.dumps(ocsf_detection_finding(row), separators=(",", ":")) + "\n"
        for row in rows
    )
    return Response(body, media_type="application/x-ndjson")


class FindingRuleView(BaseModel):
    rule_id: str
    rule_version: int
    max_mode: FindingMode
    action_kind: str | None
    mode: FindingMode
    effective_mode: FindingMode
    unavailable_reason: Literal["auto_executor_not_installed"] | None
    open_findings: int


# Before /findings/{finding_id}, which would take rules for an id.
@router.get("/findings/rules", response_model=list[FindingRuleView])
async def finding_rules(
    user: User = Depends(require("findings.read", legacy_detail=READER_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> list[FindingRuleView]:
    tenant_id = _tenant_id(user)
    modes = await finding_modes(session, tenant_id)
    open_counts = {
        rule_id: count
        for rule_id, count in await session.execute(
            select(Finding.rule_id, func.count())
            .where(
                Finding.organization_id == tenant_id,
                Finding.status_id != STATUS_RESOLVED,
            )
            .group_by(Finding.rule_id)
        )
    }
    return [
        FindingRuleView(
            rule_id=rule_id,
            rule_version=RULE_VERSIONS.get(rule_id, RULE_VERSION),
            max_mode=spec.MAX_MODE,
            action_kind=spec.ACTION_KIND,
            mode=modes.get(rule_id, "observe"),
            effective_mode=effective_mode(rule_id, modes),
            unavailable_reason="auto_executor_not_installed"
            if modes.get(rule_id) == "auto"
            else None,
            open_findings=open_counts.get(rule_id, 0),
        )
        for rule_id, spec in sorted(FINDING_RULES.items())
    ]


@router.get("/findings/{finding_id}", response_model=FindingV1)
async def get_finding(
    finding_id: UUID,
    user: User = Depends(require("findings.read", legacy_detail=READER_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> FindingV1:
    return finding_from_row(await _owned_finding(session, user, finding_id, lock=False))


class FindingRuleFacts(BaseModel):
    rule_id: str
    rule_version: int
    title: str
    max_mode: FindingMode
    action_kind: str | None
    blast_radius: str
    playbook: str
    doc: str | None = Field(
        description="The rule's section of FINDINGS.md (markdown, at most 16 KB); "
        "null when the rule has none."
    )


class FindingExplanation(BaseModel):
    finding: FindingV1
    rule: FindingRuleFacts | None = Field(
        description="Null for a rule this build no longer knows."
    )


@router.get("/findings/{finding_id}/explain", response_model=FindingExplanation)
async def explain_finding(
    finding_id: UUID,
    user: User = Depends(require("findings.read", legacy_detail=READER_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> FindingExplanation:
    # The facts an agent explains a finding from; shim calls no model.
    row = await _owned_finding(session, user, finding_id, lock=False)
    spec = FINDING_RULES.get(row.rule_id)
    return FindingExplanation(
        finding=finding_from_row(row),
        rule=None
        if spec is None
        else FindingRuleFacts(
            rule_id=row.rule_id,
            rule_version=RULE_VERSIONS.get(row.rule_id, RULE_VERSION),
            title=spec.TITLE,
            max_mode=spec.MAX_MODE,
            action_kind=spec.ACTION_KIND,
            blast_radius=spec.BLAST_RADIUS,
            playbook=spec.PLAYBOOK,
            doc=rule_doc(row.rule_id),
        ),
    )


@router.patch("/findings/{finding_id}", response_model=FindingV1)
async def update_finding(
    finding_id: UUID,
    patch: FindingPatch,
    user: User = Depends(require("findings.manage", legacy_detail=ADMIN_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> FindingV1:
    finding = await _owned_finding(session, user, finding_id, lock=True)
    before = _FINDING_STATUSES[finding.status_id]
    allowed = _FINDING_STATUS_IDS[patch.status]
    # "open" keeps an open finding's workflow state and reopens a closed one as new.
    target = finding.status_id if finding.status_id in allowed else allowed[0]
    conflict = HTTPException(
        status_code=409, detail="Another open finding exists for this subject"
    )
    if finding.status_id == STATUS_RESOLVED and target != STATUS_RESOLVED:
        if await session.scalar(
            select(Finding.id).where(
                Finding.organization_id == finding.organization_id,
                Finding.rule_id == finding.rule_id,
                Finding.subject_key == finding.subject_key,
                Finding.status_id != STATUS_RESOLVED,
            )
        ):
            raise conflict
    if target != finding.status_id:
        finding.status_id = target
        resolved = target == STATUS_RESOLVED
        finding.resolved_at = datetime.now(timezone.utc) if resolved else None
        finding.resolved_by = str(user.id) if resolved else None
        try:
            # The worker can open a finding for this subject after the check.
            await session.flush()
        except IntegrityError as exc:
            await session.rollback()
            if getattr(exc.orig, "sqlstate", None) == "23505":
                raise conflict from exc
            raise
        await _audit(
            session,
            user,
            "tenant.finding_status_changed",
            str(finding.id),
            details={
                "rule_id": finding.rule_id,
                **change_details(
                    {"status": before}, {"status": _FINDING_STATUSES[target]}
                ),
            },
        )
        await session.commit()
        await session.refresh(finding)
    return finding_from_row(finding)


async def _owned_finding(
    session: AsyncSession, user: User, finding_id: UUID, *, lock: bool
) -> Finding:
    statement = select(Finding).where(
        Finding.id == finding_id, Finding.organization_id == _tenant_id(user)
    )
    finding = await session.scalar(
        statement.with_for_update(of=Finding) if lock else statement
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


for _module in (
    members,
    teams,
    api_keys,
    providers,
    configuration,
    record_sets,
    budgets,
    analytics,
    archive,
    activity,
    usage,
    deployments,
):
    router.include_router(_module.router)
