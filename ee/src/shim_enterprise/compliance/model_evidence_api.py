"""Model evidence documents: create, list, download, and the facts behind each."""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from typing import Annotated, Any, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import AwareDatetime, BaseModel, Field, StringConstraints, model_validator
from sqlalchemy import exists, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.ai_act.audit_writer import gateway_version
from shim_enterprise.ai_act.models import AIActAuditLog
from shim_enterprise.api.enterprise_deps import require
from shim_enterprise.compliance.models import ModelEvidenceFile
from shim_enterprise.compliance.services.model_evidence import (
    collect,
    facts_digest,
    render_model_evidence_pdf,
)
from shim_enterprise.core.database import bounded_read, get_db
from shim_enterprise.rules.models import OrganizationRuleSet
from shim_enterprise.rules.preview import stored_rules
from shim_enterprise.rules.route_triggers import MAX_SHADOW_WINDOW
from shim_enterprise.tenants.audit import record_management_action as _audit
from shim.billing.pricing import DEFAULT_PRICE_BOOK
from shim_enterprise.tenants.models import ModelDeployment, User

router = APIRouter(prefix="/management/model-evidence", tags=["compliance"])
_RuleId = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,47}$")]
_Model = Annotated[str, StringConstraints(min_length=1, max_length=200)]


class EvidenceInput(BaseModel):
    kind: Literal["model_selection", "routing"]
    title: str = Field(min_length=1, max_length=120)
    note: str | None = Field(default=None, max_length=2_000)
    start: AwareDatetime
    end: AwareDatetime
    current: _Model | None = None
    candidates: list[_Model] = Field(default=[], max_length=3)
    change_tests: list[_RuleId] = Field(default=[], max_length=10)
    canaries: list[_RuleId] = Field(default=[], max_length=10)
    route_rules: list[_RuleId] = Field(default=[], max_length=20)

    @model_validator(mode="after")
    def complete(self) -> EvidenceInput:
        if not self.start < self.end <= datetime.now(timezone.utc):
            raise ValueError("start is before end, and end is not in the future")
        if self.end - self.start > MAX_SHADOW_WINDOW:
            raise ValueError("the window is at most 31 days")
        if self.kind == "model_selection" and (
            self.current is None
            or not self.candidates
            or self.current in self.candidates
        ):
            raise ValueError(
                "model_selection needs current and 1 to 3 candidates other than it"
            )
        if self.kind == "routing" and not self.route_rules:
            raise ValueError("routing needs 1 to 20 route_rules")
        return self


class EvidenceWindow(BaseModel):
    start: datetime
    end: datetime


class EvidenceView(BaseModel):
    id: UUID
    kind: str
    title: str
    window: EvidenceWindow
    sha256: str
    facts_sha256: str
    size_bytes: int
    generated_at: datetime
    generated_by: UUID | None
    audit_event_id: str
    anchored: bool


class EvidencePage(BaseModel):
    items: list[EvidenceView]
    total: int
    limit: int
    offset: int


def _view(row: Any, anchored: bool) -> dict[str, Any]:
    return {
        "id": row.id,
        "kind": row.kind,
        "title": row.title,
        "window": {"start": row.window_start, "end": row.window_end},
        "sha256": row.sha256,
        "facts_sha256": row.facts_sha256,
        "size_bytes": row.size_bytes,
        "generated_at": row.generated_at,
        "generated_by": row.generated_by,
        "audit_event_id": row.audit_event_id,
        "anchored": anchored,
    }


@router.post("", response_model=EvidenceView, status_code=201)
async def create_model_evidence(
    payload: EvidenceInput,
    user: User = Depends(require("compliance.manage")),
    session: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    tenant_id = user.organization_id
    if payload.kind == "model_selection":
        names = [payload.current, *payload.candidates]
        registered = set(
            await session.scalars(
                select(ModelDeployment.alias).where(
                    ModelDeployment.organization_id == tenant_id,
                    ModelDeployment.alias.in_(names),
                )
            )
        )
        for path, name in [("current", payload.current)] + [
            (f"candidates[{index}]", name)
            for index, name in enumerate(payload.candidates)
        ]:
            if name not in registered and not any(
                DEFAULT_PRICE_BOOK.supports(name, provider)
                for provider in ("openai", "anthropic", "google")
            ):
                raise HTTPException(
                    status_code=422,
                    detail={
                        "code": "MODEL_UNKNOWN",
                        "path": path,
                        "message": "Not a registered alias or a catalog model.",
                    },
                )
    sources = payload.model_dump(
        include={"current", "candidates", "change_tests", "canaries", "route_rules"}
    )
    now = datetime.now(timezone.utc)
    async with bounded_read(session):
        facts = await collect(
            session,
            tenant_id,
            kind=payload.kind,
            title=payload.title,
            note=payload.note,
            start=payload.start,
            end=payload.end,
            sources=sources,
            rule_set=stored_rules(await session.get(OrganizationRuleSet, tenant_id)),
            generated_at=now,
            generator_version=gateway_version(),
        )
    document_id, event_id = uuid4(), f"management:{uuid4()}"
    # The file names its audit entry, so the entry's id is chosen before rendering.
    content = await render_model_evidence_pdf(facts, event_id, str(document_id))
    digest, facts_sha256 = sha256(content).hexdigest(), facts_digest(facts)
    await _audit(
        session,
        user,
        "tenant.model_evidence_generated",
        str(document_id),
        details={
            "kind": payload.kind,
            "sha256": digest,
            "facts_sha256": facts_sha256,
            "size_bytes": len(content),
            "window_start": payload.start.isoformat(),
            "window_end": payload.end.isoformat(),
        },
        event_id=event_id,
    )
    row = ModelEvidenceFile(
        id=document_id,
        organization_id=tenant_id,
        kind=payload.kind,
        title=payload.title,
        window_start=payload.start,
        window_end=payload.end,
        sources=sources,
        facts=facts,
        facts_sha256=facts_sha256,
        sha256=digest,
        content=content,
        size_bytes=len(content),
        generated_at=now,
        generated_by=user.id,
        generator_version=gateway_version(),
        audit_event_id=event_id,
    )
    session.add(row)
    await session.commit()
    return _view(row, anchored=False)


def _anchored(tenant_id: UUID) -> Any:
    return exists().where(
        AIActAuditLog.organization_id == tenant_id,
        AIActAuditLog.request_id == ModelEvidenceFile.audit_event_id,
    )


@router.get("", response_model=EvidencePage)
async def list_model_evidence(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    user: User = Depends(require("audit.read")),
    session: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    tenant_id = user.organization_id
    owned = ModelEvidenceFile.organization_id == tenant_id
    # The listing never loads the files themselves.
    columns = [
        column
        for column in ModelEvidenceFile.__table__.columns
        if column.name not in {"content", "facts", "sources"}
    ]
    rows = await session.execute(
        select(*columns, _anchored(tenant_id).label("anchored"))
        .where(owned)
        .order_by(ModelEvidenceFile.generated_at.desc(), ModelEvidenceFile.id)
        .limit(limit)
        .offset(offset)
    )
    total = await session.scalar(select(func.count()).where(owned))
    return {
        "items": [_view(row, row.anchored) for row in rows],
        "total": total or 0,
        "limit": limit,
        "offset": offset,
    }


async def _owned(session: AsyncSession, tenant_id: UUID, document_id: UUID):
    row = await session.scalar(
        select(ModelEvidenceFile).where(
            ModelEvidenceFile.organization_id == tenant_id,
            ModelEvidenceFile.id == document_id,
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="No model evidence document")
    return row


@router.get(
    "/{document_id}",
    response_class=Response,
    responses={200: {"content": {"application/pdf": {}}, "description": "The PDF."}},
)
async def download_model_evidence(
    document_id: UUID,
    user: User = Depends(require("audit.read")),
    session: AsyncSession = Depends(get_db),
) -> Response:
    row = await _owned(session, user.organization_id, document_id)
    await _audit(
        session,
        user,
        "tenant.model_evidence_downloaded",
        str(row.id),
        details={"sha256": row.sha256},
    )
    await session.commit()
    return Response(
        row.content,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="shim-model-evidence-{row.id}.pdf"',
            "X-Content-SHA256": row.sha256,
        },
    )


@router.get("/{document_id}/facts")
async def model_evidence_facts(
    document_id: UUID,
    response: Response,
    user: User = Depends(require("audit.read")),
    session: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    row = await _owned(session, user.organization_id, document_id)
    response.headers["X-Content-SHA256"] = row.facts_sha256
    return row.facts
