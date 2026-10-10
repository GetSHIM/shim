"""Incidents: the record, its notification clock and its OCSF export."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.api.enterprise_deps import (
    ADMIN_REQUIRED,
    READER_REQUIRED,
    require,
)
from shim_enterprise.core.database import get_db
from shim_enterprise.findings.models import Finding
from shim_enterprise.incidents.models import (
    Incident,
    IncidentNotification,
    IncidentStatus,
    Regime,
)
from shim_enterprise.incidents.service import (
    BREACH_REGIMES,
    STATUS_MOVES,
    due_at,
    evidence_summary,
    link_problems,
    notification_state,
    ocsf_incident_finding,
)
from shim_enterprise.tenants.audit import record_management_action as _audit
from shim_enterprise.tenants.models import User

router = APIRouter(prefix="/compliance/incidents", tags=["compliance"])

MAX_LINKS = 100
MAX_SUBMISSIONS = 20
MAX_EXPORT_ROWS = 10_000
BreachField = Literal[
    "data_categories",
    "approx_subjects",
    "approx_records",
    "likely_consequences",
    "measures_taken",
    "measures_planned",
    "contact_person",
    "subjects_informed",
    "subjects_informed_how",
]
_READ = require("incidents.read", legacy_detail=READER_REQUIRED)
_MANAGE = require("incidents.manage", legacy_detail=ADMIN_REQUIRED)


class Breach(BaseModel):
    """The breach register fields; the organization's own text, never exported."""

    model_config = ConfigDict(extra="forbid")

    data_categories: list[Annotated[str, Field(max_length=100)]] | None = Field(
        default=None, max_length=20
    )
    approx_subjects: str | None = Field(default=None, max_length=100)
    approx_records: str | None = Field(default=None, max_length=100)
    likely_consequences: str | None = Field(default=None, max_length=2000)
    measures_taken: str | None = Field(default=None, max_length=2000)
    measures_planned: str | None = Field(default=None, max_length=2000)
    contact_person: str | None = Field(default=None, max_length=200)
    subjects_informed: bool | None = None
    subjects_informed_how: str | None = Field(default=None, max_length=500)


class Links(BaseModel):
    """References only: no content is copied from the linked rows."""

    model_config = ConfigDict(extra="forbid")

    finding_ids: list[UUID] = Field(default_factory=list, max_length=MAX_LINKS)
    request_ids: list[Annotated[str, Field(min_length=1, max_length=255)]] = Field(
        default_factory=list, max_length=MAX_LINKS
    )
    audit_seqs: list[Annotated[int, Field(ge=1)]] = Field(
        default_factory=list, max_length=MAX_LINKS
    )


class IncidentInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=2000)
    severity_id: int = Field(ge=1, le=5)
    owner_user_id: UUID | None = None
    occurred_at: datetime | None = None
    aware_at: datetime | None = Field(
        default=None, description="When the organization became aware; defaults to now."
    )
    is_suspected_breach: bool = False
    breach: Breach = Field(default_factory=Breach)
    links: Links = Field(default_factory=Links)


class IncidentPatch(BaseModel):
    """Only the fields sent change; each link list replaces the stored one."""

    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    severity_id: int | None = Field(default=None, ge=1, le=5)
    owner_user_id: UUID | None = None
    occurred_at: datetime | None = None
    aware_at: datetime | None = None
    is_suspected_breach: bool | None = None
    breach: Breach | None = None
    links: Links | None = None

    @model_validator(mode="after")
    def required_fields_stay_set(self) -> IncidentPatch:
        for name in (
            "title",
            "description",
            "severity_id",
            "aware_at",
            "is_suspected_breach",
            "breach",
            "links",
        ):
            if name in self.model_fields_set and getattr(self, name) is None:
                raise ValueError(f"{name} cannot be null")
        return self


class StatusChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: IncidentStatus
    note: str | None = Field(default=None, max_length=1000)


class NotificationInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    required: bool = True
    not_required_reason: str | None = Field(default=None, min_length=1, max_length=1000)

    @model_validator(mode="after")
    def reason_when_not_required(self) -> NotificationInput:
        if not self.required and self.not_required_reason is None:
            raise ValueError("A notification that is not required needs a reason")
        return self


class SubmissionInput(BaseModel):
    """Information sent in stages; shim records it and sends nothing itself."""

    model_config = ConfigDict(extra="forbid")

    submitted_at: datetime | None = Field(
        default=None, description="When the information was sent; defaults to now."
    )
    reference: str = Field(min_length=1, max_length=200)
    fields_sent: list[BreachField] = Field(default_factory=list)
    note: str | None = Field(default=None, max_length=1000)
    late_reason: str | None = Field(default=None, min_length=1, max_length=1000)


class NotificationView(BaseModel):
    regime: Regime
    due_at: datetime | None
    required: bool
    not_required_reason: str | None
    state: Literal["submitted", "not_required", "overdue", "open"]
    submissions: list[dict[str, Any]]
    reminded: list[str]


class IncidentView(BaseModel):
    id: UUID
    title: str
    description: str
    severity_id: int
    status: IncidentStatus
    owner_user_id: UUID | None
    opened_by: str
    occurred_at: datetime | None
    aware_at: datetime
    is_suspected_breach: bool
    breach: dict[str, Any]
    links: dict[str, Any]
    resolved_at: datetime | None
    closed_at: datetime | None
    created_at: datetime
    updated_at: datetime
    notifications: list[NotificationView]
    evidence_summary: dict[str, Any] | None = Field(
        default=None,
        description="Entity types, providers, models and findings of the linked "
        "rows, computed on read; suggests data_categories, never written into breach.",
    )


class IncidentPage(BaseModel):
    items: list[IncidentView]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=200)
    offset: int = Field(ge=0)


_INCIDENT_FIELDS = tuple(
    name
    for name in IncidentView.model_fields
    if name not in {"notifications", "evidence_summary"}
)
_NOTIFICATION_FIELDS = tuple(
    name for name in NotificationView.model_fields if name != "state"
)


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _check_dates(
    occurred_at: datetime | None, aware_at: datetime, now: datetime
) -> None:
    if aware_at > now:
        raise HTTPException(422, "aware_at cannot be in the future")
    if occurred_at is not None and occurred_at > aware_at:
        raise HTTPException(422, "occurred_at cannot be after aware_at")


async def _check_references(
    session: AsyncSession, tenant_id: UUID, links: Links, owner_user_id: UUID | None
) -> None:
    problems = await link_problems(session, tenant_id, links.model_dump(mode="json"))
    if problems:
        raise HTTPException(
            422, f"links.{problems[0]} holds ids this organization does not have"
        )
    if owner_user_id is not None and not await session.scalar(
        select(User.id).where(
            User.id == owner_user_id, User.organization_id == tenant_id
        )
    ):
        raise HTTPException(422, "owner_user_id is not a member of this organization")


async def _owned(
    session: AsyncSession, user: User, incident_id: UUID, *, write: bool
) -> Incident:
    statement = select(Incident).where(
        Incident.id == incident_id, Incident.organization_id == user.organization_id
    )
    incident = await session.scalar(statement.with_for_update() if write else statement)
    if incident is None:
        raise HTTPException(404, "Incident not found")
    if write and incident.status == "closed":
        raise HTTPException(409, "A closed incident cannot change; open a new one")
    return incident


async def _notifications(
    session: AsyncSession, incident_ids: list[UUID]
) -> dict[UUID, list[IncidentNotification]]:
    rows: dict[UUID, list[IncidentNotification]] = {}
    for row in await session.scalars(
        select(IncidentNotification)
        .where(IncidentNotification.incident_id.in_(incident_ids))
        .order_by(IncidentNotification.regime)
    ):
        rows.setdefault(row.incident_id, []).append(row)
    return rows


def _view(
    incident: Incident,
    notifications: list[IncidentNotification],
    now: datetime,
    summary: dict[str, Any] | None = None,
) -> IncidentView:
    return IncidentView.model_validate(
        {
            **{name: getattr(incident, name) for name in _INCIDENT_FIELDS},
            "notifications": [
                {
                    **{name: getattr(row, name) for name in _NOTIFICATION_FIELDS},
                    "state": notification_state(row, now),
                }
                for row in notifications
            ],
            "evidence_summary": summary,
        }
    )


async def _detail(session: AsyncSession, incident: Incident) -> IncidentView:
    await session.refresh(incident)
    rows = await _notifications(session, [incident.id])
    return _view(
        incident,
        rows.get(incident.id, []),
        datetime.now(timezone.utc),
        await evidence_summary(session, incident),
    )


async def _sync_clock(
    session: AsyncSession, incident: Incident, *, aware_changed: bool
) -> None:
    """Create the breach duties once flagged; move deadlines nobody has met yet."""
    rows = (await _notifications(session, [incident.id])).get(incident.id, [])
    present = {row.regime for row in rows}
    if incident.is_suspected_breach:
        for regime in BREACH_REGIMES:
            if regime not in present:
                session.add(
                    IncidentNotification(
                        organization_id=incident.organization_id,
                        incident_id=incident.id,
                        regime=regime,
                        due_at=due_at(regime, incident.aware_at),
                    )
                )
    if aware_changed:
        for row in rows:
            if not row.submissions:
                row.due_at = due_at(row.regime, incident.aware_at)


def _filters(
    user: User,
    status_filter: IncidentStatus | None,
    severity_id: int | None,
    suspected_breach: bool | None,
) -> list[Any]:
    filters: list[Any] = [Incident.organization_id == user.organization_id]
    if status_filter is not None:
        filters.append(Incident.status == status_filter)
    if severity_id is not None:
        filters.append(Incident.severity_id == severity_id)
    if suspected_breach is not None:
        filters.append(Incident.is_suspected_breach.is_(suspected_breach))
    return filters


@router.get("", response_model=IncidentPage)
async def list_incidents(
    status_filter: IncidentStatus | None = Query(default=None, alias="status"),
    severity_id: int | None = Query(default=None, ge=1, le=5),
    suspected_breach: bool | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    user: User = Depends(_READ),
    session: AsyncSession = Depends(get_db),
) -> IncidentPage:
    filters = _filters(user, status_filter, severity_id, suspected_breach)
    total = await session.scalar(select(func.count(Incident.id)).where(*filters))
    incidents = (
        await session.scalars(
            select(Incident)
            .where(*filters)
            .order_by(Incident.updated_at.desc(), Incident.id)
            .limit(limit)
            .offset(offset)
        )
    ).all()
    rows = await _notifications(session, [incident.id for incident in incidents])
    now = datetime.now(timezone.utc)
    return IncidentPage(
        items=[_view(item, rows.get(item.id, []), now) for item in incidents],
        total=total or 0,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/export",
    response_class=Response,
    responses={
        200: {
            "content": {"application/x-ndjson": {}},
            "description": "One OCSF Incident Finding per line.",
        }
    },
)
async def export_incidents(
    status_filter: IncidentStatus | None = Query(default=None, alias="status"),
    severity_id: int | None = Query(default=None, ge=1, le=5),
    suspected_breach: bool | None = Query(default=None),
    user: User = Depends(_READ),
    session: AsyncSession = Depends(get_db),
) -> Response:
    incidents = (
        await session.scalars(
            select(Incident)
            .where(*_filters(user, status_filter, severity_id, suspected_breach))
            .order_by(Incident.updated_at.desc(), Incident.id)
            .limit(MAX_EXPORT_ROWS + 1)
        )
    ).all()
    if len(incidents) > MAX_EXPORT_ROWS:
        raise HTTPException(
            422, f"synchronous incident exports are limited to {MAX_EXPORT_ROWS} rows"
        )
    rows = await _notifications(session, [incident.id for incident in incidents])
    finding_ids = {
        UUID(item)
        for incident in incidents
        for item in incident.links.get("finding_ids") or ()
    }
    titles = {
        str(finding_id): title
        for finding_id, title in await session.execute(
            select(Finding.id, Finding.title).where(
                Finding.organization_id == user.organization_id,
                Finding.id.in_(finding_ids),
            )
        )
    }
    now = datetime.now(timezone.utc)
    body = "".join(
        json.dumps(
            ocsf_incident_finding(incident, rows.get(incident.id, []), titles, now=now),
            separators=(",", ":"),
        )
        + "\n"
        for incident in incidents
    )
    return Response(body, media_type="application/x-ndjson")


@router.get("/{incident_id}", response_model=IncidentView)
async def get_incident(
    incident_id: UUID,
    user: User = Depends(_READ),
    session: AsyncSession = Depends(get_db),
) -> IncidentView:
    return await _detail(session, await _owned(session, user, incident_id, write=False))


@router.post("", response_model=IncidentView, status_code=201)
async def open_incident(
    payload: IncidentInput,
    user: User = Depends(_MANAGE),
    session: AsyncSession = Depends(get_db),
) -> IncidentView:
    now = datetime.now(timezone.utc)
    aware_at = _utc(payload.aware_at or now)
    occurred_at = None if payload.occurred_at is None else _utc(payload.occurred_at)
    _check_dates(occurred_at, aware_at, now)
    await _check_references(
        session, user.organization_id, payload.links, payload.owner_user_id
    )
    incident = Incident(
        organization_id=user.organization_id,
        title=payload.title,
        description=payload.description,
        severity_id=payload.severity_id,
        owner_user_id=payload.owner_user_id,
        opened_by=str(user.id),
        occurred_at=occurred_at,
        aware_at=aware_at,
        is_suspected_breach=payload.is_suspected_breach,
        breach=payload.breach.model_dump(mode="json", exclude_none=True),
        links=payload.links.model_dump(mode="json"),
    )
    session.add(incident)
    await session.flush()
    await _sync_clock(session, incident, aware_changed=False)
    await _audit(
        session,
        user,
        "tenant.incident_opened",
        str(incident.id),
        details={
            "severity_id": incident.severity_id,
            "is_suspected_breach": incident.is_suspected_breach,
        },
    )
    await session.commit()
    return await _detail(session, incident)


@router.patch("/{incident_id}", response_model=IncidentView)
async def update_incident(
    incident_id: UUID,
    patch: IncidentPatch,
    user: User = Depends(_MANAGE),
    session: AsyncSession = Depends(get_db),
) -> IncidentView:
    incident = await _owned(session, user, incident_id, write=True)
    sent = patch.model_fields_set
    now = datetime.now(timezone.utc)
    aware_at = _utc(patch.aware_at) if patch.aware_at else incident.aware_at
    occurred_at = (
        (None if patch.occurred_at is None else _utc(patch.occurred_at))
        if "occurred_at" in sent
        else incident.occurred_at
    )
    _check_dates(occurred_at, aware_at, now)
    links = patch.links or Links.model_validate(incident.links)
    await _check_references(
        session,
        user.organization_id,
        links,
        patch.owner_user_id if "owner_user_id" in sent else None,
    )
    values: dict[str, Any] = {
        name: getattr(patch, name)
        for name in sent
        if name not in {"aware_at", "occurred_at", "breach", "links"}
    }
    values["aware_at"], values["occurred_at"] = aware_at, occurred_at
    if patch.breach is not None:
        values["breach"] = patch.breach.model_dump(mode="json", exclude_none=True)
    if patch.links is not None:
        values["links"] = patch.links.model_dump(mode="json")
    changed = sorted(
        name for name, value in values.items() if getattr(incident, name) != value
    )
    details: dict[str, Any] = {"fields": changed}
    if "aware_at" in changed:
        details["aware_at"] = {
            "before": incident.aware_at.isoformat(),
            "after": aware_at.isoformat(),
        }
    for name in changed:
        setattr(incident, name, values[name])
    await _sync_clock(session, incident, aware_changed="aware_at" in changed)
    if changed:
        await _audit(
            session, user, "tenant.incident_updated", str(incident.id), details=details
        )
    await session.commit()
    return await _detail(session, incident)


@router.post("/{incident_id}/status", response_model=IncidentView)
async def change_incident_status(
    incident_id: UUID,
    change: StatusChange,
    user: User = Depends(_MANAGE),
    session: AsyncSession = Depends(get_db),
) -> IncidentView:
    incident = await _owned(session, user, incident_id, write=True)
    before = incident.status
    if change.status not in STATUS_MOVES[before]:
        raise HTTPException(
            409, f"An incident cannot move from {before} to {change.status}"
        )
    now = datetime.now(timezone.utc)
    incident.status = change.status
    if change.status == "resolved":
        incident.resolved_at = now
    elif change.status == "in_progress" and before == "resolved":
        incident.resolved_at = None
    elif change.status == "closed":
        incident.closed_at = now
    await _audit(
        session,
        user,
        "tenant.incident_status_changed",
        str(incident.id),
        details={"before": before, "after": change.status, "note": change.note},
    )
    await session.commit()
    return await _detail(session, incident)


@router.put("/{incident_id}/notifications/{regime}", response_model=IncidentView)
async def set_incident_notification(
    incident_id: UUID,
    regime: Regime,
    payload: NotificationInput,
    user: User = Depends(_MANAGE),
    session: AsyncSession = Depends(get_db),
) -> IncidentView:
    incident = await _owned(session, user, incident_id, write=True)
    row = await session.scalar(
        select(IncidentNotification).where(
            IncidentNotification.incident_id == incident.id,
            IncidentNotification.regime == regime,
        )
    )
    if row is None:
        row = IncidentNotification(
            organization_id=incident.organization_id,
            incident_id=incident.id,
            regime=regime,
            due_at=due_at(regime, incident.aware_at),
        )
        session.add(row)
    row.required = payload.required
    row.not_required_reason = None if payload.required else payload.not_required_reason
    await _audit(
        session,
        user,
        "tenant.incident_notification_recorded",
        str(incident.id),
        details={"regime": regime, "required": payload.required},
    )
    await session.commit()
    return await _detail(session, incident)


@router.post(
    "/{incident_id}/notifications/{regime}/submissions",
    response_model=IncidentView,
    status_code=201,
)
async def record_incident_submission(
    incident_id: UUID,
    regime: Regime,
    payload: SubmissionInput,
    user: User = Depends(_MANAGE),
    session: AsyncSession = Depends(get_db),
) -> IncidentView:
    incident = await _owned(session, user, incident_id, write=True)
    row = await session.scalar(
        select(IncidentNotification)
        .where(
            IncidentNotification.incident_id == incident.id,
            IncidentNotification.regime == regime,
        )
        .with_for_update()
    )
    if row is None:
        raise HTTPException(404, "This incident has no notification row for the regime")
    if len(row.submissions) >= MAX_SUBMISSIONS:
        raise HTTPException(
            422, f"A notification holds at most {MAX_SUBMISSIONS} submissions"
        )
    now = datetime.now(timezone.utc)
    submitted_at = _utc(payload.submitted_at or now)
    if submitted_at > now:
        raise HTTPException(422, "submitted_at cannot be in the future")
    if row.due_at is not None and submitted_at > row.due_at and not payload.late_reason:
        raise HTTPException(422, "A submission after the deadline needs late_reason")
    row.submissions = [
        *row.submissions,
        {
            "submitted_at": submitted_at.isoformat(),
            "reference": payload.reference,
            "fields_sent": list(dict.fromkeys(payload.fields_sent)),
            "note": payload.note,
            "late_reason": payload.late_reason,
            "recorded_by": str(user.id),
        },
    ]
    await _audit(
        session,
        user,
        "tenant.incident_notification_recorded",
        str(incident.id),
        details={"regime": regime, "reference": payload.reference},
    )
    await session.commit()
    return await _detail(session, incident)
