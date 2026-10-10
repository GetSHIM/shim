"""The incident clock, its derived states, the OCSF export and the deadline reminders."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime, timedelta
import logging
from typing import Any, Literal
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.ai_act.models import AIActAuditLog
from shim_enterprise.billing.models import RequestLifecycle
from shim_enterprise.compliance.classification import classify
from shim_enterprise.compliance.reporting import entity_sums
from shim_enterprise.findings.models import Finding
from shim_enterprise.findings.service import OCSF_VERSION
from shim_enterprise.incidents.models import Incident, IncidentNotification
from shim_enterprise.outbox.handlers import (
    INCIDENT_DEADLINE_APPROACHING,
    INCIDENT_DEADLINE_MISSED,
)
from shim_enterprise.outbox.publisher import OutboxWriter
from shim.gateway.contracts.ids import TenantId

logger = logging.getLogger(__name__)

# Legal deadlines from becoming aware: KVKK Board decision 2019/10 and GDPR Art. 33.
# Fixed facts for the organization's counsel to confirm; None is "without undue delay".
DEADLINE_HOURS: dict[str, int | None] = {
    "kvkk_board": 72,
    "kvkk_data_subjects": None,
    "gdpr_authority": 72,
}
BREACH_REGIMES = ("kvkk_board", "kvkk_data_subjects")
REMIND_BEFORE = timedelta(hours=24)
STATUS_MOVES: dict[str, frozenset[str]] = {
    "new": frozenset({"in_progress"}),
    "in_progress": frozenset({"on_hold", "resolved"}),
    "on_hold": frozenset({"in_progress"}),
    "resolved": frozenset({"in_progress", "closed"}),
    "closed": frozenset(),
}
# OCSF Incident Finding status_id and caption per incident status.
OCSF_STATUSES = {
    "new": (1, "New"),
    "in_progress": (2, "In Progress"),
    "on_hold": (3, "On Hold"),
    "resolved": (4, "Resolved"),
    "closed": (5, "Closed"),
}
OCSF_ACTIVITIES = {"new": 1, "in_progress": 2, "on_hold": 2, "resolved": 3, "closed": 3}
NotificationState = Literal["submitted", "not_required", "overdue", "open"]
_LINK_ACTIONS = ("pii_entities", "monitored_entities", "blocked_entities")


def due_at(regime: str, aware_at: datetime) -> datetime | None:
    hours = DEADLINE_HOURS[regime]
    return None if hours is None else aware_at + timedelta(hours=hours)


def notification_state(row: IncidentNotification, now: datetime) -> NotificationState:
    if not row.required:
        return "not_required"
    if row.submissions:
        return "submitted"
    if row.due_at is not None and row.due_at < now:
        return "overdue"
    return "open"


async def link_problems(
    session: AsyncSession, tenant_id: UUID, links: dict[str, list[Any]]
) -> list[str]:
    """The link lists holding an id this organization does not have."""
    checks = (
        ("finding_ids", Finding.id, Finding.organization_id),
        ("request_ids", RequestLifecycle.request_id, RequestLifecycle.organization_id),
        ("audit_seqs", AIActAuditLog.seq, AIActAuditLog.organization_id),
    )
    problems = []
    for name, column, owner in checks:
        wanted = set(links.get(name) or ())
        if wanted and await session.scalar(
            select(func.count(func.distinct(column))).where(
                owner == tenant_id, column.in_(wanted)
            )
        ) != len(wanted):
            problems.append(name)
    return problems


async def evidence_summary(session: AsyncSession, incident: Incident) -> dict[str, Any]:
    """Computed on read from the linked rows; shim never writes it into `breach`."""
    request_ids = list(incident.links.get("request_ids") or ())
    finding_ids = list(incident.links.get("finding_ids") or ())
    window = (
        RequestLifecycle.organization_id == incident.organization_id,
        RequestLifecycle.request_id.in_(request_ids),
    )
    counts: dict[str, dict[str, int]] = {}
    providers: list[str] = []
    models: list[str] = []
    if request_ids:
        for key in _LINK_ACTIONS:
            for entity, total in await session.execute(entity_sums(key, window)):
                counts.setdefault(entity, {})[key] = int(total)
        used = (
            await session.execute(
                select(
                    func.array_agg(func.distinct(RequestLifecycle.provider)),
                    func.array_agg(
                        func.distinct(
                            func.coalesce(
                                RequestLifecycle.provider_model,
                                RequestLifecycle.requested_model,
                            )
                        )
                    ),
                ).where(*window)
            )
        ).one()
        providers = sorted(name for name in used[0] or () if name)
        models = sorted(name for name in used[1] or () if name)
    findings = (
        (
            await session.execute(
                select(Finding.id, Finding.rule_id, Finding.severity_id)
                .where(
                    Finding.organization_id == incident.organization_id,
                    Finding.id.in_(finding_ids),
                )
                .order_by(Finding.rule_id, Finding.id)
            )
        ).all()
        if finding_ids
        else []
    )
    return {
        "entity_types": [
            {
                "entity_type": entity,
                "kvkk_category": classify(entity).kvkk_category,
                "masked": by_action.get("pii_entities", 0),
                "monitored": by_action.get("monitored_entities", 0),
                "blocked": by_action.get("blocked_entities", 0),
            }
            for entity, by_action in sorted(counts.items())
        ],
        "providers": providers,
        "models": models,
        "findings": [
            {"id": str(row.id), "rule_id": row.rule_id, "severity_id": row.severity_id}
            for row in findings
        ],
    }


def _epoch_ms(value: datetime) -> int:
    return int(value.timestamp() * 1000)


def ocsf_incident_finding(
    incident: Incident,
    notifications: Sequence[IncidentNotification],
    finding_titles: dict[str, str],
    *,
    now: datetime,
) -> dict[str, Any]:
    """One OCSF 1.3.0 Incident Finding (class 2005); no breach text, no contact person."""
    activity_id = OCSF_ACTIVITIES[incident.status]
    status_id, status = OCSF_STATUSES[incident.status]
    linked = [
        {"uid": finding_id, "title": finding_titles[finding_id]}
        for finding_id in incident.links.get("finding_ids") or ()
        if finding_id in finding_titles
    ]
    record: dict[str, Any] = {
        "class_uid": 2005,
        "class_name": "Incident Finding",
        "category_uid": 2,
        "category_name": "Findings",
        "activity_id": activity_id,
        "type_uid": 200500 + activity_id,
        "time": _epoch_ms(incident.updated_at),
        "severity_id": incident.severity_id,
        "status_id": status_id,
        "status": status,
        "metadata": {
            "version": OCSF_VERSION,
            "uid": str(incident.id),
            "product": {"name": "shim", "vendor_name": "shim"},
        },
        "finding_info_list": linked
        or [{"uid": str(incident.id), "title": incident.title}],
        "desc": incident.description,
        "is_suspected_breach": incident.is_suspected_breach,
        "unmapped": {
            "notifications": [
                {
                    "regime": row.regime,
                    "due_at": None if row.due_at is None else row.due_at.isoformat(),
                    "state": notification_state(row, now),
                    "submissions": len(row.submissions),
                    "references": [item["reference"] for item in row.submissions],
                }
                for row in notifications
            ],
            "request_ids": list(incident.links.get("request_ids") or ()),
            "audit_seqs": list(incident.links.get("audit_seqs") or ()),
        },
    }
    if incident.occurred_at is not None:
        record["start_time"] = _epoch_ms(incident.occurred_at)
    if incident.owner_user_id is not None:
        record["assignee"] = {"uid": str(incident.owner_user_id)}
    return record


def _due_rows(now: datetime) -> tuple[Any, ...]:
    return (
        IncidentNotification.required.is_(True),
        IncidentNotification.due_at.is_not(None),
        IncidentNotification.due_at <= now + REMIND_BEFORE,
        func.jsonb_array_length(IncidentNotification.submissions) == 0,
        ~IncidentNotification.reminded.contains(["missed"]),
    )


async def remind_incident_deadlines(
    session_factory: Callable[[], Any], *, now: datetime
) -> tuple[int, int]:
    """Write each deadline's reminder intents once; returns intents and failed organizations."""
    async with session_factory() as session:
        tenant_ids = (
            await session.scalars(
                select(IncidentNotification.organization_id)
                .where(*_due_rows(now))
                .distinct()
                .order_by(IncidentNotification.organization_id)
            )
        ).all()
    written = failed = 0
    for tenant_id in tenant_ids:
        async with session_factory() as session:
            try:
                written += await _remind_organization(session, tenant_id, now)
                await session.commit()
            except Exception as exc:
                await session.rollback()
                failed += 1
                logger.error(
                    "Incident reminders failed organization_id=%s type=%s",
                    tenant_id,
                    type(exc).__name__,
                )
    return written, failed


async def _remind_organization(
    session: AsyncSession, tenant_id: UUID, now: datetime
) -> int:
    rows = (
        await session.execute(
            select(IncidentNotification, Incident.title)
            .join(Incident, Incident.id == IncidentNotification.incident_id)
            .where(IncidentNotification.organization_id == tenant_id, *_due_rows(now))
            .order_by(IncidentNotification.due_at, IncidentNotification.id)
            .with_for_update(of=IncidentNotification)
        )
    ).all()
    written = 0
    for row, title in rows:
        assert row.due_at is not None
        stage = "missed" if row.due_at <= now else "24h"
        if stage in row.reminded:
            continue
        await OutboxWriter().append(
            session,
            organization_id=TenantId(tenant_id),
            values={
                "event_type": INCIDENT_DEADLINE_MISSED
                if stage == "missed"
                else INCIDENT_DEADLINE_APPROACHING,
                "aggregate_type": "incident",
                "aggregate_id": str(row.incident_id),
                "idempotency_key": f"incident:{row.incident_id}:{row.regime}:{stage}",
                "payload": {
                    "organization_id": str(tenant_id),
                    "incident_id": str(row.incident_id),
                    "title": title,
                    "regime": row.regime,
                    "due_at": row.due_at.isoformat(),
                    "stage": stage,
                },
                "status": "pending",
                "next_attempt_at": now,
            },
        )
        row.reminded = [*row.reminded, stage]
        written += 1
    return written
