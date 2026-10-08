"""The four gateway rules, their evaluation, and the OCSF form of a finding."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import logging
from typing import Any
from uuid import UUID

from sqlalchemy import ARRAY, Text, func, select, type_coerce, update
from sqlalchemy.dialects.postgresql import aggregate_order_by, insert
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.billing.models import RequestLifecycle, UsageLedger
from shim_enterprise.findings.models import Finding
from shim_enterprise.tenants.models import ModelDeployment, Organization


logger = logging.getLogger(__name__)

RETRY_STORM = "gateway.retry_storm"
REPEAT_SPEND = "gateway.repeat_spend"
UNUSED_DEPLOYMENT = "gateway.unused_deployment"
ANSWER_QUALITY = "gateway.answer_quality"
RULE_VERSION = 1

RETRY_BUCKET = timedelta(minutes=15)
RETRY_BUCKETS = 4
RETRY_STORM_MIN_REQUESTS = 20
REPEAT_SPEND_MIN_SHARE = Decimal("0.10")
REPEAT_SPEND_MIN_USD = Decimal("1")
UNUSED_DEPLOYMENT_AGE = timedelta(days=30)
ANSWER_QUALITY_WINDOW = timedelta(hours=24)
ANSWER_QUALITY_MIN_REQUESTS = 50
ANSWER_QUALITY_MIN_RATE = Decimal("0.05")
AUTO_RESOLVE_AFTER = timedelta(days=7)
EVIDENCE_REQUEST_IDS = 20

STATUS_IDS = {"new": 1, "in_progress": 2, "suppressed": 3, "resolved": 4}
STATUS_RESOLVED = STATUS_IDS["resolved"]
OCSF_VERSION = "1.3.0"

# Rule id: (title, OCSF severity_id, remediation text). Every fix is reversible,
# and its doc is the rule's section of ee/docs/FINDINGS.md.
RULES: dict[str, tuple[str, int, str]] = {
    RETRY_STORM: (
        "Retry storm from one API key",
        3,
        "Find the client behind this key and make it back off: honour "
        "Retry-After, add jittered exponential backoff and cap retries. When "
        "abandoned requests co-occur, raise the client's timeout above the "
        "model's answer time instead of retrying.",
    ),
    REPEAT_SPEND: (
        "Repeated requests are a large share of a key's spend",
        3,
        "Stop resending identical requests from this key: retry only on "
        "retryable errors, deduplicate in the client, or cache the answer.",
    ),
    UNUSED_DEPLOYMENT: (
        "Registered deployment receives no traffic",
        2,
        "Disable or delete the deployment if nobody uses it, or point callers "
        "at its alias.",
    ),
    ANSWER_QUALITY: (
        "A model often truncates, refuses or returns empty answers",
        2,
        "For truncation, raise the output token limit or shorten the expected "
        "answer; for empty or refused answers, review the prompt and the "
        "model choice.",
    ),
}

_EPOCH = datetime(2000, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True, slots=True)
class Detection:
    rule_id: str
    subject_key: str
    subject: dict[str, Any]
    summary: str
    evidence: dict[str, Any]
    impact: dict[str, Any] | None = None


def _request_ids(condition: Any) -> Any:
    ordered = func.array_agg(
        aggregate_order_by(RequestLifecycle.request_id, RequestLifecycle.started_at)
    ).filter(condition)
    return type_coerce(ordered, ARRAY(Text))[1:EVIDENCE_REQUEST_IDS]


# A request has at most one spend settlement (one spend reservation per request,
# read with scalar_one_or_none by the ledger, and one settlement per reservation),
# so this join never repeats a lifecycle row.
_PRICED_SETTLEMENT = (
    (UsageLedger.organization_id == RequestLifecycle.organization_id)
    & (UsageLedger.request_id == RequestLifecycle.request_id)
    & (UsageLedger.event_type == "spend_settlement")
    & UsageLedger.event_metadata["pricing"]["pricing_resolution"]
    .as_string()
    .is_distinct_from("unknown")
)


def _repeated() -> Any:
    return RequestLifecycle.lifecycle_metadata["repeat_chain_length"].as_integer() >= 2


async def _retry_storms(
    session: AsyncSession, tenant_id: UUID, now: datetime
) -> list[Detection]:
    bucket = func.date_bin(RETRY_BUCKET, RequestLifecycle.started_at, _EPOCH)
    current = _EPOCH + (now - _EPOCH) // RETRY_BUCKET * RETRY_BUCKET
    repeated = _repeated()
    count = func.count().filter(repeated)
    rows = await session.execute(
        select(
            RequestLifecycle.api_key_id,
            bucket.label("bucket"),
            count.label("repeated"),
            func.count()
            .filter(RequestLifecycle.status.in_(("client_disconnected", "timeout")))
            .label("abandoned"),
            func.coalesce(
                func.sum(UsageLedger.cost_usd).filter(repeated), Decimal("0")
            ).label("cost"),
            _request_ids(repeated).label("request_ids"),
        )
        .select_from(RequestLifecycle)
        .outerjoin(UsageLedger, _PRICED_SETTLEMENT)
        .where(
            RequestLifecycle.organization_id == tenant_id,
            RequestLifecycle.started_at >= current - RETRY_BUCKET * (RETRY_BUCKETS - 1),
            RequestLifecycle.started_at <= now,
            RequestLifecycle.api_key_id.is_not(None),
        )
        .group_by(RequestLifecycle.api_key_id, bucket)
        .having(count >= RETRY_STORM_MIN_REQUESTS)
        .order_by(RequestLifecycle.api_key_id, count.desc(), bucket.desc())
    )
    worst: dict[UUID, Any] = {}
    for row in rows:
        worst.setdefault(row.api_key_id, row)
    return [
        Detection(
            rule_id=RETRY_STORM,
            subject_key=f"api_key:{key_id}",
            subject={"api_key_id": str(key_id)},
            summary=(
                f"One API key sent {row.repeated} repeated requests in the 15 minutes "
                f"from {row.bucket:%Y-%m-%d %H:%M} UTC."
            ),
            evidence={
                "window_start": row.bucket.isoformat(),
                "window_minutes": 15,
                "repeated_requests": row.repeated,
                "threshold": RETRY_STORM_MIN_REQUESTS,
                "abandoned_requests": row.abandoned,
                "request_ids": list(row.request_ids or []),
            },
            impact={"cost_usd": str(row.cost), "requests": row.repeated},
        )
        for key_id, row in worst.items()
    ]


async def _repeat_spend(
    session: AsyncSession, tenant_id: UUID, now: datetime
) -> list[Detection]:
    month_start = now.astimezone(timezone.utc).replace(
        day=1, hour=0, minute=0, second=0, microsecond=0
    )
    repeated = _repeated()
    known = func.coalesce(func.sum(UsageLedger.cost_usd), Decimal("0"))
    repeated_cost = func.coalesce(
        func.sum(UsageLedger.cost_usd).filter(repeated), Decimal("0")
    )
    rows = await session.execute(
        select(
            RequestLifecycle.api_key_id,
            known.label("known"),
            repeated_cost.label("repeated_cost"),
            func.count().filter(repeated).label("repeated"),
            _request_ids(repeated).label("request_ids"),
        )
        .select_from(RequestLifecycle)
        .outerjoin(UsageLedger, _PRICED_SETTLEMENT)
        .where(
            RequestLifecycle.organization_id == tenant_id,
            RequestLifecycle.started_at >= month_start,
            RequestLifecycle.started_at <= now,
            RequestLifecycle.api_key_id.is_not(None),
        )
        .group_by(RequestLifecycle.api_key_id)
        .having(
            repeated_cost >= REPEAT_SPEND_MIN_USD,
            repeated_cost >= known * REPEAT_SPEND_MIN_SHARE,
        )
        .order_by(RequestLifecycle.api_key_id)
    )
    return [
        Detection(
            rule_id=REPEAT_SPEND,
            subject_key=f"api_key:{row.api_key_id}",
            subject={"api_key_id": str(row.api_key_id)},
            summary=(
                f"Repeated requests cost {row.repeated_cost:.2f} USD of this API "
                f"key's {row.known:.2f} USD known spend this month."
            ),
            evidence={
                "period_start": month_start.isoformat(),
                "repeated_cost_usd": str(row.repeated_cost),
                "known_spend_usd": str(row.known),
                "share": str(round(row.repeated_cost / row.known, 4)),
                "repeated_requests": row.repeated,
                "request_ids": list(row.request_ids or []),
            },
            impact={"cost_usd": str(row.repeated_cost), "requests": row.repeated},
        )
        for row in rows
    ]


async def _unused_deployments(
    session: AsyncSession, tenant_id: UUID, now: datetime
) -> list[Detection]:
    since = now - UNUSED_DEPLOYMENT_AGE
    deployments = (
        await session.execute(
            select(
                ModelDeployment.id, ModelDeployment.alias, ModelDeployment.created_at
            )
            .where(
                ModelDeployment.organization_id == tenant_id,
                ModelDeployment.enabled.is_(True),
                ModelDeployment.created_at <= since,
            )
            .order_by(ModelDeployment.alias)
        )
    ).all()
    if not deployments:
        return []
    used = set(
        await session.scalars(
            select(RequestLifecycle.requested_model)
            .where(
                RequestLifecycle.organization_id == tenant_id,
                RequestLifecycle.started_at >= since,
                RequestLifecycle.requested_model.in_(
                    [row.alias for row in deployments]
                ),
            )
            .group_by(RequestLifecycle.requested_model)
        )
    )
    return [
        Detection(
            rule_id=UNUSED_DEPLOYMENT,
            subject_key=f"deployment:{row.alias}",
            subject={"deployment_id": str(row.id), "alias": row.alias},
            summary=f"Deployment {row.alias} has had no requests in 30 days.",
            evidence={
                "created_at": row.created_at.isoformat(),
                "window_days": UNUSED_DEPLOYMENT_AGE.days,
                "requests": 0,
            },
        )
        for row in deployments
        if row.alias not in used
    ]


async def _answer_quality(
    session: AsyncSession, tenant_id: UUID, now: datetime
) -> list[Detection]:
    model = func.coalesce(
        RequestLifecycle.provider_model, RequestLifecycle.requested_model
    )
    outcome = RequestLifecycle.lifecycle_metadata["completion_outcome"].as_string()
    settled = func.count().filter(outcome.is_not(None))
    rows = await session.execute(
        select(
            model.label("model"),
            settled.label("settled"),
            func.count().filter(outcome == "truncated").label("truncated"),
            func.count().filter(outcome == "empty").label("empty"),
            func.count().filter(outcome == "refused").label("refused"),
            _request_ids(outcome.in_(("truncated", "empty", "refused"))).label(
                "request_ids"
            ),
        )
        .where(
            RequestLifecycle.organization_id == tenant_id,
            RequestLifecycle.started_at >= now - ANSWER_QUALITY_WINDOW,
            RequestLifecycle.started_at <= now,
        )
        .group_by(model)
        .having(settled >= ANSWER_QUALITY_MIN_REQUESTS)
        .order_by(model)
    )
    detections = []
    for row in rows:
        truncated_rate = Decimal(row.truncated) / row.settled
        unanswered_rate = Decimal(row.empty + row.refused) / row.settled
        if max(truncated_rate, unanswered_rate) < ANSWER_QUALITY_MIN_RATE:
            continue
        detections.append(
            Detection(
                rule_id=ANSWER_QUALITY,
                subject_key=f"model:{row.model}",
                subject={"model": row.model},
                summary=(
                    f"In the last 24 hours {row.model} truncated {row.truncated} and "
                    f"left empty or refused {row.empty + row.refused} of "
                    f"{row.settled} answers."
                ),
                evidence={
                    "window_hours": 24,
                    "settled_requests": row.settled,
                    "truncated": row.truncated,
                    "empty": row.empty,
                    "refused": row.refused,
                    "truncated_rate": str(round(truncated_rate, 4)),
                    "empty_or_refused_rate": str(round(unanswered_rate, 4)),
                    "threshold_rate": str(ANSWER_QUALITY_MIN_RATE),
                    "request_ids": list(row.request_ids or []),
                },
            )
        )
    return detections


async def evaluate_organization(
    session: AsyncSession, tenant_id: UUID, *, now: datetime
) -> list[Detection]:
    detections = [
        detection
        for rule in (_retry_storms, _repeat_spend, _unused_deployments, _answer_quality)
        for detection in await rule(session, tenant_id, now)
    ]
    for detection in detections:
        title, severity_id, fix = RULES[detection.rule_id]
        statement = insert(Finding).values(
            organization_id=tenant_id,
            rule_id=detection.rule_id,
            rule_version=RULE_VERSION,
            subject_key=detection.subject_key,
            subject=detection.subject,
            title=title,
            summary=detection.summary,
            severity_id=severity_id,
            first_seen_at=now,
            last_seen_at=now,
            evidence=detection.evidence,
            impact=detection.impact,
            remediation={
                "text": fix,
                "reversible": True,
                "doc": f"ee/docs/FINDINGS.md#{detection.rule_id.replace('.', '')}",
            },
        )
        await session.execute(
            statement.on_conflict_do_update(
                index_elements=["organization_id", "rule_id", "subject_key"],
                index_where=Finding.status_id != STATUS_RESOLVED,
                set_={
                    "last_seen_at": now,
                    "occurrences": Finding.occurrences + 1,
                    "summary": statement.excluded.summary,
                    "evidence": statement.excluded.evidence,
                    "impact": statement.excluded.impact,
                    "updated_at": func.now(),
                },
            )
        )
    await session.execute(
        update(Finding)
        .where(
            Finding.organization_id == tenant_id,
            Finding.status_id != STATUS_RESOLVED,
            Finding.last_seen_at < now - AUTO_RESOLVE_AFTER,
        )
        .values(status_id=STATUS_RESOLVED, resolved_at=now, resolved_by="system")
    )
    return detections


async def evaluate_findings(
    session_factory: Callable[[], Any], *, now: datetime
) -> None:
    """Evaluate every rule for every active organization, one transaction each."""
    async with session_factory() as session:
        tenant_ids = (
            await session.scalars(
                select(Organization.id).where(Organization.archived_at.is_(None))
            )
        ).all()
    for tenant_id in tenant_ids:
        async with session_factory() as session:
            try:
                await evaluate_organization(session, tenant_id, now=now)
                await session.commit()
            except Exception as exc:
                await session.rollback()
                logger.error(
                    "Findings evaluation failed organization_id=%s type=%s",
                    tenant_id,
                    type(exc).__name__,
                )


def ocsf_detection_finding(finding: Finding) -> dict[str, Any]:
    if finding.status_id == STATUS_RESOLVED:
        activity_id = 3
    elif finding.occurrences > 1 or finding.status_id != STATUS_IDS["new"]:
        activity_id = 2
    else:
        activity_id = 1
    return {
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "category_uid": 2,
        "category_name": "Findings",
        "activity_id": activity_id,
        "type_uid": 200400 + activity_id,
        "time": _epoch_ms(finding.resolved_at or finding.last_seen_at),
        "severity_id": finding.severity_id,
        "status_id": finding.status_id,
        "metadata": {
            "version": OCSF_VERSION,
            "product": {"name": "shim", "vendor_name": "shim"},
        },
        "finding_info": {
            "uid": str(finding.id),
            "title": finding.title,
            "desc": finding.summary,
            "first_seen_time": _epoch_ms(finding.first_seen_at),
            "last_seen_time": _epoch_ms(finding.last_seen_at),
        },
        "unmapped": {
            "rule_id": finding.rule_id,
            "rule_version": finding.rule_version,
            "subject": finding.subject,
            "occurrences": finding.occurrences,
            "evidence": finding.evidence,
            "impact": finding.impact,
            "remediation": finding.remediation,
        },
    }


def _epoch_ms(value: datetime) -> int:
    return int(value.timestamp() * 1000)
