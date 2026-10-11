"""The four gateway rules, their evaluation, and the OCSF form of a finding."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
import logging
from typing import Any, Literal, cast
from uuid import UUID

from sqlalchemy import ARRAY, Text, func, select, type_coerce, update
from sqlalchemy.dialects.postgresql import aggregate_order_by, insert
from sqlalchemy.ext.asyncio import AsyncSession

from shim.findings import (
    EvidenceRef,
    Finding as FindingV1,
    Impact,
    Remediation,
    Subject,
    Text as FindingText,
    Window,
)
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

SEVERITIES = ("informational", "low", "medium", "high", "critical")


@dataclass(frozen=True, slots=True)
class RuleSpec:
    """A rule's constant text and ladder facts; templates take measurement names only."""

    TITLE: str
    SEVERITY_ID: int
    SUMMARY: Mapping[str, str]
    REMEDIATION_TEXT: Mapping[str, str]
    MAX_MODE: Literal["observe", "suggest", "auto"]
    REVERSIBLE: bool
    BLAST_RADIUS: Literal["key", "team", "deployment", "model", "tenant", "app"]
    RISK_CLASS: Literal["privacy", "cost", "reliability", "quality"]
    PLAYBOOK: str


def _playbook(rule_id: str) -> str:
    return f"ee/docs/FINDINGS.md#{rule_id.replace('.', '')}"


RULES: dict[str, RuleSpec] = {
    RETRY_STORM: RuleSpec(
        TITLE="Retry storm from one API key",
        SEVERITY_ID=3,
        SUMMARY={
            "en": "One API key sent {repeated_requests} repeated requests within "
            "{window_minutes} minutes; the threshold is {threshold}.",
            "tr": "Bir API anahtarı {window_minutes} dakika içinde "
            "{repeated_requests} tekrarlanan istek gönderdi; eşik {threshold}.",
        },
        REMEDIATION_TEXT={
            "en": "Find the client behind this key and make it back off: honour "
            "Retry-After, add jittered exponential backoff and cap retries. When "
            "abandoned requests co-occur, raise the client's timeout above the "
            "model's answer time instead of retrying.",
            "tr": "Bu anahtarın arkasındaki istemciyi bulun ve geri çekilmesini "
            "sağlayın: Retry-After başlığına uyun, rastgele gecikmeli üstel geri "
            "çekilme ekleyin ve yeniden denemeleri sınırlayın. Yarıda bırakılan "
            "istekler de varsa yeniden denemek yerine istemcinin zaman aşımını "
            "modelin yanıt süresinin üstüne çıkarın.",
        },
        MAX_MODE="suggest",
        REVERSIBLE=True,
        BLAST_RADIUS="key",
        RISK_CLASS="cost",
        PLAYBOOK=_playbook(RETRY_STORM),
    ),
    REPEAT_SPEND: RuleSpec(
        TITLE="Repeated requests are a large share of a key's spend",
        SEVERITY_ID=3,
        SUMMARY={
            "en": "Repeated requests cost {repeated_cost_usd:.2f} USD of this API "
            "key's {known_spend_usd:.2f} USD known spend this month.",
            "tr": "Tekrarlanan istekler bu API anahtarının bu ayki "
            "{known_spend_usd:.2f} USD bilinen harcamasının "
            "{repeated_cost_usd:.2f} USD tutarındaki kısmını oluşturdu.",
        },
        REMEDIATION_TEXT={
            "en": "Stop resending identical requests from this key: retry only on "
            "retryable errors, deduplicate in the client, or cache the answer.",
            "tr": "Bu anahtardan aynı istekleri yeniden göndermeyi durdurun: yalnızca "
            "yeniden denenebilir hatalarda yeniden deneyin, istemcide "
            "tekilleştirin ya da yanıtı önbelleğe alın.",
        },
        MAX_MODE="suggest",
        REVERSIBLE=True,
        BLAST_RADIUS="key",
        RISK_CLASS="cost",
        PLAYBOOK=_playbook(REPEAT_SPEND),
    ),
    UNUSED_DEPLOYMENT: RuleSpec(
        TITLE="Registered deployment receives no traffic",
        SEVERITY_ID=2,
        SUMMARY={
            "en": "This deployment has had no requests in {window_days} days.",
            "tr": "Bu dağıtım {window_days} gündür hiç istek almadı.",
        },
        REMEDIATION_TEXT={
            "en": "Disable or delete the deployment if nobody uses it, or point "
            "callers at its alias.",
            "tr": "Kimse kullanmıyorsa dağıtımı devre dışı bırakın ya da silin; ya "
            "da çağıranları takma adına yönlendirin.",
        },
        MAX_MODE="auto",
        REVERSIBLE=True,
        BLAST_RADIUS="deployment",
        RISK_CLASS="cost",
        PLAYBOOK=_playbook(UNUSED_DEPLOYMENT),
    ),
    ANSWER_QUALITY: RuleSpec(
        TITLE="A model often truncates, refuses or returns empty answers",
        SEVERITY_ID=2,
        SUMMARY={
            "en": "In the last {window_hours} hours this model truncated "
            "{truncated}, left empty {empty} and refused {refused} of "
            "{settled_requests} answers.",
            "tr": "Son {window_hours} saatte bu model {settled_requests} yanıttan "
            "{truncated} tanesini kesti, {empty} tanesini boş bıraktı ve "
            "{refused} tanesini reddetti.",
        },
        REMEDIATION_TEXT={
            "en": "For truncation, raise the output token limit or shorten the "
            "expected answer; for empty or refused answers, review the prompt and "
            "the model choice.",
            "tr": "Kesilme için çıktı token sınırını yükseltin ya da beklenen yanıtı "
            "kısaltın; boş ya da reddedilen yanıtlar için istemi ve model seçimini "
            "gözden geçirin.",
        },
        MAX_MODE="observe",
        REVERSIBLE=True,
        BLAST_RADIUS="model",
        RISK_CLASS="quality",
        PLAYBOOK=_playbook(ANSWER_QUALITY),
    ),
}


def measurements(evidence: Mapping[str, Any]) -> dict[str, int | float]:
    """The numbers of a row's evidence; request ids and other strings stay out."""

    values: dict[str, int | float] = {}
    for name, value in evidence.items():
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            values[name] = value
        elif isinstance(value, (float, str)):
            try:
                number = Decimal(str(value))
            except InvalidOperation:
                continue
            if number.is_finite():
                values[name] = float(number)
    return values


def render(template: str, values: Mapping[str, int | float]) -> str:
    return template.format(**values)


_EPOCH = datetime(2000, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True, slots=True)
class Detection:
    rule_id: str
    subject_key: str
    subject: dict[str, Any]
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
        spec = RULES[detection.rule_id]
        statement = insert(Finding).values(
            organization_id=tenant_id,
            rule_id=detection.rule_id,
            rule_version=RULE_VERSION,
            subject_key=detection.subject_key,
            subject=detection.subject,
            title=spec.TITLE,
            summary=render(spec.SUMMARY["en"], measurements(detection.evidence)),
            severity_id=spec.SEVERITY_ID,
            first_seen_at=now,
            last_seen_at=now,
            evidence=detection.evidence,
            impact=detection.impact,
            remediation={
                "text": spec.REMEDIATION_TEXT["en"],
                "reversible": spec.REVERSIBLE,
                "doc": spec.PLAYBOOK,
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


_SUBJECT_KINDS = (
    ("api_key_id", "key"),
    ("deployment_id", "deployment"),
    ("model", "model"),
)
_STATUSES: dict[
    int,
    tuple[
        Literal["open", "resolved", "dismissed"],
        Literal["new", "in_progress", "suppressed", "resolved"],
    ],
] = {
    1: ("open", "new"),
    2: ("open", "in_progress"),
    3: ("dismissed", "suppressed"),
    4: ("resolved", "resolved"),
}


def finding_from_row(row: Finding) -> FindingV1:
    spec = RULES[row.rule_id]
    values = measurements(row.evidence)
    field, kind = next(item for item in _SUBJECT_KINDS if item[0] in row.subject)
    status, status_detail = _STATUSES[row.status_id]
    impact = row.impact or {}
    usd = impact.get("cost_usd")
    return FindingV1(
        schema_version="1",
        id=str(row.id),
        # Validated by the model; the column holds one of its sources.
        source=cast(Literal["gateway", "litellm", "shim-cli"], row.source),
        rule_id=row.rule_id,
        rule_version=row.rule_version,
        title=spec.TITLE,
        summary=FindingText(
            en=render(spec.SUMMARY["en"], values), tr=render(spec.SUMMARY["tr"], values)
        ),
        severity=SEVERITIES[row.severity_id - 1],
        status=status,
        status_detail=status_detail,
        subject=Subject(kind=kind, id=str(row.subject[field])),
        window=Window(
            start=row.first_seen_at.astimezone(timezone.utc),
            end=row.last_seen_at.astimezone(timezone.utc),
        ),
        occurrences=row.occurrences,
        evidence=[
            EvidenceRef(kind="request", id=request_id)
            for request_id in row.evidence.get("request_ids") or []
        ],
        measurements=values,
        impact=Impact(
            requests=impact.get("requests"),
            tokens=None,
            usd=None if usd is None else format(Decimal(str(usd)), "f"),
            risk_class=spec.RISK_CLASS,
        ),
        remediation=Remediation(
            mode="observe",
            max_mode=spec.MAX_MODE,
            action=None,
            reversible=bool(row.remediation.get("reversible", spec.REVERSIBLE)),
            blast_radius=spec.BLAST_RADIUS,
            proof_after=None,
            text=FindingText(**spec.REMEDIATION_TEXT),
        ),
        playbook=row.remediation.get("doc") or spec.PLAYBOOK,
    )


def ocsf_detection_finding(row: Finding) -> dict[str, Any]:
    finding = finding_from_row(row)
    if finding.status == "resolved":
        activity_id = 3
    elif row.occurrences > 1 or finding.status_detail != "new":
        activity_id = 2
    else:
        activity_id = 1
    v1 = finding.model_dump(mode="json")
    return {
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "category_uid": 2,
        "category_name": "Findings",
        "activity_id": activity_id,
        "type_uid": 200400 + activity_id,
        "time": _epoch_ms(row.resolved_at or finding.window.end),
        "severity_id": SEVERITIES.index(finding.severity) + 1,
        "status_id": STATUS_IDS[finding.status_detail or "new"],
        "metadata": {
            "version": OCSF_VERSION,
            "product": {"name": "shim", "vendor_name": "shim"},
        },
        "finding_info": {
            "uid": finding.id,
            "title": finding.title,
            "desc": finding.summary.en,
            "first_seen_time": _epoch_ms(finding.window.start),
            "last_seen_time": _epoch_ms(finding.window.end),
        },
        "unmapped": {
            "schema_version": finding.schema_version,
            "summary_tr": finding.summary.tr,
            **{
                key: v1[key]
                for key in ("evidence", "measurements", "impact", "remediation")
            },
        },
    }


def _epoch_ms(value: datetime) -> int:
    return int(value.timestamp() * 1000)
