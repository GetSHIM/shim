"""The monthly evidence file: collected, rendered, stored once and announced."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import hashlib
import logging
from typing import Any, Literal
from uuid import UUID
from xml.sax.saxutils import escape

from sqlalchemy import Text, cast, distinct, func, select, true
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.ai_act.audit_writer import gateway_version
from shim_enterprise.ai_act.models import AIActAuditLog
from shim_enterprise.ai_act.verify import AuditVerificationLimitExceeded, verify_chain
from shim_enterprise.billing.models import RequestLifecycle
from shim_enterprise.billing.read_models import BillingBreakdown, BillingReadModels
from shim_enterprise.compliance.models import MonthlyEvidenceFile
from shim_enterprise.compliance.reporting import (
    NOT_RECORDED,
    NOT_RECORDED_CELL,
    build_pdf,
    evidence_table,
    lifecycle_window,
    recorded_entity_sums,
    report_styles,
)
from shim_enterprise.findings.models import Finding
from shim_enterprise.outbox.handlers import EVIDENCE_MONTHLY_READY
from shim_enterprise.outbox.publisher import OutboxWriter
from shim_enterprise.tenants.models import ApiKey, Organization, Team, User
from shim.gateway.contracts.ids import TenantId


logger = logging.getLogger(__name__)

_TITLE = "Aylık Kanıt Dosyası"
_COVER = (
    "Bu dosya gateway trafiğinin ölçümüdür; denetim, sertifika veya uygunluk "
    "beyanı değildir."
)
_MASK_KEYS = (
    ("pii_entities", "Maskelenen"),
    ("monitored_entities", "İzlenen"),
    ("blocked_entities", "Durdurulan"),
)
# Audited reads and exports of evidence and content (section 7).
ACCESS_ACTIONS = (
    "compliance.kvkk_report_generated",
    "compliance.audit_report_generated",
    "compliance.readiness_report_generated",
    "compliance.audit_bundle_exported",
    "compliance.audit_verified",
    "tenant.requests_exported",
    "tenant.billing_exported",
    "tenant.evidence_downloaded",
    "tenant.request_content_opened",
)
NO_ACCESS_THIS_MONTH = "Bu ay kayıtlı erişim yok."
ACCESS_NOT_RECORDED = "Okuma ve dışa aktarma kayıtları bu kurum için henüz tutulmuyor."
MODEL_ACCESS_ROWS = 50
MODEL_ACCESS_MODELS = 10


class EvidenceFileExists(ValueError):
    """The organization already has a file of this kind for this period."""


@dataclass(frozen=True, slots=True)
class MonthlyWindow:
    period: str
    kind: str
    start: datetime
    end: datetime

    def describe(self) -> str:
        return f"{self.start:%Y-%m-%d %H:%M} – {self.end:%Y-%m-%d %H:%M} UTC"


@dataclass(frozen=True, slots=True)
class MonthlyEvidence:
    tenant_id: UUID
    organization_name: str
    window: MonthlyWindow
    generated_at: datetime
    by_provider: tuple[BillingBreakdown, ...]
    by_model: tuple[BillingBreakdown, ...]
    entities: dict[str, dict[tuple[str, str], int] | None]
    bulk_disclosures: int | None
    response_entities: dict[str, int] | None
    denials: tuple[tuple[str, str, int], ...]
    changes: tuple[tuple[str, str, int], ...]
    chain: dict[str, Any] | str
    findings: tuple[tuple[str, int, int, int], ...]
    # Action, user id, current role and count; empty with a note when none.
    access: tuple[tuple[str, str, str, int], ...]
    access_note: str | None
    # Key name, team name, providers, models and requests.
    model_access: tuple[tuple[str, str, str, str, int], ...]


def monthly_window(period: str, *, now: datetime) -> MonthlyWindow:
    """A closed month is `monthly`; the current month is `monthly_partial`."""
    try:
        start = datetime.strptime(period, "%Y-%m").replace(tzinfo=timezone.utc)
    except ValueError:
        raise ValueError("period must be YYYY-MM") from None
    following = (start + timedelta(days=32)).replace(day=1)
    if following <= now:
        return MonthlyWindow(
            period, "monthly", start, following - timedelta(microseconds=1)
        )
    if start <= now:
        return MonthlyWindow(period, "monthly_partial", start, now)
    raise ValueError("a future month has no evidence yet")


def previous_period(now: datetime) -> str:
    first = now.astimezone(timezone.utc).replace(day=1)
    return f"{first - timedelta(days=1):%Y-%m}"


async def entity_counts(
    session: AsyncSession, tenant_id: UUID, start: datetime, end: datetime, key: str
) -> dict[tuple[str, str], int] | None:
    """Per provider and entity type, or None when no request recorded the key."""
    provider = func.coalesce(RequestLifecycle.provider, "unknown")
    rows = await recorded_entity_sums(
        session, key, lifecycle_window(tenant_id, start, end), provider
    )
    return None if rows is None else {(row[0], row[1]): int(row[2]) for row in rows}


async def usage_breakdowns(
    session: AsyncSession, tenant_id: UUID, start: datetime, end: datetime
) -> tuple[tuple[BillingBreakdown, ...], tuple[BillingBreakdown, ...]]:
    """Settled requests and cost in the window, by provider and by model."""

    async def by(
        group_by: Literal["provider", "model"],
    ) -> tuple[BillingBreakdown, ...]:
        return tuple(
            await BillingReadModels().breakdown(
                session,
                tenant_id=TenantId(tenant_id),
                start_at=start,
                end_at=end,
                group_by=group_by,
                limit=None,
            )
        )

    return await by("provider"), await by("model")


async def collect_monthly_evidence(
    session: AsyncSession, tenant_id: UUID, window: MonthlyWindow, *, now: datetime
) -> MonthlyEvidence:
    metadata = RequestLifecycle.lifecycle_metadata
    in_window = lifecycle_window(tenant_id, window.start, window.end)
    bulk = None
    if await session.scalar(
        select(RequestLifecycle.id)
        .where(*in_window, metadata.has_key("bulk_disclosure"))
        .limit(1)
    ):
        bulk = await session.scalar(
            select(func.count()).where(
                *in_window, func.jsonb_typeof(metadata["bulk_disclosure"]) == "object"
            )
        )
    response = await entity_counts(
        session, tenant_id, window.start, window.end, "response_entities"
    )
    response_by_type: dict[str, int] | None = None
    if response is not None:
        response_by_type = {}
        for (_, entity), count in response.items():
            response_by_type[entity] = response_by_type.get(entity, 0) + count

    audit_window = (
        AIActAuditLog.organization_id == tenant_id,
        AIActAuditLog.created_at >= window.start,
        AIActAuditLog.created_at <= window.end,
    )
    actor_type = func.coalesce(
        AIActAuditLog.extra["actor_type"].as_string(), NOT_RECORDED
    )
    changes = await session.execute(
        select(AIActAuditLog.endpoint, actor_type, func.count())
        .where(*audit_window, AIActAuditLog.event_type == "management_action")
        .group_by(AIActAuditLog.endpoint, actor_type)
        .order_by(AIActAuditLog.endpoint, actor_type)
    )
    try:
        chain: dict[str, Any] | str = await verify_chain(
            session, tenant_id, start=window.start, end=window.end
        )
    except AuditVerificationLimitExceeded as exc:
        chain = f"Doğrulama çalışmadı: {exc}."

    opened = func.count().filter(
        Finding.first_seen_at >= window.start, Finding.first_seen_at <= window.end
    )
    still_open = func.count().filter(
        Finding.first_seen_at <= window.end,
        (Finding.resolved_at.is_(None)) | (Finding.resolved_at > window.end),
    )
    resolved = func.count().filter(
        Finding.resolved_at >= window.start, Finding.resolved_at <= window.end
    )
    findings = await session.execute(
        select(Finding.rule_id, opened, still_open, resolved)
        .where(
            Finding.organization_id == tenant_id,
            Finding.first_seen_at <= window.end,
            (Finding.resolved_at.is_(None)) | (Finding.resolved_at >= window.start),
        )
        .group_by(Finding.rule_id)
        .order_by(Finding.rule_id)
    )
    by_provider, by_model = await usage_breakdowns(
        session, tenant_id, window.start, window.end
    )
    access, access_note = await access_counts(session, tenant_id, window)
    organization_name = (
        await session.execute(
            select(Organization.name).where(Organization.id == tenant_id)
        )
    ).scalar_one()
    return MonthlyEvidence(
        tenant_id=tenant_id,
        organization_name=organization_name,
        window=window,
        generated_at=now,
        by_provider=by_provider,
        by_model=by_model,
        entities={
            key: await entity_counts(session, tenant_id, window.start, window.end, key)
            for key, _ in _MASK_KEYS
        },
        bulk_disclosures=bulk,
        response_entities=response_by_type,
        denials=await denial_counts(session, tenant_id, window.start, window.end),
        changes=tuple((str(a), str(b), int(c)) for a, b, c in changes),
        chain=chain,
        findings=tuple((str(a), int(b), int(c), int(d)) for a, b, c, d in findings),
        access=access,
        access_note=access_note,
        model_access=await model_access(session, tenant_id, window),
    )


async def access_counts(
    session: AsyncSession, tenant_id: UUID, window: MonthlyWindow
) -> tuple[tuple[tuple[str, str, str, int], ...], str | None]:
    """Audited evidence and content reads by action and actor, or why there are none."""
    audited = (
        AIActAuditLog.organization_id == tenant_id,
        AIActAuditLog.event_type == "management_action",
        AIActAuditLog.endpoint.in_(ACCESS_ACTIONS),
        AIActAuditLog.created_at <= window.end,
    )
    rows = await session.execute(
        select(AIActAuditLog.endpoint, AIActAuditLog.actor, User.role, User.kind)
        .add_columns(func.count())
        .select_from(AIActAuditLog)
        .outerjoin(
            User,
            (User.organization_id == tenant_id)
            & (cast(User.id, Text) == AIActAuditLog.actor),
        )
        .where(*audited, AIActAuditLog.created_at >= window.start)
        .group_by(AIActAuditLog.endpoint, AIActAuditLog.actor, User.role, User.kind)
        .order_by(AIActAuditLog.endpoint, func.count().desc(), AIActAuditLog.actor)
    )
    access = tuple(
        (
            str(action),
            actor or "—",
            "—"
            if role is None
            else role + (", servis hesabı" if kind == "service" else ""),
            int(count),
        )
        for action, actor, role, kind, count in rows
    )
    if access:
        return access, None
    earlier = await session.scalar(
        select(AIActAuditLog.created_at)
        .where(*audited)
        .order_by(AIActAuditLog.created_at)
        .limit(1)
    )
    return (), NO_ACCESS_THIS_MONTH if earlier else ACCESS_NOT_RECORDED


async def model_access(
    session: AsyncSession, tenant_id: UUID, window: MonthlyWindow
) -> tuple[tuple[str, str, str, str, int], ...]:
    """Requests by API key and team with the providers and models they called."""
    team_id = RequestLifecycle.lifecycle_metadata["team_id"].as_string()
    model = func.coalesce(
        RequestLifecycle.provider_model, RequestLifecycle.requested_model
    )
    rows = (
        await session.execute(
            select(
                ApiKey.name,
                Team.name,
                func.array_agg(distinct(RequestLifecycle.provider)),
                func.array_agg(distinct(model)),
                func.count(),
            )
            .select_from(RequestLifecycle)
            .outerjoin(
                ApiKey,
                (ApiKey.organization_id == tenant_id)
                & (ApiKey.id == RequestLifecycle.api_key_id),
            )
            .outerjoin(
                Team,
                (Team.organization_id == tenant_id) & (cast(Team.id, Text) == team_id),
            )
            .where(*lifecycle_window(tenant_id, window.start, window.end))
            .group_by(RequestLifecycle.api_key_id, ApiKey.name, team_id, Team.name)
            .order_by(func.count().desc(), ApiKey.name, Team.name)
        )
    ).all()

    def row(key, team, providers, models, requests) -> tuple[str, str, str, str, int]:
        names = sorted({name for name in models if name})
        shown = names[:MODEL_ACCESS_MODELS] + (
            ["…"] if len(names) > MODEL_ACCESS_MODELS else []
        )
        return (
            key or "—",
            team or "—",
            ", ".join(sorted({name for name in providers if name})) or "—",
            "\n".join(shown) or "—",
            int(requests),
        )

    top = [row(*item) for item in rows[:MODEL_ACCESS_ROWS]]
    rest = rows[MODEL_ACCESS_ROWS:]
    if rest:
        top.append(
            row(
                "diğer",
                None,
                [p for item in rest for p in item[2]],
                [m for item in rest for m in item[3]],
                sum(item[4] for item in rest),
            )
        )
    return tuple(top)


async def denial_counts(
    session: AsyncSession, tenant_id: UUID, start: datetime, end: datetime
) -> tuple[tuple[str, str, int], ...]:
    """Deny verdicts in the audit chain, by rule and reason code."""
    verdicts = (
        func.jsonb_array_elements(AIActAuditLog.policy_verdicts)
        .table_valued("value")
        .lateral()
    )
    rule = verdicts.c.value.op("->>")("rule_id")
    reason = verdicts.c.value.op("->>")("reason_code")
    rows = await session.execute(
        select(rule, func.coalesce(reason, "unspecified"), func.count())
        .select_from(AIActAuditLog)
        .join(verdicts, true())
        .where(
            AIActAuditLog.organization_id == tenant_id,
            AIActAuditLog.created_at >= start,
            AIActAuditLog.created_at <= end,
            verdicts.c.value.op("->>")("outcome") == "deny",
        )
        .group_by(rule, reason)
        .order_by(func.count().desc(), rule)
    )
    return tuple((str(a), str(b), int(c)) for a, b, c in rows)


def _cost(rows: tuple[BillingBreakdown, ...]) -> str:
    if any(row.unpriced_requests for row in rows):
        unpriced = sum(row.unpriced_requests for row in rows)
        return f"bilinmiyor (fiyatı bilinmeyen {unpriced} istek)"
    return f"{sum((row.cost_usd for row in rows), Decimal()):.6f} USD"


def _traffic_rows(rows: tuple[BillingBreakdown, ...]) -> list[list[str]]:
    return [
        [
            row.key,
            str(row.request_count),
            "bilinmiyor" if row.unpriced_requests else f"{row.cost_usd:.6f}",
        ]
        for row in rows
    ] or [["—", "0", "0"]]


def _monthly_story(evidence: MonthlyEvidence, styles: Any) -> list[Any]:
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, Spacer

    window = evidence.window

    def text(value: str) -> Any:
        return Paragraph(escape(value), styles["Normal"])

    def source(table: str, note: str = "") -> str:
        return f"Kaynak: {table}, dönem: {window.describe()}." + (
            f" {note}" if note else ""
        )

    def section(title: str, source_line: str, *body: Any) -> list[Any]:
        return [
            Spacer(1, 5 * mm),
            Paragraph(title, styles["Heading2"]),
            text(source_line),
            Spacer(1, 2 * mm),
            *body,
        ]

    entity_types = sorted(
        {
            key
            for counts in evidence.entities.values()
            if counts is not None
            for key in counts
        }
    )
    entity_rows = [
        [
            provider,
            entity,
            *(
                NOT_RECORDED_CELL
                if counts is None
                else str(counts.get((provider, entity), 0))
                for counts in (evidence.entities[key] for key, _ in _MASK_KEYS)
            ),
        ]
        for provider, entity in entity_types
    ] or [
        [
            "—",
            "—",
            *(
                "0" if evidence.entities[key] is not None else NOT_RECORDED_CELL
                for key, _ in _MASK_KEYS
            ),
        ]
    ]
    chain = evidence.chain
    if isinstance(chain, str):
        chain_text = chain
    elif chain["ok"]:
        chain_text = (
            f"Zincir doğrulandı: {chain['rows_checked']} satır okundu, dönemde "
            f"{chain['rows_selected']} satır yazıldı, son doğrulanan sıra "
            f"{chain['last_verified_seq']}."
        )
    else:
        chain_text = f"Zincir doğrulanamadı: ilk kırılma {chain['first_break']}."
    header = "<br/>".join(
        escape(line)
        for line in (
            f"Kurum: {evidence.organization_name} ({evidence.tenant_id})",
            f"Dönem: {window.period}"
            + (" (ay sürüyor)" if window.kind == "monthly_partial" else ""),
            f"Aralık: {window.describe()}",
            f"Oluşturulma: {evidence.generated_at:%Y-%m-%d %H:%M UTC}",
        )
    )
    response = evidence.response_entities
    return [
        Paragraph(_TITLE, styles["Title"]),
        Paragraph(header, styles["Normal"]),
        Spacer(1, 3 * mm),
        text(_COVER),
        *section(
            "1. Trafik",
            source(
                "usage_ledger ve request_lifecycle",
                f"Toplam maliyet: {_cost(evidence.by_provider)}.",
            ),
            evidence_table(
                _traffic_rows(evidence.by_provider),
                ["Sağlayıcı", "İstek", "Maliyet (USD)"],
            ),
            Spacer(1, 2 * mm),
            evidence_table(
                _traffic_rows(evidence.by_model), ["Model", "İstek", "Maliyet (USD)"]
            ),
        ),
        *section(
            "2. Kurumdan ne çıktı",
            source(
                "request_lifecycle",
                "Sayılar istek başına farklı değerlerin varlık türüne göre toplamıdır.",
            ),
            evidence_table(
                entity_rows,
                ["Sağlayıcı", "Varlık türü", *(label for _, label in _MASK_KEYS)],
            ),
            Spacer(1, 2 * mm),
            text(
                "Toplu ifşa: "
                + (
                    NOT_RECORDED
                    if evidence.bulk_disclosures is None
                    else str(evidence.bulk_disclosures)
                )
            ),
            text(
                "Yanıtlardaki kişisel veri: "
                + (
                    NOT_RECORDED
                    if response is None
                    else ", ".join(
                        f"{entity} {count}"
                        for entity, count in sorted(response.items())
                    )
                    or "yok"
                )
            ),
        ),
        *section(
            "3. Ne durduruldu",
            source("ai_act_audit_log", "Sonucu deny olan politika kararları."),
            evidence_table(
                [[rule, reason, str(count)] for rule, reason, count in evidence.denials]
                or [["—", "—", "0"]],
                ["Kural", "Gerekçe kodu", "İstek"],
            ),
        ),
        *section(
            "4. Kim neyi değiştirdi",
            source(
                "ai_act_audit_log",
                "Yönetim işlemleri, işleme ve kullanıcı türüne göre.",
            ),
            evidence_table(
                [
                    [action, actor, str(count)]
                    for action, actor, count in evidence.changes
                ]
                or [["—", "—", "0"]],
                ["İşlem", "Kullanıcı türü", "Adet"],
            ),
        ),
        *section(
            "5. Denetim zinciri",
            source(
                "ai_act_audit_log",
                "Dönemden önceki son günlük çapadan doğrulanır.",
            ),
            text(chain_text),
        ),
        *section(
            "6. Bulgular",
            source("findings", "İlk görülen veya kapanan bulgular."),
            evidence_table(
                [
                    [rule, str(opened), str(still_open), str(resolved)]
                    for rule, opened, still_open, resolved in evidence.findings
                ]
                or [["—", "0", "0", "0"]],
                ["Kural", "Açılan", "Dönem sonunda açık", "Kapanan"],
            ),
        ),
        *section(
            "7. Kim neye erişti",
            source("ai_act_audit_log ve request_lifecycle"),
            Paragraph("Kanıt ve içerik erişimi", styles["Heading3"]),
            text(evidence.access_note)
            if evidence.access_note
            else evidence_table(
                [
                    [action, actor, role, str(count)]
                    for action, actor, role, count in evidence.access
                ],
                ["İşlem", "Kullanıcı", "Güncel rol", "Adet"],
            ),
            Spacer(1, 2 * mm),
            Paragraph("Model erişimi", styles["Heading3"]),
            evidence_table(
                [
                    [key, team, providers, models, str(requests)]
                    for key, team, providers, models, requests in evidence.model_access
                ]
                or [["—", "—", "—", "—", "0"]],
                ["API anahtarı", "Takım", "Sağlayıcı", "Model", "İstek"],
            ),
        ),
    ]


def render_monthly_pdf(evidence: MonthlyEvidence) -> bytes:
    return build_pdf(_monthly_story(evidence, report_styles()), _TITLE)


async def generate_monthly_evidence(
    session: AsyncSession, tenant_id: UUID, window: MonthlyWindow, *, now: datetime
) -> MonthlyEvidenceFile:
    """Store one file and its ready notice in the caller's transaction."""
    evidence = await collect_monthly_evidence(session, tenant_id, window, now=now)
    content = await asyncio.to_thread(render_monthly_pdf, evidence)
    digest = hashlib.sha256(content).hexdigest()
    stored = await session.scalar(
        insert(MonthlyEvidenceFile)
        .values(
            organization_id=tenant_id,
            kind=window.kind,
            period=window.period,
            format="pdf",
            content=content,
            sha256=digest,
            size_bytes=len(content),
            generated_at=now,
            generator_version=gateway_version(),
        )
        .on_conflict_do_nothing(constraint="uq_evidence_reports_period")
        .returning(MonthlyEvidenceFile)
    )
    if stored is None:
        raise EvidenceFileExists(
            f"a {window.kind} file for {window.period} already exists"
        )
    await OutboxWriter().append(
        session,
        organization_id=TenantId(tenant_id),
        values={
            "event_type": EVIDENCE_MONTHLY_READY,
            "aggregate_type": "organization",
            "aggregate_id": str(tenant_id),
            "idempotency_key": f"evidence:{window.kind}:{window.period}",
            "payload": {
                "organization_id": str(tenant_id),
                "kind": window.kind,
                "period": window.period,
                "sha256": digest,
                "size_bytes": len(content),
                "generated_at": now.isoformat(),
            },
            "status": "pending",
            "next_attempt_at": now,
        },
    )
    return stored


async def generate_due_monthly_evidence(
    session_factory: Callable[[], Any], *, now: datetime
) -> tuple[int, int]:
    """The previous month's file for each active organization with traffic in it.

    Returns the files written and the organizations that failed.
    """
    window = monthly_window(previous_period(now), now=now)
    async with session_factory() as session:
        due = (
            await session.scalars(
                select(Organization.id)
                .where(
                    Organization.archived_at.is_(None),
                    select(RequestLifecycle.id)
                    .where(*lifecycle_window(Organization.id, window.start, window.end))
                    .exists(),
                    ~select(MonthlyEvidenceFile.id)
                    .where(
                        MonthlyEvidenceFile.organization_id == Organization.id,
                        MonthlyEvidenceFile.kind == "monthly",
                        MonthlyEvidenceFile.period == window.period,
                    )
                    .exists(),
                )
                .order_by(Organization.id)
            )
        ).all()
    generated = failed = 0
    for tenant_id in due:
        async with session_factory() as session:
            try:
                await generate_monthly_evidence(session, tenant_id, window, now=now)
                await session.commit()
                generated += 1
            except EvidenceFileExists:
                await session.rollback()
            except Exception as exc:
                await session.rollback()
                failed += 1
                logger.error(
                    "Monthly evidence failed organization_id=%s type=%s",
                    tenant_id,
                    type(exc).__name__,
                )
    return generated, failed
