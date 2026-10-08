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

from sqlalchemy import func, select, true
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.ai_act.audit_writer import gateway_version
from shim_enterprise.ai_act.models import AIActAuditLog
from shim_enterprise.ai_act.verify import AuditVerificationLimitExceeded, verify_chain
from shim_enterprise.billing.models import RequestLifecycle
from shim_enterprise.billing.read_models import BillingBreakdown, BillingReadModels
from shim_enterprise.compliance.models import MonthlyEvidenceFile
from shim_enterprise.compliance.reporting import (
    build_pdf,
    entity_sums,
    evidence_table,
    lifecycle_window,
    report_styles,
)
from shim_enterprise.findings.models import Finding
from shim_enterprise.outbox.handlers import EVIDENCE_MONTHLY_READY
from shim_enterprise.outbox.publisher import OutboxWriter
from shim_enterprise.tenants.models import Organization
from shim.gateway.contracts.ids import TenantId


logger = logging.getLogger(__name__)

NOT_RECORDED = "not recorded in this version"
_COVER = (
    "This file is a measurement of the gateway traffic shim recorded for this "
    "organization. It is not an audit, an assessment or a certification, and it "
    "contains no prompt, answer or detected value."
)
_MASK_KEYS = (
    ("pii_entities", "Masked"),
    ("monitored_entities", "Monitored"),
    ("blocked_entities", "Blocked"),
)


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
    metadata = RequestLifecycle.lifecycle_metadata
    in_window = lifecycle_window(tenant_id, start, end)
    if not await session.scalar(
        select(RequestLifecycle.id).where(*in_window, metadata.has_key(key)).limit(1)
    ):
        return None
    provider = func.coalesce(RequestLifecycle.provider, "unknown")
    rows = await session.execute(entity_sums(key, in_window, provider))
    return {(row[0], row[1]): int(row[2]) for row in rows}


async def collect_monthly_evidence(
    session: AsyncSession, tenant_id: UUID, window: MonthlyWindow, *, now: datetime
) -> MonthlyEvidence:
    async def breakdown(
        group_by: Literal["provider", "model"],
    ) -> tuple[BillingBreakdown, ...]:
        return tuple(
            await BillingReadModels().breakdown(
                session,
                tenant_id=TenantId(tenant_id),
                start_at=window.start,
                end_at=window.end,
                group_by=group_by,
                limit=None,
            )
        )

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
        chain = f"Verification could not run: {exc}."

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
    return MonthlyEvidence(
        tenant_id=tenant_id,
        window=window,
        generated_at=now,
        by_provider=await breakdown("provider"),
        by_model=await breakdown("model"),
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
    )


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
        return f"unknown ({unpriced} unpriced request(s))"
    return f"{sum((row.cost_usd for row in rows), Decimal()):.6f} USD"


def _traffic_rows(rows: tuple[BillingBreakdown, ...]) -> list[list[str]]:
    return [
        [
            row.key,
            str(row.request_count),
            "unknown" if row.unpriced_requests else f"{row.cost_usd:.6f}",
        ]
        for row in rows
    ] or [["—", "0", "0"]]


def render_monthly_pdf(evidence: MonthlyEvidence) -> bytes:
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, Spacer

    styles = report_styles()
    window = evidence.window
    lifecycle_source = (
        f"Source: request_lifecycle, requests started {window.describe()}."
    )
    audit_source = f"Source: ai_act_audit_log, rows written {window.describe()}."

    def section(title: str, source: str, *body: Any) -> list[Any]:
        return [
            Spacer(1, 5 * mm),
            Paragraph(title, styles["Heading2"]),
            Paragraph(source, styles["Normal"]),
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
                NOT_RECORDED
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
                "0" if evidence.entities[key] is not None else NOT_RECORDED
                for key, _ in _MASK_KEYS
            ),
        ]
    ]
    chain = evidence.chain
    if isinstance(chain, str):
        chain_text = chain
    elif chain["ok"]:
        chain_text = (
            f"The chain verified: {chain['rows_checked']} row(s) read, "
            f"{chain['rows_selected']} written in the window, last verified "
            f"sequence {chain['last_verified_seq']}."
        )
    else:
        chain_text = f"The chain did not verify: first break {chain['first_break']}."

    story = [
        Paragraph("Monthly Evidence File", styles["Title"]),
        Paragraph(
            f"Organization: {evidence.tenant_id}<br/>"
            f"Period: {window.period}"
            + (" (month in progress)" if window.kind == "monthly_partial" else "")
            + f"<br/>Window: {window.describe()}<br/>"
            f"Generated: {evidence.generated_at:%Y-%m-%d %H:%M UTC}",
            styles["Normal"],
        ),
        Spacer(1, 3 * mm),
        Paragraph(_COVER, styles["Normal"]),
        *section(
            "1. Traffic",
            "Source: usage_ledger settlements joined to request_lifecycle, settled "
            f"{window.describe()}. Total cost: {_cost(evidence.by_provider)}.",
            evidence_table(
                _traffic_rows(evidence.by_provider),
                ["Provider", "Requests", "Cost USD"],
            ),
            Spacer(1, 2 * mm),
            evidence_table(
                _traffic_rows(evidence.by_model), ["Model", "Requests", "Cost USD"]
            ),
        ),
        *section(
            "2. What left",
            lifecycle_source
            + " Counts are distinct values per request, summed, by entity type.",
            evidence_table(
                entity_rows,
                ["Provider", "Entity type", *(label for _, label in _MASK_KEYS)],
            ),
            Spacer(1, 2 * mm),
            Paragraph(
                "Bulk disclosures: "
                + (
                    NOT_RECORDED
                    if evidence.bulk_disclosures is None
                    else str(evidence.bulk_disclosures)
                ),
                styles["Normal"],
            ),
            Paragraph(
                "Personal data in answers: "
                + (
                    NOT_RECORDED
                    if evidence.response_entities is None
                    else ", ".join(
                        f"{entity} {count}"
                        for entity, count in sorted(evidence.response_entities.items())
                    )
                    or "none"
                ),
                styles["Normal"],
            ),
        ),
        *section(
            "3. What was stopped",
            audit_source + " Policy verdicts with outcome deny.",
            evidence_table(
                [[rule, reason, str(count)] for rule, reason, count in evidence.denials]
                or [["—", "—", "0"]],
                ["Rule", "Reason code", "Requests"],
            ),
        ),
        *section(
            "4. Who changed what",
            audit_source + " Management actions by action and actor type.",
            evidence_table(
                [
                    [action, actor, str(count)]
                    for action, actor, count in evidence.changes
                ]
                or [["—", "—", "0"]],
                ["Action", "Actor type", "Count"],
            ),
        ),
        *section(
            "5. Audit chain",
            audit_source + " Verified from the latest daily anchor before the window.",
            Paragraph(chain_text, styles["Normal"]),
        ),
        *section(
            "6. Findings",
            f"Source: findings, first seen or resolved {window.describe()}.",
            evidence_table(
                [
                    [rule, str(opened), str(still_open), str(resolved)]
                    for rule, opened, still_open, resolved in evidence.findings
                ]
                or [["—", "0", "0", "0"]],
                ["Rule", "Opened", "Open at end", "Resolved"],
            ),
        ),
    ]
    return build_pdf(story, "Monthly Evidence File")


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
