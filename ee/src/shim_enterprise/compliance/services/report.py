"""Tenant-isolated exposure evidence rendering for compliance findings."""

from __future__ import annotations

import asyncio
from collections import Counter
import csv
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import io
from typing import cast
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.compliance.classification import severity_rank
from shim_enterprise.compliance.models import ComplianceConnector, ComplianceFinding
from shim_enterprise.compliance.reporting import (
    REPORT_FONT,
    REPORT_FONT_BOLD,
    ensure_report_fonts,
    evidence_table,
)


@dataclass(frozen=True, slots=True)
class FindingEvidence:
    occurred_at: datetime
    severity: str
    entity_type: str
    kvkk_category: str | None
    gdpr_category: str | None
    actor_email: str | None
    model: str | None
    content_id: str
    value_hash: str


@dataclass(frozen=True, slots=True)
class ExposureEvidence:
    tenant_id: UUID
    connector_id: UUID | None
    start: datetime
    end: datetime
    findings: tuple[FindingEvidence, ...]

    def counts(self, attribute: str, *, limit: int | None = None) -> dict[str, int]:
        values = (
            str(value)
            for finding in self.findings
            if (value := getattr(finding, attribute)) is not None
        )
        counts = Counter(values).most_common(limit)
        return dict(counts)


_CSV_FIELDS = (
    "occurred_at",
    "severity",
    "entity_type",
    "kvkk_category",
    "gdpr_category",
    "actor_email",
    "model",
    "content_id",
    "value_hash",
)
_METHODOLOGY = (
    "This evidence contains tenant-scoped detector metadata and salted value "
    "hashes. Raw prompts, raw provider payloads, and raw detected values are not "
    "included. Legal interpretation remains the customer's responsibility."
)
MAX_SYNC_REPORT_FINDINGS = 10_000
MAX_SYNC_REPORT_WINDOW = timedelta(days=31)


class ReportLimitExceeded(ValueError):
    """Raised before an interactive report exceeds its resource budget."""


async def collect_exposure_evidence(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    start: datetime,
    end: datetime,
    connector_id: UUID | None,
) -> ExposureEvidence:
    if start > end:
        raise ValueError("report start must not be after end")
    if end - start > MAX_SYNC_REPORT_WINDOW:
        raise ReportLimitExceeded("synchronous reports are limited to 31 days")
    statement = (
        select(ComplianceFinding)
        .join(
            ComplianceConnector,
            ComplianceFinding.connector_id == ComplianceConnector.id,
        )
        .where(
            ComplianceConnector.organization_id == tenant_id,
            ComplianceFinding.occurred_at >= start,
            ComplianceFinding.occurred_at <= end,
        )
        .order_by(
            ComplianceFinding.occurred_at.desc(),
            ComplianceFinding.id.desc(),
        )
        .limit(MAX_SYNC_REPORT_FINDINGS + 1)
    )
    if connector_id is not None:
        statement = statement.where(ComplianceFinding.connector_id == connector_id)
    rows = tuple((await session.execute(statement)).scalars())
    if len(rows) > MAX_SYNC_REPORT_FINDINGS:
        raise ReportLimitExceeded(
            f"synchronous reports are limited to {MAX_SYNC_REPORT_FINDINGS} findings"
        )
    findings = tuple(
        FindingEvidence(
            occurred_at=cast(datetime, row.occurred_at),
            severity=row.severity,
            entity_type=row.entity_type,
            kvkk_category=row.kvkk_category,
            gdpr_category=row.gdpr_category,
            actor_email=row.actor_email,
            model=row.model,
            content_id=row.content_id,
            value_hash=row.value_hash,
        )
        for row in rows
    )
    return ExposureEvidence(tenant_id, connector_id, start, end, findings)


def _safe_csv(value: object | None) -> str:
    if isinstance(value, datetime):
        value = value.isoformat()
    rendered = "" if value is None else str(value)
    return (
        f"'{rendered}"
        if rendered.lstrip().startswith(("=", "+", "-", "@"))
        else rendered
    )


def _render_csv(evidence: ExposureEvidence) -> bytes:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(_CSV_FIELDS)
    for finding in evidence.findings:
        writer.writerow(_safe_csv(getattr(finding, field)) for field in _CSV_FIELDS)
    return output.getvalue().encode("utf-8-sig")


def _count_rows(counts: dict[str, int]) -> list[list[str]]:
    return [[name, str(count)] for name, count in counts.items()] or [["—", "0"]]


def _render_pdf(evidence: ExposureEvidence) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

    ensure_report_fonts()
    styles = getSampleStyleSheet()
    for style_name, font in (
        ("Title", REPORT_FONT_BOLD),
        ("Heading2", REPORT_FONT_BOLD),
        ("Normal", REPORT_FONT),
    ):
        styles[style_name].fontName = font

    output = io.BytesIO()
    document = SimpleDocTemplate(
        output,
        pagesize=A4,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        title="KVKK Exposure Evidence",
    )
    scope = (
        f"connector {evidence.connector_id}"
        if evidence.connector_id is not None
        else "all tenant connectors"
    )
    story = [
        Paragraph("KVKK Exposure Evidence", styles["Title"]),
        Paragraph(
            f"Period: {evidence.start.date()} – {evidence.end.date()}<br/>"
            f"Generated: {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}<br/>"
            f"Scope: {scope}",
            styles["Normal"],
        ),
        Spacer(1, 6 * mm),
        Paragraph("Finding summary", styles["Heading2"]),
        Paragraph(
            f"{len(evidence.findings)} metadata-only finding(s) in range.",
            styles["Normal"],
        ),
        Spacer(1, 3 * mm),
        evidence_table(
            _count_rows(
                dict(
                    sorted(
                        evidence.counts("severity").items(),
                        key=lambda item: severity_rank(item[0]),
                        reverse=True,
                    )
                )
            ),
            ["Severity", "Count"],
        ),
        Spacer(1, 5 * mm),
        Paragraph("Entity types", styles["Heading2"]),
        evidence_table(
            _count_rows(evidence.counts("entity_type", limit=15)),
            ["Entity type", "Count"],
        ),
        Spacer(1, 5 * mm),
        Paragraph("KVKK categories", styles["Heading2"]),
        evidence_table(
            _count_rows(evidence.counts("kvkk_category")),
            ["Category", "Count"],
        ),
        Spacer(1, 5 * mm),
        Paragraph("Actors", styles["Heading2"]),
        evidence_table(
            _count_rows(evidence.counts("actor_email", limit=20)),
            ["Actor", "Findings"],
        ),
        Spacer(1, 6 * mm),
        Paragraph("Evidence boundary", styles["Heading2"]),
        Paragraph(_METHODOLOGY, styles["Normal"]),
    ]
    document.build(story)
    return output.getvalue()


async def generate_report(
    session: AsyncSession,
    *,
    org_id: UUID,
    start: datetime,
    end: datetime,
    connector_id: UUID | None = None,
    fmt: str = "pdf",
) -> tuple[bytes, str, str]:
    evidence = await collect_exposure_evidence(
        session,
        tenant_id=org_id,
        start=start,
        end=end,
        connector_id=connector_id,
    )
    date_suffix = end.strftime("%Y%m%d")
    if fmt == "csv":
        return _render_csv(evidence), "text/csv", f"kvkk_exposure_{date_suffix}.csv"
    if fmt != "pdf":
        raise ValueError("report format must be pdf or csv")
    content = await asyncio.to_thread(_render_pdf, evidence)
    return content, "application/pdf", f"kvkk_exposure_{date_suffix}.pdf"
