"""Tenant-isolated exposure evidence rendering for compliance findings."""

from __future__ import annotations

import asyncio
from collections import Counter
import csv
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import io
from typing import Any, cast
from uuid import UUID
from xml.sax.saxutils import escape

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.compliance.classification import classify, severity_rank
from shim_enterprise.compliance.models import ComplianceConnector, ComplianceFinding
from shim_enterprise.compliance.reporting import (
    NOT_RECORDED_CELL,
    build_pdf,
    evidence_table,
    lifecycle_window,
    recorded_entity_sums,
    report_styles,
    safe_csv,
)
from shim_enterprise.tenants.models import Organization


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


# Entity type, KVKK category, then masked, monitored, blocked and seen in answers;
# None is an action no request in the window recorded.
GatewayDetection = tuple[str, str, int | None, int | None, int | None, int | None]


@dataclass(frozen=True, slots=True)
class ExposureEvidence:
    tenant_id: UUID
    organization_name: str
    connector_id: UUID | None
    start: datetime
    end: datetime
    findings: tuple[FindingEvidence, ...]
    gateway_detections: tuple[GatewayDetection, ...] = ()

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
    "source",
    "count",
)
# Lifecycle metadata map, CSV source and PDF column of each gateway action.
_GATEWAY_ACTIONS = (
    ("pii_entities", "gateway_masked", "Maskelenen"),
    ("monitored_entities", "gateway_monitored", "İzlenen"),
    ("blocked_entities", "gateway_blocked", "Durdurulan"),
    ("response_entities", "gateway_response", "Yanıtta\ngörülen"),
)
_TITLE = "KVKK Kişisel Veri Maruziyet Kanıtı"
_SEVERITIES = {"critical": "kritik", "high": "yüksek", "medium": "orta", "low": "düşük"}
_GATEWAY_METHODOLOGY = (
    "Sayılar, gateway'in istek kurumdan çıkmadan önce tespit ettiği farklı "
    "değerlerin istek başına toplamıdır ve kurumun istek kayıtlarından alınır. "
    "Maskelenen değer modele sahte bir değerle gitti, izlenen değer olduğu gibi "
    "gitti, durdurulan istek modele hiç gitmedi. Yanıtta görülen, modelin "
    "cevabında olup isteğin kendisinde olmayan değerlerdir. Tespit edilen hiçbir "
    "değer saklanmaz."
)
_METHODOLOGY = (
    "Bu kanıt yalnız kuruma ait tespit üst verisini ve tuzlanmış değer özetlerini "
    "içerir. Ham istekler, sağlayıcıya giden ham içerik ve tespit edilen ham "
    "değerler yer almaz. Hukuki değerlendirme kurumun sorumluluğundadır."
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
    organization_name = (
        await session.execute(
            select(Organization.name).where(Organization.id == tenant_id)
        )
    ).scalar_one()
    evidence = ExposureEvidence(
        tenant_id=tenant_id,
        organization_name=organization_name,
        connector_id=connector_id,
        start=start,
        end=end,
        findings=findings,
    )
    if connector_id is not None:
        return evidence
    window = lifecycle_window(tenant_id, start, end)
    sums: list[dict[str, int] | None] = []
    for key, _, _ in _GATEWAY_ACTIONS:
        rows = await recorded_entity_sums(session, key, window)
        sums.append(None if rows is None else {e: int(c) for e, c in rows})
    entities = sorted({entity for counts in sums if counts for entity in counts})
    detections = tuple(
        cast(
            GatewayDetection,
            (
                entity,
                classify(entity).kvkk_category,
                *(None if counts is None else counts.get(entity, 0) for counts in sums),
            ),
        )
        for entity in entities
    )
    return replace(evidence, gateway_detections=detections)


def _render_csv(evidence: ExposureEvidence) -> bytes:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(_CSV_FIELDS)
    for finding in evidence.findings:
        writer.writerow(
            [safe_csv(getattr(finding, field)) for field in _CSV_FIELDS[:-2]]
            + ["connector", "1"]
        )
    gateway_rows = sorted(
        (entity, source, count)
        for entity, _, *counts in evidence.gateway_detections
        for (_, source, _), count in zip(_GATEWAY_ACTIONS, counts, strict=True)
        if count
    )
    for entity, source, count in gateway_rows:
        classification = classify(entity)
        writer.writerow(
            safe_csv(value)
            for value in (
                None,
                classification.severity,
                entity,
                classification.kvkk_category,
                classification.gdpr_category,
                None,
                None,
                None,
                None,
                source,
                count,
            )
        )
    return output.getvalue().encode("utf-8-sig")


def _count_rows(counts: dict[str, int]) -> list[list[str]]:
    return [[name, str(count)] for name, count in counts.items()] or [["—", "0"]]


def _kvkk_story(evidence: ExposureEvidence, styles: Any) -> list[Any]:
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, Spacer

    scope = (
        f"bağlayıcı {evidence.connector_id}"
        if evidence.connector_id is not None
        else "tüm bağlayıcılar ve gateway"
    )
    header = "<br/>".join(
        escape(line)
        for line in (
            f"Kurum: {evidence.organization_name} ({evidence.tenant_id})",
            f"Dönem: {evidence.start.date()} – {evidence.end.date()}",
            f"Oluşturulma: {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}",
            f"Kapsam: {scope}",
        )
    )
    severities = sorted(
        evidence.counts("severity").items(),
        key=lambda item: severity_rank(item[0]),
        reverse=True,
    )
    return [
        Paragraph(_TITLE, styles["Title"]),
        Paragraph(header, styles["Normal"]),
        Spacer(1, 6 * mm),
        Paragraph("Bulgu özeti", styles["Heading2"]),
        Paragraph(
            f"Dönemde yalnız üst veri içeren {len(evidence.findings)} bulgu var.",
            styles["Normal"],
        ),
        Spacer(1, 3 * mm),
        evidence_table(
            _count_rows({_SEVERITIES.get(name, name): n for name, n in severities}),
            ["Önem", "Adet"],
        ),
        Spacer(1, 5 * mm),
        Paragraph("Varlık türleri", styles["Heading2"]),
        evidence_table(
            _count_rows(evidence.counts("entity_type", limit=15)),
            ["Varlık türü", "Adet"],
        ),
        Spacer(1, 5 * mm),
        Paragraph("KVKK kategorileri", styles["Heading2"]),
        evidence_table(
            _count_rows(evidence.counts("kvkk_category")),
            ["Kategori", "Adet"],
        ),
        Spacer(1, 5 * mm),
        Paragraph("Kullanıcılar", styles["Heading2"]),
        evidence_table(
            _count_rows(evidence.counts("actor_email", limit=20)),
            ["Kullanıcı", "Bulgu"],
        ),
        *(
            []
            if evidence.connector_id is not None
            else [
                Spacer(1, 5 * mm),
                Paragraph("Gateway tespitleri", styles["Heading2"]),
                Paragraph(_GATEWAY_METHODOLOGY, styles["Normal"]),
                Spacer(1, 3 * mm),
                evidence_table(
                    [
                        [
                            entity,
                            category,
                            *(
                                NOT_RECORDED_CELL if count is None else str(count)
                                for count in counts
                            ),
                        ]
                        for entity, category, *counts in evidence.gateway_detections
                    ]
                    or [["—"] * 6],
                    [
                        "Varlık türü",
                        "KVKK kategorisi",
                        *(label for _, _, label in _GATEWAY_ACTIONS),
                    ],
                ),
            ]
        ),
        Spacer(1, 6 * mm),
        Paragraph("Kanıt sınırı", styles["Heading2"]),
        Paragraph(_METHODOLOGY, styles["Normal"]),
    ]


def _render_pdf(evidence: ExposureEvidence) -> bytes:
    return build_pdf(_kvkk_story(evidence, report_styles()), _TITLE)


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
