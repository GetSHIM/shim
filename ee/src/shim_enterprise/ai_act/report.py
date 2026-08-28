"""Typed, evidence-only framework assessment and export."""

from __future__ import annotations

import asyncio
import csv
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
import io
from pathlib import Path
from typing import Any, Literal
from uuid import UUID

import yaml
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.ai_act.models import (
    AIActAuditAnchor,
    AIActAuditLog,
    OversightPolicy,
    OversightRequest,
)
from shim_enterprise.ai_act.retention import (
    RETENTION_FLOOR_DAYS,
    effective_retention_days,
)
from shim_enterprise.ai_act.verify import verify_chain
from shim_enterprise.compliance.models import ComplianceConnector, ComplianceFinding
from shim_enterprise.compliance.reporting import (
    REPORT_FONT,
    REPORT_FONT_BOLD,
    ensure_report_fonts,
    evidence_table,
)


FRAMEWORK_ORDER = ("ai_act", "kvkk", "gdpr", "soc2", "iso27001")
_MAPPING_DIRECTORY = Path(__file__).with_name("control_mappings")
_DISCLAIMER = (
    "This export maps observed product evidence to selected technical controls. "
    "It is not legal advice, certification, or an attestation; control applicability "
    "and sufficiency require independent review."
)


@dataclass(frozen=True, slots=True)
class ControlDefinition:
    identifier: str
    title: str
    description: str
    evidence_source: str


@dataclass(frozen=True, slots=True)
class FrameworkDefinition:
    identifier: str
    title: str
    note: str
    controls: tuple[ControlDefinition, ...]


@dataclass(frozen=True, slots=True)
class EvidenceSnapshot:
    tenant_id: UUID
    start: datetime
    end: datetime
    audit_rows: int
    pii_rows: int
    anchors: int
    chain_valid: bool
    chain_break: object | None
    retention_days: int
    oversight_policies: int
    oversight_events: int
    findings: int
    connectors: int


@dataclass(frozen=True, slots=True)
class ControlAssessment:
    control: ControlDefinition
    status: Literal["satisfied", "gap"]
    evidence: str


@dataclass(frozen=True, slots=True)
class FrameworkAssessment:
    framework: FrameworkDefinition
    controls: tuple[ControlAssessment, ...]

    @property
    def satisfied(self) -> int:
        return sum(item.status == "satisfied" for item in self.controls)

    @property
    def gaps(self) -> int:
        return len(self.controls) - self.satisfied


@dataclass(frozen=True, slots=True)
class EvidenceReport:
    snapshot: EvidenceSnapshot
    frameworks: tuple[FrameworkAssessment, ...]


def _required_text(value: Any, field: str, source: Path) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{source.name}: {field} must be non-empty text")
    return value.strip()


@lru_cache(maxsize=1)
def load_frameworks() -> dict[str, FrameworkDefinition]:
    """Load and validate the versioned mapping assets once per process."""

    loaded: dict[str, FrameworkDefinition] = {}
    for source in sorted(_MAPPING_DIRECTORY.glob("*.yaml")):
        raw = yaml.safe_load(source.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or not isinstance(raw.get("controls"), list):
            raise ValueError(f"{source.name}: invalid framework mapping")
        identifier = _required_text(raw.get("framework"), "framework", source)
        if identifier in loaded:
            raise ValueError(f"duplicate framework mapping: {identifier}")
        controls = tuple(
            ControlDefinition(
                identifier=_required_text(item.get("id"), "control.id", source),
                title=_required_text(item.get("title"), "control.title", source),
                description=str(item.get("description") or ""),
                evidence_source=_required_text(
                    item.get("evidence_source"), "control.evidence_source", source
                ),
            )
            for item in raw["controls"]
            if isinstance(item, dict)
        )
        if len(controls) != len(raw["controls"]):
            raise ValueError(f"{source.name}: every control must be an object")
        loaded[identifier] = FrameworkDefinition(
            identifier=identifier,
            title=_required_text(raw.get("title"), "title", source),
            note=str(raw.get("note") or ""),
            controls=controls,
        )
    return loaded


async def _count(session: AsyncSession, statement: Any) -> int:
    return int(await session.scalar(statement) or 0)


async def collect_evidence(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    start: datetime,
    end: datetime,
    connector_id: UUID | None,
) -> EvidenceSnapshot:
    if start > end:
        raise ValueError("evidence start must not be after end")
    audit_scope = (
        AIActAuditLog.organization_id == tenant_id,
        AIActAuditLog.created_at >= start,
        AIActAuditLog.created_at <= end,
    )
    finding_count = (
        select(func.count(ComplianceFinding.id))
        .join(
            ComplianceConnector,
            ComplianceFinding.connector_id == ComplianceConnector.id,
        )
        .where(
            ComplianceConnector.organization_id == tenant_id,
            ComplianceFinding.occurred_at >= start,
            ComplianceFinding.occurred_at <= end,
        )
    )
    if connector_id is not None:
        finding_count = finding_count.where(
            ComplianceFinding.connector_id == connector_id
        )
    integrity = await verify_chain(session, tenant_id, start=start, end=end)
    return EvidenceSnapshot(
        tenant_id=tenant_id,
        start=start,
        end=end,
        audit_rows=await _count(
            session, select(func.count(AIActAuditLog.id)).where(*audit_scope)
        ),
        pii_rows=await _count(
            session,
            select(func.count(AIActAuditLog.id)).where(
                *audit_scope, AIActAuditLog.pii_detected.is_(True)
            ),
        ),
        anchors=await _count(
            session,
            select(func.count(AIActAuditAnchor.id)).where(
                AIActAuditAnchor.organization_id == tenant_id,
                AIActAuditAnchor.anchor_date >= start.astimezone(timezone.utc).date(),
                AIActAuditAnchor.anchor_date <= end.astimezone(timezone.utc).date(),
            ),
        ),
        chain_valid=bool(integrity["ok"]),
        chain_break=integrity["first_break"],
        retention_days=effective_retention_days(),
        oversight_policies=await _count(
            session,
            select(func.count(OversightPolicy.id)).where(
                OversightPolicy.organization_id == tenant_id
            ),
        ),
        oversight_events=await _count(
            session,
            select(func.count(OversightRequest.id)).where(
                OversightRequest.organization_id == tenant_id,
                OversightRequest.created_at >= start,
                OversightRequest.created_at <= end,
            ),
        ),
        findings=await _count(session, finding_count),
        connectors=await _count(
            session,
            select(func.count(ComplianceConnector.id)).where(
                ComplianceConnector.organization_id == tenant_id
            ),
        ),
    )


def _evidence(source: str, snapshot: EvidenceSnapshot) -> tuple[bool, str]:
    if source == "audit_logging":
        return snapshot.audit_rows > 0, f"{snapshot.audit_rows} audit row(s)"
    if source == "chain_integrity":
        valid = snapshot.audit_rows > 0 and snapshot.chain_valid
        return valid, (
            f"chain verified with {snapshot.anchors} anchor(s)"
            if valid
            else "chain is empty or did not verify"
        )
    if source == "retention_6_months":
        return (
            snapshot.retention_days >= RETENTION_FLOOR_DAYS,
            f"{snapshot.retention_days} configured day(s); floor is "
            f"{RETENTION_FLOOR_DAYS}",
        )
    if source == "human_oversight":
        present = bool(snapshot.oversight_policies or snapshot.oversight_events)
        return present, (
            f"{snapshot.oversight_policies} policy row(s), "
            f"{snapshot.oversight_events} decision event(s)"
        )
    if source == "findings_monitoring":
        return snapshot.connectors > 0, (
            f"{snapshot.connectors} connector(s), {snapshot.findings} finding(s)"
        )
    if source == "pii_minimization":
        return snapshot.audit_rows > 0, (
            f"{snapshot.pii_rows} of {snapshot.audit_rows} row(s) recorded PII"
        )
    if source == "access_control":
        return snapshot.audit_rows > 0, (
            f"{snapshot.audit_rows} tenant-owned row(s) available for review"
        )
    if source == "transparency_disclosure":
        return False, "no synthetic-content disclosure fact is recorded"
    return False, f"unrecognized evidence source: {source}"


def assess(
    frameworks: list[str],
    snapshot: EvidenceSnapshot,
) -> EvidenceReport:
    definitions = load_frameworks()
    requested = set(frameworks)
    sections: list[FrameworkAssessment] = []
    for identifier in FRAMEWORK_ORDER:
        if identifier not in requested or identifier not in definitions:
            continue
        framework = definitions[identifier]
        controls = []
        for control in framework.controls:
            satisfied, evidence = _evidence(control.evidence_source, snapshot)
            controls.append(
                ControlAssessment(
                    control=control,
                    status="satisfied" if satisfied else "gap",
                    evidence=evidence,
                )
            )
        sections.append(FrameworkAssessment(framework, tuple(controls)))
    return EvidenceReport(snapshot, tuple(sections))


def _render_csv(report: EvidenceReport) -> bytes:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        ("framework", "control_id", "title", "status", "evidence_source", "evidence")
    )
    for section in report.frameworks:
        for assessment in section.controls:
            writer.writerow(
                (
                    section.framework.identifier,
                    assessment.control.identifier,
                    assessment.control.title,
                    assessment.status,
                    assessment.control.evidence_source,
                    assessment.evidence,
                )
            )
    return output.getvalue().encode("utf-8-sig")


def _render_pdf(report: EvidenceReport) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

    ensure_report_fonts()
    styles = getSampleStyleSheet()
    styles["Title"].fontName = REPORT_FONT_BOLD
    styles["Heading2"].fontName = REPORT_FONT_BOLD
    styles["Normal"].fontName = REPORT_FONT
    snapshot = report.snapshot
    output = io.BytesIO()
    document = SimpleDocTemplate(
        output,
        pagesize=A4,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        title="Compliance Evidence Assessment",
    )
    story = [
        Paragraph("Compliance Evidence Assessment", styles["Title"]),
        Paragraph(
            f"Period: {snapshot.start.date()} – {snapshot.end.date()}<br/>"
            f"Generated: {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}<br/>"
            f"Frameworks: {', '.join(item.framework.identifier for item in report.frameworks)}",
            styles["Normal"],
        ),
        Spacer(1, 5 * mm),
        Paragraph("Evidence summary", styles["Heading2"]),
        evidence_table(
            [
                [
                    "Audit rows",
                    str(snapshot.audit_rows),
                    "Chain",
                    "verified" if snapshot.chain_valid else "not verified",
                ],
                [
                    "Anchors",
                    str(snapshot.anchors),
                    "Retention",
                    str(snapshot.retention_days),
                ],
                [
                    "Findings",
                    str(snapshot.findings),
                    "Oversight",
                    str(snapshot.oversight_events),
                ],
            ],
            ["Metric", "Value", "Metric", "Value"],
        ),
        Spacer(1, 6 * mm),
    ]
    for section in report.frameworks:
        story.extend(
            [
                Paragraph(
                    f"{section.framework.title} "
                    f"({section.satisfied} satisfied / {section.gaps} gap)",
                    styles["Heading2"],
                ),
                evidence_table(
                    [
                        [
                            item.control.identifier,
                            item.status.upper(),
                            item.evidence,
                        ]
                        for item in section.controls
                    ]
                    or [["—", "—", "—"]],
                    ["Control", "Status", "Evidence"],
                ),
                Spacer(1, 6 * mm),
            ]
        )
    story.extend(
        [
            Paragraph("Evidence limitation", styles["Heading2"]),
            Paragraph(_DISCLAIMER, styles["Normal"]),
        ]
    )
    document.build(story)
    return output.getvalue()


async def generate_audit_report(
    session: AsyncSession,
    *,
    org_id: UUID,
    frameworks: list[str],
    start: datetime,
    end: datetime,
    connector_id: UUID | None = None,
    fmt: str = "pdf",
) -> tuple[bytes, str, str]:
    snapshot = await collect_evidence(
        session,
        tenant_id=org_id,
        start=start,
        end=end,
        connector_id=connector_id,
    )
    report = assess(frameworks, snapshot)
    suffix = end.strftime("%Y%m%d")
    if fmt == "csv":
        return _render_csv(report), "text/csv", f"compliance_evidence_{suffix}.csv"
    if fmt != "pdf":
        raise ValueError("report format must be pdf or csv")
    content = await asyncio.to_thread(_render_pdf, report)
    return content, "application/pdf", f"compliance_evidence_{suffix}.pdf"
