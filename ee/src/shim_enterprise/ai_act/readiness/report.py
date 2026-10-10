"""The ISO/IEC 42001 mapping, its measured and input evidence, and the report."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Sequence
import csv
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from functools import lru_cache
from importlib import resources
import io
from uuid import UUID
from xml.sax.saxutils import escape

import yaml
from sqlalchemy import Uuid, cast, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.ai_act.models import AIActAuditLog, ReadinessDeclaration
from shim_enterprise.ai_act.report import collect_evidence
from shim_enterprise.ai_act.retention import RETENTION_FLOOR_DAYS
from shim_enterprise.ai_act.verify import AuditVerificationLimitExceeded
from shim_enterprise.billing.models import (
    REQUEST_LIFECYCLE_TERMINAL_STATUSES,
    RequestLifecycle,
)
from shim_enterprise.billing.read_models import BillingBreakdown
from shim_enterprise.compliance.classification import classify
from shim_enterprise.compliance.reporting import (
    build_pdf,
    evidence_table,
    lifecycle_window,
    report_styles,
    safe_csv,
)
from shim_enterprise.compliance.services.monthly_evidence import (
    denial_counts,
    entity_counts,
    usage_breakdowns,
)
from shim_enterprise.observability.model_inventory import ModelInventoryReadModel
from shim_enterprise.tenants.models import ModelDeployment, Team


FRAMEWORK = "iso42001"
SOURCES = ("measured", "input", "declared")
MAX_READINESS_WINDOW = timedelta(days=366)
NOT_DECLARED = "not declared"
COVER = (
    "This report shows which ISO/IEC 42001 Annex A controls shim can evidence from "
    "gateway traffic, and records the organization's own statements for the rest. "
    "It is not an audit, a certification or a statement of conformity."
)
UNVERIFIED = (
    "Control numbers and titles have not yet been checked against the published "
    "standard."
)
# reportlab cannot split a table row across pages, so one cell stays well under a
# page: a long summary or note is cut here and read whole in the CSV.
_PDF_TEXT_LIMIT = 900


@dataclass(frozen=True, slots=True)
class ReadinessControl:
    identifier: str
    title: str
    source: str
    evidence: str | None
    rule: str | None


@dataclass(frozen=True, slots=True)
class ReadinessMapping:
    verified_against_standard: bool
    controls: tuple[ReadinessControl, ...]

    def control(self, identifier: str) -> ReadinessControl | None:
        return next(
            (item for item in self.controls if item.identifier == identifier), None
        )


@dataclass(frozen=True, slots=True)
class Evidence:
    present: bool
    summary: str


@dataclass(frozen=True, slots=True)
class ReadinessRow:
    control: ReadinessControl
    evidence: Evidence | None
    declaration: ReadinessDeclaration | None

    @property
    def declared(self) -> str:
        if self.declaration is not None:
            return self.declaration.status
        return NOT_DECLARED if self.control.source == "declared" else ""


@lru_cache(maxsize=1)
def load_mapping() -> ReadinessMapping:
    """Load and validate the packaged mapping once per process."""
    raw = yaml.safe_load(
        resources.files("shim_enterprise.ai_act.readiness")
        .joinpath(f"{FRAMEWORK}.yaml")
        .read_text(encoding="utf-8")
    )
    if (
        not isinstance(raw, dict)
        or raw.get("framework") != FRAMEWORK
        or not isinstance(raw.get("verified_against_standard"), bool)
        or not isinstance(raw.get("controls"), list)
    ):
        raise ValueError(f"{FRAMEWORK}.yaml: invalid readiness mapping")
    controls = []
    for item in raw["controls"]:
        source = item.get("source") if isinstance(item, dict) else None
        if source not in SOURCES:
            raise ValueError(f"{FRAMEWORK}.yaml: invalid control {item!r}")
        evidence, rule = item.get("evidence"), item.get("rule")
        if (source == "declared") != (evidence is None) or (
            evidence is not None and (evidence not in EVIDENCE or not rule)
        ):
            raise ValueError(f"{FRAMEWORK}.yaml: invalid evidence for {item['id']}")
        controls.append(
            ReadinessControl(
                identifier=str(item["id"]),
                title=str(item["title"]),
                source=source,
                evidence=evidence,
                rule=rule,
            )
        )
    if len({control.identifier for control in controls}) != len(controls):
        raise ValueError(f"{FRAMEWORK}.yaml: duplicate control ids")
    return ReadinessMapping(raw["verified_against_standard"], tuple(controls))


def _share(part: int, whole: int) -> str:
    return f"{part} of {whole}" + (f" ({part / whole:.1%})" if whole else "")


@dataclass(frozen=True, slots=True)
class Traffic:
    """Window facts several evidence keys read, queried once per report."""

    requests: int
    providers: Sequence[BillingBreakdown]
    models: Sequence[BillingBreakdown]
    personal_data: dict[tuple[str, str], int]


async def measure_traffic(
    session: AsyncSession, tenant_id: UUID, start: datetime, end: datetime
) -> Traffic:
    providers, models = await usage_breakdowns(session, tenant_id, start, end)
    requests = await session.scalar(
        select(func.count()).where(*lifecycle_window(tenant_id, start, end))
    )
    return Traffic(
        requests=int(requests or 0),
        providers=providers,
        models=models,
        personal_data=await entity_counts(
            session, tenant_id, start, end, "pii_entities"
        )
        or {},
    )


async def _operation(
    session: AsyncSession,
    tenant_id: UUID,
    start: datetime,
    end: datetime,
    traffic: Traffic,
) -> Evidence:
    scope = lifecycle_window(tenant_id, start, end)
    terminal = await session.scalar(
        select(func.count()).where(
            *scope,
            RequestLifecycle.status.in_(tuple(REQUEST_LIFECYCLE_TERMINAL_STATUSES)),
        )
    )
    # A semi-join, not an EXISTS probe per lifecycle row.
    with_audit = await session.scalar(
        select(func.count()).where(
            *scope,
            RequestLifecycle.request_id.in_(
                select(AIActAuditLog.request_id).where(
                    AIActAuditLog.organization_id == tenant_id
                )
            ),
        )
    )
    requests, with_audit, terminal = traffic.requests, with_audit or 0, terminal or 0
    return Evidence(
        requests > 0 and with_audit > 0,
        f"{requests} request(s); {_share(with_audit, requests)} with an audit row; "
        f"{_share(terminal, requests)} with a terminal status.",
    )


async def _event_logs(
    session: AsyncSession,
    tenant_id: UUID,
    start: datetime,
    end: datetime,
    traffic: Traffic,
) -> Evidence:
    try:
        snapshot = await collect_evidence(
            session, tenant_id=tenant_id, start=start, end=end, connector_id=None
        )
    except AuditVerificationLimitExceeded as exc:
        return Evidence(False, f"Chain verification could not run: {exc}.")
    verified = "chain verified" if snapshot.chain_valid else "chain did not verify"
    return Evidence(
        snapshot.audit_rows > 0
        and snapshot.chain_valid
        and snapshot.retention_days >= RETENTION_FLOOR_DAYS,
        f"{snapshot.audit_rows} audit row(s); {verified}; {snapshot.anchors} daily "
        f"anchor(s); retention {snapshot.retention_days} days.",
    )


async def _responsible_use(
    session: AsyncSession,
    tenant_id: UUID,
    start: datetime,
    end: datetime,
    traffic: Traffic,
) -> Evidence:
    verdicts = RequestLifecycle.lifecycle_metadata["policy_verdicts"]
    privacy = verdicts.contains([{"rule_id": "privacy.input"}])
    admission = verdicts.contains([{"stage": "admission"}])
    requests, with_privacy, with_admission, with_both = (
        await session.execute(
            select(
                func.count(),
                func.count().filter(privacy),
                func.count().filter(admission),
                func.count().filter(privacy, admission),
            ).where(*lifecycle_window(tenant_id, start, end))
        )
    ).one()
    denials = await denial_counts(session, tenant_id, start, end)
    denied = (
        "; ".join(f"{rule} {reason}: {count}" for rule, reason, count in denials)
        or "none"
    )
    return Evidence(
        with_both > 0,
        f"{_share(with_privacy, requests)} request(s) with a privacy.input verdict; "
        f"{_share(with_admission, requests)} with an admission verdict; denials: "
        f"{denied}.",
    )


def _usage(rows: Sequence[BillingBreakdown]) -> str:
    return (
        ", ".join(
            f"{row.key} {row.request_count} request(s) "
            + (
                "cost unknown"
                if row.unpriced_requests
                else f"{row.cost_usd.quantize(Decimal('0.000001'))} USD"
            )
            for row in rows
        )
        or "none"
    )


async def _suppliers(
    session: AsyncSession,
    tenant_id: UUID,
    start: datetime,
    end: datetime,
    traffic: Traffic,
) -> Evidence:
    return Evidence(
        bool(traffic.providers),
        f"Providers: {_usage(traffic.providers)}. Models: {_usage(traffic.models)}.",
    )


async def _deployments_in_use(
    session: AsyncSession, tenant_id: UUID, start: datetime, end: datetime
) -> list[str]:
    used = (
        select(RequestLifecycle.id)
        .where(
            *lifecycle_window(tenant_id, start, end),
            RequestLifecycle.requested_model == ModelDeployment.alias,
        )
        .correlate(ModelDeployment)
        .exists()
    )
    return list(
        await session.scalars(
            select(ModelDeployment.alias)
            .where(ModelDeployment.organization_id == tenant_id, used)
            .order_by(ModelDeployment.alias)
        )
    )


async def _tooling(
    session: AsyncSession,
    tenant_id: UUID,
    start: datetime,
    end: datetime,
    traffic: Traffic,
) -> Evidence:
    suppliers = await _suppliers(session, tenant_id, start, end, traffic)
    deployments = await _deployments_in_use(session, tenant_id, start, end)
    return Evidence(
        suppliers.present,
        f"{suppliers.summary} Registered deployments in use: "
        f"{', '.join(deployments) or 'none'}.",
    )


async def _resource_documentation(
    session: AsyncSession,
    tenant_id: UUID,
    start: datetime,
    end: datetime,
    traffic: Traffic,
) -> Evidence:
    inventory = await ModelInventoryReadModel().read(
        session, tenant_id=tenant_id, start_at=start, end_at=end
    )
    deployments = sorted(
        (item.alias, item.owner, item.declared_version)
        for item in inventory.items
        if item.route == "registry"
    )
    # The inventory's catalog items, so this report and the inventory read agree.
    unregistered = sorted(
        {
            item.model
            for item in inventory.items
            if item.route == "catalog" and item.model
        }
    )
    documented = all(owner and version for _, owner, version in deployments)
    return Evidence(
        bool(deployments) and documented,
        "Registered deployments: "
        + (
            ", ".join(
                f"{alias} (owner {owner}, version {version})"
                for alias, owner, version in deployments
            )
            or "none"
        )
        + ". Models in traffic outside the registry: "
        + (", ".join(str(model) for model in unregistered) or "none")
        + ".",
    )


async def _intended_use(
    session: AsyncSession,
    tenant_id: UUID,
    start: datetime,
    end: datetime,
    traffic: Traffic,
) -> Evidence:
    metadata = RequestLifecycle.lifecycle_metadata
    tagged = or_(
        func.jsonb_array_length(
            func.coalesce(metadata["tags"], func.jsonb_build_array())
        )
        > 0,
        metadata["cost_center"].as_string().not_in(("untagged", "")),
    )
    requests, labelled = (
        await session.execute(
            select(func.count(), func.count().filter(tagged)).where(
                *lifecycle_window(tenant_id, start, end)
            )
        )
    ).one()
    return Evidence(
        requests > 0,
        f"{_share(labelled, requests)} request(s) carry a tag or a cost center.",
    )


async def _personal_data(
    session: AsyncSession,
    tenant_id: UUID,
    start: datetime,
    end: datetime,
    traffic: Traffic,
) -> Evidence:
    return Evidence(
        traffic.requests > 0,
        "Personal data masked, by type and provider: "
        + (
            ", ".join(
                f"{entity} via {provider} {count}"
                for (provider, entity), count in sorted(traffic.personal_data.items())
            )
            or "none"
        )
        + ".",
    )


async def _inventory(
    session: AsyncSession,
    tenant_id: UUID,
    start: datetime,
    end: datetime,
    traffic: Traffic,
) -> Evidence:
    team_ids = RequestLifecycle.lifecycle_metadata["team_id"].as_string()
    teams = list(
        await session.scalars(
            select(Team.name)
            .where(
                Team.organization_id == tenant_id,
                Team.id.in_(
                    select(cast(team_ids, Uuid)).where(
                        *lifecycle_window(tenant_id, start, end),
                        team_ids.is_not(None),
                    )
                ),
            )
            .order_by(Team.name)
        )
    )
    categories = sorted(
        {
            f"{classify(entity).kvkk_category or 'unclassified'} ({entity})"
            for _, entity in traffic.personal_data
        }
    )
    return Evidence(
        traffic.requests > 0,
        f"Models: {', '.join(row.key for row in traffic.models) or 'none'}. "
        f"Providers: {', '.join(row.key for row in traffic.providers) or 'none'}. "
        f"Teams: {', '.join(teams) or 'none'}. "
        f"Data categories at runtime: {', '.join(categories) or 'none'}.",
    )


EVIDENCE: dict[
    str,
    Callable[[AsyncSession, UUID, datetime, datetime, Traffic], Awaitable[Evidence]],
] = {
    "operation": _operation,
    "event_logs": _event_logs,
    "responsible_use": _responsible_use,
    "suppliers": _suppliers,
    "tooling": _tooling,
    "resource_documentation": _resource_documentation,
    "intended_use": _intended_use,
    "personal_data": _personal_data,
    "inventory": _inventory,
}


async def collect_readiness(
    session: AsyncSession, tenant_id: UUID, start: datetime, end: datetime
) -> list[ReadinessRow]:
    mapping = load_mapping()
    traffic = await measure_traffic(session, tenant_id, start, end)
    measured: dict[str, Evidence] = {}
    for control in mapping.controls:
        if control.evidence is not None and control.evidence not in measured:
            measured[control.evidence] = await EVIDENCE[control.evidence](
                session, tenant_id, start, end, traffic
            )
    declarations = {
        row.control_id: row
        for row in await session.scalars(
            select(ReadinessDeclaration).where(
                ReadinessDeclaration.organization_id == tenant_id,
                ReadinessDeclaration.framework == FRAMEWORK,
            )
        )
    }
    return [
        ReadinessRow(
            control,
            measured.get(control.evidence) if control.evidence else None,
            declarations.get(control.identifier),
        )
        for control in mapping.controls
    ]


_CSV_FIELDS = (
    "control_id",
    "title",
    "source",
    "evidence_present",
    "evidence",
    "rule",
    "declaration",
    "note",
)


def render_csv(rows: list[ReadinessRow], *, verified: bool) -> bytes:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerows([[COVER], *([] if verified else [[UNVERIFIED]]), []])
    writer.writerow(_CSV_FIELDS)
    for row in rows:
        note = row.declaration.note if row.declaration else None
        writer.writerow(
            (
                row.control.identifier,
                row.control.title,
                row.control.source,
                "" if row.evidence is None else str(row.evidence.present).lower(),
                "" if row.evidence is None else row.evidence.summary,
                row.control.rule or "",
                row.declared,
                # A spreadsheet must not read the organization's note as a formula.
                safe_csv(note),
            )
        )
    return output.getvalue().encode("utf-8-sig")


def render_pdf(
    rows: list[ReadinessRow],
    *,
    tenant_id: UUID,
    start: datetime,
    end: datetime,
    verified: bool,
) -> bytes:
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, Spacer

    styles = report_styles()
    cell = styles["Normal"].clone("cell", fontSize=8, leading=10)

    def bounded(text: str) -> str:
        if len(text) <= _PDF_TEXT_LIMIT:
            return text
        return f"{text[:_PDF_TEXT_LIMIT]}… (truncated, see CSV)"

    def detail(row: ReadinessRow) -> str:
        parts = []
        if row.evidence is not None:
            parts.append(
                ("Evidence present. " if row.evidence.present else "No evidence. ")
                + bounded(row.evidence.summary)
            )
        if row.declared:
            parts.append(f"Declaration: {row.declared}.")
        if row.declaration is not None and row.declaration.note:
            parts.append(bounded(row.declaration.note))
        return escape(" ".join(parts))

    story = [
        Paragraph("ISO/IEC 42001 Readiness", styles["Title"]),
        Paragraph(
            f"Organization: {tenant_id}<br/>"
            f"Window: {start:%Y-%m-%d %H:%M} – {end:%Y-%m-%d %H:%M} UTC<br/>"
            f"Generated: {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}",
            styles["Normal"],
        ),
        Spacer(1, 3 * mm),
        Paragraph(COVER, styles["Normal"]),
        *(
            []
            if verified
            else [Spacer(1, 2 * mm), Paragraph(UNVERIFIED, styles["Normal"])]
        ),
        Spacer(1, 3 * mm),
        Paragraph(
            "Measured rows come from request_lifecycle, the audit chain and the "
            "model registry over the window; input rows are numbers for the "
            "organization's own statement; declared rows hold the organization's "
            "statement only.",
            styles["Normal"],
        ),
        Spacer(1, 4 * mm),
        evidence_table(
            [
                [
                    row.control.identifier,
                    Paragraph(escape(row.control.title), cell),
                    row.control.source,
                    Paragraph(detail(row), cell),
                ]
                for row in rows
            ],
            ["Control", "Title", "Source", "Evidence or declaration"],
            # Fixed widths: A4 less two 14 mm margins.
            [18 * mm, 42 * mm, 20 * mm, 102 * mm],
        ),
    ]
    return build_pdf(story, "ISO/IEC 42001 Readiness", side_margin=14)


async def generate_readiness_report(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    start: datetime,
    end: datetime,
    fmt: str,
) -> tuple[bytes, str, str]:
    rows = await collect_readiness(session, tenant_id, start, end)
    suffix = end.strftime("%Y%m%d")
    verified = load_mapping().verified_against_standard
    if fmt == "csv":
        return (
            render_csv(rows, verified=verified),
            "text/csv",
            f"iso42001_readiness_{suffix}.csv",
        )
    content = await asyncio.to_thread(
        render_pdf, rows, tenant_id=tenant_id, start=start, end=end, verified=verified
    )
    return content, "application/pdf", f"iso42001_readiness_{suffix}.pdf"
