"""Read-only tenant projections for the AI governance overview."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, cast
from uuid import UUID

from sqlalchemy import Select, case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.ai_act.models import AIActAuditAnchor, AIActAuditLog
from shim_enterprise.ai_act.retention import (
    RETENTION_FLOOR_DAYS,
    effective_retention_days,
)
from shim_enterprise.compliance.models import ComplianceConnector, ComplianceFinding
from shim_enterprise.observability.analytics_projection import RequestLog


@dataclass(frozen=True, slots=True)
class OverviewWindow:
    start: datetime | None = None
    end: datetime | None = None

    def constrain(self, statement: Select[Any], column: Any) -> Select[Any]:
        if self.start is not None:
            statement = statement.where(column >= self.start)
        if self.end is not None:
            statement = statement.where(column <= self.end)
        return statement


def empty_overview() -> dict[str, dict[str, object]]:
    return {
        "detective": {
            "total_findings": 0,
            "by_severity": {},
            "by_entity_type": {},
            "by_kvkk_category": {},
        },
        "preventive": {
            "total_requests": 0,
            "pii_detected_requests": 0,
            "redaction_rate": 0.0,
            "cache_hit_rate": 0.0,
            "top_entity_types": {},
        },
        "audit_log": {
            "total_rows": 0,
            "coverage": 0.0,
            "retention_days": effective_retention_days(),
            "retention_floor_days": RETENTION_FLOOR_DAYS,
            "last_anchor_date": None,
            "last_anchor_root": None,
        },
        "connectors": {
            "total": 0,
            "healthy": 0,
            "errored": 0,
            "max_lag_seconds": 0.0,
        },
    }


class OverviewProjector:
    """Build the four metadata-only sections without crossing tenant scope."""

    def __init__(
        self,
        session: AsyncSession,
        tenant_id: UUID,
        window: OverviewWindow,
    ) -> None:
        self.session = session
        self.tenant_id = tenant_id
        self.window = window

    def _finding_query(self, *columns: Any) -> Select[Any]:
        statement = (
            select(*columns)
            .join(
                ComplianceConnector,
                ComplianceFinding.connector_id == ComplianceConnector.id,
            )
            .where(ComplianceConnector.organization_id == self.tenant_id)
        )
        return self.window.constrain(statement, ComplianceFinding.occurred_at)

    async def detective(self) -> dict[str, object]:
        total = int(
            await self.session.scalar(
                self._finding_query(func.count(ComplianceFinding.id))
            )
            or 0
        )

        async def counts(column: Any) -> dict[str, int]:
            result = await self.session.execute(
                self._finding_query(column, func.count(ComplianceFinding.id)).group_by(
                    column
                )
            )
            return {
                str(value): int(count)
                for value, count in result.all()
                if value is not None
            }

        return {
            "total_findings": total,
            "by_severity": await counts(ComplianceFinding.severity),
            "by_entity_type": await counts(ComplianceFinding.entity_type),
            "by_kvkk_category": await counts(ComplianceFinding.kvkk_category),
        }

    async def preventive(self) -> dict[str, object]:
        totals = select(
            func.count(RequestLog.id),
            func.sum(case((RequestLog.pii_detected.is_(True), 1), else_=0)),
            func.sum(case((RequestLog.is_cache_hit.is_(True), 1), else_=0)),
        ).where(RequestLog.organization_id == self.tenant_id)
        totals = self.window.constrain(totals, RequestLog.timestamp)
        request_count, pii_count, cache_count = (
            await self.session.execute(totals)
        ).one()
        requests = int(request_count or 0)
        pii = int(pii_count or 0)
        cache = int(cache_count or 0)

        entities_query = select(AIActAuditLog.pii_entities).where(
            AIActAuditLog.organization_id == self.tenant_id,
            AIActAuditLog.pii_detected.is_(True),
        )
        entities_query = self.window.constrain(entities_query, AIActAuditLog.created_at)
        entity_counts: Counter[str] = Counter()
        for (entities,) in (await self.session.execute(entities_query)).all():
            if isinstance(entities, dict):
                entity_counts.update(
                    {str(name): int(count) for name, count in entities.items()}
                )

        return {
            "total_requests": requests,
            "pii_detected_requests": pii,
            "redaction_rate": pii / requests if requests else 0.0,
            "cache_hit_rate": cache / requests if requests else 0.0,
            "top_entity_types": dict(entity_counts.most_common(15)),
        }

    async def audit(self, request_count: int) -> dict[str, object]:
        count_query = select(func.count(AIActAuditLog.id)).where(
            AIActAuditLog.organization_id == self.tenant_id,
            AIActAuditLog.event_type == "ai_request",
        )
        count_query = self.window.constrain(count_query, AIActAuditLog.created_at)
        audit_count = int(await self.session.scalar(count_query) or 0)
        anchor = (
            await self.session.execute(
                select(AIActAuditAnchor)
                .where(AIActAuditAnchor.organization_id == self.tenant_id)
                .order_by(AIActAuditAnchor.anchor_date.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        coverage = (
            min(1.0, audit_count / request_count)
            if request_count
            else float(bool(audit_count))
        )
        return {
            "total_rows": audit_count,
            "coverage": coverage,
            "retention_days": effective_retention_days(),
            "retention_floor_days": RETENTION_FLOOR_DAYS,
            "last_anchor_date": anchor.anchor_date.isoformat() if anchor else None,
            "last_anchor_root": anchor.root_hash if anchor else None,
        }

    async def connectors(self) -> dict[str, object]:
        connectors = list(
            (
                await self.session.execute(
                    select(ComplianceConnector).where(
                        ComplianceConnector.organization_id == self.tenant_id
                    )
                )
            ).scalars()
        )
        now = datetime.now(timezone.utc)
        lags = [
            max(0.0, (now - connector.last_success_at).total_seconds())
            for connector in connectors
            if connector.last_success_at is not None
        ]
        errored = sum(
            connector.status == "error" or bool(connector.consecutive_errors)
            for connector in connectors
        )
        return {
            "total": len(connectors),
            "healthy": sum(
                connector.status == "active" and not connector.consecutive_errors
                for connector in connectors
            ),
            "errored": errored,
            "max_lag_seconds": max(lags, default=0.0),
        }


async def build_overview(
    session: AsyncSession,
    org_id: UUID,
    start: datetime | None = None,
    end: datetime | None = None,
) -> dict[str, dict[str, object]]:
    if start is not None and end is not None and start > end:
        raise ValueError("overview start must not be after end")
    projector = OverviewProjector(session, org_id, OverviewWindow(start, end))
    preventive = await projector.preventive()
    return {
        "detective": await projector.detective(),
        "preventive": preventive,
        "audit_log": await projector.audit(cast(int, preventive["total_requests"])),
        "connectors": await projector.connectors(),
    }
