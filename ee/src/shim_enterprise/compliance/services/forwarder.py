"""Durable compliance delivery-intent construction."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.compliance.classification import meets_threshold
from shim_enterprise.compliance.models import (
    ComplianceConnector,
    ComplianceForwardTarget,
)
from shim.gateway.contracts.ids import TenantId
from shim_enterprise.outbox.publisher import OutboxWriter


DELIVERY_EVENT = "compliance.connector_delivery_requested"


class ComplianceForwarderService:
    """Append post-commit delivery work without performing external I/O."""

    async def handle_run(
        self,
        session: AsyncSession,
        connector: ComplianceConnector,
        findings: list[dict[str, Any]],
    ) -> dict[str, int]:
        targets = await self._targets(session, connector.id)
        queued = 0
        for target in targets:
            eligible = [
                finding
                for finding in findings
                if meets_threshold(finding["severity"], target.min_severity)
            ]
            if target.kind != "siem_webhook" and eligible:
                body = _summary_payload(connector, eligible)
                await self._append(
                    session,
                    connector,
                    target,
                    body=body,
                    delivery_key=_summary_key(connector, eligible),
                )
                queued += 1
                continue
            for finding in eligible:
                body = _finding_payload(connector, finding)
                await self._append(
                    session,
                    connector,
                    target,
                    body=body,
                    delivery_key=_finding_key(body),
                )
                queued += 1
        return {"deliveries_queued": queued}

    async def send_operational_alert(
        self,
        session: AsyncSession,
        connector: ComplianceConnector,
        *,
        kind: str,
        message: str,
    ) -> dict[str, int]:
        now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        body = {
            "source": "shim-compliance",
            "event_type": "connector_health",
            "provider": connector.provider,
            "connector_id": str(connector.id),
            "kind": kind,
            "message": message[:1_000],
            "occurred_at": now.isoformat(),
        }
        digest = hashlib.sha256(
            json.dumps((kind, message[:1_000]), separators=(",", ":")).encode()
        ).hexdigest()[:24]
        targets = await self._targets(session, connector.id)
        for target in targets:
            await self._append(
                session,
                connector,
                target,
                body=body,
                delivery_key=f"health:{now:%Y%m%d%H}:{digest}",
            )
        return {"deliveries_queued": len(targets)}

    @staticmethod
    async def _targets(
        session: AsyncSession,
        connector_id: Any,
    ) -> tuple[ComplianceForwardTarget, ...]:
        statement = (
            select(ComplianceForwardTarget)
            .where(
                ComplianceForwardTarget.connector_id == connector_id,
                ComplianceForwardTarget.enabled.is_(True),
            )
            .with_for_update(read=True, of=ComplianceForwardTarget)
        )
        return tuple((await session.execute(statement)).scalars())

    @staticmethod
    async def _append(
        session: AsyncSession,
        connector: ComplianceConnector,
        target: ComplianceForwardTarget,
        *,
        body: dict[str, Any],
        delivery_key: str,
    ) -> None:
        tenant_id = TenantId(connector.organization_id)
        await OutboxWriter().append(
            session,
            organization_id=tenant_id,
            values={
                "event_type": DELIVERY_EVENT,
                "aggregate_type": "compliance_connector",
                "aggregate_id": str(connector.id),
                "idempotency_key": (
                    f"compliance:{connector.id}:target:{target.id}:{delivery_key}"
                ),
                "payload": {
                    "organization_id": str(tenant_id),
                    "connector_id": str(connector.id),
                    "target_id": str(target.id),
                    "target_kind": target.kind,
                    "secret_ref": target.secret_ref,
                    "body": body,
                },
                "status": "pending",
                "next_attempt_at": datetime.now(timezone.utc),
            },
        )


def _finding_payload(
    connector: ComplianceConnector,
    finding: dict[str, Any],
) -> dict[str, Any]:
    occurred = finding.get("occurred_at")
    return {
        "source": "shim-compliance",
        "event_type": "pii_finding",
        "provider": connector.provider,
        "connector_id": str(connector.id),
        "severity": finding["severity"],
        "entity_type": finding["entity_type"],
        "content_id": finding.get("content_id"),
        "value_hash": finding.get("value_hash"),
        "match_offset": finding.get("match_offset"),
        "match_length": finding.get("match_length"),
        "occurred_at": (
            occurred.isoformat() if hasattr(occurred, "isoformat") else occurred
        ),
    }


def _finding_key(body: dict[str, Any]) -> str:
    digest = hashlib.sha256(
        json.dumps(body, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
    return f"finding:{digest[:32]}"


def _summary_payload(
    connector: ComplianceConnector,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    by_severity: dict[str, int] = {}
    by_entity_type: dict[str, int] = {}
    for finding in findings:
        severity = str(finding["severity"])
        entity_type = str(finding["entity_type"])
        by_severity[severity] = by_severity.get(severity, 0) + 1
        by_entity_type[entity_type] = by_entity_type.get(entity_type, 0) + 1
    return {
        "source": "shim-compliance",
        "event_type": "pii_finding_summary",
        "provider": connector.provider,
        "connector_id": str(connector.id),
        "finding_count": len(findings),
        "by_severity": by_severity,
        "by_entity_type": by_entity_type,
    }


def _summary_key(
    connector: ComplianceConnector,
    findings: list[dict[str, Any]],
) -> str:
    finding_keys = sorted(
        _finding_key(_finding_payload(connector, finding)) for finding in findings
    )
    return _finding_key({"findings": finding_keys})
