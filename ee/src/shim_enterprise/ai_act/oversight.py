"""Asynchronous, tenant-scoped human-oversight evaluation and decisions."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any, Literal
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.ai_act.audit_writer import write_audit_row
from shim_enterprise.ai_act.models import (
    AIActAuditLog,
    OversightPolicy,
    OversightRequest,
)
from shim_enterprise.compliance.classification import (
    classify,
    meets_threshold,
    severity_rank,
)
from shim_enterprise.core.config import settings


class OversightStateError(RuntimeError):
    """Raised when an oversight transition violates the state machine."""


_TRIGGER_LIST_FIELDS = ("models", "endpoints", "entity_types")
_TRIGGER_FIELDS = frozenset((*_TRIGGER_LIST_FIELDS, "pii_detected", "min_severity"))


def validate_trigger(trigger: Mapping[str, Any]) -> None:
    """Reject policies that cannot be evaluated safely and predictably."""

    if not isinstance(trigger, Mapping) or not trigger:
        raise ValueError("trigger must not be empty")
    unknown = set(trigger).difference(_TRIGGER_FIELDS)
    if unknown:
        raise ValueError(
            f"trigger contains unsupported fields: {', '.join(sorted(unknown))}"
        )
    for field in _TRIGGER_LIST_FIELDS:
        if field not in trigger:
            continue
        values = trigger[field]
        if (
            not isinstance(values, list)
            or not values
            or any(not isinstance(value, str) or not value for value in values)
        ):
            raise ValueError(f"{field} must be a non-empty list of non-empty strings")
    if "pii_detected" in trigger and not isinstance(trigger["pii_detected"], bool):
        raise ValueError("pii_detected must be a boolean")
    if "min_severity" in trigger and (
        not isinstance(trigger["min_severity"], str)
        or severity_rank(trigger["min_severity"]) < 0
    ):
        raise ValueError("min_severity must be low, medium, high, or critical")


def _event_max_severity(pii_entities: Mapping[str, int]) -> str | None:
    severities = [classify(entity_type).severity for entity_type in pii_entities]
    return max(severities, key=severity_rank, default=None)


def matches_trigger(
    trigger: Mapping[str, Any],
    event: Mapping[str, Any],
) -> bool:
    """Match every configured condition; an empty trigger matches nothing."""

    try:
        validate_trigger(trigger)
    except ValueError:
        return False
    checks: list[bool] = []
    for field in ("models", "endpoints"):
        if field in trigger:
            allowed = trigger[field]
            event_field = "model" if field == "models" else "endpoint"
            checks.append(event.get(event_field) in allowed)
    raw_entities = event.get("pii_entities")
    entities = raw_entities if isinstance(raw_entities, Mapping) else {}
    if "entity_types" in trigger:
        entity_types = trigger["entity_types"]
        checks.append(bool(set(entities).intersection(entity_types)))
    if "pii_detected" in trigger:
        checks.append(event.get("pii_detected") is trigger["pii_detected"])
    if "min_severity" in trigger:
        minimum = trigger["min_severity"]
        maximum = _event_max_severity(entities)
        checks.append(maximum is not None and meets_threshold(maximum, minimum))
    return bool(checks) and all(checks)


async def _append_audit_event(
    session: AsyncSession,
    *,
    organization_id: UUID,
    event_type: str,
    request_ref: str,
    details: dict[str, Any],
) -> None:
    await write_audit_row(
        {
            "organization_id": organization_id,
            "event_type": event_type,
            "request_id": request_ref,
            "pii_detected": False,
            "pii_entities": {},
            "policy_verdicts": [details.get("decision") or event_type],
            "extra": details,
        },
        session,
    )


async def run_oversight_evaluation(
    session: AsyncSession,
    *,
    org_id: UUID | None = None,
    lookback_seconds: int = 86_400,
    now: datetime | None = None,
) -> dict[str, int]:
    """Create at most one oversight request for each matching audit entry."""

    if lookback_seconds <= 0:
        raise ValueError("lookback_seconds must be positive")
    current = now or datetime.now(timezone.utc)
    policy_query = select(OversightPolicy).where(OversightPolicy.enabled.is_(True))
    row_query = select(AIActAuditLog).where(
        AIActAuditLog.event_type == "ai_request",
        AIActAuditLog.created_at >= current - timedelta(seconds=lookback_seconds),
    )
    if org_id is not None:
        policy_query = policy_query.where(OversightPolicy.organization_id == org_id)
        row_query = row_query.where(AIActAuditLog.organization_id == org_id)

    policies = (
        await session.execute(
            policy_query.order_by(OversightPolicy.organization_id, OversightPolicy.id)
        )
    ).scalars()
    by_tenant: dict[UUID, list[OversightPolicy]] = {}
    for policy in policies:
        by_tenant.setdefault(policy.organization_id, []).append(policy)
    if not by_tenant:
        return {"evaluated": 0, "created": 0}

    rows = list(
        (
            await session.execute(
                row_query.order_by(AIActAuditLog.organization_id, AIActAuditLog.seq)
            )
        ).scalars()
    )
    audit_ids = [row.id for row in rows]
    existing = set()
    if audit_ids:
        existing = set(
            (
                await session.execute(
                    select(OversightRequest.audit_log_id).where(
                        OversightRequest.audit_log_id.in_(audit_ids)
                    )
                )
            ).scalars()
        )

    evaluated = 0
    created = 0
    for row in rows:
        policies_for_tenant = by_tenant.get(row.organization_id, [])
        if not policies_for_tenant:
            continue
        evaluated += 1
        if row.id in existing:
            continue
        event = {
            "model": row.model,
            "endpoint": row.endpoint,
            "pii_detected": row.pii_detected,
            "pii_entities": row.pii_entities,
        }
        policy = next(
            (
                candidate
                for candidate in policies_for_tenant
                if matches_trigger(candidate.trigger, event)
            ),
            None,
        )
        if policy is None:
            continue
        request = OversightRequest(
            organization_id=row.organization_id,
            policy_id=policy.id,
            request_ref=row.request_id or str(row.id),
            audit_log_id=row.id,
            reason=f"Matched policy '{policy.name}'",
            trigger_detail={"policy_id": str(policy.id), "trigger": policy.trigger},
            status="pending",
            expires_at=current
            + timedelta(
                seconds=policy.ttl_seconds or settings.OVERSIGHT_DEFAULT_TTL_SECONDS
            ),
        )
        session.add(request)
        await session.flush()
        await _append_audit_event(
            session,
            organization_id=row.organization_id,
            event_type="oversight_triggered",
            request_ref=request.request_ref,
            details={
                "oversight_request_id": str(request.id),
                "policy_id": str(policy.id),
            },
        )
        existing.add(row.id)
        created += 1
    return {"evaluated": evaluated, "created": created}


async def decide(
    session: AsyncSession,
    request_id: UUID,
    org_id: UUID,
    *,
    decision: Literal["approve", "reject"],
    note: str | None,
    approver: str | None,
) -> OversightRequest:
    """Atomically approve or reject one pending tenant-owned request."""

    request = (
        await session.execute(
            select(OversightRequest)
            .where(
                OversightRequest.id == request_id,
                OversightRequest.organization_id == org_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if request is None:
        raise OversightStateError("oversight request not found")
    current = datetime.now(timezone.utc)
    if request.status != "pending" or (
        request.expires_at is not None and request.expires_at <= current
    ):
        raise OversightStateError("oversight request is no longer pending")

    request.status = "approved" if decision == "approve" else "rejected"
    request.approver = approver
    request.decision_note = note
    request.decided_at = current
    await _append_audit_event(
        session,
        organization_id=org_id,
        event_type="oversight_decision",
        request_ref=request.request_ref,
        details={
            "oversight_request_id": str(request.id),
            "decision": request.status,
        },
    )
    return request


async def expire_pending(
    session: AsyncSession,
    *,
    org_id: UUID | None = None,
    now: datetime | None = None,
) -> dict[str, int]:
    """Expire due requests under row locks and record the policy default."""

    current = now or datetime.now(timezone.utc)
    query = (
        select(OversightRequest, OversightPolicy.default_on_timeout)
        .outerjoin(
            OversightPolicy,
            (OversightRequest.policy_id == OversightPolicy.id)
            & (OversightRequest.organization_id == OversightPolicy.organization_id),
        )
        .where(
            OversightRequest.status == "pending",
            OversightRequest.expires_at <= current,
        )
    )
    if org_id is not None:
        query = query.where(OversightRequest.organization_id == org_id)

    expired = 0
    requests = await session.execute(
        query.with_for_update(skip_locked=True, of=OversightRequest)
    )
    for request, default_action in requests:
        default_action = default_action or "allow"
        request.status = "expired"
        request.decided_at = current
        request.decision_note = f"TTL expired; default action: {default_action}"
        await _append_audit_event(
            session,
            organization_id=request.organization_id,
            event_type="oversight_decision",
            request_ref=request.request_ref,
            details={
                "oversight_request_id": str(request.id),
                "decision": "expired",
                "default_action": default_action,
            },
        )
        expired += 1
    return {"expired": expired}
