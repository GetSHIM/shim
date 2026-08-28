"""Trusted audit-policy resolution before any response boundary is crossed."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.billing.models import AuditIntent
from shim_enterprise.core.config import settings
from shim_enterprise.gateway.contracts.audit import validate_audit_intent
from shim.gateway.contracts.context import AuditPolicy
from shim.gateway.contracts.ids import ApiKeyId, RequestId, TenantId, UserId
from shim.gateway.contracts.inference import ScanVerdict
from shim.gateway.contracts.principal import ActorType
from shim.observability.metrics import bounded_label
from shim.observability.tracing import start_span
from shim_enterprise.outbox.publisher import OutboxWriter


class AuditIntentPersistenceError(RuntimeError):
    """A required audit intent could not be persisted durably."""


_AUDIT_REPLAY_FIELDS = (
    "organization_id",
    "request_id",
    "event_type",
    "actor_type",
    "api_key_id",
    "user_id",
    "audit_policy_mode",
    "input_hash",
    "output_hash",
    "pii_entities",
    "provider",
    "model",
    "usage_summary",
    "lifecycle_status",
    "outbox_event_id",
    "created_at",
)


class AuditIntentRepository:
    """Tenant-scoped preflight and terminal audit intent writes."""

    @staticmethod
    async def create(
        session: AsyncSession,
        *,
        organization_id: TenantId,
        values: Mapping[str, Any],
    ) -> AuditIntent:
        payload = dict(values)
        validate_audit_intent(organization_id, payload)
        payload["organization_id"] = organization_id
        request_id = payload["request_id"]
        event_type = payload["event_type"]
        with start_span(
            "gateway.audit_intent",
            event_type=bounded_label("event_type", event_type),
        ):
            try:
                statement = (
                    insert(AuditIntent)
                    .values(**payload)
                    .on_conflict_do_nothing(
                        index_elements=[
                            AuditIntent.organization_id,
                            AuditIntent.request_id,
                            AuditIntent.event_type,
                        ]
                    )
                    .returning(AuditIntent)
                )
                intent = (await session.execute(statement)).scalar_one_or_none()
                if intent is not None:
                    return intent
                intent = await AuditIntentRepository.fetch(
                    session,
                    organization_id=organization_id,
                    request_id=request_id,
                    event_type=event_type,
                )
                if intent is None:
                    raise AuditIntentPersistenceError("audit intent identity conflict")
                if any(
                    getattr(intent, field) != payload[field]
                    for field in _AUDIT_REPLAY_FIELDS
                    if field in payload
                ):
                    raise AuditIntentPersistenceError("audit intent identity conflict")
                return intent
            except AuditIntentPersistenceError:
                raise
            except Exception as exc:
                raise AuditIntentPersistenceError(
                    "audit intent persistence failed"
                ) from exc

    @staticmethod
    async def fetch(
        session: AsyncSession,
        *,
        organization_id: TenantId,
        request_id: RequestId,
        event_type: str,
    ) -> AuditIntent | None:
        statement = select(AuditIntent).where(
            AuditIntent.organization_id == organization_id,
            AuditIntent.request_id == request_id,
            AuditIntent.event_type == event_type,
        )
        return (await session.execute(statement)).scalar_one_or_none()


def resolve_audit_policy(
    tier_definition: Mapping[str, object] | None,
) -> AuditPolicy:
    """Build a validated audit policy from trusted tenant configuration."""

    if not settings.AI_ACT_AUDIT_ENABLED:
        return AuditPolicy(mode="off")
    if not tier_definition:
        return AuditPolicy(mode="best_effort")
    features = tier_definition.get("features")
    if features is None:
        return AuditPolicy(mode="best_effort")
    if not isinstance(features, Mapping):
        raise ValueError("tier features must be an object")
    raw_policy = features.get("audit_policy")
    if raw_policy is None:
        raw_policy = {"mode": features.get("audit_policy_mode", "best_effort")}
    if not isinstance(raw_policy, Mapping):
        raise ValueError("audit policy must be an object")
    return AuditPolicy.model_validate(dict(raw_policy))


def scan_audit_payload(
    *,
    tenant_id: TenantId,
    api_key_id: ApiKeyId | None,
    user_id: UserId | None,
    request_id: RequestId,
    source: str,
    started_at: datetime,
    completed_at: datetime,
    input_hash: str | None,
    output_hash: str | None,
    entity_counts: dict[str, int],
    verdict: ScanVerdict | None,
    lifecycle_status: Literal["completed", "internal_error"],
) -> dict[str, object]:
    return {
        "organization_id": str(tenant_id),
        "api_key_id": str(api_key_id) if api_key_id is not None else None,
        "actor": str(user_id) if user_id is not None else None,
        "event_type": "ai_request",
        "request_id": str(request_id),
        "model": None,
        "provider": None,
        "endpoint": "scan",
        "input_hash": input_hash,
        "output_hash": output_hash,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "pii_detected": bool(entity_counts),
        "pii_entities": entity_counts,
        "policy_verdicts": [verdict] if verdict is not None else [],
        "is_cache_hit": False,
        "latency_ms": max(0, int((completed_at - started_at).total_seconds() * 1_000)),
        "cost_usd": 0.0,
        "extra": {
            "audit_event_type": "completion",
            "entity_count": sum(entity_counts.values()),
            "entity_types": sorted(entity_counts),
            "lifecycle_status": lifecycle_status,
            "operation_type": "pii_scan",
            "scan_source": source,
        },
    }


async def persist_scan_audit_completion(
    *,
    session: AsyncSession,
    tenant_id: TenantId,
    request_id: RequestId,
    actor_type: ActorType,
    api_key_id: ApiKeyId | None,
    user_id: UserId | None,
    audit_mode: Literal["best_effort", "strict"],
    input_hash: str | None,
    output_hash: str | None,
    entity_counts: dict[str, int],
    lifecycle_status: Literal["completed", "internal_error"],
    audit_payload: dict[str, object],
    completed_at: datetime,
) -> UUID:
    outbox_event = await OutboxWriter().append(
        session,
        organization_id=tenant_id,
        values={
            "event_type": "audit.chain_append_requested",
            "aggregate_type": "request",
            "aggregate_id": str(request_id),
            "idempotency_key": f"request:{request_id}:outbox:audit.completion",
            "payload": audit_payload,
            "status": "pending",
            "next_attempt_at": completed_at,
        },
    )
    completion = await AuditIntentRepository.create(
        session,
        organization_id=tenant_id,
        values={
            "request_id": str(request_id),
            "actor_type": actor_type,
            "api_key_id": api_key_id,
            "user_id": user_id,
            "event_type": "completion",
            "audit_policy_mode": audit_mode,
            "input_hash": input_hash,
            "output_hash": output_hash,
            "pii_entities": entity_counts,
            "provider": None,
            "model": None,
            "usage_summary": {
                "entity_count": sum(entity_counts.values()),
                "entity_type_count": len(entity_counts),
            },
            "lifecycle_status": lifecycle_status,
            "outbox_event_id": outbox_event.id,
        },
    )
    return completion.id
