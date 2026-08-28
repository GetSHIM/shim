"""Pure construction of terminal gateway outbox intents."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from types import MappingProxyType
from typing import Any, Mapping


@dataclass(frozen=True, slots=True)
class GatewayOutboxIntent:
    event_type: str
    aggregate_id: str
    idempotency_key: str
    payload: Mapping[str, Any]
    available_at: datetime

    def persistence_values(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type,
            "aggregate_type": "request",
            "aggregate_id": self.aggregate_id,
            "idempotency_key": self.idempotency_key,
            "payload": dict(self.payload),
            "status": "pending",
            "next_attempt_at": self.available_at,
        }


def audit_completion_intent(
    lifecycle: Any,
    preflight: Any,
    quota_event: Any,
    spend_event: Any | None,
    *,
    lifecycle_status: str,
    output_hash: str | None,
    completed_at: datetime,
) -> GatewayOutboxIntent:
    actual_cost = spend_event.cost_usd if spend_event is not None else Decimal("0")
    estimated = quota_event.estimated or (
        spend_event is not None and spend_event.estimated
    )
    payload = {
        "organization_id": str(lifecycle.organization_id),
        "api_key_id": (
            str(lifecycle.api_key_id) if lifecycle.api_key_id is not None else None
        ),
        "actor": str(lifecycle.user_id) if lifecycle.user_id is not None else None,
        "event_type": "ai_request",
        "request_id": lifecycle.request_id,
        "model": lifecycle.provider_model or lifecycle.requested_model,
        "provider": lifecycle.provider,
        "endpoint": lifecycle.source_endpoint,
        "input_hash": preflight.input_hash,
        "output_hash": output_hash,
        "prompt_tokens": quota_event.prompt_tokens,
        "completion_tokens": quota_event.completion_tokens,
        "pii_detected": bool(preflight.pii_entities),
        "pii_entities": dict(preflight.pii_entities or {}),
        "policy_verdicts": [],
        "is_cache_hit": lifecycle.cache_status == "hit",
        "latency_ms": max(
            0,
            int((completed_at - lifecycle.started_at).total_seconds() * 1000),
        ),
        "cost_usd": float(actual_cost),
        "extra": {
            "audit_event_type": "completion",
            "lifecycle_status": lifecycle_status,
            "usage_estimated": estimated,
        },
    }
    return GatewayOutboxIntent(
        event_type="audit.chain_append_requested",
        aggregate_id=lifecycle.request_id,
        idempotency_key=f"request:{lifecycle.request_id}:outbox:audit.completion",
        payload=MappingProxyType(payload),
        available_at=completed_at,
    )


def analytics_terminal_intent(
    lifecycle: Any,
    quota_event: Any,
    spend_event: Any | None,
    *,
    lifecycle_status: str,
    completed_at: datetime,
) -> GatewayOutboxIntent:
    event_type = (
        "analytics.request_completed"
        if lifecycle_status == "completed"
        else "analytics.request_failed"
    )
    lifecycle_metadata = lifecycle.lifecycle_metadata or {}
    payload = {
        "organization_id": str(lifecycle.organization_id),
        "request_id": lifecycle.request_id,
        "api_key_id": str(lifecycle.api_key_id),
        "timestamp": completed_at.isoformat(),
        "prompt_tokens": quota_event.prompt_tokens,
        "completion_tokens": quota_event.completion_tokens,
        "latency_ms": max(
            0,
            int((completed_at - lifecycle.started_at).total_seconds() * 1000),
        ),
        "is_cache_hit": lifecycle.cache_status == "hit",
        "pii_detected": lifecycle.pii_detected,
        "path": lifecycle.source_endpoint,
        "model": lifecycle.provider_model or lifecycle.requested_model,
        "provider": lifecycle.provider,
        "cost_usd": float(
            spend_event.cost_usd if spend_event is not None else Decimal("0")
        ),
        "lifecycle_status": lifecycle_status,
        "usage_estimated": quota_event.estimated
        or (spend_event is not None and spend_event.estimated),
        "cost_center": lifecycle_metadata.get("cost_center", "untagged"),
        "team": lifecycle_metadata.get("team"),
        "tags": list(lifecycle_metadata.get("tags") or []),
    }
    return GatewayOutboxIntent(
        event_type=event_type,
        aggregate_id=lifecycle.request_id,
        idempotency_key=f"request:{lifecycle.request_id}:outbox:analytics.terminal",
        payload=MappingProxyType(payload),
        available_at=completed_at,
    )
