"""Failure settlement after quota or provider execution has begun."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal, cast

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.billing.models import RequestLifecycle
from shim.gateway.contracts.ids import ApiKeyId, RequestId, TenantId, UserId
from shim.gateway.contracts.principal import ActorType
from shim_enterprise.gateway.pipeline.audit_intent import (
    AuditIntentRepository,
    persist_scan_audit_completion,
    scan_audit_payload,
)
from shim_enterprise.observability.lifecycle import RequestLifecycleRepository
from shim_enterprise.outbox.publisher import OutboxWriter


@dataclass(frozen=True, slots=True)
class ScanRecoveryResult:
    request_id: RequestId
    audit_payload: dict[str, object] | None


class ScanReconciler:
    """Terminally reconcile provider-free scans stranded after admission."""

    async def recover_stale(
        self,
        session: AsyncSession,
        *,
        now: datetime,
        batch_size: int = 100,
    ) -> tuple[ScanRecoveryResult, ...]:
        if now.tzinfo is None:
            raise ValueError("scan recovery time must be timezone-aware")
        if batch_size < 1:
            raise ValueError("scan recovery batch size must be positive")
        statement = (
            select(RequestLifecycle)
            .where(
                RequestLifecycle.source_endpoint == "scan",
                RequestLifecycle.status == "accepted",
                RequestLifecycle.reconciliation_due_at.is_not(None),
                RequestLifecycle.reconciliation_due_at <= now,
                RequestLifecycle.reconciled_at.is_(None),
            )
            .order_by(
                RequestLifecycle.reconciliation_due_at,
                RequestLifecycle.request_id,
            )
            .limit(batch_size)
            .with_for_update(skip_locked=True)
        )
        stale = tuple((await session.execute(statement)).scalars())
        return tuple(
            [
                await self._recover_one(session, lifecycle, now=now)
                for lifecycle in stale
            ]
        )

    async def _recover_one(
        self,
        session: AsyncSession,
        lifecycle: RequestLifecycle,
        *,
        now: datetime,
    ) -> ScanRecoveryResult:
        tenant_id = TenantId(lifecycle.organization_id)
        request_id = RequestId(lifecycle.request_id)
        api_key_id = (
            ApiKeyId(lifecycle.api_key_id) if lifecycle.api_key_id is not None else None
        )
        user_id = UserId(lifecycle.user_id) if lifecycle.user_id is not None else None
        metadata = dict(lifecycle.lifecycle_metadata or {})
        source = str(metadata.get("scan_source", "unknown"))
        if source not in {"chatgpt", "gemini", "unknown"}:
            source = "unknown"
        audit_mode = metadata.get("audit_mode", "off")
        if audit_mode not in {"off", "best_effort", "strict"}:
            raise ValueError("stranded scan has invalid audit mode")
        preflight = await AuditIntentRepository.fetch(
            session,
            organization_id=tenant_id,
            request_id=request_id,
            event_type="preflight",
        )
        if audit_mode != "off" and preflight is None:
            raise ValueError("stranded audited scan has no preflight intent")

        payload = None
        if preflight is not None:
            payload = scan_audit_payload(
                tenant_id=tenant_id,
                api_key_id=api_key_id,
                user_id=user_id,
                request_id=request_id,
                source=source,
                started_at=lifecycle.started_at,
                completed_at=now,
                input_hash=preflight.input_hash,
                output_hash=None,
                entity_counts={},
                verdict=None,
                lifecycle_status="internal_error",
            )
            await persist_scan_audit_completion(
                session=session,
                tenant_id=tenant_id,
                request_id=request_id,
                actor_type=cast(ActorType, lifecycle.actor_type),
                api_key_id=api_key_id,
                user_id=user_id,
                audit_mode=cast(
                    Literal["best_effort", "strict"],
                    preflight.audit_policy_mode,
                ),
                input_hash=preflight.input_hash,
                output_hash=None,
                entity_counts={},
                lifecycle_status="internal_error",
                audit_payload=payload,
                completed_at=now,
            )
        updated = await RequestLifecycleRepository.update(
            session,
            organization_id=tenant_id,
            request_id=request_id,
            values={
                "status": "internal_error",
                "privacy_status": "failed",
                "failed_at": now,
                "reconciled_at": now,
                "reconciliation_due_at": None,
                "terminal_error_code": "STALE_SCAN_RECOVERED",
                "terminal_error_message": (
                    "Scan expired before terminal privacy state was persisted."
                ),
            },
        )
        if updated is None:
            raise ValueError("stranded scan lifecycle disappeared")
        await OutboxWriter().append(
            session,
            organization_id=tenant_id,
            values={
                "event_type": "gateway.reconciliation",
                "aggregate_type": "request",
                "aggregate_id": str(request_id),
                "idempotency_key": (
                    f"request:{request_id}:outbox:gateway.reconciliation"
                ),
                "payload": {
                    "organization_id": str(tenant_id),
                    "request_id": str(request_id),
                    "lifecycle_status": "internal_error",
                    "urgent": True,
                },
                "status": "pending",
                "next_attempt_at": now,
            },
        )
        return ScanRecoveryResult(request_id=request_id, audit_payload=payload)
