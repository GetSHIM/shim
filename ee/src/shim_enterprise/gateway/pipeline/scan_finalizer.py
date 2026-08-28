"""Enterprise scan lifecycle and audit finalization."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.billing.models import RequestLifecycle
from shim_enterprise.gateway.contracts.enterprise_errors import ScanPersistenceError
from shim_enterprise.gateway.contracts.enterprise_scan import ScanRequest
from shim_enterprise.gateway.pipeline.audit_intent import (
    persist_scan_audit_completion,
    scan_audit_payload,
)
from shim.gateway.pipeline.privacy import ScanPrivacyOutcome
from shim_enterprise.gateway.pipeline.scan_policy import ResolvedScanActor
from shim_enterprise.observability.lifecycle import RequestLifecycleRepository


class ScanFinalizer:
    """Persist one terminal privacy state and its audit delivery intent."""

    async def success(
        self,
        session: AsyncSession,
        *,
        request: ScanRequest,
        actor: ResolvedScanActor,
        privacy: ScanPrivacyOutcome,
        started_at: datetime,
        completed_at: datetime,
        input_hash: str,
        output_hash: str,
    ) -> UUID | None:
        payload = scan_audit_payload(
            tenant_id=request.tenant_id,
            api_key_id=request.api_key_id,
            user_id=request.user_id,
            request_id=request.request_id,
            source=request.source,
            started_at=started_at,
            completed_at=completed_at,
            input_hash=input_hash,
            output_hash=output_hash,
            entity_counts=privacy.entity_counts,
            verdict=privacy.verdict,
            lifecycle_status="completed",
        )
        try:
            await self._lock(session, request)
            updated = await RequestLifecycleRepository.update(
                session,
                organization_id=request.tenant_id,
                request_id=request.request_id,
                values={
                    "status": "completed",
                    "privacy_status": (
                        "detected" if privacy.entity_counts else "clean"
                    ),
                    "pii_detected": bool(privacy.entity_counts),
                    "completed_at": completed_at,
                    "reconciled_at": completed_at,
                    "reconciliation_due_at": None,
                },
            )
            if updated is None:
                raise ScanPersistenceError()
            completion_id = None
            if actor.audit_mode != "off":
                completion_id = await persist_scan_audit_completion(
                    session=session,
                    tenant_id=request.tenant_id,
                    request_id=request.request_id,
                    actor_type=request.actor_type,
                    api_key_id=request.api_key_id,
                    user_id=request.user_id,
                    audit_mode=actor.audit_mode,
                    input_hash=input_hash,
                    output_hash=output_hash,
                    entity_counts=privacy.entity_counts,
                    lifecycle_status="completed",
                    audit_payload=payload,
                    completed_at=completed_at,
                )
            await session.commit()
            return completion_id
        except Exception:
            await session.rollback()
            raise ScanPersistenceError() from None

    async def failure(
        self,
        session: AsyncSession,
        *,
        request: ScanRequest,
        actor: ResolvedScanActor,
        started_at: datetime,
        input_hash: str,
    ) -> None:
        failed_at = datetime.now(timezone.utc)
        payload = scan_audit_payload(
            tenant_id=request.tenant_id,
            api_key_id=request.api_key_id,
            user_id=request.user_id,
            request_id=request.request_id,
            source=request.source,
            started_at=started_at,
            completed_at=failed_at,
            input_hash=input_hash,
            output_hash=None,
            entity_counts={},
            verdict=None,
            lifecycle_status="internal_error",
        )
        try:
            await self._lock(session, request)
            updated = await RequestLifecycleRepository.update(
                session,
                organization_id=request.tenant_id,
                request_id=request.request_id,
                values={
                    "status": "internal_error",
                    "privacy_status": "failed",
                    "failed_at": failed_at,
                    "reconciled_at": failed_at,
                    "reconciliation_due_at": None,
                    "terminal_error_code": "INTERNAL_ERROR",
                    "terminal_error_message": "PII analysis could not be completed.",
                },
            )
            if updated is None:
                raise ScanPersistenceError()
            if actor.audit_mode != "off":
                await persist_scan_audit_completion(
                    session=session,
                    tenant_id=request.tenant_id,
                    request_id=request.request_id,
                    actor_type=request.actor_type,
                    api_key_id=request.api_key_id,
                    user_id=request.user_id,
                    audit_mode=actor.audit_mode,
                    input_hash=input_hash,
                    output_hash=None,
                    entity_counts={},
                    lifecycle_status="internal_error",
                    audit_payload=payload,
                    completed_at=failed_at,
                )
            await session.commit()
        except Exception:
            await session.rollback()
            raise ScanPersistenceError() from None

    @staticmethod
    async def _lock(
        session: AsyncSession,
        request: ScanRequest,
    ) -> RequestLifecycle:
        lifecycle = (
            await session.execute(
                select(RequestLifecycle)
                .where(
                    RequestLifecycle.organization_id == request.tenant_id,
                    RequestLifecycle.request_id == request.request_id,
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
        if lifecycle is None or lifecycle.reconciled_at is not None:
            raise ScanPersistenceError()
        return lifecycle
