"""Enterprise provider-free scan execution pipeline."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.core.config import settings
from shim_enterprise.gateway.contracts.enterprise_errors import (
    ScanLimitExceeded,
    ScanPersistenceError,
)
from shim_enterprise.gateway.contracts.enterprise_scan import (
    ScanExecutionResult,
    ScanRequest,
    ScanUsageStatus,
)
from shim.gateway.contracts.errors import ScanAnalysisError
from shim.gateway.contracts.ids import RequestId
from shim.gateway.contracts.inference import ScanInput
from shim.gateway.contracts.principal import AuthenticatedPrincipal
from shim_enterprise.gateway.pipeline.scan_finalizer import ScanFinalizer
from shim_enterprise.gateway.pipeline.scan_policy import (
    ResolvedScanActor,
    ScanPolicyResolver,
)
from shim.gateway.pipeline.privacy import ScanPrivacyStage
from shim_enterprise.gateway.pipeline.quota_reservation import ScanAdmissionRepository
from shim_enterprise.observability.enterprise_metrics import QUOTA_RESERVATION_TOTAL
from shim.observability.metrics import REQUESTS_TOTAL, bounded_label
from shim.observability.tracing import start_span
from shim.privacy.classification import content_ref
from shim.privacy.pii_scrubber import PIIScrubberService


class ScanExecutionPipeline:
    """Order the enterprise provider-free scan stages."""

    def __init__(
        self,
        *,
        scrubber: PIIScrubberService | None = None,
        policy_resolver: ScanPolicyResolver | None = None,
        admission: ScanAdmissionRepository | None = None,
        finalizer: ScanFinalizer | None = None,
    ) -> None:
        self.policy_resolver = policy_resolver or ScanPolicyResolver()
        self.admission = admission or ScanAdmissionRepository()
        self.privacy = ScanPrivacyStage(scrubber or PIIScrubberService())
        self.finalizer = finalizer or ScanFinalizer()

    async def execute(
        self,
        scan_input: ScanInput,
        principal: AuthenticatedPrincipal,
        session: AsyncSession,
    ) -> ScanExecutionResult:
        actor: ResolvedScanActor | None = None
        outcome = "server_error"
        with start_span(
            "gateway.request",
            endpoint="/v1/scan",
            method="POST",
            protocol="scan",
        ) as span:
            try:
                actor = await self._resolve(principal, session)
                result = await self._execute(scan_input, actor, session)
            except ScanLimitExceeded:
                outcome = "rejected"
                raise
            except HTTPException as exc:
                outcome = "client_error" if exc.status_code < 500 else "server_error"
                raise
            else:
                outcome = "success"
                return result
            finally:
                span.set_attribute("status", outcome)
                REQUESTS_TOTAL.labels(
                    endpoint="/v1/scan",
                    status=outcome,
                    tenant_tier=bounded_label(
                        "tenant_tier", actor.tier if actor is not None else "default"
                    ),
                ).inc()

    async def usage(
        self,
        principal: AuthenticatedPrincipal,
        session: AsyncSession,
    ) -> ScanUsageStatus:
        actor: ResolvedScanActor | None = None
        outcome = "server_error"
        try:
            actor = await self._resolve(principal, session)
            usage = await self.admission.usage(
                session,
                actor=actor,
                now=datetime.now(timezone.utc),
            )
        except HTTPException as exc:
            outcome = "client_error" if exc.status_code < 500 else "server_error"
            raise
        else:
            outcome = "success"
            return usage
        finally:
            REQUESTS_TOTAL.labels(
                endpoint="/v1/scan/usage",
                status=outcome,
                tenant_tier=bounded_label(
                    "tenant_tier", actor.tier if actor is not None else "default"
                ),
            ).inc()

    async def _execute(
        self,
        scan_input: ScanInput,
        actor: ResolvedScanActor,
        session: AsyncSession,
    ) -> ScanExecutionResult:
        request = ScanRequest(
            request_id=RequestId(f"scan_{uuid4().hex}"),
            tenant_id=actor.tenant_id,
            actor_type=actor.actor_type,
            api_key_id=actor.api_key_id,
            user_id=actor.user_id,
            text=scan_input.text,
            source=scan_input.source,
        )
        started_at = datetime.now(timezone.utc)
        audit_salt = settings.COMPLIANCE_HASH_SALT or settings.SECRET_KEY
        input_hash = content_ref(audit_salt, request.text)
        with start_span("gateway.quota_reservation") as quota_span:
            try:
                admission = await self.admission.admit(
                    session,
                    request=request,
                    actor=actor,
                    started_at=started_at,
                    input_hash=input_hash,
                )
            except ScanLimitExceeded:
                quota_span.set_attribute("status", "rejected")
                QUOTA_RESERVATION_TOTAL.labels(status="rejected").inc()
                raise
            except Exception:
                quota_span.set_attribute("status", "failed")
                QUOTA_RESERVATION_TOTAL.labels(status="failed").inc()
                raise
            quota_span.set_attribute("status", "reserved")
            QUOTA_RESERVATION_TOTAL.labels(status="reserved").inc()

        with start_span("gateway.privacy", action="detected") as privacy_span:
            try:
                privacy = self.privacy.analyze(
                    request.text,
                    config=actor.pii_config,
                    policy=actor.policy,
                )
            except ScanAnalysisError:
                privacy_span.set_attribute("status", "failed")
                await self.finalizer.failure(
                    session,
                    request=request,
                    actor=actor,
                    started_at=started_at,
                    input_hash=input_hash,
                )
                raise
            privacy_span.set_attributes(
                {"pii_detected": bool(privacy.entity_counts), "status": "success"}
            )

        completed_at = datetime.now(timezone.utc)
        output_hash = content_ref(
            audit_salt,
            json.dumps(
                {
                    "entity_counts": privacy.entity_counts,
                    "verdict": privacy.verdict,
                },
                separators=(",", ":"),
                sort_keys=True,
            ),
        )
        completion_id = await self.finalizer.success(
            session,
            request=request,
            actor=actor,
            privacy=privacy,
            started_at=started_at,
            completed_at=completed_at,
            input_hash=input_hash,
            output_hash=output_hash,
        )
        return ScanExecutionResult(
            request_id=request.request_id,
            verdict=privacy.verdict,
            entities_found=list(privacy.entities),
            entity_types=list(privacy.entity_types),
            policy=actor.policy,
            audit_preflight_intent_id=admission.audit_preflight_intent_id,
            audit_completion_intent_id=completion_id,
            **admission.usage.model_dump(),
        )

    async def _resolve(
        self,
        principal: AuthenticatedPrincipal,
        session: AsyncSession,
    ) -> ResolvedScanActor:
        with start_span(
            "gateway.auth",
            actor_type=principal.actor_type,
            source_endpoint="scan",
        ) as span:
            try:
                actor = await self.policy_resolver.resolve(principal, session)
            except HTTPException:
                span.set_attribute("status", "rejected")
                raise
            except Exception:
                span.set_attribute("status", "failed")
                await session.rollback()
                raise ScanPersistenceError() from None
            span.set_attribute("status", "success")
            return actor
