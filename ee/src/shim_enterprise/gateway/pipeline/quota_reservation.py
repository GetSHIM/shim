"""Kernel coordination for authoritative PostgreSQL quota and spend."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
import hashlib
import hmac
import json
import logging
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import TYPE_CHECKING, Any, Literal, cast
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import desc, func, select, text

from shim_enterprise.core.config import settings
from shim_enterprise.core.errors import PersistenceError
from shim.privacy.classification import content_ref
from shim.privacy.retention import REQUEST_PRIVACY_RETENTION
from shim.billing.pricing import DEFAULT_PRICE_BOOK, compute_cost_usd
from shim_enterprise.gateway.contracts.enterprise_errors import (
    ScanLimitExceeded,
    ScanPersistenceError,
)
from shim_enterprise.gateway.contracts.enterprise_scan import (
    ScanRequest,
    ScanUsageStatus,
)
from shim.gateway.contracts.ids import RequestId, TenantId
from shim.gateway.kernel.result import PreparedInference
from shim.gateway.streaming.finalization import StreamFinalization
from shim.gateway.usage import UsageFailureReason
from shim_enterprise.billing.ledger import (
    DurableAccountingRepository,
    FailureReservationState,
    FinalizationCommand,
    FinalizationResult,
    QuotaLimitExceeded,
    QuotaPolicySnapshot,
    QuotaReservationCommand,
    ReservationResult,
    SpendLimitExceeded,
    SpendPolicySnapshot,
    SpendReservationCommand,
    TerminalAction,
)
from shim_enterprise.billing.models import RequestLifecycle
from shim_enterprise.observability.lifecycle import RequestLifecycleRepository
from shim_enterprise.gateway.pipeline.audit_intent import (
    AuditIntentPersistenceError,
    persist_token_count_audit,
    AuditIntentRepository,
)
from shim_enterprise.gateway.pipeline.scan_policy import ResolvedScanActor
from shim_enterprise.gateway.pipeline.outbox import rejection_intent
from shim_enterprise.outbox.publisher import OutboxWriter
from shim_enterprise.tenants.models import (
    ApiKey,
    ProviderSecret,
    TierDefinition,
    Team,
    TeamMembership,
    User,
)
from shim_enterprise.observability.enterprise_metrics import (
    QUOTA_RESERVATION_TOTAL,
    USAGE_SETTLEMENT_TOTAL,
)
from shim.observability.tracing import start_span

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from shim.gateway.kernel.result import AdmissionState


class AccountingPersistenceError(PersistenceError):
    """An authoritative accounting transaction could not be committed."""


logger = logging.getLogger(__name__)


def _system_prompt_hash(prepared: PreparedInference) -> str | None:
    """Hash only explicitly supplied system content, before privacy transformation."""

    payload = prepared.payload
    material: dict[str, Any] = {}
    field = {
        "chat": None,
        "responses": "instructions",
        "messages": "system",
        "generate_content": "systemInstruction",
    }[prepared.protocol]
    if field is not None and payload.get(field) is not None:
        material[field] = payload[field]
    if prepared.protocol in {"chat", "responses"}:
        messages = payload.get("messages" if prepared.protocol == "chat" else "input")
        if isinstance(messages, list):
            instructions = [
                {"role": item["role"], "content": item["content"]}
                for item in messages
                if isinstance(item, dict)
                and item.get("role") in ("system", "developer")
                and item.get("content") is not None
            ]
            if instructions:
                material["messages"] = instructions
    if not material:
        return None
    canonical = json.dumps(
        [
            "shim.system_prompt.v1",
            str(prepared.tenant_id),
            prepared.protocol,
            {
                "deployment_id": prepared.target.deployment_id
                if prepared.target
                else None,
                "deployment_kind": prepared.deployment_kind,
            },
            material,
        ],
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    key = (settings.COMPLIANCE_HASH_SALT or settings.SECRET_KEY).encode("utf-8")
    return "hmac-sha256:v1:" + hmac.digest(key, canonical, "sha256").hex()


class AccountingPolicyLoader:
    """Load current quota/spend policy while locking its authoritative row."""

    async def quota(
        self,
        session: AsyncSession,
        prepared: PreparedInference,
    ) -> QuotaPolicySnapshot:
        api_key_statement = (
            select(ApiKey)
            .where(
                ApiKey.organization_id == prepared.tenant_id,
                ApiKey.id == prepared.api_key_id,
            )
            .execution_options(populate_existing=True)
            .with_for_update()
        )
        api_key = (await session.execute(api_key_statement)).scalar_one_or_none()
        if api_key is None:
            raise AccountingPersistenceError("accounting API key no longer exists")

        now = datetime.now(timezone.utc)
        expiry = api_key.expires_at
        if expiry is not None and expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if not api_key.is_active or (expiry is not None and expiry <= now):
            raise HTTPException(status_code=401, detail="Invalid API Key")
        if (
            api_key.allowed_models is not None
            and prepared.model not in api_key.allowed_models
        ):
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "MODEL_NOT_ALLOWED",
                    "message": "Model is not allowed by API-key policy.",
                },
            )
        owner = await session.scalar(
            select(User).where(
                User.id == api_key.user_id,
                User.organization_id == api_key.organization_id,
                User.is_active.is_(True),
                User.role != "auditor",
            )
        )
        if owner is None:
            raise HTTPException(status_code=401, detail="Invalid API Key")
        team_policy = None
        if api_key.team_id is not None:
            if owner.role not in {"owner", "admin"} and not await session.scalar(
                select(TeamMembership.user_id).where(
                    TeamMembership.organization_id == api_key.organization_id,
                    TeamMembership.team_id == api_key.team_id,
                    TeamMembership.user_id == owner.id,
                )
            ):
                raise HTTPException(
                    status_code=403, detail="API-key owner is no longer a team member"
                )
            team = await session.scalar(
                select(Team)
                .where(
                    Team.organization_id == api_key.organization_id,
                    Team.id == api_key.team_id,
                )
                .with_for_update(read=True)
            )
            if team is None:
                raise AccountingPersistenceError("accounting team no longer exists")
            team_policy = QuotaPolicySnapshot(
                version=self._version(
                    f"team:{team.id}:{team.updated_at}",
                    (
                        team.daily_request_limit,
                        team.monthly_request_limit,
                        team.monthly_token_limit,
                    ),
                ),
                daily_request_limit=team.daily_request_limit,
                monthly_request_limit=team.monthly_request_limit,
                monthly_token_limit=team.monthly_token_limit,
            )
        tier_statement = (
            select(TierDefinition)
            .where(TierDefinition.slug == api_key.tier)
            .execution_options(populate_existing=True)
            .with_for_update(read=True)
        )
        tier = (await session.execute(tier_statement)).scalar_one_or_none()
        if tier is None:
            policy = prepared.context.tier_policy
            values = (
                policy.daily_request_limit,
                policy.monthly_request_limit,
                policy.monthly_token_limit,
            )
            return QuotaPolicySnapshot(
                version=self._version(
                    "quota-default",
                    (*values, team_policy.version if team_policy else None),
                ),
                daily_request_limit=values[0],
                monthly_request_limit=values[1],
                monthly_token_limit=values[2],
                team_id=api_key.team_id,
                team_policy=team_policy,
            )

        values = (
            self._unlimited(tier.daily_request_limit),
            self._unlimited(tier.monthly_request_limit),
            self._unlimited(tier.monthly_token_limit),
        )
        return QuotaPolicySnapshot(
            version=self._version(
                f"quota:{tier.slug}:{getattr(tier, 'updated_at', None)}",
                (*values, team_policy.version if team_policy else None),
            ),
            daily_request_limit=values[0],
            monthly_request_limit=values[1],
            monthly_token_limit=values[2],
            team_id=api_key.team_id,
            team_policy=team_policy,
        )

    async def spend(
        self,
        session: AsyncSession,
        prepared: PreparedInference,
        ephemeral_byok: bool,
    ) -> SpendPolicySnapshot:
        if ephemeral_byok:
            return SpendPolicySnapshot(
                version="spend:ephemeral-byok:unlimited:v1",
                monthly_limit_usd=None,
            )

        statement = (
            select(ProviderSecret)
            .where(
                ProviderSecret.organization_id == prepared.tenant_id,
                ProviderSecret.provider == str(prepared.provider),
                *(
                    [ProviderSecret.id == UUID(prepared.target.credential_reference)]
                    if prepared.target
                    else []
                ),
            )
            .order_by(desc(ProviderSecret.created_at), desc(ProviderSecret.id))
            .limit(1)
            .execution_options(populate_existing=True)
            .with_for_update()
        )
        secret = (await session.execute(statement)).scalar_one_or_none()
        if secret is None:
            return SpendPolicySnapshot(
                version=f"spend:{prepared.provider}:no-secret:v1",
                monthly_limit_usd=None,
            )
        limit = (
            Decimal(str(secret.monthly_limit_usd))
            if secret.monthly_limit_usd is not None
            else None
        )
        return SpendPolicySnapshot(
            version=self._version(
                f"spend:{prepared.provider}:{secret.id}:{secret.updated_at}",
                (limit,),
            ),
            monthly_limit_usd=limit,
        )

    @staticmethod
    def _unlimited(value: int | None) -> int | None:
        return None if value is None or value < 0 else value

    @staticmethod
    def _version(namespace: str, values: tuple[Any, ...]) -> str:
        digest = hashlib.sha256(
            json.dumps(
                [namespace, *values],
                default=str,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        return digest[:24]


class DurableAccountingCoordinator:
    """Own short accounting transactions at kernel stage boundaries."""

    def __init__(
        self,
        repository: DurableAccountingRepository | None = None,
        policy_loader: AccountingPolicyLoader | None = None,
    ) -> None:
        self.repository = repository or DurableAccountingRepository()
        self.policy_loader = policy_loader or AccountingPolicyLoader()

    async def reserve_quota(
        self,
        prepared: PreparedInference,
        admission: AdmissionState,
        session: AsyncSession,
    ) -> ReservationResult:
        policy: QuotaPolicySnapshot | None = None
        with start_span("gateway.quota_reservation") as span:
            try:
                policy = await self.policy_loader.quota(session, prepared)
                prepared.record_verdict(
                    "quota.requests_and_tokens",
                    stage="admission",
                    outcome="allow",
                    reason_code="QUOTA_RESERVED",
                    policy_version=policy.version,
                )
                result = await self.repository.reserve_quota(
                    session,
                    QuotaReservationCommand(
                        tenant_id=prepared.tenant_id,
                        api_key_id=prepared.api_key_id,
                        request_id=prepared.request_id,
                        requested_model=prepared.model,
                        source_endpoint=prepared.source_endpoint,
                        started_at=prepared.context.started_at,
                        reconciliation_due_at=_provider_reconciliation_due_at(
                            prepared.context.started_at,
                            prepared.provider,
                        ),
                        estimated_input_tokens=admission.estimated_input_tokens,
                        maximum_output_tokens=admission.maximum_output_tokens,
                        cost_center=admission.cost_center,
                        tags=admission.tags,
                        team=prepared.policy.team,
                        stream=prepared.stream,
                        repeat_chain_length=admission.repeat_chain_length,
                        system_prompt_hash=_system_prompt_hash(prepared),
                        deployment_kind=prepared.deployment_kind,
                        policy=policy,
                        audit_policy_mode=prepared.context.audit_policy.mode,
                        policy_verdicts=tuple(
                            verdict.model_dump(mode="json")
                            for verdict in prepared.policy_verdicts
                        ),
                    ),
                )
                await session.commit()
                outcome = "replayed" if result.replayed else "reserved"
                QUOTA_RESERVATION_TOTAL.labels(status=outcome).inc()
                span.set_attribute("status", outcome)
                return result
            except (QuotaLimitExceeded, HTTPException) as error:
                await session.rollback()
                access_denied = isinstance(error, HTTPException)
                prepared.record_verdict(
                    "api_key.access" if access_denied else "quota.requests_and_tokens",
                    stage="admission",
                    outcome="deny",
                    reason_code=(
                        "API_KEY_ACCESS_DENIED" if access_denied else "QUOTA_EXCEEDED"
                    ),
                    policy_version=policy.version if policy is not None else None,
                )
                QUOTA_RESERVATION_TOTAL.labels(status="rejected").inc()
                span.set_attribute("status", "rejected")
                raise
            except Exception as exc:
                await session.rollback()
                prepared.record_verdict(
                    "quota.requests_and_tokens",
                    stage="admission",
                    outcome="error",
                    reason_code="QUOTA_UNAVAILABLE",
                    policy_version=policy.version if policy is not None else None,
                )
                QUOTA_RESERVATION_TOTAL.labels(status="failed").inc()
                span.set_attribute("status", "failed")
                if isinstance(exc, AccountingPersistenceError):
                    raise
                raise AccountingPersistenceError("quota reservation failed") from exc

    async def reserve_spend(
        self,
        prepared: PreparedInference,
        ephemeral_byok: bool,
        session: AsyncSession,
    ) -> ReservationResult:
        if prepared.admission is None or prepared.privacy is None:
            raise ValueError("spend reservation requires admission and privacy")
        provider = prepared.provider
        command: SpendReservationCommand | None = None
        try:
            policy = await self.policy_loader.spend(
                session,
                prepared,
                ephemeral_byok,
            )
            prepared.record_verdict(
                "spend.provider_monthly",
                stage="provider_spend",
                outcome="allow",
                reason_code="SPEND_UNLIMITED"
                if policy.monthly_limit_usd is None
                else "SPEND_RESERVED",
                policy_version=policy.version,
            )
            estimated_cost = compute_cost_usd(
                prepared.pricing_model,
                prepared.admission.estimated_input_tokens,
                prepared.admission.maximum_output_tokens,
                str(prepared.provider),
                unpriced=prepared.unpriced,
            )
            input_hash = content_ref(
                settings.COMPLIANCE_HASH_SALT or settings.SECRET_KEY,
                json.dumps(prepared.payload, sort_keys=True, default=str),
            )
            privacy_facts = REQUEST_PRIVACY_RETENTION.durable_facts(prepared.privacy)
            command = SpendReservationCommand(
                tenant_id=prepared.tenant_id,
                api_key_id=prepared.api_key_id,
                request_id=prepared.request_id,
                requested_model=prepared.model,
                provider=provider,
                provider_model=prepared.pricing_model,
                estimated_cost_usd=estimated_cost,
                pricing_metadata=DEFAULT_PRICE_BOOK.resolved_price_metadata(
                    prepared.pricing_model,
                    str(prepared.provider),
                    input_tokens=prepared.admission.estimated_input_tokens,
                    output_tokens=prepared.admission.maximum_output_tokens,
                    unpriced=prepared.unpriced,
                ),
                cache_status="bypass",
                audit_policy_mode=prepared.context.audit_policy.mode,
                policy=policy,
                input_hash=input_hash,
                pii_entities=dict(
                    cast(Mapping[str, int], privacy_facts["pii_entities"])
                ),
                policy_verdicts=tuple(
                    verdict.model_dump(mode="json")
                    for verdict in prepared.policy_verdicts
                ),
            )
            if prepared.unpriced and policy.monthly_limit_usd is not None:
                raise SpendLimitExceeded("MODEL_PRICE_UNKNOWN")
            result = await self.repository.reserve_provider_spend(
                session,
                command,
            )
            await session.commit()
            return result
        except SpendLimitExceeded as exc:
            await session.rollback()
            if command is None:
                raise
            prepared.record_verdict(
                "spend.provider_monthly",
                stage="provider_spend",
                outcome="deny",
                reason_code="MODEL_PRICE_UNKNOWN"
                if str(exc) == "MODEL_PRICE_UNKNOWN"
                else "SPEND_LIMIT_EXCEEDED",
                policy_version=command.policy.version,
            )
            command = replace(
                command,
                policy_verdicts=tuple(
                    verdict.model_dump(mode="json")
                    for verdict in prepared.policy_verdicts
                ),
            )
            try:
                await self.repository.write_spend_denial_preflight(session, command)
                await session.commit()
            except Exception as audit_error:
                await session.rollback()
                if command.audit_policy_mode == "strict":
                    raise AuditIntentPersistenceError(
                        "required spend-denial audit preflight failed"
                    ) from audit_error
                logger.warning(
                    "Spend-denial audit preflight could not be persisted type=%s",
                    type(audit_error).__name__,
                )
            raise
        except Exception as exc:
            await session.rollback()
            prepared.record_verdict(
                "spend.provider_monthly",
                stage="provider_spend",
                outcome="error",
                reason_code="SPEND_UNAVAILABLE",
                policy_version=command.policy.version if command is not None else None,
            )
            if isinstance(exc, AuditIntentPersistenceError):
                raise
            if isinstance(exc, AccountingPersistenceError):
                raise
            raise AccountingPersistenceError("spend reservation failed") from exc

    async def record_privacy(
        self,
        prepared: PreparedInference,
        session: AsyncSession,
    ) -> None:
        if prepared.privacy is None:
            raise ValueError("privacy outcome is required")
        privacy_facts = REQUEST_PRIVACY_RETENTION.durable_facts(prepared.privacy)
        try:
            lifecycle = await RequestLifecycleRepository.update(
                session,
                organization_id=prepared.tenant_id,
                request_id=prepared.request_id,
                values={
                    "privacy_status": privacy_facts["privacy_status"],
                    "pii_detected": privacy_facts["pii_detected"],
                    "lifecycle_metadata": RequestLifecycle.lifecycle_metadata.op("||")(
                        {
                            "policy_verdicts": [
                                verdict.model_dump(mode="json")
                                for verdict in prepared.policy_verdicts
                            ],
                            "pii_entities": dict(prepared.privacy.pii_entities),
                        }
                    ),
                },
            )
            if lifecycle is None:
                raise AccountingPersistenceError("privacy lifecycle is missing")
            await session.commit()
        except Exception as exc:
            await session.rollback()
            if isinstance(exc, AccountingPersistenceError):
                raise
            raise AccountingPersistenceError("privacy lifecycle update failed") from exc

    async def mark_provider_started(
        self,
        prepared: PreparedInference,
        session: AsyncSession,
    ) -> None:
        now = datetime.now(timezone.utc)
        try:
            lifecycle = await RequestLifecycleRepository.transition(
                session,
                organization_id=prepared.tenant_id,
                request_id=prepared.request_id,
                target_status="provider_started",
                expected_statuses={"provider_pending"},
                values={
                    "provider_started_at": now,
                    "reconciliation_due_at": _provider_reconciliation_due_at(
                        now,
                        prepared.provider,
                    ),
                },
            )
            if lifecycle is None:
                raise AccountingPersistenceError("provider lifecycle is missing")
            await session.commit()
        except Exception as exc:
            await session.rollback()
            if isinstance(exc, AccountingPersistenceError):
                raise
            raise AccountingPersistenceError("provider start marker failed") from exc

    async def failure_reservation_state(
        self,
        prepared: PreparedInference,
        session: AsyncSession,
    ) -> FailureReservationState:
        try:
            await session.rollback()
            return await self.repository.failure_reservation_state(
                session,
                tenant_id=prepared.tenant_id,
                request_id=prepared.request_id,
            )
        except Exception as exc:
            try:
                await session.rollback()
            except Exception as rollback_exc:
                raise AccountingPersistenceError(
                    "failure reservation state cleanup failed"
                ) from rollback_exc
            if isinstance(exc, AccountingPersistenceError):
                raise
            raise AccountingPersistenceError(
                "failure reservation state is unavailable"
            ) from exc

    async def mark_stream_started(
        self,
        prepared: PreparedInference,
        session: AsyncSession,
    ) -> None:
        started_at = datetime.now(timezone.utc)
        try:
            await self.repository.mark_stream_started(
                session,
                tenant_id=prepared.tenant_id,
                request_id=prepared.request_id,
                started_at=started_at,
                reconciliation_due_at=_provider_reconciliation_due_at(
                    started_at,
                    prepared.provider,
                ),
            )
            await session.commit()
        except Exception as exc:
            await session.rollback()
            if isinstance(exc, AccountingPersistenceError):
                raise
            raise AccountingPersistenceError("stream start marker failed") from exc

    async def heartbeat_stream(
        self,
        prepared: PreparedInference,
        session: AsyncSession,
    ) -> None:
        now = datetime.now(timezone.utc)
        try:
            await self.repository.heartbeat_stream(
                session,
                tenant_id=prepared.tenant_id,
                request_id=prepared.request_id,
                reconciliation_due_at=_provider_reconciliation_due_at(
                    now,
                    prepared.provider,
                ),
            )
            await session.commit()
        except Exception as exc:
            await session.rollback()
            if isinstance(exc, AccountingPersistenceError):
                raise
            raise AccountingPersistenceError("stream heartbeat failed") from exc

    async def finalize(
        self,
        session: AsyncSession,
        command: FinalizationCommand,
    ) -> FinalizationResult:
        try:
            result = await self.repository.finalize(session, command)
            await session.commit()
            outcome = (
                "replayed"
                if result.replayed
                else (
                    "refunded"
                    if command.quota_action is TerminalAction.REFUND
                    else "settled"
                )
            )
            USAGE_SETTLEMENT_TOTAL.labels(status=outcome).inc()
            return result
        except AuditIntentPersistenceError:
            await session.rollback()
            USAGE_SETTLEMENT_TOTAL.labels(status="failed").inc()
            raise
        except Exception as exc:
            await session.rollback()
            USAGE_SETTLEMENT_TOTAL.labels(status="failed").inc()
            raise AccountingPersistenceError("accounting finalization failed") from exc

    async def signal_urgent_reconciliation(
        self,
        session: AsyncSession,
        *,
        tenant_id: TenantId,
        request_id: RequestId,
        occurred_at: datetime,
        reason: str,
    ) -> bool:
        try:
            signaled = await self.repository.signal_urgent_reconciliation(
                session,
                tenant_id=tenant_id,
                request_id=request_id,
                occurred_at=occurred_at,
                reason=reason,
            )
            await session.commit()
            return signaled
        except Exception as exc:
            await session.rollback()
            if isinstance(exc, AccountingPersistenceError):
                raise
            raise AccountingPersistenceError(
                "urgent reconciliation signal failed"
            ) from exc

    async def refund(
        self,
        session: AsyncSession,
        prepared: PreparedInference,
        *,
        spend_reserved: bool,
        error_code: str,
        lifecycle_status: Literal["failed", "rejected"] = "failed",
        error_message: str = "Request ended before a provider value was delivered.",
    ) -> FinalizationResult:
        return await self.finalize(
            session,
            FinalizationCommand(
                tenant_id=prepared.tenant_id,
                request_id=prepared.request_id,
                quota_action=TerminalAction.REFUND,
                spend_action=(
                    TerminalAction.REFUND if spend_reserved else TerminalAction.NONE
                ),
                lifecycle_status=lifecycle_status,
                terminal_error_code=error_code,
                terminal_error_message=error_message,
                policy_verdicts=tuple(
                    verdict.model_dump(mode="json")
                    for verdict in prepared.policy_verdicts
                ),
            ),
        )


class DurableUsageLifecycle:
    """Open one short enterprise accounting session per lifecycle verb."""

    def __init__(
        self,
        accounting: DurableAccountingCoordinator,
        session_factory: Callable[[], AsyncSession],
    ) -> None:
        self.accounting = accounting
        self.session_factory = session_factory

    async def reject(self, prepared: PreparedInference) -> None:
        mode = prepared.context.audit_policy.mode
        if mode == "off":
            return
        try:
            async with self.session_factory() as session:
                lifecycle = await RequestLifecycleRepository.get(
                    session,
                    organization_id=prepared.tenant_id,
                    request_id=prepared.request_id,
                )
                if lifecycle is not None:
                    # Admission may have committed before its acknowledgement failed.
                    verdict = prepared.policy_verdicts[-1]
                    await self.accounting.refund(
                        session,
                        prepared,
                        spend_reserved=False,
                        error_code=verdict.reason_code,
                        lifecycle_status="rejected"
                        if verdict.outcome == "deny"
                        else "failed",
                    )
                    return
                intent = rejection_intent(prepared)
                outbox = await OutboxWriter().append(
                    session,
                    organization_id=prepared.tenant_id,
                    values=intent.persistence_values(),
                )
                await AuditIntentRepository.create(
                    session,
                    organization_id=prepared.tenant_id,
                    values={
                        "request_id": str(prepared.request_id),
                        "actor_type": prepared.context.actor_type,
                        "api_key_id": prepared.api_key_id,
                        "user_id": prepared.context.user_id,
                        "event_type": "completion",
                        "audit_policy_mode": mode,
                        "provider": str(prepared.provider),
                        "model": intent.payload["model"],
                        "lifecycle_status": intent.payload["extra"]["lifecycle_status"],
                        "outbox_event_id": outbox.id,
                    },
                )
                await session.commit()
        except Exception as error:
            if mode == "strict":
                raise AuditIntentPersistenceError(
                    "required rejection audit failed"
                ) from error
            logger.error(
                "Rejection audit could not be persisted type=%s", type(error).__name__
            )

    async def record_token_count(
        self, prepared: PreparedInference, input_tokens: int | None
    ) -> None:
        if prepared.context.audit_policy.mode == "off":
            return
        async with self.session_factory() as session:
            try:
                await persist_token_count_audit(
                    session, prepared, input_tokens, datetime.now(timezone.utc)
                )
                await session.commit()
            except Exception as exc:
                await session.rollback()
                if prepared.context.audit_policy.mode == "strict":
                    raise AuditIntentPersistenceError(
                        "required token-count audit failed"
                    ) from exc
                logger.warning("Token-count audit failed type=%s", type(exc).__name__)

    async def admit(
        self,
        prepared: PreparedInference,
        admission: AdmissionState,
    ) -> None:
        async with self.session_factory() as session:
            await self.accounting.reserve_quota(prepared, admission, session)

    async def record_privacy(self, prepared: PreparedInference) -> None:
        async with self.session_factory() as session:
            await self.accounting.record_privacy(prepared, session)

    async def reserve_provider_spend(
        self,
        prepared: PreparedInference,
        *,
        ephemeral_byok: bool,
    ) -> None:
        async with self.session_factory() as session:
            await self.accounting.reserve_spend(
                prepared,
                ephemeral_byok,
                session,
            )

    async def mark_provider_started(self, prepared: PreparedInference) -> None:
        async with self.session_factory() as session:
            await self.accounting.mark_provider_started(prepared, session)

    async def mark_stream_started(self, prepared: PreparedInference) -> None:
        async with self.session_factory() as session:
            await self.accounting.mark_stream_started(prepared, session)

    async def heartbeat_stream(self, prepared: PreparedInference) -> None:
        async with self.session_factory() as session:
            await self.accounting.heartbeat_stream(prepared, session)

    async def finalize(
        self,
        prepared: PreparedInference,
        terminal: StreamFinalization,
    ) -> None:
        usage = terminal.usage
        try:
            async with self.session_factory() as session:
                await self.accounting.finalize(
                    session,
                    FinalizationCommand(
                        tenant_id=prepared.tenant_id,
                        request_id=prepared.request_id,
                        quota_action=TerminalAction.SETTLE,
                        spend_action=TerminalAction.SETTLE,
                        prompt_tokens=usage.prompt_tokens,
                        completion_tokens=usage.completion_tokens,
                        actual_cost_usd=usage.settlement_cost_usd,
                        provider_model=usage.provider_model,
                        pricing_metadata=usage.pricing_metadata,
                        estimated=usage.estimated,
                        lifecycle_status=terminal.terminal_status,
                        terminal_error_code=terminal.error_code,
                        terminal_error_message=terminal.error_message,
                        output_hash=usage.output_hash,
                        provider_finish_reasons=usage.provider_finish_reasons,
                        ttft_ms=usage.ttft_ms,
                        completed_at=terminal.completed_at,
                    ),
                )
        except AuditIntentPersistenceError:
            if not prepared.stream:
                raise
            try:
                async with self.session_factory() as session:
                    await self.accounting.signal_urgent_reconciliation(
                        session,
                        tenant_id=prepared.tenant_id,
                        request_id=prepared.request_id,
                        occurred_at=terminal.completed_at,
                        reason="AUDIT_INTENT_FAILED",
                    )
            except Exception as exc:
                logger.critical(
                    "Strict audit completion and urgent reconciliation signal "
                    "failed type=%s",
                    type(exc).__name__,
                )
            raise

    async def fail(
        self,
        prepared: PreparedInference,
        *,
        reason: UsageFailureReason,
    ) -> None:
        try:
            async with self.session_factory() as session:
                if reason == "admission_aborted":
                    spend_reserved = False
                    error_code = "ADMISSION_ABORTED"
                    error_message = (
                        "Request ended before a provider value was delivered."
                    )
                else:
                    state = await self.accounting.failure_reservation_state(
                        prepared,
                        session,
                    )
                    spend_reserved = state.spend_reserved
                    if reason == "provider_rejected_without_usage":
                        error_code = "PROVIDER_UNAVAILABLE"
                        error_message = (
                            "The provider rejected the request without usage."
                        )
                    elif state.provider_started:
                        error_code = "PROVIDER_USAGE_UNAVAILABLE"
                        error_message = (
                            "Provider execution began but usage could not be verified."
                        )
                    else:
                        error_code = "REQUEST_ABORTED"
                        error_message = (
                            "Request ended before a provider value was delivered."
                        )
                denied = next(
                    (
                        verdict
                        for verdict in reversed(prepared.policy_verdicts)
                        if verdict.outcome == "deny"
                    ),
                    None,
                )
                await self.accounting.refund(
                    session,
                    prepared,
                    spend_reserved=spend_reserved,
                    error_code=denied.reason_code if denied is not None else error_code,
                    error_message=error_message,
                    lifecycle_status="rejected" if denied is not None else "failed",
                )
        except AuditIntentPersistenceError:
            if prepared.context.audit_policy.mode == "strict":
                raise
            logger.error("Rejected request audit unavailable; stale recovery retained")
        except Exception as exc:
            logger.error(
                "Durable accounting finalization failed; stale recovery retained "
                "type=%s",
                type(exc).__name__,
            )


@dataclass(frozen=True, slots=True)
class ScanAdmission:
    usage: ScanUsageStatus
    audit_preflight_intent_id: UUID | None


class ScanAdmissionRepository:
    """Atomically admit and count provider-free scans in PostgreSQL."""

    async def admit(
        self,
        session: AsyncSession,
        *,
        request: ScanRequest,
        actor: ResolvedScanActor,
        started_at: datetime,
        input_hash: str,
    ) -> ScanAdmission:
        counted = bool(request.text.strip())
        try:
            await session.execute(
                text(
                    "SELECT pg_advisory_xact_lock("
                    "hashtextextended(:scan_subject_month, 0))"
                ),
                {"scan_subject_month": _scan_lock_key(actor, started_at)},
            )
            count = await self.count(session, actor=actor, now=started_at)
            if counted and actor.scan_limit != -1 and count >= actor.scan_limit:
                await RequestLifecycleRepository.create(
                    session,
                    organization_id=request.tenant_id,
                    values={
                        **_scan_lifecycle_values(request, actor, started_at, False),
                        "status": "rejected",
                        "failed_at": started_at,
                        "reconciled_at": started_at,
                        "reconciliation_due_at": None,
                        "terminal_error_code": "SCAN_LIMIT_EXCEEDED",
                        "terminal_error_message": "Monthly scan limit exceeded.",
                    },
                )
                await session.commit()
                raise ScanLimitExceeded(
                    scan_usage_status(count, actor.scan_limit, started_at)
                )

            await RequestLifecycleRepository.create(
                session,
                organization_id=request.tenant_id,
                values=_scan_lifecycle_values(request, actor, started_at, counted),
            )
            preflight_id = None
            if actor.audit_mode != "off":
                preflight = await AuditIntentRepository.create(
                    session,
                    organization_id=request.tenant_id,
                    values={
                        "request_id": str(request.request_id),
                        "actor_type": request.actor_type,
                        "api_key_id": request.api_key_id,
                        "user_id": request.user_id,
                        "event_type": "preflight",
                        "audit_policy_mode": actor.audit_mode,
                        "input_hash": input_hash,
                        "output_hash": None,
                        "pii_entities": {},
                        "provider": None,
                        "model": None,
                        "usage_summary": {"scan_counted": int(counted)},
                        "lifecycle_status": "accepted",
                    },
                )
                preflight_id = preflight.id
            await session.commit()
            return ScanAdmission(
                usage=scan_usage_status(
                    count + int(counted), actor.scan_limit, started_at
                ),
                audit_preflight_intent_id=preflight_id,
            )
        except ScanLimitExceeded:
            raise
        except Exception:
            await session.rollback()
            raise ScanPersistenceError() from None

    async def usage(
        self,
        session: AsyncSession,
        *,
        actor: ResolvedScanActor,
        now: datetime,
    ) -> ScanUsageStatus:
        try:
            count = await self.count(session, actor=actor, now=now)
        except Exception:
            await session.rollback()
            raise ScanPersistenceError() from None
        return scan_usage_status(count, actor.scan_limit, now)

    @staticmethod
    async def count(
        session: AsyncSession,
        *,
        actor: ResolvedScanActor,
        now: datetime,
    ) -> int:
        month_start, next_month = scan_month_bounds(now)
        statement = select(
            func.coalesce(
                func.sum(
                    RequestLifecycle.lifecycle_metadata["scan_count_delta"].as_integer()
                ),
                0,
            )
        ).where(
            RequestLifecycle.organization_id == actor.tenant_id,
            RequestLifecycle.source_endpoint == "scan",
            RequestLifecycle.started_at >= month_start,
            RequestLifecycle.started_at < next_month,
            RequestLifecycle.lifecycle_metadata["scan_counted"].as_string() == "true",
            RequestLifecycle.lifecycle_metadata["scan_subject_user_id"].as_string()
            == str(actor.subject_id),
        )
        return int((await session.execute(statement)).scalar_one())


def scan_month_bounds(now: datetime) -> tuple[datetime, datetime]:
    current = now.astimezone(timezone.utc)
    start = current.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    next_month = (
        start.replace(year=start.year + 1, month=1)
        if start.month == 12
        else start.replace(month=start.month + 1)
    )
    return start, next_month


def scan_usage_status(count: int, limit: int, now: datetime) -> ScanUsageStatus:
    _, next_month = scan_month_bounds(now)
    return ScanUsageStatus(
        scan_count=count,
        scan_limit=limit,
        scans_remaining=-1 if limit == -1 else max(0, limit - count),
        resets_at=None if limit == -1 else next_month.isoformat(),
    )


def _provider_reconciliation_due_at(started_at: datetime, provider: str) -> datetime:
    timeout_seconds = {
        "openai": max(
            settings.OPENAI_CONNECT_TIMEOUT_SECONDS,
            settings.OPENAI_READ_TIMEOUT_SECONDS,
            settings.OPENAI_WRITE_TIMEOUT_SECONDS,
            settings.OPENAI_POOL_TIMEOUT_SECONDS,
        ),
        "anthropic": max(
            settings.ANTHROPIC_CONNECT_TIMEOUT_SECONDS,
            settings.ANTHROPIC_READ_TIMEOUT_SECONDS,
            settings.ANTHROPIC_WRITE_TIMEOUT_SECONDS,
            settings.ANTHROPIC_POOL_TIMEOUT_SECONDS,
        ),
    }.get(provider, settings.GOOGLE_TIMEOUT_SECONDS)
    return started_at + timedelta(
        seconds=settings.GATEWAY_RECONCILIATION_GRACE_SECONDS + max(60, timeout_seconds)
    )


def _scan_lock_key(actor: ResolvedScanActor, now: datetime) -> str:
    return f"scan:user:{actor.subject_id}:{now.astimezone(timezone.utc):%Y-%m}"


def _scan_lifecycle_values(
    request: ScanRequest,
    actor: ResolvedScanActor,
    started_at: datetime,
    counted: bool,
) -> dict[str, object]:
    return {
        "request_id": str(request.request_id),
        "actor_type": request.actor_type,
        "api_key_id": request.api_key_id,
        "user_id": request.user_id,
        "source_endpoint": "scan",
        "status": "accepted",
        "provider": None,
        "provider_model": None,
        "requested_model": None,
        "stream": False,
        "cache_status": "not_applicable",
        "privacy_status": "pending",
        "pii_detected": False,
        "started_at": started_at,
        "reconciliation_due_at": started_at
        + timedelta(seconds=settings.GATEWAY_RECONCILIATION_GRACE_SECONDS + 300),
        "lifecycle_metadata": {
            "audit_mode": actor.audit_mode,
            "scan_counted": counted,
            "scan_count_delta": int(counted),
            "scan_subject_user_id": str(actor.subject_id),
            "scan_source": request.source,
            "tier": actor.tier,
            "policy": actor.policy,
            "input_character_count": len(request.text),
        },
    }
