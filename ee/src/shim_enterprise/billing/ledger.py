"""Authoritative PostgreSQL quota, spend, and reconciliation transactions."""

from __future__ import annotations

import calendar
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from enum import Enum
from typing import Any, Literal, cast
from uuid import UUID

from sqlalchemy import and_, or_, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from shim.gateway.contracts.ids import ApiKeyId, ProviderId, RequestId, TenantId
from shim_enterprise.core.errors import IdentityConflictError
from shim_enterprise.billing.models import (
    QuotaPeriodUsage,
    RequestLifecycle,
    SpendPeriodUsage,
    UsageLedger,
)
from shim_enterprise.gateway.pipeline.audit_intent import AuditIntentRepository
from shim_enterprise.observability.lifecycle import RequestLifecycleRepository
from shim_enterprise.outbox.publisher import OutboxWriter
from shim_enterprise.gateway.pipeline.outbox import (
    analytics_terminal_intent,
    audit_completion_intent,
)
from shim.gateway.usage import UsageLimitExceeded


class AccountingConflictError(IdentityConflictError):
    """Persisted accounting identity or counter state conflicts with the request."""


_USAGE_LEDGER_REPLAY_FIELDS = (
    "request_id",
    "organization_id",
    "api_key_id",
    "requested_model",
    "provider",
    "provider_model",
    "event_type",
    "idempotency_key",
    "reservation_event_id",
    "request_count",
    "prompt_tokens",
    "completion_tokens",
    "total_tokens",
    "estimated",
    "cost_usd",
    "currency",
    "period_allocations",
    "event_metadata",
)


def _usage_ledger_replay_conflicts(
    ledger_entry: UsageLedger,
    values: Mapping[str, Any],
) -> bool:
    return any(
        getattr(ledger_entry, field) != values[field]
        for field in _USAGE_LEDGER_REPLAY_FIELDS
        if field in values
    )


def _event_pricing(
    ledger_entry: UsageLedger | None,
) -> dict[str, str | int] | None:
    metadata = getattr(ledger_entry, "event_metadata", None)
    if not isinstance(metadata, Mapping):
        return None
    pricing = metadata.get("pricing")
    return dict(pricing) if isinstance(pricing, Mapping) else None


class UsageLedgerRepository:
    """Append-only access to tenant-scoped quota and spend events."""

    @staticmethod
    async def append(
        session: AsyncSession,
        *,
        organization_id: TenantId,
        values: Mapping[str, Any],
    ) -> UsageLedger:
        payload = dict(values)
        payload["organization_id"] = organization_id
        idempotency_key = payload["idempotency_key"]
        statement = (
            insert(UsageLedger)
            .values(**payload)
            .on_conflict_do_nothing(
                index_elements=[
                    UsageLedger.organization_id,
                    UsageLedger.idempotency_key,
                ]
            )
            .returning(UsageLedger)
        )
        ledger_entry = (await session.execute(statement)).scalar_one_or_none()
        if ledger_entry is not None:
            return ledger_entry
        ledger_entry = await UsageLedgerRepository.fetch(
            session,
            organization_id=organization_id,
            idempotency_key=idempotency_key,
        )
        if ledger_entry is None:
            raise AccountingConflictError("usage ledger identity conflict")
        if _usage_ledger_replay_conflicts(ledger_entry, payload):
            raise AccountingConflictError("usage ledger identity conflict")
        return ledger_entry

    @staticmethod
    async def fetch(
        session: AsyncSession,
        *,
        organization_id: TenantId,
        idempotency_key: str,
    ) -> UsageLedger | None:
        statement = select(UsageLedger).where(
            UsageLedger.organization_id == organization_id,
            UsageLedger.idempotency_key == idempotency_key,
        )
        return (await session.execute(statement)).scalar_one_or_none()


class QuotaLimitExceeded(UsageLimitExceeded):
    """Current authoritative request or token policy denied admission."""


class SpendLimitExceeded(UsageLimitExceeded):
    """Current authoritative provider spend policy denied admission."""


class TerminalAction(str, Enum):
    SETTLE = "settlement"
    REFUND = "refund"
    NONE = "none"


@dataclass(frozen=True)
class QuotaPolicySnapshot:
    """Quota limits loaded under lock, or version-checked, by the caller."""

    version: str
    daily_request_limit: int | None
    monthly_request_limit: int | None
    monthly_token_limit: int | None

    def __post_init__(self) -> None:
        limits = (
            self.daily_request_limit,
            self.monthly_request_limit,
            self.monthly_token_limit,
        )
        if any(limit is not None and limit < 0 for limit in limits):
            raise ValueError("quota limits must be nonnegative or null")


@dataclass(frozen=True)
class SpendPolicySnapshot:
    """Provider spend limit loaded under lock, or version-checked, by the caller."""

    version: str
    monthly_limit_usd: Decimal | None

    def __post_init__(self) -> None:
        if self.monthly_limit_usd is not None and self.monthly_limit_usd < 0:
            raise ValueError("provider spend limit must be nonnegative or null")


@dataclass(frozen=True)
class QuotaReservationCommand:
    tenant_id: TenantId
    api_key_id: ApiKeyId
    request_id: RequestId
    requested_model: str
    source_endpoint: str
    started_at: datetime
    reconciliation_due_at: datetime
    estimated_input_tokens: int
    maximum_output_tokens: int
    policy: QuotaPolicySnapshot
    cost_center: str = "untagged"
    tags: tuple[str, ...] = ()
    team: str | None = None
    stream: bool = False

    def __post_init__(self) -> None:
        if self.estimated_input_tokens < 0 or self.maximum_output_tokens < 0:
            raise ValueError("reserved token counts must be nonnegative")
        if self.started_at.tzinfo is None or self.reconciliation_due_at.tzinfo is None:
            raise ValueError("accounting timestamps must be timezone-aware")
        if not self.cost_center.strip():
            raise ValueError("cost center cannot be empty")


@dataclass(frozen=True)
class SpendReservationCommand:
    tenant_id: TenantId
    api_key_id: ApiKeyId
    request_id: RequestId
    requested_model: str
    provider: ProviderId
    provider_model: str
    estimated_cost_usd: Decimal
    pricing_metadata: dict[str, str | int]
    cache_status: Literal["miss", "bypass"]
    audit_policy_mode: Literal["off", "best_effort", "strict"]
    policy: SpendPolicySnapshot
    input_hash: str | None = None
    pii_entities: dict[str, int] | None = None

    def __post_init__(self) -> None:
        if self.estimated_cost_usd < 0:
            raise ValueError("reserved provider cost must be nonnegative")
        if not self.pricing_metadata:
            raise ValueError("provider spend requires pricing metadata")
        if self.cache_status not in {"miss", "bypass"}:
            raise ValueError("provider spend is forbidden for cache hits")


@dataclass(frozen=True)
class FinalizationCommand:
    tenant_id: TenantId
    request_id: RequestId
    quota_action: TerminalAction
    spend_action: TerminalAction = TerminalAction.NONE
    prompt_tokens: int = 0
    completion_tokens: int = 0
    actual_cost_usd: Decimal = Decimal("0")
    provider_model: str | None = None
    pricing_metadata: dict[str, str | int] | None = None
    estimated: bool = False
    lifecycle_status: Literal[
        "completed",
        "provider_error",
        "client_disconnected",
        "timeout",
        "cancelled",
        "internal_error",
        "rejected",
        "failed",
    ] = "completed"
    terminal_error_code: str | None = None
    terminal_error_message: str | None = None
    output_hash: str | None = None
    completed_at: datetime | None = None
    reconciliation_urgent: bool = False

    def __post_init__(self) -> None:
        if self.quota_action is TerminalAction.NONE:
            raise ValueError("every accepted request requires a quota finalization")
        if self.prompt_tokens < 0 or self.completion_tokens < 0:
            raise ValueError("final token counts must be nonnegative")
        if self.actual_cost_usd < 0:
            raise ValueError("final provider cost must be nonnegative")
        if self.provider_model is not None and not self.provider_model.strip():
            raise ValueError("final provider model cannot be blank")
        if self.pricing_metadata is not None and not self.pricing_metadata:
            raise ValueError("final pricing metadata cannot be empty")
        if self.terminal_error_code in {
            "PROVIDER_USAGE_UNAVAILABLE",
            "STALE_RESERVATION_RECOVERED",
        } and (
            self.quota_action is TerminalAction.SETTLE
            or self.spend_action is TerminalAction.SETTLE
        ):
            raise ValueError("unverified provider usage cannot be settled")


@dataclass(frozen=True, slots=True)
class FailureReservationState:
    provider_started: bool
    spend_reserved: bool


@dataclass(frozen=True)
class ReservationResult:
    event_id: UUID
    policy_version: str
    period_allocations: tuple[dict[str, object], ...]
    replayed: bool


@dataclass(frozen=True)
class FinalizationResult:
    request_id: RequestId
    quota_event_id: UUID
    spend_event_id: UUID | None
    replayed: bool
    audit_payload: dict[str, Any] | None = None


class DurableAccountingRepository:
    """Apply accounting mutations inside a caller-owned database transaction."""

    async def reserve_quota(
        self,
        session: AsyncSession,
        command: QuotaReservationCommand,
    ) -> ReservationResult:
        await RequestLifecycleRepository.create(
            session,
            organization_id=command.tenant_id,
            values={
                "request_id": str(command.request_id),
                "actor_type": "api_key",
                "api_key_id": command.api_key_id,
                "user_id": None,
                "source_endpoint": command.source_endpoint,
                "status": "accepted",
                "provider": None,
                "provider_model": None,
                "requested_model": command.requested_model,
                "stream": command.stream,
                "started_at": command.started_at,
                "reconciliation_due_at": command.reconciliation_due_at,
                "lifecycle_metadata": {
                    "quota_policy_version": command.policy.version,
                    "cost_center": command.cost_center,
                    "tags": list(command.tags),
                    "team": command.team,
                },
            },
        )
        reservation, replayed = await self._insert_reservation(
            session,
            tenant_id=command.tenant_id,
            values={
                "request_id": str(command.request_id),
                "api_key_id": command.api_key_id,
                "requested_model": command.requested_model,
                "provider": None,
                "provider_model": None,
                "event_type": "quota_reservation",
                "idempotency_key": (f"request:{command.request_id}:quota:reservation"),
                "request_count": 1,
                "prompt_tokens": command.estimated_input_tokens,
                "completion_tokens": command.maximum_output_tokens,
                "total_tokens": (
                    command.estimated_input_tokens + command.maximum_output_tokens
                ),
                "estimated": True,
                "cost_usd": Decimal("0"),
                "period_allocations": [],
                "event_metadata": {
                    "policy_version": command.policy.version,
                    "cost_center": command.cost_center,
                    "tags": list(command.tags),
                    "team": command.team,
                },
            },
        )
        self._validate_quota_reservation(reservation, command)
        if replayed:
            return self._reservation_result(
                reservation,
                command.policy.version,
                replayed=True,
            )

        allocations = await self._reserve_quota_periods(session, command)
        await self._store_allocations(
            session,
            reservation.id,
            command.tenant_id,
            allocations,
        )
        return ReservationResult(
            event_id=reservation.id,
            policy_version=command.policy.version,
            period_allocations=tuple(allocations),
            replayed=False,
        )

    async def reserve_provider_spend(
        self,
        session: AsyncSession,
        command: SpendReservationCommand,
    ) -> ReservationResult:
        reservation, replayed = await self._insert_reservation(
            session,
            tenant_id=command.tenant_id,
            values={
                "request_id": str(command.request_id),
                "api_key_id": command.api_key_id,
                "requested_model": command.requested_model,
                "provider": str(command.provider),
                "provider_model": command.provider_model,
                "event_type": "spend_reservation",
                "idempotency_key": (
                    f"request:{command.request_id}:spend:{command.provider}:reservation"
                ),
                "request_count": 0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
                "estimated": True,
                "cost_usd": command.estimated_cost_usd,
                "period_allocations": [],
                "event_metadata": {
                    "cache_status": command.cache_status,
                    "policy_version": command.policy.version,
                    "pricing": dict(command.pricing_metadata),
                },
            },
        )
        self._validate_spend_reservation(reservation, command)
        if replayed:
            await self._write_preflight(session, command)
            return self._reservation_result(
                reservation,
                command.policy.version,
                replayed=True,
            )

        allocation = await self._reserve_spend_period(session, command)
        await self._store_allocations(
            session,
            reservation.id,
            command.tenant_id,
            [allocation],
        )
        await self._write_preflight(session, command)
        lifecycle = await RequestLifecycleRepository.update(
            session,
            organization_id=command.tenant_id,
            request_id=command.request_id,
            values={
                "status": "provider_pending",
                "provider": str(command.provider),
                "provider_model": command.provider_model,
                "cache_status": command.cache_status,
            },
        )
        if lifecycle is None:
            raise ValueError("spend reservation requires an accepted lifecycle")
        return ReservationResult(
            event_id=reservation.id,
            policy_version=command.policy.version,
            period_allocations=(allocation,),
            replayed=False,
        )

    async def write_spend_denial_preflight(
        self,
        session: AsyncSession,
        command: SpendReservationCommand,
    ) -> None:
        """Persist the required/attempted audit fact after spend denial rollback."""

        await self._write_preflight(
            session,
            command,
            lifecycle_status="spend_denied",
            usage_summary={"denial_reason": "spend_limit_exceeded"},
        )

    async def finalize(
        self,
        session: AsyncSession,
        command: FinalizationCommand,
    ) -> FinalizationResult:
        lifecycle = await self._lock_lifecycle(
            session,
            command.tenant_id,
            command.request_id,
        )
        quota_reservation = await self._lock_reservation(
            session,
            command.tenant_id,
            command.request_id,
            "quota_reservation",
        )
        spend_reservation = (
            await self._lock_reservation(
                session,
                command.tenant_id,
                command.request_id,
                "spend_reservation",
            )
            if command.spend_action is not TerminalAction.NONE
            else None
        )
        return await self._finalize_locked(
            session,
            command,
            lifecycle,
            quota_reservation,
            spend_reservation,
        )

    async def failure_reservation_state(
        self,
        session: AsyncSession,
        *,
        tenant_id: TenantId,
        request_id: RequestId,
    ) -> FailureReservationState:
        """Lock and return the durable facts that determine failure finalization."""

        lifecycle = await self._lock_lifecycle(session, tenant_id, request_id)
        spend_reservation = await self._find_reservation(
            session,
            tenant_id,
            request_id,
            "spend_reservation",
            lock=True,
        )
        return FailureReservationState(
            provider_started=lifecycle.provider_started_at is not None,
            spend_reserved=spend_reservation is not None,
        )

    async def _finalize_locked(
        self,
        session: AsyncSession,
        command: FinalizationCommand,
        lifecycle: RequestLifecycle,
        quota_reservation: UsageLedger,
        spend_reservation: UsageLedger | None,
    ) -> FinalizationResult:
        quota_event, quota_replayed = await self._transition_reservation(
            session,
            command.tenant_id,
            quota_reservation,
            command.quota_action,
            prompt_tokens=command.prompt_tokens,
            completion_tokens=command.completion_tokens,
            cost_usd=Decimal("0"),
            estimated=command.estimated,
        )

        spend_event: UsageLedger | None = None
        spend_replayed = False
        if command.spend_action is not TerminalAction.NONE:
            if spend_reservation is None:
                raise AccountingConflictError("spend_reservation does not exist")
            spend_event, spend_replayed = await self._transition_reservation(
                session,
                command.tenant_id,
                spend_reservation,
                command.spend_action,
                prompt_tokens=0,
                completion_tokens=0,
                cost_usd=command.actual_cost_usd,
                estimated=command.estimated,
                provider_model=command.provider_model,
                pricing_metadata=command.pricing_metadata,
            )

        all_replayed = quota_replayed and (
            command.spend_action is TerminalAction.NONE or spend_replayed
        )
        terminal_status = (
            lifecycle.status
            if all_replayed and lifecycle.reconciled_at is not None
            else command.lifecycle_status
        )
        completed_at = (
            lifecycle.reconciled_at
            if all_replayed and lifecycle.reconciled_at is not None
            else command.completed_at or datetime.now(timezone.utc)
        )
        if command.provider_model is not None:
            lifecycle.provider_model = command.provider_model
        audit_payload = await self._write_audit_completion(
            session,
            lifecycle,
            quota_event=quota_event,
            spend_event=spend_event,
            lifecycle_status=terminal_status,
            output_hash=command.output_hash,
            completed_at=completed_at,
        )
        await self._enqueue_analytics_projection(
            session,
            lifecycle,
            quota_event=quota_event,
            spend_event=spend_event,
            lifecycle_status=terminal_status,
            completed_at=completed_at,
        )
        if all_replayed and lifecycle.reconciled_at is not None:
            return FinalizationResult(
                request_id=command.request_id,
                quota_event_id=quota_event.id,
                spend_event_id=spend_event.id if spend_event is not None else None,
                replayed=True,
                audit_payload=audit_payload,
            )

        if command.lifecycle_status in {"provider_error", "timeout"}:
            await self._append_provider_error(session, lifecycle, command)

        lifecycle_values: dict[str, object] = {
            "status": command.lifecycle_status,
            "reconciled_at": completed_at,
            "reconciliation_due_at": None,
            "terminal_error_code": command.terminal_error_code,
            "terminal_error_message": command.terminal_error_message,
        }
        if command.provider_model is not None:
            lifecycle_values["provider_model"] = command.provider_model
        if command.lifecycle_status == "completed":
            lifecycle_values["completed_at"] = completed_at
        else:
            lifecycle_values["failed_at"] = completed_at
        if command.lifecycle_status == "client_disconnected":
            lifecycle_values["client_disconnected_at"] = completed_at
        updated = await RequestLifecycleRepository.update(
            session,
            organization_id=command.tenant_id,
            request_id=command.request_id,
            values=lifecycle_values,
        )
        if updated is None or updated.id != lifecycle.id:
            raise AccountingConflictError(
                "request lifecycle disappeared during finalization"
            )
        await self._enqueue_reconciliation_event(
            session,
            command.tenant_id,
            command.request_id,
            lifecycle_status=command.lifecycle_status,
            urgent=command.reconciliation_urgent,
            occurred_at=completed_at,
        )
        return FinalizationResult(
            request_id=command.request_id,
            quota_event_id=quota_event.id,
            spend_event_id=spend_event.id if spend_event is not None else None,
            replayed=all_replayed,
            audit_payload=audit_payload,
        )

    async def mark_stream_started(
        self,
        session: AsyncSession,
        *,
        tenant_id: TenantId,
        request_id: RequestId,
        started_at: datetime,
        reconciliation_due_at: datetime,
    ) -> RequestLifecycle:
        """Record first-byte readiness without opening a long transaction."""

        if started_at.tzinfo is None or started_at.utcoffset() is None:
            raise ValueError("stream start time must be timezone-aware")
        if (
            reconciliation_due_at.tzinfo is None
            or reconciliation_due_at.utcoffset() is None
        ):
            raise ValueError("stream reconciliation time must be timezone-aware")
        lifecycle = await self._lock_lifecycle(session, tenant_id, request_id)
        if not lifecycle.stream:
            raise AccountingConflictError("non-stream request cannot start a stream")
        if lifecycle.stream_started_at is not None:
            return lifecycle
        if lifecycle.reconciled_at is not None:
            raise AccountingConflictError("terminal request cannot start a stream")
        updated = await RequestLifecycleRepository.update(
            session,
            organization_id=tenant_id,
            request_id=request_id,
            values={
                "status": "streaming",
                "stream_started_at": started_at,
                "reconciliation_due_at": reconciliation_due_at,
            },
        )
        if updated is None:
            raise AccountingConflictError("stream lifecycle disappeared")
        return updated

    async def heartbeat_stream(
        self,
        session: AsyncSession,
        *,
        tenant_id: TenantId,
        request_id: RequestId,
        reconciliation_due_at: datetime,
    ) -> RequestLifecycle:
        lifecycle = await self._lock_lifecycle(session, tenant_id, request_id)
        if lifecycle.status != "streaming" or lifecycle.reconciled_at is not None:
            raise AccountingConflictError("terminal request cannot heartbeat a stream")
        updated = await RequestLifecycleRepository.update(
            session,
            organization_id=tenant_id,
            request_id=request_id,
            values={"reconciliation_due_at": reconciliation_due_at},
        )
        if updated is None:
            raise AccountingConflictError("stream lifecycle disappeared")
        return updated

    async def signal_urgent_reconciliation(
        self,
        session: AsyncSession,
        *,
        tenant_id: TenantId,
        request_id: RequestId,
        occurred_at: datetime,
        reason: str,
    ) -> bool:
        """Advance stale recovery and durably surface a post-boundary failure."""

        if occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
            raise ValueError("urgent reconciliation time must be timezone-aware")
        lifecycle = await self._lock_lifecycle(session, tenant_id, request_id)
        if lifecycle.reconciled_at is not None:
            return False
        updated = await RequestLifecycleRepository.update(
            session,
            organization_id=tenant_id,
            request_id=request_id,
            values={"reconciliation_due_at": occurred_at},
        )
        if updated is None:
            raise AccountingConflictError("urgent reconciliation lifecycle disappeared")
        await OutboxWriter().append(
            session,
            organization_id=tenant_id,
            values={
                "event_type": "gateway.reconciliation",
                "aggregate_type": "request",
                "aggregate_id": str(request_id),
                "idempotency_key": (
                    f"request:{request_id}:outbox:gateway.reconciliation.urgent"
                ),
                "payload": {
                    "organization_id": str(tenant_id),
                    "request_id": str(request_id),
                    "lifecycle_status": lifecycle.status,
                    "urgent": True,
                    "reason": reason,
                },
                "status": "pending",
                "next_attempt_at": occurred_at,
            },
        )
        return True

    async def recover_stale(
        self,
        session: AsyncSession,
        *,
        now: datetime,
        batch_size: int = 100,
    ) -> tuple[FinalizationResult, ...]:
        if now.tzinfo is None:
            raise ValueError("stale recovery time must be timezone-aware")
        if batch_size <= 0:
            raise ValueError("stale recovery batch size must be positive")

        statement = (
            select(RequestLifecycle)
            .join(
                UsageLedger,
                and_(
                    UsageLedger.organization_id == RequestLifecycle.organization_id,
                    UsageLedger.request_id == RequestLifecycle.request_id,
                    UsageLedger.event_type == "quota_reservation",
                ),
            )
            .where(
                RequestLifecycle.reconciliation_due_at.is_not(None),
                RequestLifecycle.reconciliation_due_at <= now,
                RequestLifecycle.reconciled_at.is_(None),
                RequestLifecycle.status.not_in(("completed", "failed")),
            )
            .order_by(
                RequestLifecycle.reconciliation_due_at,
                RequestLifecycle.request_id,
            )
            .limit(batch_size)
            .with_for_update(skip_locked=True, of=RequestLifecycle)
        )
        stale = tuple((await session.execute(statement)).scalars().unique())
        results: list[FinalizationResult] = []
        for lifecycle in stale:
            tenant_id = TenantId(lifecycle.organization_id)
            request_id = RequestId(lifecycle.request_id)
            quota_reservation = await self._lock_reservation(
                session,
                tenant_id,
                request_id,
                "quota_reservation",
            )
            spend_reservation = await self._find_reservation(
                session,
                tenant_id,
                request_id,
                "spend_reservation",
                lock=True,
            )
            provider_started = lifecycle.provider_started_at is not None
            spend_action = (
                TerminalAction.REFUND
                if spend_reservation is not None
                else TerminalAction.NONE
            )
            terminal_status = (
                "rejected" if lifecycle.status == "routing_rejected" else "failed"
            )
            terminal_error_code = (
                lifecycle.terminal_error_code
                if terminal_status == "rejected"
                else "STALE_RESERVATION_RECOVERED"
            )
            terminal_error_message = (
                lifecycle.terminal_error_message
                if terminal_status == "rejected"
                else "Request expired before provider usage could be verified."
            )
            results.append(
                await self._finalize_locked(
                    session,
                    FinalizationCommand(
                        tenant_id=tenant_id,
                        request_id=request_id,
                        quota_action=TerminalAction.REFUND,
                        spend_action=spend_action,
                        lifecycle_status=terminal_status,
                        terminal_error_code=terminal_error_code,
                        terminal_error_message=terminal_error_message,
                        completed_at=now,
                        reconciliation_urgent=provider_started,
                    ),
                    lifecycle,
                    quota_reservation,
                    spend_reservation,
                )
            )
        return tuple(results)

    async def _reserve_quota_periods(
        self,
        session: AsyncSession,
        command: QuotaReservationCommand,
    ) -> list[dict[str, object]]:
        token_delta = command.estimated_input_tokens + command.maximum_output_tokens
        periods: list[tuple[str, date, date, int | None, int | None, int]] = []
        request_date = command.started_at.astimezone(timezone.utc).date()
        if command.policy.daily_request_limit is not None:
            periods.append(
                (
                    "daily",
                    request_date,
                    request_date + timedelta(days=1),
                    command.policy.daily_request_limit,
                    None,
                    0,
                )
            )
        month_start, month_end = self._month_bounds(request_date)
        # The monthly row is also the durable usage accumulator for unlimited
        # policies.  Omitting it would leave a reservation with no allocation
        # to settle or refund later.
        periods.append(
            (
                "monthly",
                month_start,
                month_end,
                command.policy.monthly_request_limit,
                command.policy.monthly_token_limit,
                token_delta,
            )
        )

        allocations: list[dict[str, object]] = []
        for period_type, start, end, request_limit, token_limit, tokens in sorted(
            periods,
            key=lambda item: (item[0], item[1]),
        ):
            if request_limit is not None and 1 > request_limit:
                raise QuotaLimitExceeded(f"{period_type} request quota exceeded")
            if token_limit is not None and tokens > token_limit:
                raise QuotaLimitExceeded(f"{period_type} token quota exceeded")
            row = await self._conditional_quota_upsert(
                session,
                command,
                period_type=period_type,
                period_start=start,
                period_end=end,
                request_delta=1,
                token_delta=tokens,
                request_limit=request_limit,
                token_limit=token_limit,
            )
            if row is None:
                raise QuotaLimitExceeded(f"{period_type} quota exceeded")
            allocations.append(
                {
                    "counter_type": "quota",
                    "period_row_id": str(row.id),
                    "period_type": period_type,
                    "period_start": start.isoformat(),
                    "period_end": end.isoformat(),
                    "reserved_requests": 1,
                    "reserved_tokens": tokens,
                }
            )
        return allocations

    async def _conditional_quota_upsert(
        self,
        session: AsyncSession,
        command: QuotaReservationCommand,
        *,
        period_type: str,
        period_start: date,
        period_end: date,
        request_delta: int,
        token_delta: int,
        request_limit: int | None,
        token_limit: int | None,
    ) -> QuotaPeriodUsage | None:
        statement = insert(QuotaPeriodUsage).values(
            organization_id=command.tenant_id,
            api_key_id=command.api_key_id,
            period_type=period_type,
            period_start=period_start,
            period_end=period_end,
            reserved_requests=request_delta,
            reserved_tokens=token_delta,
            limit_requests=request_limit,
            limit_tokens=token_limit,
        )
        excluded = statement.excluded
        statement = statement.on_conflict_do_update(
            index_elements=[
                QuotaPeriodUsage.organization_id,
                QuotaPeriodUsage.api_key_id,
                QuotaPeriodUsage.period_type,
                QuotaPeriodUsage.period_start,
            ],
            set_={
                "reserved_requests": (
                    QuotaPeriodUsage.reserved_requests + excluded.reserved_requests
                ),
                "reserved_tokens": (
                    QuotaPeriodUsage.reserved_tokens + excluded.reserved_tokens
                ),
                "limit_requests": excluded.limit_requests,
                "limit_tokens": excluded.limit_tokens,
                "updated_at": datetime.now(timezone.utc),
            },
            where=and_(
                or_(
                    excluded.limit_requests.is_(None),
                    QuotaPeriodUsage.reserved_requests
                    + QuotaPeriodUsage.settled_requests
                    + excluded.reserved_requests
                    <= excluded.limit_requests,
                ),
                or_(
                    excluded.limit_tokens.is_(None),
                    QuotaPeriodUsage.reserved_tokens
                    + QuotaPeriodUsage.settled_tokens
                    + excluded.reserved_tokens
                    <= excluded.limit_tokens,
                ),
            ),
        ).returning(QuotaPeriodUsage)
        return (await session.execute(statement)).scalar_one_or_none()

    async def _reserve_spend_period(
        self,
        session: AsyncSession,
        command: SpendReservationCommand,
    ) -> dict[str, object]:
        lifecycle = await RequestLifecycleRepository.get(
            session,
            organization_id=command.tenant_id,
            request_id=command.request_id,
        )
        if lifecycle is None or lifecycle.status not in {
            "accepted",
            "routing_pending",
            "provider_pending",
        }:
            raise ValueError("provider spend requires an accepted request")
        if (
            command.policy.monthly_limit_usd is not None
            and command.estimated_cost_usd > command.policy.monthly_limit_usd
        ):
            raise SpendLimitExceeded("monthly provider spend limit exceeded")

        request_date = lifecycle.started_at.astimezone(timezone.utc).date()
        period_start, period_end = self._month_bounds(request_date)
        statement = insert(SpendPeriodUsage).values(
            organization_id=command.tenant_id,
            provider=str(command.provider),
            period_start=period_start,
            period_end=period_end,
            reserved_usd=command.estimated_cost_usd,
            limit_usd=command.policy.monthly_limit_usd,
        )
        excluded = statement.excluded
        statement = statement.on_conflict_do_update(
            index_elements=[
                SpendPeriodUsage.organization_id,
                SpendPeriodUsage.provider,
                SpendPeriodUsage.period_start,
            ],
            set_={
                "reserved_usd": SpendPeriodUsage.reserved_usd + excluded.reserved_usd,
                "limit_usd": excluded.limit_usd,
                "updated_at": datetime.now(timezone.utc),
            },
            where=or_(
                excluded.limit_usd.is_(None),
                SpendPeriodUsage.reserved_usd
                + SpendPeriodUsage.settled_usd
                + excluded.reserved_usd
                <= excluded.limit_usd,
            ),
        ).returning(SpendPeriodUsage)
        row = (await session.execute(statement)).scalar_one_or_none()
        if row is None:
            raise SpendLimitExceeded("monthly provider spend limit exceeded")
        return {
            "counter_type": "spend",
            "period_row_id": str(row.id),
            "period_type": "monthly",
            "period_start": period_start.isoformat(),
            "period_end": period_end.isoformat(),
            "reserved_usd": str(command.estimated_cost_usd),
        }

    async def _insert_reservation(
        self,
        session: AsyncSession,
        *,
        tenant_id: TenantId,
        values: Mapping[str, Any],
    ) -> tuple[UsageLedger, bool]:
        payload = dict(values)
        payload["organization_id"] = tenant_id
        statement = (
            insert(UsageLedger)
            .values(**payload)
            .on_conflict_do_nothing(
                index_elements=[
                    UsageLedger.organization_id,
                    UsageLedger.idempotency_key,
                ]
            )
            .returning(UsageLedger)
        )
        created = (await session.execute(statement)).scalar_one_or_none()
        if created is not None:
            return created, False
        existing = await UsageLedgerRepository.fetch(
            session,
            organization_id=tenant_id,
            idempotency_key=str(values["idempotency_key"]),
        )
        if existing is None:
            raise AccountingConflictError("reservation idempotency conflict")
        return existing, True

    async def _store_allocations(
        self,
        session: AsyncSession,
        event_id: UUID,
        tenant_id: TenantId,
        allocations: list[dict[str, object]],
    ) -> None:
        statement = (
            update(UsageLedger)
            .where(
                UsageLedger.organization_id == tenant_id,
                UsageLedger.id == event_id,
            )
            .values(period_allocations=allocations)
            .returning(UsageLedger.id)
        )
        if (await session.execute(statement)).scalar_one_or_none() is None:
            raise AccountingConflictError("reservation allocation event disappeared")

    async def _write_preflight(
        self,
        session: AsyncSession,
        command: SpendReservationCommand,
        *,
        lifecycle_status: str = "provider_pending",
        usage_summary: Mapping[str, object] | None = None,
    ) -> None:
        if command.audit_policy_mode == "off":
            return
        lifecycle = await RequestLifecycleRepository.get(
            session,
            organization_id=command.tenant_id,
            request_id=command.request_id,
        )
        if lifecycle is None:
            raise AccountingConflictError("audit preflight requires a lifecycle")
        await AuditIntentRepository.create(
            session,
            organization_id=command.tenant_id,
            values={
                "request_id": str(command.request_id),
                "actor_type": lifecycle.actor_type,
                "api_key_id": lifecycle.api_key_id,
                "user_id": lifecycle.user_id,
                "event_type": "preflight",
                "audit_policy_mode": command.audit_policy_mode,
                "input_hash": command.input_hash,
                "output_hash": None,
                "pii_entities": dict(command.pii_entities or {}),
                "provider": str(command.provider),
                "model": command.provider_model,
                "usage_summary": dict(usage_summary or {}),
                "lifecycle_status": lifecycle_status,
            },
        )

    async def _write_audit_completion(
        self,
        session: AsyncSession,
        lifecycle: RequestLifecycle,
        *,
        quota_event: UsageLedger,
        spend_event: UsageLedger | None,
        lifecycle_status: str,
        output_hash: str | None,
        completed_at: datetime,
    ) -> dict[str, Any] | None:
        preflight = await AuditIntentRepository.fetch(
            session,
            organization_id=TenantId(lifecycle.organization_id),
            request_id=RequestId(lifecycle.request_id),
            event_type="preflight",
        )
        if preflight is None:
            return None

        intent = audit_completion_intent(
            lifecycle,
            preflight,
            quota_event,
            spend_event,
            lifecycle_status=lifecycle_status,
            output_hash=output_hash,
            completed_at=completed_at,
        )
        outbox = await OutboxWriter().append(
            session,
            organization_id=TenantId(lifecycle.organization_id),
            values=intent.persistence_values(),
        )
        await AuditIntentRepository.create(
            session,
            organization_id=TenantId(lifecycle.organization_id),
            values={
                "request_id": lifecycle.request_id,
                "actor_type": lifecycle.actor_type,
                "api_key_id": lifecycle.api_key_id,
                "user_id": lifecycle.user_id,
                "event_type": "completion",
                "audit_policy_mode": preflight.audit_policy_mode,
                "input_hash": preflight.input_hash,
                "output_hash": output_hash,
                "pii_entities": dict(preflight.pii_entities or {}),
                "provider": lifecycle.provider,
                "model": lifecycle.provider_model or lifecycle.requested_model,
                "usage_summary": {
                    "prompt_tokens": quota_event.prompt_tokens,
                    "completion_tokens": quota_event.completion_tokens,
                    "total_tokens": quota_event.total_tokens,
                },
                "lifecycle_status": lifecycle_status,
                "outbox_event_id": outbox.id,
            },
        )
        return dict(outbox.payload)

    async def _enqueue_analytics_projection(
        self,
        session: AsyncSession,
        lifecycle: RequestLifecycle,
        *,
        quota_event: UsageLedger,
        spend_event: UsageLedger | None,
        lifecycle_status: str,
        completed_at: datetime,
    ) -> None:
        """Queue one idempotent analytics projection from canonical facts."""

        intent = analytics_terminal_intent(
            lifecycle,
            quota_event,
            spend_event,
            lifecycle_status=lifecycle_status,
            completed_at=completed_at,
        )
        await OutboxWriter().append(
            session,
            organization_id=TenantId(lifecycle.organization_id),
            values=intent.persistence_values(),
        )

    async def _append_provider_error(
        self,
        session: AsyncSession,
        lifecycle: RequestLifecycle,
        command: FinalizationCommand,
    ) -> None:
        if lifecycle.provider is None or lifecycle.provider_model is None:
            raise AccountingConflictError(
                "provider error requires a persisted provider route"
            )
        await UsageLedgerRepository.append(
            session,
            organization_id=command.tenant_id,
            values={
                "request_id": str(command.request_id),
                "api_key_id": lifecycle.api_key_id,
                "requested_model": lifecycle.requested_model,
                "provider": lifecycle.provider,
                "provider_model": lifecycle.provider_model,
                "event_type": "provider_error",
                "idempotency_key": f"request:{command.request_id}:provider:error",
                "reservation_event_id": None,
                "request_count": 0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
                "estimated": command.estimated,
                "cost_usd": Decimal("0"),
                "period_allocations": [],
                "event_metadata": {
                    "lifecycle_status": command.lifecycle_status,
                    "error_code": command.terminal_error_code,
                },
            },
        )

    async def _lock_lifecycle(
        self,
        session: AsyncSession,
        tenant_id: TenantId,
        request_id: RequestId,
    ) -> RequestLifecycle:
        statement = (
            select(RequestLifecycle)
            .where(
                RequestLifecycle.organization_id == tenant_id,
                RequestLifecycle.request_id == request_id,
            )
            .with_for_update()
        )
        lifecycle = (await session.execute(statement)).scalar_one_or_none()
        if lifecycle is None:
            raise AccountingConflictError("request lifecycle does not exist")
        return lifecycle

    async def _lock_reservation(
        self,
        session: AsyncSession,
        tenant_id: TenantId,
        request_id: RequestId,
        event_type: Literal["quota_reservation", "spend_reservation"],
    ) -> UsageLedger:
        reservation = await self._find_reservation(
            session,
            tenant_id,
            request_id,
            event_type,
            lock=True,
        )
        if reservation is None:
            raise AccountingConflictError(f"{event_type} does not exist")
        return reservation

    async def _find_reservation(
        self,
        session: AsyncSession,
        tenant_id: TenantId,
        request_id: RequestId,
        event_type: Literal["quota_reservation", "spend_reservation"],
        *,
        lock: bool,
    ) -> UsageLedger | None:
        statement = select(UsageLedger).where(
            UsageLedger.organization_id == tenant_id,
            UsageLedger.request_id == request_id,
            UsageLedger.event_type == event_type,
        )
        if lock:
            statement = statement.with_for_update()
        return (await session.execute(statement)).scalar_one_or_none()

    async def _transition_reservation(
        self,
        session: AsyncSession,
        tenant_id: TenantId,
        reservation: UsageLedger,
        action: TerminalAction,
        *,
        prompt_tokens: int,
        completion_tokens: int,
        cost_usd: Decimal,
        estimated: bool,
        provider_model: str | None = None,
        pricing_metadata: dict[str, str | int] | None = None,
    ) -> tuple[UsageLedger, bool]:
        if action is TerminalAction.NONE:
            raise ValueError("reservation transition requires settle or refund")
        kind = "quota" if reservation.event_type == "quota_reservation" else "spend"
        settles_quota = kind == "quota" and action is TerminalAction.SETTLE
        settles_spend = kind == "spend" and action is TerminalAction.SETTLE
        terminal_type = f"{kind}_{action.value}"
        provider_scope = f":{reservation.provider}" if kind == "spend" else ""
        idempotency_key = (
            f"request:{reservation.request_id}:{kind}{provider_scope}:{action.value}"
        )
        reservation_pricing = _event_pricing(reservation)
        if (
            pricing_metadata is not None
            and reservation_pricing is not None
            and pricing_metadata.get("catalog_version")
            != reservation_pricing.get("catalog_version")
        ):
            raise AccountingConflictError("reservation pricing version conflict")
        terminal_metadata: dict[str, object] = {"terminal_action": action.value}
        effective_pricing = (
            dict(pricing_metadata)
            if pricing_metadata is not None
            else reservation_pricing
        )
        if effective_pricing is not None:
            terminal_metadata["pricing"] = effective_pricing
        terminal_values: dict[str, Any] = {
            "request_id": reservation.request_id,
            "api_key_id": reservation.api_key_id,
            "requested_model": reservation.requested_model,
            "provider": reservation.provider,
            "provider_model": (
                provider_model
                if kind == "spend" and provider_model is not None
                else reservation.provider_model
            ),
            "event_type": terminal_type,
            "idempotency_key": idempotency_key,
            "reservation_event_id": reservation.id,
            "request_count": reservation.request_count if settles_quota else 0,
            "prompt_tokens": prompt_tokens if settles_quota else 0,
            "completion_tokens": completion_tokens if settles_quota else 0,
            "total_tokens": (prompt_tokens + completion_tokens if settles_quota else 0),
            "estimated": estimated,
            "cost_usd": cost_usd if settles_spend else Decimal("0"),
            "event_metadata": terminal_metadata,
        }
        existing = (
            await session.execute(
                select(UsageLedger)
                .where(
                    UsageLedger.organization_id == tenant_id,
                    UsageLedger.reservation_event_id == reservation.id,
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
        if existing is not None:
            if _usage_ledger_replay_conflicts(existing, terminal_values):
                raise AccountingConflictError("reservation terminal identity conflict")
            return existing, True

        terminal_allocations = await self._apply_period_transitions(
            session,
            tenant_id,
            reservation,
            action,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            cost_usd=cost_usd,
        )
        terminal_values["period_allocations"] = terminal_allocations
        event = await UsageLedgerRepository.append(
            session,
            organization_id=tenant_id,
            values=terminal_values,
        )
        if event.reservation_event_id != reservation.id:
            raise AccountingConflictError("competing reservation terminal conflict")
        return event, False

    async def _apply_period_transitions(
        self,
        session: AsyncSession,
        tenant_id: TenantId,
        reservation: UsageLedger,
        action: TerminalAction,
        *,
        prompt_tokens: int,
        completion_tokens: int,
        cost_usd: Decimal,
    ) -> list[dict[str, object]]:
        allocations = sorted(
            reservation.period_allocations,
            key=lambda item: (
                str(item.get("counter_type")),
                str(item.get("period_type")),
                str(item.get("period_start")),
                str(item.get("period_row_id")),
            ),
        )
        if not allocations:
            raise AccountingConflictError("reservation has no period allocations")
        terminal: list[dict[str, object]] = []
        for allocation in allocations:
            counter_type = allocation.get("counter_type")
            if counter_type == "quota":
                terminal.append(
                    await self._apply_quota_transition(
                        session,
                        tenant_id,
                        reservation,
                        allocation,
                        action,
                        prompt_tokens=prompt_tokens,
                        completion_tokens=completion_tokens,
                    )
                )
            elif counter_type == "spend":
                terminal.append(
                    await self._apply_spend_transition(
                        session,
                        tenant_id,
                        reservation,
                        allocation,
                        action,
                        cost_usd=cost_usd,
                    )
                )
            else:
                raise AccountingConflictError("unknown reservation counter type")
        return terminal

    async def _apply_quota_transition(
        self,
        session: AsyncSession,
        tenant_id: TenantId,
        reservation: UsageLedger,
        allocation: Mapping[str, object],
        action: TerminalAction,
        *,
        prompt_tokens: int,
        completion_tokens: int,
    ) -> dict[str, object]:
        row_id = UUID(str(allocation["period_row_id"]))
        reserved_requests = cast(int, allocation["reserved_requests"])
        reserved_tokens = cast(int, allocation["reserved_tokens"])
        settled_requests = (
            reservation.request_count if action is TerminalAction.SETTLE else 0
        )
        settled_tokens = (
            prompt_tokens + completion_tokens
            if action is TerminalAction.SETTLE
            and allocation["period_type"] == "monthly"
            else 0
        )
        statement = (
            update(QuotaPeriodUsage)
            .where(
                QuotaPeriodUsage.organization_id == tenant_id,
                QuotaPeriodUsage.id == row_id,
                QuotaPeriodUsage.reserved_requests >= reserved_requests,
                QuotaPeriodUsage.reserved_tokens >= reserved_tokens,
            )
            .values(
                reserved_requests=(
                    QuotaPeriodUsage.reserved_requests - reserved_requests
                ),
                reserved_tokens=QuotaPeriodUsage.reserved_tokens - reserved_tokens,
                settled_requests=(QuotaPeriodUsage.settled_requests + settled_requests),
                settled_tokens=QuotaPeriodUsage.settled_tokens + settled_tokens,
                updated_at=datetime.now(timezone.utc),
            )
            .returning(QuotaPeriodUsage.id)
        )
        if (await session.execute(statement)).scalar_one_or_none() is None:
            raise AccountingConflictError("quota reservation counter conflict")
        return {
            **dict(allocation),
            "released_requests": reserved_requests,
            "released_tokens": reserved_tokens,
            "settled_requests": settled_requests,
            "settled_tokens": settled_tokens,
        }

    async def _apply_spend_transition(
        self,
        session: AsyncSession,
        tenant_id: TenantId,
        reservation: UsageLedger,
        allocation: Mapping[str, object],
        action: TerminalAction,
        *,
        cost_usd: Decimal,
    ) -> dict[str, object]:
        row_id = UUID(str(allocation["period_row_id"]))
        reserved_usd = Decimal(str(allocation["reserved_usd"]))
        settled_usd = cost_usd if action is TerminalAction.SETTLE else Decimal("0")
        statement = (
            update(SpendPeriodUsage)
            .where(
                SpendPeriodUsage.organization_id == tenant_id,
                SpendPeriodUsage.id == row_id,
                SpendPeriodUsage.provider == reservation.provider,
                SpendPeriodUsage.reserved_usd >= reserved_usd,
            )
            .values(
                reserved_usd=SpendPeriodUsage.reserved_usd - reserved_usd,
                settled_usd=SpendPeriodUsage.settled_usd + settled_usd,
                updated_at=datetime.now(timezone.utc),
            )
            .returning(SpendPeriodUsage.id)
        )
        if (await session.execute(statement)).scalar_one_or_none() is None:
            raise AccountingConflictError("spend reservation counter conflict")
        return {
            **dict(allocation),
            "released_usd": str(reserved_usd),
            "settled_usd": str(settled_usd),
        }

    async def _enqueue_reconciliation_event(
        self,
        session: AsyncSession,
        tenant_id: TenantId,
        request_id: RequestId,
        *,
        lifecycle_status: str,
        urgent: bool,
        occurred_at: datetime,
    ) -> None:
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
                    "lifecycle_status": lifecycle_status,
                    "urgent": urgent,
                },
                "status": "pending",
                "next_attempt_at": occurred_at,
            },
        )

    @staticmethod
    def _validate_quota_reservation(
        event: UsageLedger,
        command: QuotaReservationCommand,
    ) -> None:
        facts = (
            event.request_id,
            event.api_key_id,
            event.requested_model,
            event.provider,
            event.provider_model,
            event.event_type,
            event.request_count,
            event.prompt_tokens,
            event.completion_tokens,
        )
        expected = (
            str(command.request_id),
            command.api_key_id,
            command.requested_model,
            None,
            None,
            "quota_reservation",
            1,
            command.estimated_input_tokens,
            command.maximum_output_tokens,
        )
        if facts != expected:
            raise AccountingConflictError("reservation identity conflict")

    @staticmethod
    def _validate_spend_reservation(
        event: UsageLedger,
        command: SpendReservationCommand,
    ) -> None:
        facts = (
            event.request_id,
            event.api_key_id,
            event.requested_model,
            event.provider,
            event.provider_model,
            event.event_type,
            event.cost_usd,
            _event_pricing(event),
        )
        expected = (
            str(command.request_id),
            command.api_key_id,
            command.requested_model,
            str(command.provider),
            command.provider_model,
            "spend_reservation",
            command.estimated_cost_usd,
            dict(command.pricing_metadata),
        )
        if facts != expected:
            raise AccountingConflictError("reservation identity conflict")

    @staticmethod
    def _reservation_result(
        event: UsageLedger,
        policy_version: str,
        *,
        replayed: bool,
    ) -> ReservationResult:
        return ReservationResult(
            event_id=event.id,
            policy_version=str(
                event.event_metadata.get("policy_version", policy_version)
            ),
            period_allocations=tuple(dict(item) for item in event.period_allocations),
            replayed=replayed,
        )

    @staticmethod
    def _month_bounds(value: date) -> tuple[date, date]:
        start = value.replace(day=1)
        days = calendar.monthrange(value.year, value.month)[1]
        return start, start + timedelta(days=days)
