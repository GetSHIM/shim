"""Lease-based delivery worker for committed outbox events."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import logging
import os
import signal
import socket
from typing import Any, Literal
from uuid import UUID, uuid4

from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.core.config import settings
from shim_enterprise.core.database import AsyncSessionLocal, engine
from shim_enterprise.observability.enterprise_metrics import (
    AUDIT_WORKER_LAG_SECONDS,
    OUTBOX_DEAD_LETTER_TOTAL,
    OUTBOX_LAG_SECONDS,
)
from shim.observability.logging import configure_error_reporting, configure_logging
from shim.observability.metrics import bounded_label
from shim.observability.tracing import configure_tracing, shutdown_tracing
from shim_enterprise.outbox.dead_letter import (
    failure_status,
    next_retry_at,
    sanitize_failure,
)
from shim_enterprise.outbox.models import OutboxEvent
from shim_enterprise.outbox.publisher import OutboxMessage, OutboxPublisher


logger = logging.getLogger(__name__)
DeliveryOutcome = Literal["processed", "failed", "dead_letter", "lease_lost"]


@dataclass(frozen=True, slots=True)
class WorkerLimits:
    batch_size: int
    lease_seconds: int
    max_attempts: int

    def __post_init__(self) -> None:
        if self.batch_size < 1 or self.max_attempts < 1:
            raise ValueError("outbox worker bounds must be positive")
        if self.lease_seconds < 2:
            raise ValueError("outbox lease must exceed one second")


@dataclass(frozen=True, slots=True)
class WorkerPass:
    claimed: int
    processed: int
    failed: int
    dead_lettered: int
    lease_lost: int


class OutboxLeaseRepository:
    """Own short claim and acknowledgement transactions."""

    async def claim(
        self,
        session: AsyncSession,
        *,
        worker_id: str,
        now: datetime,
        lease_seconds: int,
        batch_size: int,
    ) -> tuple[OutboxMessage, ...]:
        claimable = and_(
            OutboxEvent.status.in_(("pending", "failed")),
            OutboxEvent.next_attempt_at <= now,
        )
        abandoned = and_(
            OutboxEvent.status == "processing",
            OutboxEvent.lease_expires_at <= now,
        )
        statement = (
            select(OutboxEvent)
            .where(or_(claimable, abandoned))
            .order_by(
                OutboxEvent.next_attempt_at,
                OutboxEvent.created_at,
                OutboxEvent.id,
            )
            .limit(batch_size)
            .with_for_update(skip_locked=True, of=OutboxEvent)
        )
        events = tuple((await session.execute(statement)).scalars().all())
        expires_at = now + timedelta(seconds=lease_seconds)
        for event in events:
            event.status = "processing"
            event.locked_by = worker_id
            event.lease_expires_at = expires_at
            event.attempt_count += 1
            event.updated_at = now
        await session.flush()
        return tuple(OutboxMessage.from_event(event) for event in events)

    async def acknowledge(
        self,
        session: AsyncSession,
        *,
        event_id: UUID,
        attempt_count: int,
        worker_id: str,
        now: datetime,
    ) -> bool:
        statement = (
            update(OutboxEvent)
            .where(
                OutboxEvent.id == event_id,
                OutboxEvent.status == "processing",
                OutboxEvent.attempt_count == attempt_count,
                OutboxEvent.locked_by == worker_id,
                OutboxEvent.lease_expires_at > now,
            )
            .values(
                status="processed",
                processed_at=now,
                locked_by=None,
                lease_expires_at=None,
                last_error=None,
                updated_at=now,
            )
            .returning(OutboxEvent.id)
        )
        return (await session.execute(statement)).scalar_one_or_none() is not None

    async def reject(
        self,
        session: AsyncSession,
        *,
        message: OutboxMessage,
        worker_id: str,
        now: datetime,
        max_attempts: int,
        error: BaseException,
    ) -> DeliveryOutcome | None:
        status = failure_status(message.attempt_count, max_attempts)
        statement = (
            update(OutboxEvent)
            .where(
                OutboxEvent.id == message.id,
                OutboxEvent.status == "processing",
                OutboxEvent.locked_by == worker_id,
                OutboxEvent.attempt_count == message.attempt_count,
                OutboxEvent.lease_expires_at > now,
            )
            .values(
                status=status,
                next_attempt_at=(
                    now
                    if status == "dead_letter"
                    else next_retry_at(now, message.attempt_count)
                ),
                locked_by=None,
                lease_expires_at=None,
                last_error=sanitize_failure(error),
                updated_at=now,
            )
            .returning(OutboxEvent.status)
        )
        updated = (await session.execute(statement)).scalar_one_or_none()
        return status if updated is not None else None

    async def lag(
        self,
        session: AsyncSession,
        *,
        now: datetime,
    ) -> dict[str, float]:
        statement = (
            select(OutboxEvent.event_type, func.min(OutboxEvent.created_at))
            .where(OutboxEvent.status.in_(("pending", "failed", "processing")))
            .group_by(OutboxEvent.event_type)
        )
        return {
            str(event_type): max(0.0, (now - created_at).total_seconds())
            for event_type, created_at in (await session.execute(statement)).all()
        }


class OutboxWorker:
    """Commit claims before delivery and acknowledge each message separately."""

    def __init__(
        self,
        publisher: OutboxPublisher,
        *,
        repository: OutboxLeaseRepository | None = None,
        session_factory: Callable[[], Any] = AsyncSessionLocal,
        limits: WorkerLimits | None = None,
        worker_id: str | None = None,
        interval_seconds: int | None = None,
    ) -> None:
        self.publisher = publisher
        self.repository = repository or OutboxLeaseRepository()
        self.session_factory = session_factory
        self.limits = limits or WorkerLimits(
            batch_size=settings.GATEWAY_OUTBOX_BATCH_SIZE,
            lease_seconds=settings.GATEWAY_OUTBOX_LEASE_SECONDS,
            max_attempts=settings.GATEWAY_OUTBOX_MAX_ATTEMPTS,
        )
        self.worker_id = worker_id or _worker_id()
        self.interval_seconds = (
            settings.GATEWAY_OUTBOX_INTERVAL_SECONDS
            if interval_seconds is None
            else interval_seconds
        )
        if self.interval_seconds < 1:
            raise ValueError("outbox interval must be positive")
        self._lag_labels: set[str] = set()

    async def run_once(self, *, now: datetime | None = None) -> WorkerPass:
        claim_time = now or datetime.now(timezone.utc)
        async with self.session_factory() as session:
            try:
                messages = await self.repository.claim(
                    session,
                    worker_id=self.worker_id,
                    now=claim_time,
                    lease_seconds=self.limits.lease_seconds,
                    batch_size=self.limits.batch_size,
                )
                await session.commit()
            except BaseException:
                await session.rollback()
                raise
        outcomes = await asyncio.gather(
            *(self._deliver(message, fixed_now=now) for message in messages)
        )
        await self._observe(now or datetime.now(timezone.utc))
        for message, outcome in zip(messages, outcomes, strict=True):
            if outcome == "dead_letter":
                OUTBOX_DEAD_LETTER_TOTAL.labels(
                    event_type=bounded_label("event_type", message.event_type)
                ).inc()
        return WorkerPass(
            claimed=len(messages),
            processed=outcomes.count("processed"),
            failed=outcomes.count("failed"),
            dead_lettered=outcomes.count("dead_letter"),
            lease_lost=outcomes.count("lease_lost"),
        )

    async def run(self, stop_event: asyncio.Event) -> None:
        logger.info("Outbox worker started worker_id=%s", self.worker_id)
        while not stop_event.is_set():
            try:
                await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error("Outbox pass failed type=%s", type(exc).__name__)
            try:
                await asyncio.wait_for(
                    stop_event.wait(),
                    timeout=self.interval_seconds,
                )
            except TimeoutError:
                continue

    async def _deliver(
        self,
        message: OutboxMessage,
        *,
        fixed_now: datetime | None,
    ) -> DeliveryOutcome:
        try:
            async with asyncio.timeout(self.limits.lease_seconds - 1):
                await self.publisher.publish(message)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            now = fixed_now or datetime.now(timezone.utc)
            return await self._reject(message, exc, now)
        now = fixed_now or datetime.now(timezone.utc)
        async with self.session_factory() as session:
            try:
                acknowledged = await self.repository.acknowledge(
                    session,
                    event_id=message.id,
                    attempt_count=message.attempt_count,
                    worker_id=self.worker_id,
                    now=now,
                )
                await session.commit()
            except BaseException:
                await session.rollback()
                raise
        return "processed" if acknowledged else "lease_lost"

    async def _reject(
        self,
        message: OutboxMessage,
        error: BaseException,
        now: datetime,
    ) -> DeliveryOutcome:
        async with self.session_factory() as session:
            try:
                outcome = await self.repository.reject(
                    session,
                    message=message,
                    worker_id=self.worker_id,
                    now=now,
                    max_attempts=self.limits.max_attempts,
                    error=error,
                )
                await session.commit()
            except BaseException:
                await session.rollback()
                raise
        return outcome or "lease_lost"

    async def _observe(self, now: datetime) -> None:
        async with self.session_factory() as session:
            lag = await self.repository.lag(session, now=now)
        labeled_lag: dict[str, float] = {}
        for event_type, seconds in lag.items():
            label = bounded_label("event_type", event_type)
            labeled_lag[label] = max(labeled_lag.get(label, 0), seconds)
        for event_type in self._lag_labels - labeled_lag.keys():
            OUTBOX_LAG_SECONDS.labels(event_type=event_type).set(0)
        for event_type, seconds in labeled_lag.items():
            OUTBOX_LAG_SECONDS.labels(event_type=event_type).set(seconds)
        self._lag_labels = set(labeled_lag)
        AUDIT_WORKER_LAG_SECONDS.set(
            max(
                (
                    seconds
                    for event_type, seconds in lag.items()
                    if event_type.startswith("audit.")
                ),
                default=0,
            )
        )


def _worker_id() -> str:
    return f"{socket.gethostname()}:{os.getpid()}:{uuid4().hex[:12]}"


async def main() -> None:
    from shim_enterprise.outbox.handlers import build_publisher

    configure_logging(settings.LOG_LEVEL)
    configure_error_reporting(
        sentry_dsn=settings.SENTRY_DSN,
        environment=settings.ENVIRONMENT,
    )
    configure_tracing(
        endpoint=settings.OTEL_EXPORTER_OTLP_ENDPOINT,
        service_name=settings.OTEL_SERVICE_NAME,
    )
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()
    shutdown_signals = (signal.SIGINT, signal.SIGTERM)
    for shutdown_signal in shutdown_signals:
        loop.add_signal_handler(shutdown_signal, stop_event.set)
    try:
        await OutboxWorker(build_publisher()).run(stop_event)
    finally:
        for shutdown_signal in shutdown_signals:
            loop.remove_signal_handler(shutdown_signal)
        try:
            await engine.dispose()
        finally:
            shutdown_tracing()


if __name__ == "__main__":
    asyncio.run(main())
