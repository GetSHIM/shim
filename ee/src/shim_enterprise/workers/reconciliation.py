"""Bounded recovery for stale billing and scan lifecycle reservations."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import datetime, timezone
import logging
import signal
from typing import Any

from shim_enterprise.billing.ledger import DurableAccountingRepository
from shim_enterprise.core.config import settings
from shim_enterprise.core.database import AsyncSessionLocal, engine
from shim_enterprise.gateway.pipeline.reconciliation import ScanReconciler
from shim.observability.logging import configure_error_reporting, configure_logging
from shim.observability.tracing import configure_tracing, shutdown_tracing, start_span


logger = logging.getLogger(__name__)


class ReconciliationWorker:
    """Recover stale claims in short caller-independent transactions."""

    def __init__(
        self,
        *,
        accounting: DurableAccountingRepository | None = None,
        scans: ScanReconciler | None = None,
        session_factory: Callable[[], Any] = AsyncSessionLocal,
        batch_size: int | None = None,
        interval_seconds: int | None = None,
    ) -> None:
        self.accounting = accounting or DurableAccountingRepository()
        self.scans = scans or ScanReconciler()
        self.session_factory = session_factory
        self.batch_size = (
            settings.GATEWAY_RECONCILIATION_BATCH_SIZE
            if batch_size is None
            else batch_size
        )
        self.interval_seconds = (
            settings.GATEWAY_RECONCILIATION_INTERVAL_SECONDS
            if interval_seconds is None
            else interval_seconds
        )
        if self.batch_size < 1 or self.interval_seconds < 1:
            raise ValueError("reconciliation bounds must be positive")

    async def run_once(self, *, now: datetime | None = None) -> int:
        recovery_time = now or datetime.now(timezone.utc)
        with start_span("gateway.reconciliation"):
            async with self.session_factory() as session:
                try:
                    billing = await self.accounting.recover_stale(
                        session,
                        now=recovery_time,
                        batch_size=self.batch_size,
                    )
                    scans = await self.scans.recover_stale(
                        session,
                        now=recovery_time,
                        batch_size=self.batch_size,
                    )
                    await session.commit()
                except BaseException:
                    await session.rollback()
                    raise
        return len(billing) + len(scans)

    async def run(self, stop_event: asyncio.Event) -> None:
        logger.info(
            "Gateway reconciliation worker started interval_seconds=%s",
            self.interval_seconds,
        )
        while not stop_event.is_set():
            try:
                recovered = await self.run_once()
                if recovered:
                    logger.warning(
                        "Recovered stale gateway requests count=%s", recovered
                    )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error(
                    "Gateway reconciliation pass failed type=%s",
                    type(exc).__name__,
                )
            try:
                await asyncio.wait_for(
                    stop_event.wait(),
                    timeout=self.interval_seconds,
                )
            except TimeoutError:
                continue


async def main() -> None:
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
        await ReconciliationWorker().run(stop_event)
    finally:
        for shutdown_signal in shutdown_signals:
            loop.remove_signal_handler(shutdown_signal)
        try:
            await engine.dispose()
        finally:
            shutdown_tracing()


if __name__ == "__main__":
    asyncio.run(main())
