"""Standalone audit-evidence maintenance process."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
import logging
import signal

from sqlalchemy import distinct, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from shim_enterprise.ai_act.anchor import write_anchor
from shim_enterprise.ai_act.models import AIActAuditLog
from shim_enterprise.ai_act.oversight import expire_pending, run_oversight_evaluation
from shim_enterprise.ai_act.retention import archive_expired
from shim_enterprise.core.config import settings
from shim_enterprise.core.database import AsyncSessionLocal, engine
from shim.observability.logging import configure_error_reporting, configure_logging
from shim.observability.tracing import configure_tracing, shutdown_tracing


logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class MaintenanceSummary:
    anchored_tenants: int = 0
    oversight_created: int = 0
    oversight_expired: int = 0
    archive_eligible: int = 0


class AuditMaintenanceWorker:
    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession] = AsyncSessionLocal,
        interval_seconds: int = settings.AI_ACT_AUDIT_WORKER_INTERVAL_SECONDS,
    ) -> None:
        if interval_seconds < 1:
            raise ValueError("audit maintenance interval must be positive")
        self.session_factory = session_factory
        self.interval_seconds = interval_seconds

    async def run_once(self, *, anchor_date: date | None = None) -> MaintenanceSummary:
        async with self.session_factory.begin() as session:
            anchored = (
                await self._anchor_tenants(session, anchor_date)
                if settings.AI_ACT_AUDIT_ANCHOR_ENABLED
                else 0
            )
            created = {"created": 0}
            expired = {"expired": 0}
            if settings.OVERSIGHT_ENABLED:
                created = await run_oversight_evaluation(session)
                expired = await expire_pending(session)
            archive = await archive_expired(session)
            return MaintenanceSummary(
                anchored_tenants=anchored,
                oversight_created=int(created["created"]),
                oversight_expired=int(expired["expired"]),
                archive_eligible=int(archive["eligible"]),
            )

    async def _anchor_tenants(
        self,
        session: AsyncSession,
        anchor_date: date | None,
    ) -> int:
        target = anchor_date or datetime.now(timezone.utc).date() - timedelta(days=1)
        start = datetime.combine(target, datetime.min.time(), tzinfo=timezone.utc)
        tenant_ids = (
            await session.execute(
                select(distinct(AIActAuditLog.organization_id)).where(
                    AIActAuditLog.created_at >= start,
                    AIActAuditLog.created_at < start + timedelta(days=1),
                )
            )
        ).scalars()
        anchored = 0
        for tenant_id in tenant_ids:
            try:
                async with session.begin_nested():
                    anchor = await write_anchor(session, tenant_id, target)
            except Exception as exc:
                logger.error("Tenant anchor failed type=%s", type(exc).__name__)
            else:
                anchored += int(anchor is not None)
        return anchored

    async def run(self, stop_event: asyncio.Event) -> None:
        while not stop_event.is_set():
            try:
                summary = await self.run_once()
                logger.info("Audit maintenance completed summary=%s", summary)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error(
                    "Audit maintenance pass failed type=%s", type(exc).__name__
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
        await AuditMaintenanceWorker().run(stop_event)
    finally:
        for shutdown_signal in shutdown_signals:
            loop.remove_signal_handler(shutdown_signal)
        try:
            await engine.dispose()
        finally:
            shutdown_tracing()


if __name__ == "__main__":
    asyncio.run(main())
