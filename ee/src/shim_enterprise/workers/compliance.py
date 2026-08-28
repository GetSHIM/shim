"""Standalone active-connector ingestion process."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import logging
import signal
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from shim_enterprise.cache.redis_index import CacheService
from shim_enterprise.compliance.models import ComplianceConnector
from shim_enterprise.compliance.services.ingest import ComplianceIngestService
from shim_enterprise.core.config import settings
from shim_enterprise.core.database import AsyncSessionLocal, engine
from shim.observability.logging import configure_error_reporting, configure_logging
from shim.observability.tracing import configure_tracing, shutdown_tracing


logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class SweepSummary:
    connectors: int = 0
    activities: int = 0
    content_items: int = 0
    findings: int = 0
    errors: int = 0


class ComplianceSweepWorker:
    def __init__(
        self,
        *,
        service: ComplianceIngestService | None = None,
        session_factory: async_sessionmaker[AsyncSession] = AsyncSessionLocal,
        interval_seconds: int = settings.COMPLIANCE_DEFAULT_INTERVAL_SECONDS,
    ) -> None:
        if interval_seconds < 1:
            raise ValueError("compliance sweep interval must be positive")
        self.service = service or ComplianceIngestService(cache=CacheService())
        self.session_factory = session_factory
        self.interval_seconds = interval_seconds

    async def _active_connector_ids(self) -> tuple[UUID, ...]:
        async with self.session_factory() as session:
            result = await session.execute(
                select(ComplianceConnector.id).where(
                    ComplianceConnector.status == "active"
                )
            )
            return tuple(result.scalars())

    async def run_once(self) -> SweepSummary:
        connectors = activities = content = findings = errors = 0
        for connector_id in await self._active_connector_ids():
            try:
                outcome = await self.service.run_once(connector_id)
            except Exception as exc:
                errors += 1
                logger.error("Connector ingestion failed type=%s", type(exc).__name__)
                continue
            connectors += 1
            activities += int(outcome.get("activities_ingested", 0))
            content += int(outcome.get("content_scanned", 0))
            findings += int(outcome.get("findings_created", 0))
            errors += int(outcome.get("status") == "error")
        return SweepSummary(connectors, activities, content, findings, errors)

    async def run(self, stop_event: asyncio.Event) -> None:
        while not stop_event.is_set():
            try:
                summary = await self.run_once()
                logger.info("Compliance sweep completed summary=%s", summary)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error("Compliance sweep failed type=%s", type(exc).__name__)
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
        worker = ComplianceSweepWorker()
        try:
            await worker.service.cache.connect()
            await worker.run(stop_event)
        finally:
            await worker.service.cache.close()
    finally:
        for shutdown_signal in shutdown_signals:
            loop.remove_signal_handler(shutdown_signal)
        try:
            await engine.dispose()
        finally:
            shutdown_tracing()


if __name__ == "__main__":
    asyncio.run(main())
