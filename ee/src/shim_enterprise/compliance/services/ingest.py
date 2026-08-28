"""Transactional compliance ingestion with cursor and outbox atomicity."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import logging
from typing import Any
from uuid import UUID, uuid4

import httpx
from redis.exceptions import RedisError
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from shim_enterprise.cache.redis_index import CacheService
from shim_enterprise.compliance.adapters import ComplianceAdapter, get_adapter
from shim_enterprise.compliance.adapters.anthropic import AnthropicComplianceAdapter
from shim_enterprise.compliance.adapters.openai import (
    LogFileDescriptor,
    OpenAIComplianceAdapter,
)
from shim_enterprise.compliance.health import (
    AUTH_ERROR,
    HealthAlert,
    detect_retention_gap,
    evaluate_stream_health,
)
from shim_enterprise.compliance.models import (
    ComplianceActivity,
    ComplianceConnector,
    ComplianceFinding,
    ComplianceIngestCursor,
    ComplianceLogFile,
)
from shim_enterprise.compliance.normalized import NormalizedActivity, NormalizedContent
from shim_enterprise.compliance.ratelimit import ComplianceRateLimiter
from shim_enterprise.compliance.services.forwarder import ComplianceForwarderService
from shim_enterprise.compliance.services.scan import ComplianceScanService
from shim_enterprise.core.config import settings
from shim_enterprise.core.database import AsyncSessionLocal
from shim.gateway.contracts.ids import SecretRef, TenantId
from shim_enterprise.secrets.store import SecretStore, get_secret_store


logger = logging.getLogger(__name__)
LOCK_SECONDS = 1_800
ERROR_STATUS_THRESHOLD = 5
MAX_OPENAI_PAGES = 2_000
UNLOCK_LUA = (
    "if redis.call('GET', KEYS[1]) == ARGV[1] "
    "then return redis.call('DEL', KEYS[1]) else return 0 end"
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


@dataclass(slots=True)
class RunOutcome:
    connector_id: UUID
    status: str = "completed"
    detail: str | None = None
    activities_ingested: int = 0
    content_scanned: int = 0
    findings_created: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "connector_id": self.connector_id,
            "status": self.status,
            "activities_ingested": self.activities_ingested,
            "content_scanned": self.content_scanned,
            "findings_created": self.findings_created,
            "detail": self.detail,
        }


@dataclass(slots=True)
class PersistedBatch:
    activities: int = 0
    content_units: int = 0
    findings: list[dict[str, Any]] = field(default_factory=list)


class ComplianceIngestService:
    def __init__(
        self,
        *,
        cache: CacheService,
        scan: ComplianceScanService | None = None,
        forwarder: ComplianceForwarderService | None = None,
        secret_store: SecretStore | None = None,
        session_factory: async_sessionmaker[AsyncSession] = AsyncSessionLocal,
    ) -> None:
        self.scan = scan or ComplianceScanService()
        self.forwarder = forwarder or ComplianceForwarderService()
        self.cache = cache
        self.secret_store = secret_store or get_secret_store()
        self.session_factory = session_factory

    async def _acquire_lock(self, connector_id: UUID) -> str | None:
        redis = self.cache.redis
        if redis is None:
            logger.warning("Compliance lock unavailable reason=redis_missing")
            return None
        token = uuid4().hex
        try:
            acquired = await redis.set(
                f"compliance:lock:{connector_id}",
                token,
                nx=True,
                ex=LOCK_SECONDS,
            )
        except (OSError, RedisError) as exc:
            logger.warning(
                "Compliance lock unavailable reason=redis_error type=%s",
                type(exc).__name__,
            )
            return None
        return token if acquired else None

    async def _release_lock(self, connector_id: UUID, token: str) -> None:
        redis = self.cache.redis
        if redis is None:
            return
        try:
            await redis.eval(
                UNLOCK_LUA,
                1,
                f"compliance:lock:{connector_id}",
                token,
            )
        except (OSError, RedisError):
            return

    def _adapter(
        self, connector: ComplianceConnector, credential: str
    ) -> ComplianceAdapter:
        config = dict(connector.config or {})
        if connector.provider == "anthropic":
            configured_types = config.get("scan_activity_types")
            activity_types = (
                {str(value) for value in configured_types}
                if isinstance(configured_types, list)
                else None
            )
            adapter = AnthropicComplianceAdapter(
                credential,
                content_activity_types=activity_types,
                config=config,
            )
            adapter.rate_limiter = ComplianceRateLimiter(
                settings.COMPLIANCE_ANTHROPIC_RPM,
                str(connector.id),
                cache=self.cache,
            )
            return adapter
        return get_adapter(connector.provider, credential, config=config)

    def _starting_cursor(
        self,
        connector: ComplianceConnector,
        adapter: ComplianceAdapter,
    ) -> str | None:
        if connector.cursor:
            return connector.cursor
        configured = _timestamp((connector.config or {}).get("backfill_since"))
        since = configured or (
            _now() - timedelta(hours=settings.COMPLIANCE_DEFAULT_BACKFILL_HOURS)
        )
        if isinstance(adapter, AnthropicComplianceAdapter):
            return adapter.initial_cursor(since)
        return None

    async def _upsert_activity(
        self,
        session: AsyncSession,
        connector_id: UUID,
        activity: NormalizedActivity,
    ) -> UUID | None:
        statement = (
            pg_insert(ComplianceActivity)
            .values(
                id=uuid4(),
                connector_id=connector_id,
                provider_event_id=activity.provider_event_id,
                event_type=activity.event_type,
                actor_email=activity.actor_email,
                actor_user_id=activity.actor_user_id,
                actor_ip=activity.actor_ip,
                occurred_at=activity.occurred_at,
                extras=dict(activity.extras),
            )
            .on_conflict_do_nothing(constraint="uq_compliance_activity_event")
            .returning(ComplianceActivity.id)
        )
        return (await session.execute(statement)).scalar_one_or_none()

    async def _insert_finding(
        self,
        session: AsyncSession,
        connector_id: UUID,
        activity_id: UUID,
        finding: Mapping[str, Any],
        *,
        source_log_file_id: UUID | None = None,
    ) -> bool:
        statement = (
            pg_insert(ComplianceFinding)
            .values(
                id=uuid4(),
                connector_id=connector_id,
                activity_id=activity_id,
                source_log_file_id=source_log_file_id,
                **dict(finding),
            )
            .on_conflict_do_nothing(constraint="uq_compliance_finding_dedup")
            .returning(ComplianceFinding.id)
        )
        return (await session.execute(statement)).scalar_one_or_none() is not None

    async def _scan_activity(
        self,
        session: AsyncSession,
        connector: ComplianceConnector,
        adapter: ComplianceAdapter,
        activity: NormalizedActivity,
        activity_id: UUID,
        *,
        source_log_file_id: UUID | None = None,
    ) -> PersistedBatch:
        contents: list[NormalizedContent] = []
        if activity.inline_content is not None:
            contents.append(activity.inline_content)
        else:
            for reference in activity.content_refs:
                contents.append(await adapter.fetch_content(reference))

        batch = PersistedBatch(activities=1)
        pii_config = (connector.config or {}).get("pii_config")
        validated_config = pii_config if isinstance(pii_config, dict) else None
        for content in contents:
            batch.content_units += len(content.units)
            for finding in await self.scan.scan_content(content, validated_config):
                if await self._insert_finding(
                    session,
                    connector.id,
                    activity_id,
                    finding,
                    source_log_file_id=source_log_file_id,
                ):
                    batch.findings.append(finding)
        return batch

    async def _persist_activity(
        self,
        session: AsyncSession,
        connector: ComplianceConnector,
        adapter: ComplianceAdapter,
        activity: NormalizedActivity,
        *,
        source_log_file_id: UUID | None = None,
    ) -> PersistedBatch:
        activity_id = await self._upsert_activity(
            session,
            connector.id,
            activity,
        )
        if activity_id is None:
            return PersistedBatch()
        return await self._scan_activity(
            session,
            connector,
            adapter,
            activity,
            activity_id,
            source_log_file_id=source_log_file_id,
        )

    async def _queue_findings(
        self,
        session: AsyncSession,
        connector: ComplianceConnector,
        findings: list[dict[str, Any]],
    ) -> None:
        if findings:
            await self.forwarder.handle_run(session, connector, findings)

    @staticmethod
    def _apply(outcome: RunOutcome, batch: PersistedBatch) -> None:
        outcome.activities_ingested += batch.activities
        outcome.content_scanned += batch.content_units
        outcome.findings_created += len(batch.findings)

    async def _drive_anthropic(
        self,
        session: AsyncSession,
        connector: ComplianceConnector,
        adapter: AnthropicComplianceAdapter,
        outcome: RunOutcome,
    ) -> None:
        async for activity in adapter.iter_activities(
            self._starting_cursor(connector, adapter)
        ):
            async with session.begin_nested():
                batch = await self._persist_activity(
                    session,
                    connector,
                    adapter,
                    activity,
                )
                await self._queue_findings(session, connector, batch.findings)
                connector.cursor = adapter.cursor_for(activity)
            await session.commit()
            self._apply(outcome, batch)

    async def _cursor_row(
        self,
        session: AsyncSession,
        connector_id: UUID,
        event_type: str,
    ) -> ComplianceIngestCursor:
        row = await session.scalar(
            select(ComplianceIngestCursor).where(
                ComplianceIngestCursor.connector_id == connector_id,
                ComplianceIngestCursor.event_type == event_type,
            )
        )
        if row is None:
            row = ComplianceIngestCursor(
                id=uuid4(),
                connector_id=connector_id,
                event_type=event_type,
            )
            session.add(row)
            await session.flush()
        return row

    async def _process_openai_file(
        self,
        session: AsyncSession,
        connector: ComplianceConnector,
        adapter: OpenAIComplianceAdapter,
        event_type: str,
        descriptor: LogFileDescriptor,
    ) -> PersistedBatch:
        existing = await session.scalar(
            select(ComplianceLogFile).where(
                ComplianceLogFile.connector_id == connector.id,
                ComplianceLogFile.provider_file_id == descriptor.file_id,
            )
        )
        if existing is not None and existing.status == "processed":
            return PersistedBatch()

        try:
            async with session.begin_nested():
                log_file = existing or ComplianceLogFile(
                    id=uuid4(),
                    connector_id=connector.id,
                    event_type=event_type,
                    provider_file_id=descriptor.file_id,
                )
                if existing is None:
                    session.add(log_file)
                    await session.flush()
                batch = PersistedBatch()
                record_count = 0
                async for activity in adapter.download_records(event_type, descriptor):
                    record_count += 1
                    persisted = await self._persist_activity(
                        session,
                        connector,
                        adapter,
                        activity,
                        source_log_file_id=log_file.id,
                    )
                    batch.activities += persisted.activities
                    batch.content_units += persisted.content_units
                    batch.findings.extend(persisted.findings)
                await self._queue_findings(session, connector, batch.findings)
                log_file.status = "processed"
                log_file.record_count = record_count
                log_file.window_start = descriptor.window_start
                log_file.window_end = descriptor.window_end
                log_file.processed_at = _now()
                log_file.last_error = None
            await session.commit()
            return batch
        except Exception as exc:
            await session.rollback()
            await self._mark_file_error(
                session,
                connector.id,
                event_type,
                descriptor.file_id,
                _error_code(exc),
            )
            raise

    async def _mark_file_error(
        self,
        session: AsyncSession,
        connector_id: UUID,
        event_type: str,
        file_id: str,
        error_code: str,
    ) -> None:
        statement = (
            pg_insert(ComplianceLogFile)
            .values(
                id=uuid4(),
                connector_id=connector_id,
                event_type=event_type,
                provider_file_id=file_id,
                status="error",
                last_error=error_code,
            )
            .on_conflict_do_update(
                constraint="uq_compliance_log_file_dedup",
                set_={"status": "error", "last_error": error_code},
            )
        )
        await session.execute(statement)
        await session.commit()

    async def _drive_openai_stream(
        self,
        session: AsyncSession,
        connector: ComplianceConnector,
        adapter: OpenAIComplianceAdapter,
        event_type: str,
        outcome: RunOutcome,
    ) -> None:
        cursor = await self._cursor_row(session, connector.id, event_type)
        current = _now()
        retention_floor = adapter.retention_floor(current)
        after_at = cursor.last_end_time or adapter.backfill_start(current)
        gap = detect_retention_gap(cursor.last_end_time, retention_floor, event_type)
        if gap is not None:
            await self._queue_health_alert(session, connector, gap)
            after_at = retention_floor
        after = after_at.isoformat()

        for _page in range(MAX_OPENAI_PAGES):
            page = await adapter.list_logs(event_type, after)
            for descriptor in page.descriptors:
                self._apply(
                    outcome,
                    await self._process_openai_file(
                        session,
                        connector,
                        adapter,
                        event_type,
                        descriptor,
                    ),
                )
            next_cursor = _timestamp(page.last_end_time)
            if page.has_more and next_cursor is None:
                raise RuntimeError("OpenAI compliance cursor is missing")
            if next_cursor is not None:
                if next_cursor <= after_at and page.has_more:
                    raise RuntimeError("OpenAI compliance cursor did not advance")
                cursor.last_end_time = next_cursor
                after_at = next_cursor
                after = next_cursor.isoformat()
            if page.descriptors:
                cursor.last_file_id = page.descriptors[-1].file_id
            cursor.last_success_at = _now()
            cursor.lag_seconds = (
                int(max(0.0, (_now() - cursor.last_end_time).total_seconds()))
                if cursor.last_end_time
                else None
            )
            await session.commit()
            if not page.has_more:
                return
        raise RuntimeError("OpenAI compliance page limit exceeded")

    async def _drive_openai(
        self,
        session: AsyncSession,
        connector: ComplianceConnector,
        adapter: OpenAIComplianceAdapter,
        outcome: RunOutcome,
    ) -> None:
        if connector.backfill_started_at is None:
            connector.backfill_started_at = _now()
            await session.commit()
        for event_type in adapter.event_types:
            await self._drive_openai_stream(
                session,
                connector,
                adapter,
                event_type,
                outcome,
            )
        if connector.backfill_completed_at is None:
            connector.backfill_completed_at = _now()
            await session.commit()
        await self._queue_health_state(session, connector, adapter)

    async def _queue_health_state(
        self,
        session: AsyncSession,
        connector: ComplianceConnector,
        adapter: OpenAIComplianceAdapter,
    ) -> None:
        rows = list(
            (
                await session.execute(
                    select(ComplianceIngestCursor).where(
                        ComplianceIngestCursor.connector_id == connector.id
                    )
                )
            ).scalars()
        )
        alerts = evaluate_stream_health(
            [
                {
                    "event_type": row.event_type,
                    "last_end_time": row.last_end_time,
                    "last_success_at": row.last_success_at,
                }
                for row in rows
            ],
            retention_days=adapter.retention_days(),
            risk_threshold_days=settings.COMPLIANCE_RETENTION_RISK_DAYS,
            poll_interval_seconds=settings.COMPLIANCE_DEFAULT_INTERVAL_SECONDS,
            now=_now(),
        )
        for alert in alerts:
            await self._queue_health_alert(session, connector, alert)
        await session.commit()

    async def _queue_health_alert(
        self,
        session: AsyncSession,
        connector: ComplianceConnector,
        alert: HealthAlert,
    ) -> None:
        await self.forwarder.send_operational_alert(
            session,
            connector,
            kind=alert.kind,
            message=alert.message,
        )

    async def _drive(
        self,
        session: AsyncSession,
        connector: ComplianceConnector,
        adapter: ComplianceAdapter,
        outcome: RunOutcome,
    ) -> None:
        if isinstance(adapter, AnthropicComplianceAdapter):
            await self._drive_anthropic(session, connector, adapter, outcome)
            return
        if isinstance(adapter, OpenAIComplianceAdapter):
            await self._drive_openai(session, connector, adapter, outcome)
            return
        raise TypeError("unsupported compliance adapter")

    async def run_once(self, connector_id: UUID | str) -> dict[str, Any]:
        normalized_id = (
            connector_id if isinstance(connector_id, UUID) else UUID(str(connector_id))
        )
        token = await self._acquire_lock(normalized_id)
        if token is None:
            return RunOutcome(normalized_id, status="skipped_locked").as_dict()

        outcome = RunOutcome(normalized_id)
        adapter: ComplianceAdapter | None = None
        try:
            async with self.session_factory() as session:
                connector = await session.get(ComplianceConnector, normalized_id)
                if connector is None:
                    return RunOutcome(
                        normalized_id,
                        status="error",
                        detail="CONNECTOR_NOT_FOUND",
                    ).as_dict()
                if connector.status != "active":
                    return RunOutcome(
                        normalized_id,
                        status="skipped_paused",
                    ).as_dict()
                credential = await self.secret_store.get_secret(
                    TenantId(connector.organization_id),
                    SecretRef(connector.secret_ref),
                    expected_purpose="compliance-connector-api-key",
                )
                adapter = self._adapter(connector, credential)
                try:
                    await self._drive(session, connector, adapter, outcome)
                except Exception as exc:
                    await session.rollback()
                    connector = await session.get(ComplianceConnector, normalized_id)
                    if connector is not None:
                        connector.last_run_at = _now()
                        connector.last_error = _error_code(exc)
                        connector.consecutive_errors += 1
                        if connector.consecutive_errors >= ERROR_STATUS_THRESHOLD:
                            connector.status = "error"
                        if isinstance(exc, httpx.HTTPStatusError) and (
                            exc.response.status_code in {401, 403}
                        ):
                            await self._queue_health_alert(
                                session,
                                connector,
                                HealthAlert(
                                    stream="connector",
                                    kind=AUTH_ERROR,
                                    message="Provider rejected the connector credential or scope",
                                ),
                            )
                        await session.commit()
                    outcome.status = "error"
                    outcome.detail = _error_code(exc)
                    logger.warning(
                        "Compliance ingest failed type=%s",
                        type(exc).__name__,
                    )
                    return outcome.as_dict()
                connector.last_run_at = _now()
                connector.last_success_at = connector.last_run_at
                connector.last_error = None
                connector.consecutive_errors = 0
                await session.commit()
                return outcome.as_dict()
        finally:
            if adapter is not None:
                await adapter.close()
            await self._release_lock(normalized_id, token)


def _error_code(exc: Exception) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        return f"PROVIDER_HTTP_{exc.response.status_code}"
    name = type(exc).__name__.upper()
    return f"INGEST_{name[:96]}"
