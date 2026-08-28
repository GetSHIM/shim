import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest
from sqlalchemy import text

import shim_enterprise.workers.outbox as worker_module
from shim_enterprise.outbox.publisher import OutboxMessage, OutboxPublisher
from shim_enterprise.workers.outbox import (
    OutboxLeaseRepository,
    OutboxWorker,
    WorkerLimits,
)


class SessionContext:
    def __init__(self) -> None:
        self.session = SimpleNamespace(commit=AsyncMock(), rollback=AsyncMock())

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        return None


def make_message(attempt_count: int = 1) -> OutboxMessage:
    return OutboxMessage(
        id=uuid4(),
        organization_id=uuid4(),
        event_type="test.created",
        aggregate_type="test",
        aggregate_id="aggregate-1",
        idempotency_key="test:aggregate-1:created",
        payload={},
        attempt_count=attempt_count,
        created_at=datetime(2026, 7, 12, tzinfo=timezone.utc),
    )


@pytest.mark.asyncio
async def test_worker_main_handles_shutdown_signals_and_cancellation(
    monkeypatch,
    worker_shutdown_probe,
) -> None:
    configure_logging = Mock()
    configure_error_reporting = Mock()
    configure_tracing = Mock()
    shutdown_tracing = Mock()
    engine = SimpleNamespace(dispose=AsyncMock())
    monkeypatch.setattr(
        worker_module.asyncio,
        "get_running_loop",
        lambda: worker_shutdown_probe.loop,
    )
    monkeypatch.setattr(worker_module, "configure_logging", configure_logging)
    monkeypatch.setattr(
        worker_module,
        "configure_error_reporting",
        configure_error_reporting,
    )
    monkeypatch.setattr(worker_module, "configure_tracing", configure_tracing)
    monkeypatch.setattr(worker_module, "shutdown_tracing", shutdown_tracing)
    monkeypatch.setattr(worker_module, "engine", engine)
    monkeypatch.setattr(
        "shim_enterprise.outbox.handlers.build_publisher", lambda: object()
    )
    monkeypatch.setattr(
        worker_module,
        "OutboxWorker",
        lambda _publisher: worker_shutdown_probe,
    )

    with pytest.raises(asyncio.CancelledError):
        await worker_module.main()

    worker_shutdown_probe.assert_cleaned_up()
    configure_logging.assert_called_once_with(worker_module.settings.LOG_LEVEL)
    configure_error_reporting.assert_called_once_with(
        sentry_dsn=worker_module.settings.SENTRY_DSN,
        environment=worker_module.settings.ENVIRONMENT,
    )
    configure_tracing.assert_called_once_with(
        endpoint=worker_module.settings.OTEL_EXPORTER_OTLP_ENDPOINT,
        service_name=worker_module.settings.OTEL_SERVICE_NAME,
    )
    engine.dispose.assert_awaited_once_with()
    shutdown_tracing.assert_called_once_with()


def test_worker_rejects_an_explicit_zero_interval() -> None:
    with pytest.raises(ValueError, match="interval must be positive"):
        OutboxWorker(OutboxPublisher(), interval_seconds=0)


@pytest.mark.parametrize("attempt_count", [1, 4])
@pytest.mark.asyncio
async def test_worker_commits_claim_before_delivery_and_acknowledges(
    attempt_count: int,
) -> None:
    event = make_message(attempt_count)
    repository = SimpleNamespace(
        claim=AsyncMock(return_value=(event,)),
        acknowledge=AsyncMock(return_value=True),
        reject=AsyncMock(),
        lag=AsyncMock(return_value={}),
    )
    handler = AsyncMock()
    publisher = OutboxPublisher()
    publisher.register(event.event_type, handler)
    worker = OutboxWorker(
        publisher,
        repository=repository,
        session_factory=SessionContext,
        limits=WorkerLimits(batch_size=10, lease_seconds=10, max_attempts=3),
        worker_id="worker-1",
        interval_seconds=1,
    )

    result = await worker.run_once(now=datetime(2026, 7, 12, 1, tzinfo=timezone.utc))

    assert result.claimed == 1
    assert result.processed == 1
    handler.assert_awaited_once_with(event)
    repository.acknowledge.assert_awaited_once()
    assert repository.acknowledge.await_args.kwargs["attempt_count"] == attempt_count
    repository.reject.assert_not_awaited()


@pytest.mark.asyncio
async def test_worker_dead_letters_a_poison_event() -> None:
    event = make_message(attempt_count=3)
    repository = SimpleNamespace(
        claim=AsyncMock(return_value=(event,)),
        acknowledge=AsyncMock(),
        reject=AsyncMock(return_value="dead_letter"),
        lag=AsyncMock(return_value={}),
    )
    publisher = OutboxPublisher()
    publisher.register(event.event_type, AsyncMock(side_effect=RuntimeError("failed")))
    worker = OutboxWorker(
        publisher,
        repository=repository,
        session_factory=SessionContext,
        limits=WorkerLimits(batch_size=10, lease_seconds=10, max_attempts=3),
        worker_id="worker-1",
        interval_seconds=1,
    )

    result = await worker.run_once(now=datetime(2026, 7, 12, 1, tzinfo=timezone.utc))

    assert result.dead_lettered == 1
    repository.reject.assert_awaited_once()
    repository.acknowledge.assert_not_awaited()


@pytest.mark.asyncio
async def test_repository_fences_stale_attempts_and_expired_leases(db) -> None:
    now = datetime.now(timezone.utc)
    organization_id = uuid4()
    event_id = uuid4()
    await db.execute(
        text(
            "INSERT INTO organizations (id, name, slug) "
            "VALUES (:id, 'Outbox Worker', :slug)"
        ),
        {"id": organization_id, "slug": f"outbox-worker-{uuid4().hex}"},
    )
    await db.execute(
        text(
            "INSERT INTO outbox_event ("
            "id, organization_id, event_type, aggregate_type, aggregate_id, "
            "idempotency_key, payload, status, attempt_count, next_attempt_at, "
            "locked_by, lease_expires_at) VALUES ("
            ":id, :organization_id, 'test.reclaim', 'test', 'reclaim-1', "
            ":idempotency_key, '{}', 'processing', 1, :next_attempt_at, "
            "'recovery-worker', :lease_expires_at)"
        ),
        {
            "id": event_id,
            "organization_id": organization_id,
            "idempotency_key": f"test:reclaim:{event_id}",
            "next_attempt_at": now - timedelta(seconds=20),
            "lease_expires_at": now - timedelta(seconds=10),
        },
    )

    repository = OutboxLeaseRepository()
    messages = await repository.claim(
        db,
        worker_id="recovery-worker",
        now=now,
        lease_seconds=5,
        batch_size=1,
    )

    assert len(messages) == 1
    assert messages[0].id == event_id
    assert messages[0].attempt_count == 2

    stale_acknowledged = await repository.acknowledge(
        db,
        event_id=event_id,
        attempt_count=1,
        worker_id="recovery-worker",
        now=now,
    )
    expired_at = now + timedelta(seconds=5)
    acknowledged = await repository.acknowledge(
        db,
        event_id=event_id,
        attempt_count=messages[0].attempt_count,
        worker_id="recovery-worker",
        now=expired_at,
    )
    rejected = await repository.reject(
        db,
        message=messages[0],
        worker_id="recovery-worker",
        now=expired_at,
        max_attempts=3,
        error=RuntimeError("publish failed"),
    )
    status = (
        await db.execute(
            text("SELECT status FROM outbox_event WHERE id = :id"),
            {"id": event_id},
        )
    ).scalar_one()

    assert stale_acknowledged is False
    assert acknowledged is False
    assert rejected is None
    assert status == "processing"
