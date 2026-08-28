from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest

import shim_enterprise.workers.reconciliation as worker_module
from shim_enterprise.billing.ledger import (
    AccountingConflictError,
    DurableAccountingRepository,
    FinalizationCommand,
    SpendPolicySnapshot,
    SpendReservationCommand,
    TerminalAction,
    UsageLedgerRepository,
)
from shim_enterprise.workers.reconciliation import ReconciliationWorker
from shim_enterprise.observability.lifecycle import RequestLifecycleRepository
from shim_enterprise.outbox.publisher import OutboxWriter


class SessionContext:
    def __init__(self, session) -> None:
        self.session = session

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        return None


def _result(value: object) -> SimpleNamespace:
    return SimpleNamespace(scalar_one_or_none=lambda: value)


def test_unverified_provider_usage_cannot_be_settled() -> None:
    with pytest.raises(ValueError, match="unverified provider usage"):
        FinalizationCommand(
            tenant_id=uuid4(),
            request_id="req_unverified",
            quota_action=TerminalAction.SETTLE,
            terminal_error_code="PROVIDER_USAGE_UNAVAILABLE",
        )


@pytest.mark.asyncio
async def test_usage_ledger_rejects_conflicting_payload_replay() -> None:
    organization_id = uuid4()
    idempotency_key = "request:test:spend:reservation"
    existing = SimpleNamespace(
        organization_id=organization_id,
        idempotency_key=idempotency_key,
        provider_model="gpt-5",
    )
    session = SimpleNamespace(
        execute=AsyncMock(side_effect=[_result(None), _result(existing)])
    )

    with pytest.raises(
        AccountingConflictError,
        match="^usage ledger identity conflict$",
    ):
        await UsageLedgerRepository.append(
            session,
            organization_id=organization_id,
            values={
                "idempotency_key": idempotency_key,
                "provider_model": "gpt-5-mini",
            },
        )


@pytest.mark.asyncio
async def test_terminal_replay_rejects_conflicting_usage() -> None:
    tenant_id = uuid4()
    reservation = SimpleNamespace(
        id=uuid4(),
        request_id="req_terminal_replay",
        api_key_id=uuid4(),
        requested_model="gpt-5.6-luna",
        provider=None,
        provider_model=None,
        event_type="quota_reservation",
        request_count=1,
    )
    existing = SimpleNamespace(
        request_id=reservation.request_id,
        api_key_id=reservation.api_key_id,
        requested_model=reservation.requested_model,
        provider=None,
        provider_model=None,
        event_type="quota_settlement",
        idempotency_key=f"request:{reservation.request_id}:quota:settlement",
        reservation_event_id=reservation.id,
        request_count=1,
        prompt_tokens=11,
        completion_tokens=7,
        total_tokens=18,
        estimated=False,
        cost_usd=Decimal("0"),
    )
    session = SimpleNamespace(execute=AsyncMock(return_value=_result(existing)))

    with pytest.raises(
        AccountingConflictError,
        match="^reservation terminal identity conflict$",
    ):
        await DurableAccountingRepository()._transition_reservation(
            session,
            tenant_id,
            reservation,
            TerminalAction.SETTLE,
            prompt_tokens=12,
            completion_tokens=7,
            cost_usd=Decimal("0"),
            estimated=False,
        )


def test_spend_reservation_replay_rejects_changed_pricing() -> None:
    command = SpendReservationCommand(
        tenant_id=uuid4(),
        api_key_id=uuid4(),
        request_id="req_pricing_replay",
        requested_model="gpt-5.6-luna",
        provider="openai",
        provider_model="gpt-5.6-luna",
        estimated_cost_usd=Decimal("0.01"),
        pricing_metadata={"catalog_version": "catalog-v2"},
        cache_status="miss",
        audit_policy_mode="off",
        policy=SpendPolicySnapshot(version="policy-v1", monthly_limit_usd=None),
    )
    reservation = SimpleNamespace(
        request_id=str(command.request_id),
        api_key_id=command.api_key_id,
        requested_model=command.requested_model,
        provider=str(command.provider),
        provider_model=command.provider_model,
        event_type="spend_reservation",
        cost_usd=command.estimated_cost_usd,
        event_metadata={"pricing": {"catalog_version": "catalog-v1"}},
    )

    with pytest.raises(AccountingConflictError, match="reservation identity conflict"):
        DurableAccountingRepository._validate_spend_reservation(reservation, command)


@pytest.mark.asyncio
async def test_monthly_counter_records_usage_after_a_zero_token_estimate() -> None:
    transition = await DurableAccountingRepository()._apply_quota_transition(
        SimpleNamespace(execute=AsyncMock(return_value=_result(uuid4()))),
        uuid4(),
        SimpleNamespace(request_count=1),
        {
            "period_row_id": str(uuid4()),
            "period_type": "monthly",
            "reserved_requests": 1,
            "reserved_tokens": 0,
        },
        TerminalAction.SETTLE,
        prompt_tokens=5,
        completion_tokens=3,
    )

    assert transition["settled_tokens"] == 8


@pytest.mark.asyncio
async def test_stale_recovery_refunds_unverified_provider_usage(
    monkeypatch,
) -> None:
    now = datetime(2026, 7, 24, 12, 0, tzinfo=timezone.utc)
    provider_started = SimpleNamespace(
        organization_id=uuid4(),
        request_id=f"req_{uuid4().hex}",
        provider_started_at=now,
        status="provider_started",
        terminal_error_code=None,
        terminal_error_message=None,
    )
    routing_rejected = SimpleNamespace(
        organization_id=uuid4(),
        request_id=f"req_{uuid4().hex}",
        provider_started_at=None,
        status="routing_rejected",
        terminal_error_code="ROUTE_DENIED",
        terminal_error_message="No route matched.",
    )
    stale_result = SimpleNamespace(
        scalars=lambda: SimpleNamespace(
            unique=lambda: (provider_started, routing_rejected)
        )
    )
    session = SimpleNamespace(execute=AsyncMock(return_value=stale_result))
    quota_reservations = (
        SimpleNamespace(prompt_tokens=11, completion_tokens=17),
        SimpleNamespace(prompt_tokens=23, completion_tokens=29),
    )
    spend_reservation = SimpleNamespace()
    finalization_results = (
        SimpleNamespace(replayed=False),
        SimpleNamespace(replayed=True),
    )
    repository = DurableAccountingRepository()
    monkeypatch.setattr(
        repository,
        "_lock_reservation",
        AsyncMock(side_effect=quota_reservations),
    )
    monkeypatch.setattr(
        repository,
        "_find_reservation",
        AsyncMock(side_effect=(spend_reservation, None)),
    )
    finalize_locked = AsyncMock(side_effect=finalization_results)
    monkeypatch.setattr(repository, "_finalize_locked", finalize_locked)

    recovered = await repository.recover_stale(session, now=now, batch_size=2)

    assert recovered == finalization_results
    started_call, rejected_call = finalize_locked.await_args_list
    started_command = started_call.args[1]
    assert started_call.args[2:] == (
        provider_started,
        quota_reservations[0],
        spend_reservation,
    )
    assert started_command.quota_action.value == "refund"
    assert started_command.spend_action.value == "refund"
    assert (started_command.prompt_tokens, started_command.completion_tokens) == (0, 0)
    assert started_command.actual_cost_usd == Decimal("0")
    assert started_command.pricing_metadata is None
    assert started_command.estimated is False
    assert started_command.lifecycle_status == "failed"
    assert started_command.terminal_error_code == "STALE_RESERVATION_RECOVERED"
    assert started_command.reconciliation_urgent is True

    rejected_command = rejected_call.args[1]
    assert rejected_call.args[2:] == (
        routing_rejected,
        quota_reservations[1],
        None,
    )
    assert rejected_command.quota_action.value == "refund"
    assert rejected_command.spend_action.value == "none"
    assert (rejected_command.prompt_tokens, rejected_command.completion_tokens) == (
        0,
        0,
    )
    assert rejected_command.actual_cost_usd == Decimal("0")
    assert rejected_command.estimated is False
    assert rejected_command.lifecycle_status == "rejected"
    assert rejected_command.terminal_error_code == "ROUTE_DENIED"
    assert rejected_command.terminal_error_message == "No route matched."
    assert rejected_command.reconciliation_urgent is False


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
        worker_module,
        "ReconciliationWorker",
        lambda: worker_shutdown_probe,
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


@pytest.mark.asyncio
async def test_worker_repeats_reconciliation_until_stopped(monkeypatch) -> None:
    worker = ReconciliationWorker(
        accounting=SimpleNamespace(),
        scans=SimpleNamespace(),
        session_factory=lambda: None,
        batch_size=10,
        interval_seconds=23,
    )
    stop_event = asyncio.Event()
    passes = 0
    wait_timeouts: list[int] = []

    async def run_once() -> int:
        nonlocal passes
        passes += 1
        if passes == 2:
            stop_event.set()
        return 0

    async def wait_for(waitable, *, timeout: int):
        wait_timeouts.append(timeout)
        if stop_event.is_set():
            return await waitable
        waitable.close()
        raise TimeoutError

    monkeypatch.setattr(worker, "run_once", run_once)
    monkeypatch.setattr(worker_module.asyncio, "wait_for", wait_for)

    await worker.run(stop_event)

    assert passes == 2
    assert wait_timeouts == [23, 23]


@pytest.mark.parametrize(
    "bounds",
    [{"batch_size": 0}, {"interval_seconds": 0}],
)
def test_worker_rejects_explicit_zero_bounds(bounds: dict[str, int]) -> None:
    with pytest.raises(ValueError, match="bounds must be positive"):
        ReconciliationWorker(**bounds)


@pytest.mark.asyncio
async def test_worker_commits_one_bounded_recovery_batch() -> None:
    session = SimpleNamespace(commit=AsyncMock(), rollback=AsyncMock())
    accounting = SimpleNamespace(
        recover_stale=AsyncMock(return_value=(object(), object()))
    )
    scans = SimpleNamespace(recover_stale=AsyncMock(return_value=(object(),)))
    now = datetime(2026, 7, 12, 12, 0, tzinfo=timezone.utc)
    worker = ReconciliationWorker(
        accounting=accounting,
        scans=scans,
        session_factory=lambda: SessionContext(session),
        batch_size=17,
        interval_seconds=30,
    )

    recovered = await worker.run_once(now=now)

    assert recovered == 3
    accounting.recover_stale.assert_awaited_once_with(
        session,
        now=now,
        batch_size=17,
    )
    scans.recover_stale.assert_awaited_once_with(session, now=now, batch_size=17)
    session.commit.assert_awaited_once()
    session.rollback.assert_not_awaited()


@pytest.mark.asyncio
async def test_worker_rolls_back_a_failed_batch() -> None:
    session = SimpleNamespace(commit=AsyncMock(), rollback=AsyncMock())
    accounting = SimpleNamespace(
        recover_stale=AsyncMock(side_effect=RuntimeError("database unavailable"))
    )
    worker = ReconciliationWorker(
        accounting=accounting,
        scans=SimpleNamespace(recover_stale=AsyncMock(return_value=())),
        session_factory=lambda: SessionContext(session),
        batch_size=10,
        interval_seconds=30,
    )

    with pytest.raises(RuntimeError, match="database unavailable"):
        await worker.run_once()

    session.commit.assert_not_awaited()
    session.rollback.assert_awaited_once()


@pytest.mark.asyncio
async def test_terminal_reconciliation_event_carries_tenant_identity(
    monkeypatch,
) -> None:
    append = AsyncMock()
    monkeypatch.setattr(OutboxWriter, "append", append)
    tenant_id = uuid4()
    request_id = f"req_{uuid4().hex}"
    occurred_at = datetime.now(timezone.utc)

    await DurableAccountingRepository()._enqueue_reconciliation_event(
        SimpleNamespace(),
        tenant_id,
        request_id,
        lifecycle_status="completed",
        urgent=False,
        occurred_at=occurred_at,
    )

    values = append.await_args.kwargs["values"]
    assert values["payload"] == {
        "organization_id": str(tenant_id),
        "request_id": request_id,
        "lifecycle_status": "completed",
        "urgent": False,
    }


@pytest.mark.asyncio
async def test_urgent_reconciliation_event_carries_tenant_identity(
    monkeypatch,
) -> None:
    append = AsyncMock()
    update = AsyncMock(return_value=object())
    repository = DurableAccountingRepository()
    lifecycle = SimpleNamespace(reconciled_at=None, status="accepted")
    monkeypatch.setattr(
        repository, "_lock_lifecycle", AsyncMock(return_value=lifecycle)
    )
    monkeypatch.setattr(RequestLifecycleRepository, "update", update)
    monkeypatch.setattr(OutboxWriter, "append", append)
    tenant_id = uuid4()
    request_id = f"req_{uuid4().hex}"
    occurred_at = datetime.now(timezone.utc)

    signaled = await repository.signal_urgent_reconciliation(
        SimpleNamespace(),
        tenant_id=tenant_id,
        request_id=request_id,
        occurred_at=occurred_at,
        reason="AUDIT_INTENT_FAILED",
    )

    values = append.await_args.kwargs["values"]
    assert signaled is True
    assert values["payload"] == {
        "organization_id": str(tenant_id),
        "request_id": request_id,
        "lifecycle_status": "accepted",
        "urgent": True,
        "reason": "AUDIT_INTENT_FAILED",
    }
