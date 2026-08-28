from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from uuid import UUID, uuid4

import pytest
from sqlalchemy import delete, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from shim_enterprise.core.config import settings
import shim.gateway.pipeline.postprocess as postprocess_module
from shim.gateway.kernel.result import UNSPECIFIED_PROVIDER_MODEL
from shim_enterprise.gateway.pipeline.quota_reservation import (
    AccountingPersistenceError,
    DurableAccountingCoordinator,
    DurableUsageLifecycle,
)
from shim_enterprise.gateway.pipeline.audit_intent import AuditIntentPersistenceError
from shim.gateway.pipeline.provider_execution import (
    ProviderExecutionStage,
    ProviderNonStream,
)
from shim.gateway.pipeline.postprocess import ResponsePostprocessor
from shim.gateway.streaming import StreamFinalization
from shim.gateway.streaming.meter import StreamUsageSnapshot
from shim.privacy.policies import PrivacyAction, PrivacyOutcome
from shim_enterprise.billing.ledger import (
    DurableAccountingRepository,
    FailureReservationState,
    FinalizationCommand,
    QuotaPolicySnapshot,
    QuotaReservationCommand,
    SpendReservationCommand,
    SpendLimitExceeded,
    SpendPolicySnapshot,
    TerminalAction,
)
from shim_enterprise.billing.models import (
    QuotaPeriodUsage,
    RequestLifecycle,
    SpendPeriodUsage,
    UsageLedger,
)
from shim_enterprise.observability.lifecycle import RequestLifecycleRepository
from shim_enterprise.outbox.models import OutboxEvent
from shim.privacy.classification import content_ref
from shim_enterprise.tenants.models import ApiKey, Organization, User


def _prepared(audit_mode: str = "best_effort") -> SimpleNamespace:
    return SimpleNamespace(
        tenant_id=uuid4(),
        api_key_id=uuid4(),
        request_id=f"req_{uuid4().hex}",
        provider="openai",
        protocol="chat",
        model="gpt-5.6-luna",
        stream=False,
        context=SimpleNamespace(
            audit_policy=SimpleNamespace(mode=audit_mode),
        ),
        admission=SimpleNamespace(
            estimated_input_tokens=20,
            maximum_output_tokens=30,
        ),
        payload={"messages": []},
        privacy=PrivacyOutcome(
            action=PrivacyAction.DISABLED,
            pii_detected=False,
            verification_map={},
        ),
    )


def _failure_state(
    provider_started: bool,
    spend_reserved: bool,
) -> FailureReservationState:
    return FailureReservationState(
        provider_started=provider_started,
        spend_reserved=spend_reserved,
    )


def _terminal(status: str = "completed") -> StreamFinalization:
    return StreamFinalization(
        terminal_status=status,
        usage=StreamUsageSnapshot(
            prompt_tokens=20,
            completion_tokens=30,
            settlement_cost_usd=Decimal("0.000041"),
            provider_model="gpt-5.6-luna",
            pricing_metadata={"catalog_version": "test"},
            estimated=False,
            output_hash=None,
        ),
        completed_at=datetime.now(timezone.utc),
        error_code=None,
        error_message=None,
    )


def _postprocessor(usage) -> ResponsePostprocessor:
    return ResponsePostprocessor(
        usage,
        heartbeat_interval_seconds=30,
        output_hash_salt=None,
    )


async def _create_tenant(
    session: AsyncSession,
    label: str,
) -> tuple[UUID, UUID, UUID]:
    organization_id = uuid4()
    user_id = uuid4()
    api_key_id = uuid4()
    await session.execute(
        text(
            "INSERT INTO tier_definitions "
            "(slug, name, rate_limit_rpm, rate_limit_tpm, "
            "monthly_request_limit, monthly_token_limit, features) "
            "VALUES ('free', 'Free', 60, 15000, 1000, 1000000, '{}') "
            "ON CONFLICT (slug) DO NOTHING"
        )
    )
    session.add_all(
        [
            Organization(
                id=organization_id,
                name=f"Persistence Integrity {label}",
                slug=f"persistence-integrity-{label}-{uuid4().hex}",
            ),
            User(
                id=user_id,
                organization_id=organization_id,
                email=f"persistence-integrity-{label}-{uuid4().hex}@example.com",
            ),
            ApiKey(
                id=api_key_id,
                organization_id=organization_id,
                user_id=user_id,
                key_hash=f"{label}-{uuid4().hex}",
                prefix=f"sk-{label}",
                tier="free",
                is_active=True,
            ),
        ]
    )
    await session.flush()
    return organization_id, user_id, api_key_id


@pytest.mark.asyncio
async def test_spend_denial_attempts_preflight_after_rolling_back_reservation() -> None:
    repository = SimpleNamespace(
        reserve_provider_spend=AsyncMock(
            side_effect=SpendLimitExceeded("limit exceeded")
        ),
        write_spend_denial_preflight=AsyncMock(),
    )
    policy_loader = SimpleNamespace(
        spend=AsyncMock(
            return_value=SpendPolicySnapshot(
                version="spend-v1",
                monthly_limit_usd=None,
            )
        )
    )
    session = SimpleNamespace(commit=AsyncMock(), rollback=AsyncMock())
    prepared = _prepared()
    prepared.payload = {"input": "<EMAIL_ADDRESS_ff8d9819>"}

    with pytest.raises(SpendLimitExceeded):
        await DurableAccountingCoordinator(
            repository=repository,
            policy_loader=policy_loader,
        ).reserve_spend(prepared, False, session)

    assert session.rollback.await_count == 1
    repository.write_spend_denial_preflight.assert_awaited_once()
    session.commit.assert_awaited_once()
    command = repository.write_spend_denial_preflight.await_args.args[1]
    assert command.audit_policy_mode == "best_effort"
    assert command.input_hash == content_ref(
        settings.COMPLIANCE_HASH_SALT or settings.SECRET_KEY,
        json.dumps(prepared.payload, sort_keys=True, default=str),
    )


@pytest.mark.asyncio
async def test_unspecified_reservation_is_conservative_and_nonnull() -> None:
    repository = SimpleNamespace(
        reserve_provider_spend=AsyncMock(return_value=SimpleNamespace())
    )
    policy_loader = SimpleNamespace(
        spend=AsyncMock(
            return_value=SpendPolicySnapshot(
                version="spend-v1",
                monthly_limit_usd=None,
            )
        )
    )
    session = SimpleNamespace(commit=AsyncMock(), rollback=AsyncMock())
    prepared = _prepared()
    prepared.model = UNSPECIFIED_PROVIDER_MODEL

    await DurableAccountingCoordinator(
        repository=repository,
        policy_loader=policy_loader,
    ).reserve_spend(prepared, False, session)

    command = repository.reserve_provider_spend.await_args.args[1]
    assert command.requested_model == UNSPECIFIED_PROVIDER_MODEL
    assert command.provider_model == UNSPECIFIED_PROVIDER_MODEL
    assert command.estimated_cost_usd > 0
    assert command.pricing_metadata["pricing_resolution"] == "conservative_max"


@pytest.mark.asyncio
async def test_strict_spend_denial_preflight_failure_is_authoritative() -> None:
    repository = SimpleNamespace(
        reserve_provider_spend=AsyncMock(
            side_effect=SpendLimitExceeded("limit exceeded")
        ),
        write_spend_denial_preflight=AsyncMock(
            side_effect=RuntimeError("audit unavailable")
        ),
    )
    policy_loader = SimpleNamespace(
        spend=AsyncMock(
            return_value=SpendPolicySnapshot(
                version="spend-v1",
                monthly_limit_usd=None,
            )
        )
    )
    session = SimpleNamespace(commit=AsyncMock(), rollback=AsyncMock())

    with pytest.raises(AuditIntentPersistenceError, match="required"):
        await DurableAccountingCoordinator(
            repository=repository,
            policy_loader=policy_loader,
        ).reserve_spend(_prepared("strict"), False, session)

    assert session.rollback.await_count == 2
    session.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_stream_start_marker_commits_short_lifecycle_transaction() -> None:
    repository = SimpleNamespace(mark_stream_started=AsyncMock())
    session = SimpleNamespace(commit=AsyncMock(), rollback=AsyncMock())
    prepared = _prepared()

    await DurableAccountingCoordinator(repository=repository).mark_stream_started(
        prepared,
        session,
    )

    repository.mark_stream_started.assert_awaited_once()
    call = repository.mark_stream_started.await_args
    assert call.kwargs["tenant_id"] == prepared.tenant_id
    assert call.kwargs["request_id"] == prepared.request_id
    assert call.kwargs["started_at"].tzinfo is not None
    assert call.kwargs["reconciliation_due_at"] > call.kwargs["started_at"]
    session.commit.assert_awaited_once()
    session.rollback.assert_not_awaited()


@pytest.mark.asyncio
async def test_stream_heartbeat_commits_an_extended_deadline() -> None:
    repository = SimpleNamespace(heartbeat_stream=AsyncMock())
    session = SimpleNamespace(commit=AsyncMock(), rollback=AsyncMock())
    prepared = _prepared()
    before = datetime.now(timezone.utc)

    await DurableAccountingCoordinator(repository=repository).heartbeat_stream(
        prepared,
        session,
    )

    due_at = repository.heartbeat_stream.await_args.kwargs["reconciliation_due_at"]
    assert due_at >= before + timedelta(
        seconds=max(
            settings.OPENAI_CONNECT_TIMEOUT_SECONDS,
            settings.OPENAI_READ_TIMEOUT_SECONDS,
            settings.OPENAI_WRITE_TIMEOUT_SECONDS,
            settings.OPENAI_POOL_TIMEOUT_SECONDS,
            60,
        )
        + settings.GATEWAY_RECONCILIATION_GRACE_SECONDS
    )
    session.commit.assert_awaited_once()
    session.rollback.assert_not_awaited()


@pytest.mark.asyncio
async def test_provider_start_deadline_covers_the_provider_timeout() -> None:
    session = SimpleNamespace(commit=AsyncMock(), rollback=AsyncMock())
    prepared = _prepared()
    prepared.provider = "openai"

    with patch.object(
        RequestLifecycleRepository,
        "transition",
        new=AsyncMock(return_value=SimpleNamespace()),
    ) as transition:
        await DurableAccountingCoordinator().mark_provider_started(prepared, session)

    values = transition.await_args.kwargs["values"]
    assert values["reconciliation_due_at"] - values["provider_started_at"] == (
        timedelta(
            seconds=max(
                settings.OPENAI_CONNECT_TIMEOUT_SECONDS,
                settings.OPENAI_READ_TIMEOUT_SECONDS,
                settings.OPENAI_WRITE_TIMEOUT_SECONDS,
                settings.OPENAI_POOL_TIMEOUT_SECONDS,
                60,
            )
            + settings.GATEWAY_RECONCILIATION_GRACE_SECONDS
        )
    )


@pytest.mark.asyncio
async def test_disconnected_stream_settles_reserved_usage() -> None:
    usage = SimpleNamespace(
        finalize=AsyncMock(return_value=SimpleNamespace()),
        mark_stream_started=AsyncMock(),
        heartbeat_stream=AsyncMock(),
    )
    prepared = _prepared()
    stream = _postprocessor(usage).create_stream_session(prepared)
    provider_stream = SimpleNamespace(aclose=AsyncMock())

    stream.bind(provider_stream)
    await stream.aclose()

    provider_stream.aclose.assert_awaited_once()
    terminal = usage.finalize.await_args.args[1]
    assert usage.finalize.await_args.args[0] is prepared
    assert terminal.terminal_status == "client_disconnected"


@pytest.mark.asyncio
async def test_audit_finalization_failure_preserves_typed_boundary_error() -> None:
    repository = SimpleNamespace(
        finalize=AsyncMock(
            side_effect=AuditIntentPersistenceError("completion unavailable")
        )
    )
    session = SimpleNamespace(commit=AsyncMock(), rollback=AsyncMock())

    with pytest.raises(AuditIntentPersistenceError, match="completion unavailable"):
        await DurableAccountingCoordinator(repository=repository).finalize(
            session,
            FinalizationCommand(
                tenant_id=uuid4(),
                request_id=f"req_{uuid4().hex}",
                quota_action=TerminalAction.SETTLE,
            ),
        )

    session.commit.assert_not_awaited()
    session.rollback.assert_awaited_once()


@pytest.mark.asyncio
async def test_urgent_reconciliation_signal_commits_short_transaction() -> None:
    repository = SimpleNamespace(
        signal_urgent_reconciliation=AsyncMock(return_value=True)
    )
    session = SimpleNamespace(commit=AsyncMock(), rollback=AsyncMock())
    tenant_id = uuid4()
    request_id = f"req_{uuid4().hex}"
    occurred_at = datetime.now(timezone.utc)

    signaled = await DurableAccountingCoordinator(
        repository=repository
    ).signal_urgent_reconciliation(
        session,
        tenant_id=tenant_id,
        request_id=request_id,
        occurred_at=occurred_at,
        reason="AUDIT_INTENT_FAILED",
    )

    assert signaled is True
    repository.signal_urgent_reconciliation.assert_awaited_once_with(
        session,
        tenant_id=tenant_id,
        request_id=request_id,
        occurred_at=occurred_at,
        reason="AUDIT_INTENT_FAILED",
    )
    session.commit.assert_awaited_once()
    session.rollback.assert_not_awaited()


@pytest.mark.asyncio
async def test_privacy_facts_commit_before_openai_execution() -> None:
    session = SimpleNamespace(commit=AsyncMock(), rollback=AsyncMock())
    checked = SimpleNamespace(
        tenant_id=uuid4(),
        request_id=f"req_{uuid4().hex}",
        privacy=PrivacyOutcome(
            action=PrivacyAction.SCRUBBED,
            pii_detected=True,
            verification_map={"<EMAIL_ADDRESS_ff8d9819>": "alice@example.com"},
        ),
    )

    with patch(
        "shim_enterprise.gateway.pipeline.quota_reservation.RequestLifecycleRepository.update",
        new=AsyncMock(return_value=SimpleNamespace()),
    ) as update_lifecycle:
        await DurableAccountingCoordinator().record_privacy(checked, session)

    assert update_lifecycle.await_args.kwargs["values"] == {
        "privacy_status": "scrubbed",
        "pii_detected": True,
    }
    session.commit.assert_awaited_once()
    session.rollback.assert_not_awaited()


@pytest.mark.asyncio
async def test_nonstream_openai_execution_persists_start_marker() -> None:
    invocation = SimpleNamespace(provider="openai")
    prepared = _prepared()
    usage = SimpleNamespace(mark_provider_started=AsyncMock())

    async def execute(**kwargs):
        await kwargs["provider_start_callback"]()
        return ProviderNonStream(
            payload={"id": "resp_1", "output_text": "Done"},
            request_id="upstream_req_1",
        )

    execution = SimpleNamespace(execute=AsyncMock(side_effect=execute))
    stage = ProviderExecutionStage(
        invocation,
        execution,
        usage,
    )

    response = await stage.run(prepared)

    assert response.payload["output_text"] == "Done"
    assert stage.trace_metadata(response) == {
        "provider": "openai",
        "streaming": False,
    }
    usage.mark_provider_started.assert_awaited_once_with(prepared)


@pytest.mark.asyncio
async def test_provider_start_session_closes_before_provider_execution() -> None:
    events: list[str] = []
    session = object()

    @asynccontextmanager
    async def session_scope():
        events.append("session_open")
        try:
            yield session
        finally:
            events.append("session_closed")

    accounting = SimpleNamespace(
        mark_provider_started=AsyncMock(side_effect=lambda *_: events.append("marked"))
    )
    usage = DurableUsageLifecycle(accounting, session_scope)

    async def execute(**kwargs):
        await kwargs["provider_start_callback"]()
        events.append("provider_execute")
        return ProviderNonStream(payload={}, request_id=None)

    await ProviderExecutionStage(
        SimpleNamespace(provider="openai"),
        SimpleNamespace(execute=execute),
        usage,
    ).run(_prepared())

    assert events == [
        "session_open",
        "marked",
        "session_closed",
        "provider_execute",
    ]


@pytest.mark.asyncio
async def test_nonstream_settlement_uses_the_priced_response_model() -> None:
    prepared = _prepared()
    prepared.model = UNSPECIFIED_PROVIDER_MODEL
    usage = SimpleNamespace(finalize=AsyncMock())

    await _postprocessor(usage).finalize(
        prepared,
        ProviderNonStream(
            payload={
                "model": "gpt-5.6-luna",
                "usage": {"input_tokens": 20, "output_tokens": 30},
            },
            request_id="req_upstream",
        ),
        stream_session=None,
    )

    terminal = usage.finalize.await_args.args[1]
    assert terminal.usage.settlement_cost_usd == Decimal("0.000041")
    assert terminal.usage.provider_model == "gpt-5.6-luna"
    assert terminal.usage.estimated is False


@pytest.mark.asyncio
async def test_nonstream_settlement_does_not_trust_a_cheaper_response_model() -> None:
    prepared = _prepared()
    prepared.model = "gpt-5.6"
    usage = SimpleNamespace(finalize=AsyncMock())

    await _postprocessor(usage).finalize(
        prepared,
        ProviderNonStream(
            payload={
                "model": "gpt-5.6-luna",
                "usage": {"input_tokens": 20, "output_tokens": 30},
            },
            request_id="req_upstream",
        ),
        stream_session=None,
    )

    terminal = usage.finalize.await_args.args[1]
    assert terminal.usage.settlement_cost_usd == Decimal("0.0007")


@pytest.mark.asyncio
async def test_failed_response_without_a_requested_model_uses_conservative_price() -> (
    None
):
    prepared = _prepared()
    prepared.model = UNSPECIFIED_PROVIDER_MODEL
    usage = SimpleNamespace(finalize=AsyncMock())

    await _postprocessor(usage).finalize(
        prepared,
        ProviderNonStream(
            payload={"model": "gpt-5.6-luna", "status": "failed"},
            request_id="req_upstream",
        ),
        stream_session=None,
    )

    terminal = usage.finalize.await_args.args[1]
    assert terminal.usage.settlement_cost_usd > 0
    assert terminal.usage.pricing_metadata["pricing_resolution"] == "conservative_max"
    assert terminal.terminal_status == "provider_error"


@pytest.mark.asyncio
async def test_nonstream_response_is_constructed_before_terminal_settlement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    response = SimpleNamespace(status_code=200)

    def build_response(*_args, **_kwargs):
        events.append("response_constructed")
        return response

    async def finalize(*_args):
        events.append("usage_finalized")

    monkeypatch.setattr(postprocess_module, "JSONResponse", build_response)

    result = await _postprocessor(SimpleNamespace(finalize=finalize)).finalize(
        _prepared(),
        ProviderNonStream(payload={"usage": {}}, request_id=None),
        stream_session=None,
    )

    assert result is response
    assert events == ["response_constructed", "usage_finalized"]


@pytest.mark.asyncio
async def test_failure_state_rolls_back_before_durable_read() -> None:
    expected = _failure_state(True, True)
    repository = SimpleNamespace(
        failure_reservation_state=AsyncMock(return_value=expected)
    )
    session = SimpleNamespace(rollback=AsyncMock())
    prepared = _prepared()

    state = await DurableAccountingCoordinator(
        repository=repository
    ).failure_reservation_state(prepared, session)

    assert state == expected
    session.rollback.assert_awaited_once()
    repository.failure_reservation_state.assert_awaited_once_with(
        session,
        tenant_id=prepared.tenant_id,
        request_id=prepared.request_id,
    )


@pytest.mark.asyncio
async def test_failure_state_converts_rollback_failure_to_accounting_error() -> None:
    repository = SimpleNamespace(failure_reservation_state=AsyncMock())
    session = SimpleNamespace(
        rollback=AsyncMock(
            side_effect=(
                RuntimeError("rollback failed"),
                RuntimeError("cleanup failed"),
            )
        )
    )

    with pytest.raises(
        AccountingPersistenceError,
        match="failure reservation state cleanup failed",
    ):
        await DurableAccountingCoordinator(
            repository=repository
        ).failure_reservation_state(_prepared(), session)

    repository.failure_reservation_state.assert_not_awaited()


@pytest.mark.asyncio
async def test_failure_state_converts_read_failure_to_accounting_error() -> None:
    repository = SimpleNamespace(
        failure_reservation_state=AsyncMock(side_effect=RuntimeError("read failed"))
    )
    session = SimpleNamespace(rollback=AsyncMock())

    with pytest.raises(
        AccountingPersistenceError,
        match="failure reservation state is unavailable",
    ):
        await DurableAccountingCoordinator(
            repository=repository
        ).failure_reservation_state(_prepared(), session)

    assert session.rollback.await_count == 2


@pytest.mark.asyncio
async def test_failure_before_openai_start_refunds_reserved_money() -> None:
    prepared = _prepared()
    accounting = SimpleNamespace(
        failure_reservation_state=AsyncMock(return_value=_failure_state(False, True)),
        refund=AsyncMock(),
    )
    session = object()

    @asynccontextmanager
    async def session_scope():
        yield session

    await DurableUsageLifecycle(accounting, session_scope).fail(
        prepared,
        reason="request_aborted",
    )

    accounting.failure_reservation_state.assert_awaited_once_with(prepared, session)
    accounting.refund.assert_awaited_once_with(
        session,
        prepared,
        spend_reserved=True,
        error_code="REQUEST_ABORTED",
        error_message="Request ended before a provider value was delivered.",
    )


@pytest.mark.asyncio
async def test_provider_rejection_refunds_reserved_ceiling() -> None:
    prepared = _prepared()
    accounting = SimpleNamespace(
        failure_reservation_state=AsyncMock(return_value=_failure_state(True, True)),
        refund=AsyncMock(),
    )
    session = object()

    @asynccontextmanager
    async def session_scope():
        yield session

    await DurableUsageLifecycle(accounting, session_scope).fail(
        prepared,
        reason="provider_rejected_without_usage",
    )

    accounting.failure_reservation_state.assert_awaited_once_with(prepared, session)
    accounting.refund.assert_awaited_once_with(
        session,
        prepared,
        spend_reserved=True,
        error_code="PROVIDER_UNAVAILABLE",
        error_message="The provider rejected the request without usage.",
    )


@pytest.mark.parametrize("spend_reserved", [True, False])
@pytest.mark.asyncio
async def test_failure_after_openai_start_refunds_unverified_usage(
    spend_reserved: bool,
) -> None:
    prepared = _prepared()
    accounting = SimpleNamespace(
        failure_reservation_state=AsyncMock(
            return_value=_failure_state(True, spend_reserved)
        ),
        refund=AsyncMock(),
    )
    session = object()

    @asynccontextmanager
    async def session_scope():
        yield session

    await DurableUsageLifecycle(accounting, session_scope).fail(
        prepared,
        reason="request_aborted",
    )

    accounting.failure_reservation_state.assert_awaited_once_with(prepared, session)
    accounting.refund.assert_awaited_once_with(
        session,
        prepared,
        spend_reserved=spend_reserved,
        error_code="PROVIDER_USAGE_UNAVAILABLE",
        error_message="Provider execution began but usage could not be verified.",
    )


@pytest.mark.asyncio
async def test_unavailable_failure_state_does_not_guess_a_refund() -> None:
    accounting = SimpleNamespace(
        failure_reservation_state=AsyncMock(
            side_effect=AccountingPersistenceError("state unavailable")
        ),
        refund=AsyncMock(),
    )
    session = object()

    @asynccontextmanager
    async def session_scope():
        yield session

    await DurableUsageLifecycle(accounting, session_scope).fail(
        _prepared(),
        reason="request_aborted",
    )

    accounting.refund.assert_not_awaited()


@pytest.mark.asyncio
async def test_raw_recovery_session_error_is_logged_safely(
    caplog: pytest.LogCaptureFixture,
) -> None:
    @asynccontextmanager
    async def unavailable_session():
        raise RuntimeError("database unavailable secret")
        yield object()

    await DurableUsageLifecycle(
        SimpleNamespace(),
        unavailable_session,
    ).fail(
        _prepared(),
        reason="request_aborted",
    )

    assert "RuntimeError" in caplog.text
    assert "database unavailable secret" not in caplog.text


@pytest.mark.asyncio
async def test_admission_abort_skips_failure_state_and_refunds_quota_only() -> None:
    session = object()

    @asynccontextmanager
    async def session_scope():
        yield session

    accounting = SimpleNamespace(
        failure_reservation_state=AsyncMock(),
        refund=AsyncMock(),
    )
    prepared = _prepared()

    await DurableUsageLifecycle(accounting, session_scope).fail(
        prepared,
        reason="admission_aborted",
    )

    accounting.failure_reservation_state.assert_not_awaited()
    accounting.refund.assert_awaited_once_with(
        session,
        prepared,
        spend_reserved=False,
        error_code="ADMISSION_ABORTED",
        error_message="Request ended before a provider value was delivered.",
    )


@pytest.mark.asyncio
async def test_usage_lifecycle_uses_one_distinct_session_per_verb() -> None:
    sessions: list[object] = []

    @asynccontextmanager
    async def session_scope():
        session = object()
        sessions.append(session)
        yield session

    accounting = SimpleNamespace(
        reserve_quota=AsyncMock(),
        record_privacy=AsyncMock(),
        reserve_spend=AsyncMock(),
        mark_provider_started=AsyncMock(),
        mark_stream_started=AsyncMock(),
        heartbeat_stream=AsyncMock(),
        finalize=AsyncMock(),
        failure_reservation_state=AsyncMock(return_value=_failure_state(False, False)),
        refund=AsyncMock(),
    )
    lifecycle = DurableUsageLifecycle(accounting, session_scope)
    prepared = _prepared()
    admission = prepared.admission

    await lifecycle.admit(prepared, admission)
    await lifecycle.record_privacy(prepared)
    await lifecycle.reserve_provider_spend(prepared, ephemeral_byok=False)
    await lifecycle.mark_provider_started(prepared)
    await lifecycle.mark_stream_started(prepared)
    await lifecycle.heartbeat_stream(prepared)
    await lifecycle.finalize(prepared, _terminal())
    await lifecycle.fail(prepared, reason="request_aborted")

    assert len(sessions) == len({id(session) for session in sessions}) == 8
    assert accounting.reserve_quota.await_args.args[2] is sessions[0]
    assert accounting.record_privacy.await_args.args[1] is sessions[1]
    assert accounting.reserve_spend.await_args.args[2] is sessions[2]
    assert accounting.mark_provider_started.await_args.args[1] is sessions[3]
    assert accounting.mark_stream_started.await_args.args[1] is sessions[4]
    assert accounting.heartbeat_stream.await_args.args[1] is sessions[5]
    assert accounting.finalize.await_args.args[0] is sessions[6]
    assert accounting.failure_reservation_state.await_args.args[1] is sessions[7]
    assert accounting.refund.await_args.args[0] is sessions[7]


@pytest.mark.asyncio
async def test_strict_stream_audit_failure_uses_second_recovery_session() -> None:
    sessions: list[object] = []

    @asynccontextmanager
    async def session_scope():
        session = object()
        sessions.append(session)
        yield session

    accounting = SimpleNamespace(
        finalize=AsyncMock(
            side_effect=AuditIntentPersistenceError("completion unavailable")
        ),
        signal_urgent_reconciliation=AsyncMock(),
    )
    prepared = _prepared("strict")
    prepared.stream = True

    with pytest.raises(AuditIntentPersistenceError, match="completion unavailable"):
        await DurableUsageLifecycle(accounting, session_scope).finalize(
            prepared,
            _terminal(),
        )

    assert len(sessions) == 2
    assert accounting.finalize.await_args.args[0] is sessions[0]
    accounting.signal_urgent_reconciliation.assert_awaited_once_with(
        sessions[1],
        tenant_id=prepared.tenant_id,
        request_id=prepared.request_id,
        occurred_at=accounting.finalize.await_args.args[1].completed_at,
        reason="AUDIT_INTENT_FAILED",
    )


@pytest.mark.asyncio
async def test_nonstream_audit_failure_does_not_signal_stream_recovery() -> None:
    sessions: list[object] = []

    @asynccontextmanager
    async def session_scope():
        session = object()
        sessions.append(session)
        yield session

    accounting = SimpleNamespace(
        finalize=AsyncMock(
            side_effect=AuditIntentPersistenceError("completion unavailable")
        ),
        signal_urgent_reconciliation=AsyncMock(),
    )

    with pytest.raises(AuditIntentPersistenceError, match="completion unavailable"):
        await DurableUsageLifecycle(accounting, session_scope).finalize(
            _prepared("strict"),
            _terminal(),
        )

    assert len(sessions) == 1
    accounting.signal_urgent_reconciliation.assert_not_awaited()


@pytest.mark.asyncio
async def test_failure_state_uses_durable_provider_marker(
    db,
    test_api_key,
) -> None:
    repository = DurableAccountingRepository()
    request_id = f"req_failure_state_{uuid4().hex}"
    await RequestLifecycleRepository.create(
        db,
        organization_id=test_api_key.organization_id,
        values={
            "request_id": request_id,
            "actor_type": "api_key",
            "api_key_id": test_api_key.id,
            "user_id": None,
            "source_endpoint": "chat.completions",
            "status": "provider_pending",
            "provider": "openai",
            "provider_model": "gpt-5.6-luna",
            "requested_model": "gpt-5.6-luna",
            "stream": False,
            "started_at": datetime.now(timezone.utc),
        },
    )

    assert await repository.failure_reservation_state(
        db,
        tenant_id=test_api_key.organization_id,
        request_id=request_id,
    ) == _failure_state(False, False)
    assert (
        await RequestLifecycleRepository.transition(
            db,
            organization_id=test_api_key.organization_id,
            request_id=request_id,
            target_status="provider_started",
            expected_statuses={"provider_pending"},
            values={"provider_started_at": datetime.now(timezone.utc)},
        )
        is not None
    )
    assert await repository.failure_reservation_state(
        db,
        tenant_id=test_api_key.organization_id,
        request_id=request_id,
    ) == _failure_state(True, False)


@pytest.mark.asyncio
async def test_spend_pricing_metadata_survives_terminal_fallback(
    db,
    test_api_key,
) -> None:
    repository = DurableAccountingRepository()
    request_id = f"req_pricing_metadata_{uuid4().hex}"
    started_at = datetime.now(timezone.utc)
    await repository.reserve_quota(
        db,
        QuotaReservationCommand(
            tenant_id=test_api_key.organization_id,
            api_key_id=test_api_key.id,
            request_id=request_id,
            requested_model="gpt-5.6-luna",
            source_endpoint="chat.completions",
            started_at=started_at,
            reconciliation_due_at=started_at + timedelta(minutes=2),
            estimated_input_tokens=20,
            maximum_output_tokens=30,
            policy=QuotaPolicySnapshot(
                version="pricing-quota-v1",
                daily_request_limit=None,
                monthly_request_limit=1000,
                monthly_token_limit=1_000_000,
            ),
        ),
    )
    pricing_metadata = {
        "catalog_version": "catalog-v1",
        "pricing_resolution": "catalog",
        "input_per_million": "0.2",
        "output_per_million": "1.2",
    }
    reservation = await repository.reserve_provider_spend(
        db,
        SpendReservationCommand(
            tenant_id=test_api_key.organization_id,
            api_key_id=test_api_key.id,
            request_id=request_id,
            requested_model="gpt-5.6-luna",
            provider="openai",
            provider_model="gpt-5.6-luna",
            estimated_cost_usd=Decimal("0.00004"),
            pricing_metadata=pricing_metadata,
            cache_status="miss",
            audit_policy_mode="off",
            policy=SpendPolicySnapshot(
                version="pricing-spend-v1",
                monthly_limit_usd=None,
            ),
        ),
    )
    terminal = await repository.finalize(
        db,
        FinalizationCommand(
            tenant_id=test_api_key.organization_id,
            request_id=request_id,
            quota_action=TerminalAction.SETTLE,
            spend_action=TerminalAction.SETTLE,
            prompt_tokens=20,
            completion_tokens=30,
            actual_cost_usd=Decimal("0.00004"),
            provider_model="gpt-5.6-luna",
        ),
    )

    events = tuple(
        (
            await db.execute(
                select(UsageLedger).where(
                    UsageLedger.id.in_((reservation.event_id, terminal.spend_event_id))
                )
            )
        ).scalars()
    )
    assert len(events) == 2
    assert all(event.event_metadata["pricing"] == pricing_metadata for event in events)


@pytest.mark.asyncio
async def test_delayed_provider_start_cannot_overwrite_terminal_finalization(
    async_engine,
) -> None:
    session_factory = async_sessionmaker(async_engine, expire_on_commit=False)
    request_id = f"req_lifecycle_race_{uuid4().hex}"
    started_at = datetime.now(timezone.utc)

    async with session_factory.begin() as setup:
        organization_id, user_id, api_key_id = await _create_tenant(setup, "race")

    try:
        async with session_factory() as session:
            repository = DurableAccountingRepository()
            await repository.reserve_quota(
                session,
                QuotaReservationCommand(
                    tenant_id=organization_id,
                    api_key_id=api_key_id,
                    request_id=request_id,
                    requested_model="gpt-5.6-luna",
                    source_endpoint="chat.completions",
                    started_at=started_at,
                    reconciliation_due_at=started_at + timedelta(minutes=2),
                    estimated_input_tokens=5,
                    maximum_output_tokens=32,
                    policy=QuotaPolicySnapshot(
                        version="lifecycle-race-v1",
                        daily_request_limit=None,
                        monthly_request_limit=1000,
                        monthly_token_limit=1_000_000,
                    ),
                ),
            )
            assert (
                await RequestLifecycleRepository.transition(
                    session,
                    organization_id=organization_id,
                    request_id=request_id,
                    target_status="routing_pending",
                    expected_statuses={"accepted"},
                )
                is not None
            )
            assert (
                await RequestLifecycleRepository.transition(
                    session,
                    organization_id=organization_id,
                    request_id=request_id,
                    target_status="provider_pending",
                    expected_statuses={"routing_pending"},
                )
                is not None
            )
            terminal_at = datetime.now(timezone.utc)
            await repository.finalize(
                session,
                FinalizationCommand(
                    tenant_id=organization_id,
                    request_id=request_id,
                    quota_action=TerminalAction.REFUND,
                    lifecycle_status="failed",
                    terminal_error_code="REQUEST_ABORTED",
                    completed_at=terminal_at,
                ),
            )
            await session.commit()

        prepared = SimpleNamespace(
            tenant_id=organization_id,
            request_id=request_id,
            provider="openai",
        )
        async with session_factory() as delayed_session:
            with pytest.raises(AccountingPersistenceError, match="provider lifecycle"):
                await DurableAccountingCoordinator().mark_provider_started(
                    prepared,
                    delayed_session,
                )

        async with session_factory() as verification:
            lifecycle = (
                await verification.execute(
                    select(RequestLifecycle).where(
                        RequestLifecycle.organization_id == organization_id,
                        RequestLifecycle.request_id == request_id,
                    )
                )
            ).scalar_one()

        assert lifecycle.status == "failed"
        assert lifecycle.reconciled_at == terminal_at
        assert lifecycle.provider_started_at is None
    finally:
        async with session_factory.begin() as cleanup:
            await cleanup.execute(
                delete(OutboxEvent).where(
                    OutboxEvent.organization_id == organization_id
                )
            )
            await cleanup.execute(
                delete(UsageLedger).where(
                    UsageLedger.organization_id == organization_id
                )
            )
            await cleanup.execute(
                delete(RequestLifecycle).where(
                    RequestLifecycle.organization_id == organization_id
                )
            )
            await cleanup.execute(
                delete(QuotaPeriodUsage).where(
                    QuotaPeriodUsage.organization_id == organization_id
                )
            )
            await cleanup.execute(delete(ApiKey).where(ApiKey.id == api_key_id))
            await cleanup.execute(delete(User).where(User.id == user_id))
            await cleanup.execute(
                delete(Organization).where(Organization.id == organization_id)
            )


@pytest.mark.asyncio
async def test_usage_terminal_reference_is_tenant_scoped(async_engine) -> None:
    session_factory = async_sessionmaker(async_engine, expire_on_commit=False)
    request_id = f"req_tenant_ledger_{uuid4().hex}"

    async with session_factory.begin() as setup:
        organization_id, user_id, api_key_id = await _create_tenant(setup, "owner")
        other_organization_id, other_user_id, other_api_key_id = await _create_tenant(
            setup,
            "other",
        )

    try:
        async with session_factory() as session:
            reservation = UsageLedger(
                request_id=request_id,
                organization_id=organization_id,
                api_key_id=api_key_id,
                requested_model="gpt-5.6-luna",
                provider=None,
                provider_model=None,
                event_type="quota_reservation",
                idempotency_key=f"request:{request_id}:quota:reservation",
                request_count=1,
                prompt_tokens=5,
                completion_tokens=32,
                total_tokens=37,
                estimated=True,
                cost_usd=Decimal("0"),
            )
            session.add(reservation)
            await session.flush()

            cross_tenant_terminal = UsageLedger(
                request_id=request_id,
                organization_id=other_organization_id,
                api_key_id=other_api_key_id,
                requested_model="gpt-5.6-luna",
                provider=None,
                provider_model=None,
                event_type="quota_refund",
                idempotency_key=f"request:{request_id}:quota:refund",
                reservation_event_id=reservation.id,
                request_count=0,
                prompt_tokens=0,
                completion_tokens=0,
                total_tokens=0,
                estimated=False,
                cost_usd=Decimal("0"),
            )
            with pytest.raises(IntegrityError) as cross_tenant_error:
                async with session.begin_nested():
                    session.add(cross_tenant_terminal)
                    await session.flush()
            assert "fk_usage_ledger_org_reservation_event" in str(
                cross_tenant_error.value.orig
            )

            same_tenant_terminal = UsageLedger(
                request_id=request_id,
                organization_id=organization_id,
                api_key_id=api_key_id,
                requested_model="gpt-5.6-luna",
                provider=None,
                provider_model=None,
                event_type="quota_refund",
                idempotency_key=f"request:{request_id}:quota:refund",
                reservation_event_id=reservation.id,
                request_count=0,
                prompt_tokens=0,
                completion_tokens=0,
                total_tokens=0,
                estimated=False,
                cost_usd=Decimal("0"),
            )
            session.add(same_tenant_terminal)
            await session.commit()

        async with session_factory() as verification:
            terminal = (
                await verification.execute(
                    select(UsageLedger).where(
                        UsageLedger.organization_id == organization_id,
                        UsageLedger.reservation_event_id == reservation.id,
                    )
                )
            ).scalar_one()
        assert terminal.event_type == "quota_refund"
    finally:
        async with session_factory.begin() as cleanup:
            await cleanup.execute(
                delete(UsageLedger).where(
                    UsageLedger.organization_id.in_(
                        (organization_id, other_organization_id)
                    )
                )
            )
            await cleanup.execute(
                delete(ApiKey).where(ApiKey.id.in_((api_key_id, other_api_key_id)))
            )
            await cleanup.execute(
                delete(User).where(User.id.in_((user_id, other_user_id)))
            )
            await cleanup.execute(
                delete(Organization).where(
                    Organization.id.in_((organization_id, other_organization_id))
                )
            )


@pytest.mark.asyncio
async def test_usage_reservation_is_immutable_after_initial_allocation(
    async_engine,
) -> None:
    session_factory = async_sessionmaker(async_engine, expire_on_commit=False)
    request_id = f"req_immutable_ledger_{uuid4().hex}"
    started_at = datetime.now(timezone.utc)

    async with session_factory.begin() as setup:
        organization_id, user_id, api_key_id = await _create_tenant(
            setup,
            "immutable",
        )

    try:
        async with session_factory() as session:
            repository = DurableAccountingRepository()
            reservation = await repository.reserve_quota(
                session,
                QuotaReservationCommand(
                    tenant_id=organization_id,
                    api_key_id=api_key_id,
                    request_id=request_id,
                    requested_model="gpt-5.6-luna",
                    source_endpoint="chat.completions",
                    started_at=started_at,
                    reconciliation_due_at=started_at + timedelta(minutes=2),
                    estimated_input_tokens=5,
                    maximum_output_tokens=32,
                    policy=QuotaPolicySnapshot(
                        version="immutable-v1",
                        daily_request_limit=None,
                        monthly_request_limit=1000,
                        monthly_token_limit=1_000_000,
                    ),
                ),
            )
            spend_reservation = await repository.reserve_provider_spend(
                session,
                SpendReservationCommand(
                    tenant_id=organization_id,
                    api_key_id=api_key_id,
                    request_id=request_id,
                    requested_model="gpt-5.6-luna",
                    provider="openai",
                    provider_model="gpt-5.6-luna",
                    estimated_cost_usd=Decimal("0.01"),
                    pricing_metadata={"catalog_version": "immutable-v1"},
                    cache_status="miss",
                    audit_policy_mode="off",
                    policy=SpendPolicySnapshot(
                        version="immutable-spend-v1",
                        monthly_limit_usd=Decimal("10"),
                    ),
                ),
            )
            with pytest.raises(DBAPIError) as repeated_allocation_error:
                async with session.begin_nested():
                    await session.execute(
                        text(
                            "UPDATE usage_ledger SET period_allocations = "
                            "jsonb_build_array(jsonb_build_object('tampered', true)) "
                            "WHERE id = :id"
                        ),
                        {"id": reservation.event_id},
                    )
            assert "usage_ledger is immutable" in str(
                repeated_allocation_error.value.orig
            )
            await session.commit()

            assert reservation.period_allocations
            assert spend_reservation.period_allocations
            mutations = (
                (
                    "UPDATE usage_ledger SET cost_usd = cost_usd + 1 WHERE id = :id",
                    spend_reservation.event_id,
                ),
                (
                    "UPDATE usage_ledger SET prompt_tokens = prompt_tokens + 1, "
                    "total_tokens = total_tokens + 1 WHERE id = :id",
                    reservation.event_id,
                ),
                (
                    "UPDATE usage_ledger SET metadata = "
                    "jsonb_build_object('tampered', true) WHERE id = :id",
                    reservation.event_id,
                ),
            )
            for mutation, event_id in mutations:
                with pytest.raises(DBAPIError) as mutation_error:
                    async with session.begin_nested():
                        await session.execute(
                            text(mutation),
                            {"id": event_id},
                        )
                assert "usage_ledger is immutable" in str(mutation_error.value.orig)
    finally:
        async with session_factory.begin() as cleanup:
            await cleanup.execute(
                delete(UsageLedger).where(
                    UsageLedger.organization_id == organization_id
                )
            )
            await cleanup.execute(
                delete(RequestLifecycle).where(
                    RequestLifecycle.organization_id == organization_id
                )
            )
            await cleanup.execute(
                delete(QuotaPeriodUsage).where(
                    QuotaPeriodUsage.organization_id == organization_id
                )
            )
            await cleanup.execute(
                delete(SpendPeriodUsage).where(
                    SpendPeriodUsage.organization_id == organization_id
                )
            )
            await cleanup.execute(delete(ApiKey).where(ApiKey.id == api_key_id))
            await cleanup.execute(delete(User).where(User.id == user_id))
            await cleanup.execute(
                delete(Organization).where(Organization.id == organization_id)
            )


@pytest.mark.asyncio
async def test_usage_ledger_tenant_date_event_index_matches_orm_and_database(
    db,
) -> None:
    index = next(
        index
        for index in UsageLedger.__table__.indexes
        if index.name == "ix_usage_ledger_org_created_event"
    )
    assert tuple(column.name for column in index.columns) == (
        "organization_id",
        "created_at",
        "event_type",
    )

    index_definition = (
        await db.execute(
            text(
                "SELECT indexdef FROM pg_indexes "
                "WHERE schemaname = current_schema() "
                "AND tablename = 'usage_ledger' "
                "AND indexname = 'ix_usage_ledger_org_created_event'"
            )
        )
    ).scalar_one()
    assert "(organization_id, created_at, event_type)" in index_definition


@pytest.mark.asyncio
async def test_audit_intent_outbox_reference_is_tenant_scoped(db) -> None:
    organization_id, _, api_key_id = await _create_tenant(db, "audit-owner")
    other_organization_id, _, other_api_key_id = await _create_tenant(
        db,
        "audit-other",
    )
    outbox_event_id = uuid4()
    now = datetime.now(timezone.utc)
    await db.execute(
        text(
            "INSERT INTO outbox_event ("
            "id, organization_id, event_type, aggregate_type, aggregate_id, "
            "idempotency_key, payload, next_attempt_at) VALUES ("
            ":id, :organization_id, 'audit.chain_append_requested', 'request', "
            ":aggregate_id, :idempotency_key, '{}', :next_attempt_at)"
        ),
        {
            "id": outbox_event_id,
            "organization_id": organization_id,
            "aggregate_id": f"req_{uuid4().hex}",
            "idempotency_key": f"audit-outbox:{uuid4().hex}",
            "next_attempt_at": now,
        },
    )

    insert_intent = text(
        "INSERT INTO audit_intent ("
        "id, request_id, organization_id, actor_type, api_key_id, event_type, "
        "audit_policy_mode, lifecycle_status, outbox_event_id) VALUES ("
        ":id, :request_id, :organization_id, 'api_key', :api_key_id, "
        "'completion', 'best_effort', 'completed', :outbox_event_id)"
    )
    await db.execute(
        insert_intent,
        {
            "id": uuid4(),
            "request_id": f"req_audit_valid_{uuid4().hex}",
            "organization_id": organization_id,
            "api_key_id": api_key_id,
            "outbox_event_id": outbox_event_id,
        },
    )

    invalid_references = (
        (organization_id, api_key_id, uuid4()),
        (other_organization_id, other_api_key_id, outbox_event_id),
    )
    for (
        intent_organization_id,
        intent_api_key_id,
        referenced_event_id,
    ) in invalid_references:
        with pytest.raises(IntegrityError) as reference_error:
            async with db.begin_nested():
                await db.execute(
                    insert_intent,
                    {
                        "id": uuid4(),
                        "request_id": f"req_audit_invalid_{uuid4().hex}",
                        "organization_id": intent_organization_id,
                        "api_key_id": intent_api_key_id,
                        "outbox_event_id": referenced_event_id,
                    },
                )
        assert "fk_audit_intent_org_outbox_event" in str(reference_error.value.orig)
