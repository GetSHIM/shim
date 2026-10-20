from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import hashlib
import hmac
import logging
import re
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
import csv
import io
from types import MethodType, SimpleNamespace
from unittest.mock import AsyncMock, patch
from uuid import UUID, uuid4

import pytest
from sqlalchemy import delete, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from shim.billing.attribution import CostAttribution
from shim.billing.pricing import ModelPrice, compute_cost_usd
from shim_enterprise.billing.spend import BudgetEvaluator
from shim_enterprise.core.config import settings
from shim_enterprise.api.v1 import management
import shim.gateway.pipeline.postprocess as postprocess_module
from shim.gateway.kernel.result import (
    AdmissionState,
    PreparedInference,
    InferenceTiming,
    ProviderTarget,
    UNSPECIFIED_PROVIDER_MODEL,
)
from shim_enterprise.gateway.pipeline.quota_reservation import (
    AccountingPersistenceError,
    AccountingPolicyLoader,
    DurableAccountingCoordinator,
    DurableUsageLifecycle,
)
from shim_enterprise.cache.loop_detection import (
    LoopDetectionService,
    keyed_repeat_digest,
)
from shim.gateway.contracts.context import (
    AuditPolicy,
    GatewayContext,
    PrivacyPolicy,
    TierPolicy,
)
from shim.gateway.contracts.ids import ProviderId
from shim.gateway.pipeline.admission import AdmissionStage
from shim.gateway.request_policy import BandSettings, TaskCaps
from shim.gateway.request_policy import RequestPolicyContext
from shim_enterprise.gateway.pipeline.audit_intent import AuditIntentPersistenceError
from shim_enterprise.gateway.pipeline.outbox import audit_completion_intent
from shim.gateway.pipeline.provider_execution import (
    ProviderCallError,
    ProviderExecutionStage,
    ProviderNonStream,
)
from shim.gateway.pipeline.postprocess import ResponsePostprocessor
from shim.gateway.usage import system_prompt_hash
import shim.gateway.kernel.gateway_kernel as kernel_module
from shim.gateway.kernel.gateway_kernel import GatewayKernel
from shim.gateway.streaming import StreamFinalization
from shim.gateway.streaming.meter import StreamUsageSnapshot
from shim.privacy.policies import PrivacyAction, PrivacyOutcome
from shim_enterprise.billing.ledger import (
    DurableAccountingRepository,
    FailureReservationState,
    FinalizationCommand,
    QuotaLimitExceeded,
    QuotaPolicySnapshot,
    QuotaReservationCommand,
    SpendReservationCommand,
    SpendLimitExceeded,
    SpendPolicySnapshot,
    TerminalAction,
)
from shim_enterprise.billing.models import (
    AuditIntent,
    QuotaPeriodUsage,
    RequestLifecycle,
    SpendPeriodUsage,
    UsageLedger,
)
from shim_enterprise.observability.enterprise_metrics import USAGE_SETTLEMENT_TOTAL
from shim_enterprise.observability.lifecycle import RequestLifecycleRepository
from shim_enterprise.observability import analytics_projection, overview
from shim_enterprise.outbox.models import OutboxEvent
from shim_enterprise.outbox.publisher import OutboxMessage
from shim.privacy.classification import content_ref
from shim_enterprise.tenants.models import ApiKey, Organization, ProviderSecret, User
from shim_enterprise.tenants.plans import configure_organization_quota


def _prepared(audit_mode: str = "best_effort") -> SimpleNamespace:
    prepared = SimpleNamespace(
        policy_verdicts=[],
        timing=InferenceTiming(),
        tenant_id=uuid4(),
        api_key_id=uuid4(),
        request_id=f"req_{uuid4().hex}",
        provider="openai",
        protocol="chat",
        model="gpt-5.6-luna",
        pricing_model="gpt-5.6-luna",
        target=None,
        deployment_kind="unknown",
        response_scan="off",
        response_analysis=(),
        rules=None,
        rules_evaluated=False,
        rule_matches=[],
        settings_applied=None,
        transforms_applied=None,
        route_decision=None,
        attempt=None,
        shadow=None,
        concurrency_lease=None,
        band=BandSettings(),
        approval_id=None,
        unpriced=False,
        deployment_price=None,
        stream=False,
        context=SimpleNamespace(
            audit_policy=SimpleNamespace(mode=audit_mode),
        ),
        admission=SimpleNamespace(
            estimated_input_tokens=20,
            maximum_output_tokens=30,
            task_id=None,
            trace_id=None,
            tool_call_repeats=None,
            task_calls=None,
            request_digest="digest",
            inflight_duplicate_of=None,
            queue_wait_ms=None,
        ),
        task_caps=TaskCaps(),
        payload={"messages": []},
        privacy=PrivacyOutcome(
            action=PrivacyAction.DISABLED,
            pii_detected=False,
            verification_map={},
        ),
    )

    prepared.record_verdict = MethodType(PreparedInference.record_verdict, prepared)
    prepared.warnings = []
    prepared.warn = MethodType(PreparedInference.warn, prepared)
    return prepared


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
        shim_latency_ms=0,
    )


def _postprocessor(usage) -> ResponsePostprocessor:
    return ResponsePostprocessor(
        usage,
        heartbeat_interval_seconds=30,
        output_hash_salt=None,
    )


def _system_prompt_hash(prepared) -> str | None:
    return system_prompt_hash(
        prepared, (settings.COMPLIANCE_HASH_SALT or settings.SECRET_KEY).encode("utf-8")
    )


def test_system_prompt_hash_is_keyed_scoped_and_excludes_conversation(
    monkeypatch,
) -> None:
    prepared = _prepared()
    prepared.payload = {
        "messages": [
            {"role": "system", "content": "private instruction"},
            {"role": "user", "content": "user one"},
        ]
    }
    monkeypatch.setattr(settings, "COMPLIANCE_HASH_SALT", "installation-key-one")
    original = _system_prompt_hash(prepared)
    assert original is not None and original.startswith("hmac-sha256:v1:")
    assert "private instruction" not in original
    prepared.payload["messages"][1]["content"] = "user two"
    prepared.payload["messages"][0] = {
        "content": "private instruction",
        "role": "system",
    }
    assert _system_prompt_hash(prepared) == original
    prepared.payload["messages"][0]["content"] += " "
    assert _system_prompt_hash(prepared) != original
    prepared.payload["messages"][0]["content"] = "private instruction"
    monkeypatch.setattr(settings, "COMPLIANCE_HASH_SALT", "installation-key-two")
    assert _system_prompt_hash(prepared) != original
    monkeypatch.setattr(settings, "COMPLIANCE_HASH_SALT", "installation-key-one")
    prepared.tenant_id = uuid4()
    assert _system_prompt_hash(prepared) != original
    prepared.target = ProviderTarget(
        str(uuid4()), "https://one.invalid", "one", "secret", 30, "1"
    )
    prepared.deployment_kind = "internal"
    deployment_hash = _system_prompt_hash(prepared)
    prepared.model = "renamed-alias"
    prepared.target = replace(
        prepared.target,
        base_url="https://two.invalid",
        upstream_model="two",
        declared_version="2",
    )
    assert _system_prompt_hash(prepared) == deployment_hash
    prepared.target = replace(prepared.target, deployment_id=str(uuid4()))
    assert _system_prompt_hash(prepared) != deployment_hash
    deployment_hash = _system_prompt_hash(prepared)
    prepared.deployment_kind = "external"
    assert _system_prompt_hash(prepared) != deployment_hash
    prepared.payload = {"previous_response_id": "resp_inherited"}
    assert _system_prompt_hash(prepared) is None


@pytest.mark.parametrize(
    ("protocol", "payload"),
    [
        ("responses", {"instructions": "private instruction"}),
        (
            "responses",
            {"input": [{"role": "developer", "content": "private instruction"}]},
        ),
        ("messages", {"system": [{"type": "text", "text": "private instruction"}]}),
        ("count_tokens", {"system": "private instruction"}),
        (
            "generate_content",
            {"systemInstruction": {"parts": [{"text": "private instruction"}]}},
        ),
    ],
)
def test_system_prompt_hash_covers_explicit_native_instructions(
    protocol, payload
) -> None:
    prepared = _prepared()
    prepared.protocol = protocol
    prepared.payload = payload
    assert _system_prompt_hash(prepared) is not None


@pytest.mark.asyncio
async def test_diagnostic_metadata_survives_terminal_and_outbox_replay(
    db, test_api_key, monkeypatch
) -> None:
    repository = DurableAccountingRepository()
    request_id = f"req_diagnostics_{uuid4().hex}"
    deployment_id = str(uuid4())
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
            policy=QuotaPolicySnapshot("test", None, None, None),
            repeat_chain_length=2,
            system_prompt_hash="hmac-sha256:v1:" + "a" * 64,
            deployment_kind="internal",
            deployment_id=deployment_id,
            repeat_digest="b" * 64,
            task_id="agent-run.1",
        ),
    )
    command = FinalizationCommand(
        tenant_id=test_api_key.organization_id,
        request_id=request_id,
        quota_action=TerminalAction.SETTLE,
        prompt_tokens=20,
        completion_tokens=3,
        estimated=True,
        lifecycle_status="client_disconnected",
        provider_finish_reasons={"choices.1.finish_reason": "length"},
        completion_outcome="truncated",
        ttft_ms=125.5,
        provider_latency_ms=812,
        answer_characters=40,
        tool_call_names=("lookup",),
        reasoning_seen=True,
        shim_latency_ms=0,
        cached_input_tokens=10_000,
        warnings=("MODEL_DEPRECATED", "CACHE_NOT_APPLIED"),
    )
    await repository.finalize(db, command)
    replayed = replace(
        command,
        shim_latency_ms=999,
        provider_latency_ms=1,
        answer_characters=1,
        tool_call_names=("other",),
        reasoning_seen=False,
    )
    assert (await repository.finalize(db, replayed)).replayed
    await db.flush()
    lifecycle = (
        await db.execute(
            select(RequestLifecycle).where(RequestLifecycle.request_id == request_id)
        )
    ).scalar_one()
    expected = {
        "repeat_chain_length": 2,
        "system_prompt_hash": "hmac-sha256:v1:" + "a" * 64,
        "deployment_kind": "internal",
        "provider_finish_reasons": {"choices.1.finish_reason": "length"},
        "completion_outcome": "truncated",
        "ttft_ms": 125.5,
        "provider_latency_ms": 812,
        "shim_latency_ms": 0,
        "cached_input_tokens": 10_000,
        "warnings": ["MODEL_DEPRECATED", "CACHE_NOT_APPLIED"],
    }
    assert all(
        lifecycle.lifecycle_metadata[key] == value for key, value in expected.items()
    )
    lifecycle_only = {
        "answer_characters": 40,
        "tool_call_names": ["lookup"],
        "reasoning_seen": True,
    }
    assert all(
        lifecycle.lifecycle_metadata[key] == value
        for key, value in lifecycle_only.items()
    )
    assert lifecycle.lifecycle_metadata["deployment_id"] == deployment_id
    assert lifecycle.lifecycle_metadata["repeat_digest"] == "b" * 64
    event = (
        await db.execute(
            select(OutboxEvent).where(
                OutboxEvent.aggregate_id == request_id,
                OutboxEvent.event_type == "analytics.request_failed",
            )
        )
    ).scalar_one()
    assert all(event.payload[key] == value for key, value in expected.items())
    assert "deployment_id" not in event.payload
    assert "repeat_digest" not in event.payload
    assert event.payload["task_id"] == "agent-run.1"
    audit = audit_completion_intent(
        lifecycle,
        SimpleNamespace(input_hash=None, pii_entities={}),
        SimpleNamespace(prompt_tokens=20, completion_tokens=3, estimated=True),
        None,
        lifecycle_status="client_disconnected",
        output_hash=None,
        completed_at=started_at,
    )
    # The immutable chain keeps no caller-chosen identifier.
    assert "task_id" not in audit.payload["extra"]

    @asynccontextmanager
    async def session_scope():
        yield db

    monkeypatch.setattr(analytics_projection, "AsyncSessionLocal", session_scope)
    message = OutboxMessage.from_event(event)
    await analytics_projection.project_request(message)
    await analytics_projection.project_request(message)
    projected = (
        await db.execute(
            select(analytics_projection.RequestLog).where(
                analytics_projection.RequestLog.request_id == request_id
            )
        )
    ).scalar_one()
    assert all(projected.details[key] == value for key, value in expected.items())
    assert projected.details["lifecycle_status"] == "client_disconnected"
    assert projected.details["usage_estimated"] is True
    assert projected.details["task_id"] == "agent-run.1"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("privacy", "kept"),
    [
        (PrivacyOutcome(action=PrivacyAction.DETECTED, pii_detected=False), True),
        (
            PrivacyOutcome(
                action=PrivacyAction.SCRUBBED,
                pii_detected=True,
                verification_map={"<EMAIL_ADDRESS_ff8d9819>": "alice@example.com"},
                pii_entities={"EMAIL_ADDRESS": 1},
            ),
            False,
        ),
        (
            PrivacyOutcome(
                action=PrivacyAction.SCRUBBED,
                pii_detected=True,
                blocked_entities={"SECRET": 1},
            ),
            False,
        ),
    ],
    ids=["clean", "scrubbed", "blocked"],
)
async def test_the_repeat_digest_is_cleared_when_pii_is_detected(
    db, test_api_key, privacy, kept
) -> None:
    repository = DurableAccountingRepository()
    request_id = f"req_digest_pii_{uuid4().hex}"
    deployment_id = str(uuid4())
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
            policy=QuotaPolicySnapshot("test", None, None, None),
            deployment_id=deployment_id,
            repeat_digest="b" * 64,
        ),
    )
    prepared = SimpleNamespace(
        tenant_id=test_api_key.organization_id,
        request_id=request_id,
        policy_verdicts=[],
        privacy=privacy,
        rules_evaluated=False,
        rule_matches=[],
        settings_applied=None,
        transforms_applied=None,
        route_decision=None,
        attempt=None,
        shadow=None,
        concurrency_lease=None,
        approval_id=None,
    )
    await DurableAccountingCoordinator().record_privacy(prepared, db)
    command = FinalizationCommand(
        tenant_id=test_api_key.organization_id,
        request_id=request_id,
        quota_action=TerminalAction.SETTLE,
        prompt_tokens=20,
        completion_tokens=3,
        estimated=True,
        lifecycle_status="client_disconnected",
    )
    await repository.finalize(db, command)
    assert (await repository.finalize(db, command)).replayed
    await db.flush()

    metadata = (
        await db.scalar(
            select(RequestLifecycle).where(RequestLifecycle.request_id == request_id)
        )
    ).lifecycle_metadata
    assert metadata["repeat_digest"] == ("b" * 64 if kept else None)
    assert metadata["deployment_id"] == deployment_id


@pytest.mark.asyncio
async def test_a_privacy_block_is_listed_as_rejected_with_its_counts(
    db, test_api_key, monkeypatch
) -> None:
    prepared = _prepared()
    prepared.tenant_id = test_api_key.organization_id
    prepared.api_key_id = test_api_key.id
    started_at = datetime.now(timezone.utc)
    await DurableAccountingRepository().reserve_quota(
        db,
        QuotaReservationCommand(
            tenant_id=prepared.tenant_id,
            api_key_id=prepared.api_key_id,
            request_id=prepared.request_id,
            requested_model=prepared.model,
            source_endpoint="chat.completions",
            started_at=started_at,
            reconciliation_due_at=started_at + timedelta(minutes=2),
            estimated_input_tokens=20,
            maximum_output_tokens=30,
            policy=QuotaPolicySnapshot("test", None, None, None),
        ),
    )
    prepared.privacy = PrivacyOutcome(
        action=PrivacyAction.SCRUBBED,
        pii_detected=True,
        verification_map={"<EMAIL_ADDRESS_ff8d9819>": "alice@example.com"},
        pii_entities={"EMAIL_ADDRESS": 1},
        blocked_entities={"SECRET": 1},
    )
    prepared.record_verdict(
        "privacy.input", stage="privacy", outcome="deny", reason_code="SECRET_BLOCKED"
    )

    @asynccontextmanager
    async def session_scope():
        yield db

    usage = DurableUsageLifecycle(DurableAccountingCoordinator(), session_scope)
    await usage.record_privacy(prepared)
    await usage.fail(prepared, reason="request_aborted")

    lifecycle = (
        await db.execute(
            select(RequestLifecycle).where(
                RequestLifecycle.request_id == prepared.request_id
            )
        )
    ).scalar_one()
    counts = {
        "pii_entities": {"EMAIL_ADDRESS": 1},
        "monitored_entities": {},
        "blocked_entities": {"SECRET": 1},
    }
    assert (lifecycle.status, lifecycle.terminal_error_code) == (
        "rejected",
        "SECRET_BLOCKED",
    )
    assert {key: lifecycle.lifecycle_metadata[key] for key in counts} == counts
    event = (
        await db.execute(
            select(OutboxEvent).where(
                OutboxEvent.aggregate_id == prepared.request_id,
                OutboxEvent.event_type == "analytics.request_failed",
            )
        )
    ).scalar_one()
    monkeypatch.setattr(analytics_projection, "AsyncSessionLocal", session_scope)
    await analytics_projection.project_request(OutboxMessage.from_event(event))
    page = await management.activity.list_requests(
        start=started_at - timedelta(minutes=1),
        end=None,
        status_filter=None,
        model=None,
        request_id=prepared.request_id,
        pii_detected=None,
        tag=None,
        cost_center=None,
        limit=1,
        offset=0,
        user=SimpleNamespace(
            custom_role_id=None, role="owner", organization_id=prepared.tenant_id
        ),
        session=db,
    )
    item = page.items[0]
    assert item.status == "rejected"
    assert (item.pii_entities, item.monitored_entities, item.blocked_entities) == (
        counts["pii_entities"],
        counts["monitored_entities"],
        counts["blocked_entities"],
    )


@pytest.mark.parametrize(
    ("outcome", "reason", "approval_id"),
    [
        ("deny", "APPROVAL_REQUIRED", str(uuid4())),
        ("deny", "APPROVAL_REJECTED", str(uuid4())),
        ("allow", "RULE_APPROVED", str(uuid4())),
        ("deny", "APPROVAL_QUEUE_FULL", None),
        ("deny", "RULE_BLOCKED", None),
    ],
    ids=["required", "rejected", "consumed", "queue_full", "no_gate"],
)
@pytest.mark.asyncio
async def test_the_approval_id_is_recorded_listed_and_filtered(
    db, test_api_key, monkeypatch, outcome, reason, approval_id
) -> None:
    prepared = _prepared()
    prepared.tenant_id = test_api_key.organization_id
    prepared.api_key_id = test_api_key.id
    prepared.approval_id = approval_id
    started_at = datetime.now(timezone.utc)
    await DurableAccountingRepository().reserve_quota(
        db,
        QuotaReservationCommand(
            tenant_id=prepared.tenant_id,
            api_key_id=prepared.api_key_id,
            request_id=prepared.request_id,
            requested_model=prepared.model,
            source_endpoint="chat.completions",
            started_at=started_at,
            reconciliation_due_at=started_at + timedelta(minutes=2),
            estimated_input_tokens=20,
            maximum_output_tokens=30,
            policy=QuotaPolicySnapshot("test", None, None, None),
        ),
    )
    prepared.privacy = PrivacyOutcome(action=PrivacyAction.SCRUBBED, pii_detected=False)
    prepared.record_verdict(
        "rule.kasa", stage="rules", outcome=outcome, reason_code=reason
    )

    @asynccontextmanager
    async def session_scope():
        yield db

    usage = DurableUsageLifecycle(DurableAccountingCoordinator(), session_scope)
    await usage.record_privacy(prepared)
    await usage.fail(prepared, reason="request_aborted")

    lifecycle = (
        await db.execute(
            select(RequestLifecycle).where(
                RequestLifecycle.request_id == prepared.request_id
            )
        )
    ).scalar_one()
    assert lifecycle.lifecycle_metadata.get("approval_id", "absent") == (
        approval_id or "absent"
    )
    event = (
        await db.execute(
            select(OutboxEvent).where(
                OutboxEvent.aggregate_id == prepared.request_id,
                OutboxEvent.event_type == "analytics.request_failed",
            )
        )
    ).scalar_one()
    monkeypatch.setattr(analytics_projection, "AsyncSessionLocal", session_scope)
    await analytics_projection.project_request(OutboxMessage.from_event(event))

    async def listed(**filters) -> list:
        page = await management.activity.list_requests(
            start=started_at - timedelta(minutes=1),
            end=None,
            status_filter=None,
            model=None,
            pii_detected=None,
            tag=None,
            cost_center=None,
            limit=5,
            offset=0,
            user=SimpleNamespace(
                custom_role_id=None, role="owner", organization_id=prepared.tenant_id
            ),
            session=db,
            **filters,
        )
        return page.items

    [item] = await listed(request_id=prepared.request_id)
    assert (None if item.approval_id is None else str(item.approval_id)) == approval_id
    if outcome == "deny":
        assert item.status == "rejected"
    if approval_id is not None:
        assert [
            found.request_id
            for found in await listed(request_id=None, approval_id=UUID(approval_id))
        ] == [prepared.request_id]
    assert await listed(request_id=None, approval_id=uuid4()) == []


def test_a_privacy_block_before_admission_carries_its_counts_to_the_audit() -> None:
    from shim_enterprise.gateway.pipeline.outbox import rejection_intent

    prepared = _prepared()
    prepared.source_endpoint = "messages.count_tokens"
    prepared.context = SimpleNamespace(
        user_id=None, actor_type="api_key", started_at=datetime.now(timezone.utc)
    )
    prepared.privacy = PrivacyOutcome(
        action=PrivacyAction.SCRUBBED, pii_detected=True, blocked_entities={"SECRET": 1}
    )
    prepared.record_verdict(
        "privacy.input", stage="privacy", outcome="deny", reason_code="SECRET_BLOCKED"
    )
    extra = rejection_intent(prepared).payload["extra"]

    assert extra["lifecycle_status"] == "rejected"
    assert extra["blocked_entities"] == {"SECRET": 1}
    prepared.privacy = None
    assert "blocked_entities" not in rejection_intent(prepared).payload["extra"]


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
    prepared.model = prepared.pricing_model = UNSPECIFIED_PROVIDER_MODEL

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
    # The admission estimate and the reserved maximum output, as a JSON answer without usage.
    assert (terminal.usage.prompt_tokens, terminal.usage.completion_tokens) == (20, 30)
    assert terminal.usage.estimated is True
    assert terminal.usage.settlement_cost_usd == compute_cost_usd(
        "gpt-5.6-luna", 20, 30, "openai"
    )
    assert terminal.usage.provider_finish_reasons is None
    assert terminal.usage.ttft_ms is None
    assert terminal.usage.provider_latency_ms is None


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
        policy_verdicts=[],
        rules=None,
        rules_evaluated=False,
        rule_matches=[],
        settings_applied=None,
        transforms_applied=None,
        route_decision=None,
        attempt=None,
        shadow=None,
        concurrency_lease=None,
        approval_id=None,
        tenant_id=uuid4(),
        request_id=f"req_{uuid4().hex}",
        privacy=PrivacyOutcome(
            action=PrivacyAction.SCRUBBED,
            pii_detected=True,
            pii_entities={"EMAIL_ADDRESS": 1},
            verification_map={"<EMAIL_ADDRESS_ff8d9819>": "alice@example.com"},
        ),
    )

    with patch(
        "shim_enterprise.gateway.pipeline.quota_reservation.RequestLifecycleRepository.update",
        new=AsyncMock(return_value=SimpleNamespace()),
    ) as update_lifecycle:
        await DurableAccountingCoordinator().record_privacy(checked, session)

    values = dict(update_lifecycle.await_args.kwargs["values"])
    # The JSONB merge's one bound value is everything the request adds to the metadata.
    merged = list(values.pop("lifecycle_metadata").compile().params.values())
    assert merged == [
        {
            "policy_verdicts": [],
            "pii_entities": {"EMAIL_ADDRESS": 1},
            "monitored_entities": {},
            "blocked_entities": {},
            "bulk_disclosure": None,
            "repeat_digest": None,
        }
    ]
    assert values == {
        "privacy_status": "scrubbed",
        "pii_detected": True,
    }
    assert "alice@example.com" not in json.dumps([values, merged])
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
    prepared.model = prepared.pricing_model = UNSPECIFIED_PROVIDER_MODEL
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
    prepared.model = prepared.pricing_model = "gpt-5.6"
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
    prepared.model = prepared.pricing_model = UNSPECIFIED_PROVIDER_MODEL
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
    assert terminal.usage.provider_finish_reasons == {"status": "failed"}
    assert terminal.usage.ttft_ms is None


@pytest.mark.asyncio
async def test_nonstream_response_is_constructed_before_terminal_settlement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    response = SimpleNamespace(status_code=200, headers={})

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
        lifecycle_status="failed",
        reserved=None,
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
        lifecycle_status="failed",
        reserved=None,
    )


@pytest.mark.parametrize(
    ("status_code", "error_code"),
    [
        (400, "PROVIDER_REJECTED_REQUEST"),
        (401, "INVALID_PROVIDER_CREDENTIAL"),
        (422, "PROVIDER_REJECTED_REQUEST"),
        (400, "INVALID_REQUEST"),
    ],
)
@pytest.mark.asyncio
async def test_a_provider_refusal_after_start_is_refunded_as_a_rejection(
    monkeypatch: pytest.MonkeyPatch, status_code: int, error_code: str
) -> None:
    prepared = _prepared()
    accounting = SimpleNamespace(
        failure_reservation_state=AsyncMock(return_value=_failure_state(True, True)),
        refund=AsyncMock(),
    )

    @asynccontextmanager
    async def session_scope():
        yield object()

    async def run_stage(stage, _value):
        if stage.name == "provider_execution":
            raise ProviderCallError(status_code, error_code, False, provider="openai")
        return prepared

    monkeypatch.setattr(kernel_module, "run_stage", run_stage)
    usage = DurableUsageLifecycle(accounting, session_scope)
    usage.record_privacy = AsyncMock()
    execution = SimpleNamespace(pii_scrubber=object())
    kernel = GatewayKernel(
        {"openai": execution},
        chain_store=object(),
        policy_resolver=object(),
        rate_limiter=object(),
        loop_detector=object(),
        loop_repeat_limit=3,
        loop_window_seconds=60,
        cost_tag_max_length=64,
        usage=usage,
    )

    with pytest.raises(ProviderCallError):
        await kernel._execute(SimpleNamespace(provider="openai"))

    assert accounting.refund.await_args.kwargs["error_code"] == "PROVIDER_UNAVAILABLE"
    assert accounting.refund.await_args.kwargs["spend_reserved"] is True


@pytest.mark.parametrize("spend_reserved", [True, False])
@pytest.mark.asyncio
async def test_failure_after_openai_start_settles_unverified_usage_at_the_reservation(
    spend_reserved: bool,
) -> None:
    prepared = _prepared()
    state = replace(
        _failure_state(True, spend_reserved),
        prompt_tokens=20,
        completion_tokens=30,
        cost_usd=Decimal("0.000041") if spend_reserved else Decimal("0"),
    )
    accounting = SimpleNamespace(
        failure_reservation_state=AsyncMock(return_value=state),
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
        lifecycle_status="failed",
        reserved=state,
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
        lifecycle_status="failed",
        reserved=None,
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
async def test_a_spend_estimate_reads_back_exactly_at_ledger_precision(
    db,
    test_api_key,
) -> None:
    repository = DurableAccountingRepository()
    request_id = f"req_precision_{uuid4().hex}"
    started_at = datetime.now(timezone.utc)
    await repository.reserve_quota(
        db,
        QuotaReservationCommand(
            tenant_id=test_api_key.organization_id,
            api_key_id=test_api_key.id,
            request_id=request_id,
            requested_model="gpt-6-luna",
            source_endpoint="chat.completions",
            started_at=started_at,
            reconciliation_due_at=started_at + timedelta(minutes=2),
            estimated_input_tokens=91,
            maximum_output_tokens=128_000,
            policy=QuotaPolicySnapshot(
                version="precision-quota-v1",
                daily_request_limit=None,
                monthly_request_limit=1000,
                monthly_token_limit=1_000_000,
            ),
        ),
    )
    # Unrounded, this estimate has nine decimal places and Postgres stored a
    # rounded copy that no longer matched the command: a 503 on every such request.
    estimate = compute_cost_usd(
        "gpt-6-luna",
        91,
        128_000,
        price=ModelPrice(
            input_per_million=Decimal("0.125"),
            output_per_million=Decimal("0.5"),
        ),
    )
    command = SpendReservationCommand(
        tenant_id=test_api_key.organization_id,
        api_key_id=test_api_key.id,
        request_id=request_id,
        requested_model="gpt-6-luna",
        provider="openai",
        provider_model="gpt-6-luna",
        estimated_cost_usd=estimate,
        pricing_metadata={"catalog_version": "catalog-v1"},
        cache_status="miss",
        audit_policy_mode="off",
        policy=SpendPolicySnapshot(
            version="precision-spend-v1", monthly_limit_usd=None
        ),
    )

    reservation = await repository.reserve_provider_spend(db, command)
    replay = await repository.reserve_provider_spend(db, command)

    stored = await db.get(UsageLedger, reservation.event_id)
    assert stored is not None
    assert stored.cost_usd == estimate == Decimal("0.06401138")
    assert replay.replayed


@pytest.mark.asyncio
@pytest.mark.parametrize("pricing_resolution", ["catalog", "unknown"])
async def test_spend_pricing_metadata_survives_terminal_fallback(
    db,
    test_api_key,
    pricing_resolution,
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
        "pricing_resolution": pricing_resolution,
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
    outbox_event = (
        await db.execute(
            select(OutboxEvent).where(
                OutboxEvent.aggregate_id == request_id,
                OutboxEvent.event_type == "analytics.request_completed",
            )
        )
    ).scalar_one()
    assert outbox_event.payload["pricing_resolution"] == pricing_resolution
    values = analytics_projection._projection_values(
        OutboxMessage.from_event(outbox_event)
    )
    assert values["details"]["pricing_resolution"] == pricing_resolution
    db.add(analytics_projection.RequestLog(**values))
    await db.flush()
    page = await management.activity.list_requests(
        start=None,
        end=None,
        status_filter=None,
        model=None,
        request_id=request_id,
        pii_detected=None,
        tag=None,
        cost_center=None,
        system_prompt_hash=None,
        limit=10,
        offset=0,
        user=SimpleNamespace(
            id=uuid4(),
            kind="human",
            role="owner",
            custom_role_id=None,
            organization_id=test_api_key.organization_id,
        ),
        session=db,
    )
    summary_row = (
        await db.execute(
            overview._summary_statement(
                test_api_key.organization_id,
                datetime.now(timezone.utc) - timedelta(days=1),
                datetime.now(timezone.utc) + timedelta(days=1),
            ).where(RequestLifecycle.request_id == request_id)
        )
    ).one()
    overview_summary = overview._summary_from_row(summary_row)
    assert overview_summary.requests == 1
    assert overview_summary.p95_completed_shim_latency_ms is None
    assert page.summary.p95_completed_shim_latency_ms is None
    assert page.items[0].shim_latency_ms is None
    assert overview_summary.cost_complete is (pricing_resolution != "unknown")
    assert overview_summary.unpriced_requests == (pricing_resolution == "unknown")
    assert overview_summary.settled_spend_usd == (
        None if pricing_resolution == "unknown" else Decimal("0.00004")
    )
    budget_usage = await BudgetEvaluator().aggregate(
        db,
        SimpleNamespace(organization_id=test_api_key.organization_id, scope_type="org"),
        datetime.now(timezone.utc) - timedelta(days=1),
    )
    assert budget_usage.unpriced_requests == (pricing_resolution == "unknown")
    assert budget_usage.cost_usd == (
        0 if pricing_resolution == "unknown" else Decimal("0.00004")
    )
    assert budget_usage.top_contributors[0]["cost_complete"] is (
        pricing_resolution != "unknown"
    )
    start = datetime.now(timezone.utc) - timedelta(days=1)
    end = datetime.now(timezone.utc) + timedelta(days=1)
    user = SimpleNamespace(
        id=test_api_key.user_id,
        organization_id=test_api_key.organization_id,
        kind="human",
    )
    billing = await management.usage.billing_usage(start, end, user, db)
    expected_cost = None if pricing_resolution == "unknown" else 0.00004
    assert billing.total_cost == expected_cost
    assert billing.daily_usage[0].cost_usd == expected_cost
    assert billing.cost_complete is (pricing_resolution != "unknown")
    assert billing.unpriced_requests == (pricing_resolution == "unknown")
    breakdown = await management.usage.billing_breakdown(
        start, end, "model", 100, user, db
    )
    assert breakdown.rows[0].cost_usd == (
        None if pricing_resolution == "unknown" else Decimal("0.00004")
    )
    exported = await management.usage.export_billing_breakdown(
        start, end, "model", "csv", user, db
    )
    csv_row = next(
        csv.DictReader(io.StringIO(bytes(exported.body).decode("utf-8-sig")))
    )
    assert csv_row["cost_usd"] == (
        "" if pricing_resolution == "unknown" else "0.00004000"
    )
    assert csv_row["cost_complete"] == str(pricing_resolution != "unknown")
    assert csv_row["unpriced_requests"] == str(int(pricing_resolution == "unknown"))
    assert page.total == 1
    assert page.items[0].cost_complete is (pricing_resolution != "unknown")
    assert page.summary.cost_complete is (pricing_resolution != "unknown")
    if pricing_resolution == "unknown":
        assert page.items[0].cost_usd is None
        assert page.summary.unpriced_requests == 1
        assert page.summary.settled_spend_usd == 0
    else:
        assert page.items[0].cost_usd == Decimal("0.00004")
        assert page.summary.unpriced_requests == 0
        assert page.summary.settled_spend_usd == Decimal("0.00004")


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


@pytest.mark.asyncio
async def test_quota_policy_uses_shared_tier_lock_and_exclusive_key_lock():
    from sqlalchemy.dialects import postgresql

    session = SimpleNamespace(
        scalar=AsyncMock(return_value=SimpleNamespace(role="member")),
        execute=AsyncMock(
            side_effect=[
                SimpleNamespace(
                    scalar_one_or_none=lambda: SimpleNamespace(
                        id=uuid4(),
                        billing_revision=0,
                        updated_at=None,
                        quota_monthly_request_limit=None,
                        quota_monthly_token_limit=None,
                    )
                ),
                SimpleNamespace(
                    scalar_one_or_none=lambda: SimpleNamespace(
                        tier="free",
                        expires_at=None,
                        is_active=True,
                        allowed_models=None,
                        user_id=uuid4(),
                        organization_id=uuid4(),
                        team_id=None,
                    )
                ),
                SimpleNamespace(
                    scalar_one_or_none=lambda: SimpleNamespace(
                        slug="free",
                        daily_request_limit=10,
                        monthly_request_limit=100,
                        monthly_token_limit=1000,
                    )
                ),
            ]
        ),
    )
    policy = await AccountingPolicyLoader().quota(session, _prepared())
    statements = [
        str(call.args[0].compile(dialect=postgresql.dialect()))
        for call in session.execute.await_args_list
    ]
    assert statements[0].endswith("FOR NO KEY UPDATE OF organizations")
    assert statements[1].endswith("FOR NO KEY UPDATE")
    assert statements[2].endswith("FOR SHARE")
    assert policy.daily_request_limit == 10


@pytest.mark.asyncio
async def test_spend_policy_takes_a_key_share_lock_on_the_provider_secret():
    from sqlalchemy.dialects import postgresql

    session = SimpleNamespace(
        execute=AsyncMock(return_value=SimpleNamespace(scalar_one_or_none=lambda: None))
    )

    await AccountingPolicyLoader().spend(session, _prepared(), ephemeral_byok=False)

    (call,) = session.execute.await_args_list
    statement = str(call.args[0].compile(dialect=postgresql.dialect()))
    # A deployment's foreign key into provider_secrets must not wait for spend.
    assert statement.endswith("FOR NO KEY UPDATE")


@pytest.mark.asyncio
async def test_shared_tier_allows_independent_reservations_but_fences_edits(
    async_engine,
):
    from sqlalchemy import update
    from shim_enterprise.billing.ledger import QuotaLimitExceeded
    from shim_enterprise.tenants.models import TierDefinition

    factory = async_sessionmaker(async_engine, expire_on_commit=False)
    slug = f"lock-test-{uuid4().hex}"
    async with factory.begin() as setup:
        setup.add(
            TierDefinition(
                slug=slug,
                name="Lock test",
                rate_limit_rpm=60,
                rate_limit_tpm=1000,
                daily_request_limit=1,
                monthly_request_limit=1,
                monthly_token_limit=1000,
            )
        )
        await setup.flush()
        tenants = [await _create_tenant(setup, label) for label in ("lock-a", "lock-b")]
        await setup.execute(
            update(ApiKey)
            .where(ApiKey.id.in_([key for _, _, key in tenants]))
            .values(tier=slug)
        )

    async def reserve(session, tenant):
        prepared = _prepared()
        prepared.tenant_id, _, prepared.api_key_id = tenant
        policy = await AccountingPolicyLoader().quota(session, prepared)
        now = datetime.now(timezone.utc)
        await DurableAccountingRepository().reserve_quota(
            session,
            QuotaReservationCommand(
                tenant_id=prepared.tenant_id,
                api_key_id=prepared.api_key_id,
                request_id=prepared.request_id,
                requested_model=prepared.model,
                source_endpoint="chat.completions",
                started_at=now,
                reconciliation_due_at=now + timedelta(minutes=2),
                estimated_input_tokens=1,
                maximum_output_tokens=1,
                policy=policy,
            ),
        )
        return policy

    try:
        async with factory() as first, factory() as second, factory() as contender:
            await reserve(first, tenants[0])
            await second.execute(text("SET LOCAL lock_timeout = '500ms'"))
            # This must succeed while the first tenant still holds its tier lock.
            snapshot = await reserve(second, tenants[1])
            assert snapshot.daily_request_limit == 1

            await contender.execute(text("SET LOCAL lock_timeout = '100ms'"))
            with pytest.raises(DBAPIError) as same_key:
                await reserve(contender, tenants[0])
            assert same_key.value.orig.sqlstate == "55P03"
            await contender.rollback()
            await first.commit()
            with pytest.raises(QuotaLimitExceeded):
                await reserve(contender, tenants[0])
            await contender.rollback()

            tier_update = (
                update(TierDefinition)
                .where(TierDefinition.slug == slug)
                .values(daily_request_limit=2, monthly_request_limit=2)
            )
            await contender.execute(text("SET LOCAL lock_timeout = '100ms'"))
            with pytest.raises(DBAPIError) as policy_edit:
                await contender.execute(tier_update)
            assert policy_edit.value.orig.sqlstate == "55P03"
            await contender.rollback()
            await second.rollback()
            await contender.execute(tier_update)
            await contender.commit()
            revised = await reserve(contender, tenants[1])
            assert (revised.daily_request_limit, revised.monthly_request_limit) == (
                2,
                2,
            )
            assert revised.version != snapshot.version
    finally:
        async with factory.begin() as cleanup:
            ids = [organization for organization, _, _ in tenants]
            for model in (
                UsageLedger,
                RequestLifecycle,
                QuotaPeriodUsage,
                ApiKey,
                User,
            ):
                await cleanup.execute(
                    delete(model).where(model.organization_id.in_(ids))
                )
            await cleanup.execute(delete(Organization).where(Organization.id.in_(ids)))
            await cleanup.execute(
                delete(TierDefinition).where(TierDefinition.slug == slug)
            )


@pytest.mark.asyncio
async def test_shim_latency_percentiles_exclude_historical_durations(db, test_api_key):
    repository = DurableAccountingRepository()
    now = datetime.now(timezone.utc)
    request_ids = []
    for measured in (None, 0):
        request_id = f"req_latency_{uuid4().hex}"
        request_ids.append(request_id)
        await repository.reserve_quota(
            db,
            QuotaReservationCommand(
                tenant_id=test_api_key.organization_id,
                api_key_id=test_api_key.id,
                request_id=request_id,
                requested_model="gpt-5.6-luna",
                source_endpoint="chat.completions",
                started_at=now - timedelta(seconds=20),
                reconciliation_due_at=now + timedelta(minutes=2),
                estimated_input_tokens=20,
                maximum_output_tokens=30,
                policy=QuotaPolicySnapshot("test", None, None, None),
            ),
        )
        await repository.finalize(
            db,
            FinalizationCommand(
                tenant_id=test_api_key.organization_id,
                request_id=request_id,
                quota_action=TerminalAction.SETTLE,
                completed_at=now,
                shim_latency_ms=measured,
            ),
        )
        event = (
            await db.execute(
                select(OutboxEvent).where(
                    OutboxEvent.aggregate_id == request_id,
                    OutboxEvent.event_type == "analytics.request_completed",
                )
            )
        ).scalar_one()
        db.add(
            analytics_projection.RequestLog(
                **analytics_projection._projection_values(
                    OutboxMessage.from_event(event)
                )
            )
        )
    await db.flush()
    overview_row = (
        await db.execute(
            overview._summary_statement(
                test_api_key.organization_id,
                now - timedelta(days=1),
                now + timedelta(days=1),
            ).where(RequestLifecycle.request_id.in_(request_ids))
        )
    ).one()
    request_row = (
        await db.execute(
            management.activity._request_summary_statement(
                test_api_key.organization_id,
                [
                    analytics_projection.RequestLog.organization_id
                    == test_api_key.organization_id,
                    analytics_projection.RequestLog.request_id.in_(request_ids),
                ],
            )
        )
    ).one()
    assert overview_row.requests == request_row.requests == 2
    assert overview_row.p95_completed_shim_latency_ms == 0
    assert request_row.p95_completed_shim_latency_ms == 0


@pytest.mark.asyncio
async def test_key_cost_center_and_header_tags_reach_the_quota_reservation() -> None:
    attribution = CostAttribution.resolve(
        "kampanya-ekim",
        api_key_cost_center="bireysel",
        maximum_length=64,
    )
    repository = SimpleNamespace(
        reserve_quota=AsyncMock(return_value=SimpleNamespace(replayed=False))
    )
    policy_loader = SimpleNamespace(
        quota=AsyncMock(return_value=QuotaPolicySnapshot("quota-v1", None, None, None))
    )
    prepared = _prepared()
    prepared.source_endpoint = "/v1/chat/completions"
    prepared.context.started_at = datetime.now(timezone.utc)
    prepared.policy = SimpleNamespace(team=None)
    session = SimpleNamespace(commit=AsyncMock(), rollback=AsyncMock())

    await DurableAccountingCoordinator(
        repository=repository,
        policy_loader=policy_loader,
    ).reserve_quota(
        prepared,
        AdmissionState(
            estimated_input_tokens=20,
            maximum_output_tokens=30,
            cost_center=attribution.cost_center,
            tags=attribution.tags,
        ),
        session,
    )

    command = repository.reserve_quota.await_args.args[1]
    assert command.cost_center == "bireysel"
    assert command.tags == ("kampanya-ekim",)


async def _drop_tenant(factory, organization_id: UUID) -> None:
    async with factory.begin() as cleanup:
        for model in (
            AuditIntent,
            OutboxEvent,
            UsageLedger,
            RequestLifecycle,
            QuotaPeriodUsage,
            SpendPeriodUsage,
            ProviderSecret,
            ApiKey,
            User,
        ):
            await cleanup.execute(
                delete(model).where(model.organization_id == organization_id)
            )
        await cleanup.execute(
            delete(Organization).where(Organization.id == organization_id)
        )


async def _cap_organization(session: AsyncSession, organization_id: UUID) -> None:
    organization = await session.get(Organization, organization_id)
    assert organization is not None
    organization.quota_monthly_request_limit = 1000
    organization.quota_monthly_token_limit = 1_000_000


@pytest.mark.asyncio
async def test_settlement_foreign_keys_do_not_wait_for_an_admission(async_engine):
    factory = async_sessionmaker(async_engine, expire_on_commit=False)
    async with factory.begin() as setup:
        organization_id, _, api_key_id = await _create_tenant(setup, "fence")
        await _cap_organization(setup, organization_id)

    async def reserve(session: AsyncSession, started_at: datetime) -> str:
        prepared = _prepared()
        prepared.tenant_id, prepared.api_key_id = organization_id, api_key_id
        await DurableAccountingRepository().reserve_quota(
            session,
            QuotaReservationCommand(
                tenant_id=organization_id,
                api_key_id=api_key_id,
                request_id=prepared.request_id,
                requested_model=prepared.model,
                source_endpoint="chat.completions",
                started_at=started_at,
                reconciliation_due_at=started_at + timedelta(minutes=2),
                estimated_input_tokens=20,
                maximum_output_tokens=30,
                policy=await AccountingPolicyLoader().quota(session, prepared),
                audit_policy_mode="best_effort",
            ),
        )
        return prepared.request_id

    now = datetime.now(timezone.utc)
    try:
        async with factory() as earlier:
            # Last month's counters: settlement then shares only the fenced rows.
            earlier_request = await reserve(
                earlier, now.replace(day=1) - timedelta(days=1)
            )
            await earlier.commit()
        async with factory() as admission, factory() as settlement:
            admitted_request = await reserve(admission, now)
            await settlement.execute(text("SET LOCAL lock_timeout = '2s'"))
            await DurableAccountingRepository().finalize(
                settlement,
                FinalizationCommand(
                    tenant_id=organization_id,
                    request_id=earlier_request,
                    quota_action=TerminalAction.SETTLE,
                    prompt_tokens=20,
                    completion_tokens=2,
                    lifecycle_status="completed",
                ),
            )
            await settlement.commit()
            await admission.commit()
        async with factory() as verification:
            statuses = dict(
                (
                    await verification.execute(
                        select(
                            RequestLifecycle.request_id, RequestLifecycle.status
                        ).where(RequestLifecycle.organization_id == organization_id)
                    )
                ).all()
            )
        assert statuses == {earlier_request: "completed", admitted_request: "accepted"}
    finally:
        await _drop_tenant(factory, organization_id)


@pytest.mark.asyncio
async def test_admission_fence_still_serializes_admissions_and_cap_activation(
    async_engine,
):
    factory = async_sessionmaker(async_engine, expire_on_commit=False)
    second_key_id = uuid4()
    async with factory.begin() as setup:
        organization_id, user_id, api_key_id = await _create_tenant(setup, "serial")
        setup.add(
            ApiKey(
                id=second_key_id,
                organization_id=organization_id,
                user_id=user_id,
                key_hash=f"serial-{uuid4().hex}",
                prefix="sk-serial",
                tier="free",
                is_active=True,
            )
        )

    def prepared(key_id: UUID) -> SimpleNamespace:
        value = _prepared()
        value.tenant_id, value.api_key_id = organization_id, key_id
        return value

    async def lock_wait(session: AsyncSession, operation) -> str:
        await session.execute(text("SET LOCAL lock_timeout = '100ms'"))
        with pytest.raises(DBAPIError) as waited:
            await operation
        await session.rollback()
        return waited.value.orig.sqlstate

    try:
        async with factory() as admission, factory() as contender:
            await AccountingPolicyLoader().quota(admission, prepared(api_key_id))
            other_key = AccountingPolicyLoader().quota(
                contender, prepared(second_key_id)
            )
            assert await lock_wait(contender, other_key) == "55P03"
            activation = configure_organization_quota(contender, organization_id)
            assert await lock_wait(contender, activation) == "55P03"
            await admission.rollback()

            await configure_organization_quota(contender, organization_id)
            admitting = AccountingPolicyLoader().quota(admission, prepared(api_key_id))
            assert await lock_wait(admission, admitting) == "55P03"
            await contender.rollback()
    finally:
        await _drop_tenant(factory, organization_id)


@pytest.mark.asyncio
async def test_parallel_admit_and_settle_cycles_for_one_tenant_do_not_deadlock(
    async_engine,
):
    factory = async_sessionmaker(async_engine, expire_on_commit=False)
    async with factory.begin() as setup:
        organization_id, _, api_key_id = await _create_tenant(setup, "parallel")
        await _cap_organization(setup, organization_id)
        setup.add(
            ProviderSecret(
                organization_id=organization_id,
                provider="openai",
                secret_ref="reference-parallel",
                secret_backend="fernet",
                secret_version="v2",
                masked_key="masked",
                monthly_limit_usd=Decimal("100"),
            )
        )
    coordinator = DurableAccountingCoordinator()

    async def cycle() -> None:
        prepared = _prepared()
        prepared.tenant_id, prepared.api_key_id = organization_id, api_key_id
        prepared.source_endpoint = "chat.completions"
        prepared.policy = SimpleNamespace(team=None)
        prepared.context.started_at = datetime.now(timezone.utc)
        prepared.admission.cost_center = "untagged"
        prepared.admission.tags = ()
        prepared.admission.repeat_chain_length = None
        async with factory() as session:
            await coordinator.reserve_quota(prepared, prepared.admission, session)
        async with factory() as session:
            await coordinator.reserve_spend(prepared, False, session)
        async with factory() as session:
            await coordinator.finalize(
                session,
                FinalizationCommand(
                    tenant_id=organization_id,
                    request_id=prepared.request_id,
                    quota_action=TerminalAction.SETTLE,
                    spend_action=TerminalAction.SETTLE,
                    prompt_tokens=20,
                    completion_tokens=2,
                    actual_cost_usd=Decimal("0.00001"),
                    provider_model=prepared.pricing_model,
                    lifecycle_status="completed",
                ),
            )

    try:
        results = await asyncio.gather(
            *(cycle() for _ in range(20)), return_exceptions=True
        )
        failures = [
            (
                type(result).__name__,
                getattr(getattr(result.__cause__, "orig", None), "sqlstate", None),
            )
            for result in results
            if isinstance(result, BaseException)
        ]
        assert failures == []
        async with factory() as verification:
            statuses = (
                await verification.scalars(
                    select(RequestLifecycle.status).where(
                        RequestLifecycle.organization_id == organization_id
                    )
                )
            ).all()
        assert statuses == ["completed"] * 20
    finally:
        await _drop_tenant(factory, organization_id)


def _admitted(organization_id: UUID, api_key_id: UUID) -> SimpleNamespace:
    prepared = _prepared()
    prepared.tenant_id, prepared.api_key_id = organization_id, api_key_id
    prepared.source_endpoint = "chat.completions"
    prepared.policy = SimpleNamespace(team=None)
    prepared.context.started_at = datetime.now(timezone.utc)
    prepared.admission.cost_center = "untagged"
    prepared.admission.tags = ()
    prepared.admission.repeat_chain_length = None
    return prepared


@pytest.mark.asyncio
async def test_streams_cut_after_the_first_token_settle_at_the_reservation_and_fill_the_cap(
    async_engine,
):
    factory = async_sessionmaker(async_engine, expire_on_commit=False)
    coordinator = DurableAccountingCoordinator()
    usage = DurableUsageLifecycle(coordinator, factory)
    reservation = compute_cost_usd("gpt-5.6-luna", 20, 100_000, "openai")
    async with factory.begin() as setup:
        organization_id, _, api_key_id = await _create_tenant(setup, "cutstream")
        await _cap_organization(setup, organization_id)
        setup.add(
            ProviderSecret(
                organization_id=organization_id,
                provider="openai",
                secret_ref="reference-cutstream",
                secret_backend="fernet",
                secret_version="v2",
                masked_key="masked",
                # Room for two reserved maximums, not three.
                monthly_limit_usd=reservation * 5 / 2,
            )
        )

    def request() -> SimpleNamespace:
        prepared = _admitted(organization_id, api_key_id)
        prepared.stream = True
        prepared.admission.maximum_output_tokens = 100_000
        return prepared

    async def admit(prepared) -> None:
        async with factory() as session:
            await coordinator.reserve_quota(prepared, prepared.admission, session)
        async with factory() as session:
            await coordinator.reserve_spend(prepared, False, session)

    async def events():
        yield b'data: {"choices":[{"index":0,"delta":{"content":"Hello"}}]}\n\n'
        # The provider's bill, which the client hangs up before.
        yield (
            b'data: {"choices":[{"index":0,"finish_reason":"stop"}],"usage":'
            b'{"prompt_tokens":50,"completion_tokens":90020}}\n\ndata: [DONE]\n\n'
        )

    try:
        cut = [request(), request()]
        for prepared in cut:
            await admit(prepared)
            await usage.mark_provider_started(prepared)
            stream = _postprocessor(usage).create_stream_session(prepared)
            stream.bind(events())
            await anext(stream)
            await stream.aclose()
            assert stream.terminal_status == "client_disconnected"

        refused = request()
        with pytest.raises(SpendLimitExceeded):
            await admit(refused)

        async with factory() as verification:
            period = await verification.scalar(
                select(SpendPeriodUsage).where(
                    SpendPeriodUsage.organization_id == organization_id
                )
            )
            settlements = (
                await verification.execute(
                    select(UsageLedger.cost_usd, UsageLedger.estimated).where(
                        UsageLedger.organization_id == organization_id,
                        UsageLedger.event_type == "spend_settlement",
                    )
                )
            ).all()
        assert period is not None
        assert (period.reserved_usd, period.settled_usd) == (0, 2 * reservation)
        assert sorted(settlements) == [(reservation, True)] * 2
    finally:
        await _drop_tenant(factory, organization_id)


async def _admitted_with_spend(
    factory, label: str, privacy: PrivacyOutcome | None = None, *, stream: bool = False
):
    """A tenant with one admitted request whose quota and provider spend are reserved."""

    coordinator = DurableAccountingCoordinator()
    async with factory.begin() as setup:
        organization_id, _, api_key_id = await _create_tenant(setup, label)
        await _cap_organization(setup, organization_id)
        setup.add(
            ProviderSecret(
                organization_id=organization_id,
                provider="openai",
                secret_ref=f"reference-{label}",
                secret_backend="fernet",
                secret_version="v2",
                masked_key="masked",
                monthly_limit_usd=Decimal("10"),
            )
        )
    prepared = _admitted(organization_id, api_key_id)
    prepared.stream = stream
    prepared.admission.maximum_output_tokens = 100_000
    async with factory() as session:
        await coordinator.reserve_quota(prepared, prepared.admission, session)
    if privacy is not None:
        prepared.privacy = privacy
        async with factory() as session:
            await coordinator.record_privacy(prepared, session)
    async with factory() as session:
        await coordinator.reserve_spend(prepared, False, session)
    return coordinator, prepared


async def _terminal_accounting(factory, organization_id: UUID):
    async with factory() as verification:
        events = {
            event.event_type: event
            for event in await verification.scalars(
                select(UsageLedger).where(
                    UsageLedger.organization_id == organization_id
                )
            )
        }
        quota = (
            await verification.scalars(
                select(QuotaPeriodUsage).where(
                    QuotaPeriodUsage.organization_id == organization_id,
                    QuotaPeriodUsage.period_type == "monthly",
                )
            )
        ).all()
        spend = await verification.scalar(
            select(SpendPeriodUsage).where(
                SpendPeriodUsage.organization_id == organization_id
            )
        )
        lifecycle = await verification.scalar(
            select(RequestLifecycle).where(
                RequestLifecycle.organization_id == organization_id
            )
        )
    assert quota and spend is not None and lifecycle is not None
    return events, quota, spend, lifecycle


_ANSWER_SNAPSHOT_KEYS = {
    "provider_latency_ms",
    "answer_characters",
    "tool_call_names",
    "reasoning_seen",
}


def _assert_settled_at_reservation(events, quota, spend) -> None:
    reserved_usd = events["spend_reservation"].cost_usd
    assert reserved_usd > 0
    assert "quota_refund" not in events and "spend_refund" not in events
    settled = events["quota_settlement"]
    assert (settled.prompt_tokens, settled.completion_tokens, settled.estimated) == (
        20,
        100_000,
        True,
    )
    assert (
        events["spend_settlement"].cost_usd,
        events["spend_settlement"].estimated,
    ) == (reserved_usd, True)
    assert {(row.reserved_tokens, row.settled_tokens) for row in quota} == {
        (0, 100_020)
    }
    assert (spend.reserved_usd, spend.settled_usd) == (0, reserved_usd)


def _assert_refunded(events, quota, spend) -> None:
    assert "quota_settlement" not in events and "spend_settlement" not in events
    assert events["quota_refund"].total_tokens == 0
    assert events["spend_refund"].cost_usd == 0
    assert {(row.reserved_tokens, row.settled_tokens) for row in quota} == {(0, 0)}
    assert (spend.reserved_usd, spend.settled_usd) == (0, 0)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "started", "settled", "error_code"),
    [
        (
            ProviderCallError(504, "PROVIDER_TIMEOUT", True, provider="openai"),
            True,
            True,
            "PROVIDER_USAGE_UNAVAILABLE",
        ),
        (
            ProviderCallError(408, "PROVIDER_TIMEOUT", True, provider="openai"),
            True,
            True,
            "PROVIDER_USAGE_UNAVAILABLE",
        ),
        (
            ProviderCallError(502, "PROVIDER_UNAVAILABLE", False, provider="openai"),
            True,
            True,
            "PROVIDER_USAGE_UNAVAILABLE",
        ),
        (asyncio.CancelledError(), True, True, "PROVIDER_USAGE_UNAVAILABLE"),
        (
            ProviderCallError(504, "PROVIDER_TIMEOUT", True, provider="openai"),
            False,
            False,
            "REQUEST_ABORTED",
        ),
        (
            ProviderCallError(
                400, "PROVIDER_REJECTED_REQUEST", False, provider="openai"
            ),
            True,
            False,
            "PROVIDER_UNAVAILABLE",
        ),
    ],
    ids=[
        "timeout-after-start",
        "provider-408-after-start",
        "5xx-after-start",
        "disconnect-after-start",
        "never-started",
        "4xx-after-start",
    ],
)
async def test_a_started_call_without_usage_settles_at_the_reservation(
    async_engine, error, started, settled, error_code
):
    # The provider was sent the call and may bill it in full: the reserved maximum
    # is the bill until reconciliation knows better. Only a call that never left,
    # or one the provider refused, gives its reservation back.
    factory = async_sessionmaker(async_engine, expire_on_commit=False)
    coordinator, prepared = await _admitted_with_spend(factory, "unverified")
    usage = DurableUsageLifecycle(coordinator, factory)
    try:
        if started:
            await usage.mark_provider_started(prepared)
        await usage.fail(prepared, reason=kernel_module._failure_reason(error))

        events, quota, spend, lifecycle = await _terminal_accounting(
            factory, prepared.tenant_id
        )
        if settled:
            _assert_settled_at_reservation(events, quota, spend)
        else:
            _assert_refunded(events, quota, spend)
        assert (lifecycle.status, lifecycle.terminal_error_code) == (
            "failed",
            error_code,
        )
        # Nothing was answered, so no answer snapshot is claimed.
        assert not _ANSWER_SNAPSHOT_KEYS & lifecycle.lifecycle_metadata.keys()
    finally:
        await _drop_tenant(factory, prepared.tenant_id)


@pytest.mark.asyncio
async def test_a_pii_bearing_request_writes_no_plaintext_to_any_durable_row(
    async_engine,
):
    factory = async_sessionmaker(async_engine, expire_on_commit=False)
    coordinator, prepared = await _admitted_with_spend(
        factory,
        "plaintext",
        PrivacyOutcome(
            action=PrivacyAction.SCRUBBED,
            pii_detected=True,
            pii_entities={"EMAIL_ADDRESS": 1},
            verification_map={"<EMAIL_ADDRESS_ff8d9819>": "alice@example.com"},
        ),
    )
    prepared.payload = {
        "messages": [{"role": "user", "content": "Write to <EMAIL_ADDRESS_ff8d9819>"}]
    }
    usage = DurableUsageLifecycle(coordinator, factory)
    try:
        await usage.mark_provider_started(prepared)
        await usage.fail(prepared, reason="request_aborted")

        written: dict[str, list[str]] = {}
        async with factory() as verification:
            for model in (RequestLifecycle, AuditIntent, OutboxEvent, UsageLedger):
                rows = await verification.scalars(
                    select(model).where(model.organization_id == prepared.tenant_id)
                )
                written[model.__tablename__] = [
                    json.dumps(
                        {
                            column.key: getattr(row, column.key)
                            for column in model.__mapper__.column_attrs
                        },
                        default=str,
                    )
                    for row in rows
                ]
        lifecycle = json.loads(written["request_lifecycle"][0])
        assert lifecycle["lifecycle_metadata"]["pii_entities"] == {"EMAIL_ADDRESS": 1}
        assert {json.loads(row)["event_type"] for row in written["audit_intent"]} == {
            "preflight",
            "completion",
        }
        assert written["outbox_event"]
        for table, rows in written.items():
            for row in rows:
                assert "alice@example.com" not in row, table
    finally:
        await _drop_tenant(factory, prepared.tenant_id)


@pytest.mark.asyncio
@pytest.mark.parametrize("started", [True, False], ids=["started", "never-started"])
async def test_stale_recovery_settles_a_started_call_at_the_reservation(
    async_engine, started
):
    factory = async_sessionmaker(async_engine, expire_on_commit=False)
    coordinator, prepared = await _admitted_with_spend(factory, "stale")
    try:
        if started:
            await DurableUsageLifecycle(coordinator, factory).mark_provider_started(
                prepared
            )
        # Due long before any other row, so recovery picks this one alone.
        due = datetime(2001, 1, 1, tzinfo=timezone.utc)
        async with factory.begin() as session:
            await session.execute(
                text(
                    "UPDATE request_lifecycle SET reconciliation_due_at = :due "
                    "WHERE organization_id = :organization_id"
                ),
                {"due": due, "organization_id": prepared.tenant_id},
            )
        async with factory.begin() as session:
            recovered = await DurableAccountingRepository().recover_stale(
                session, now=due, batch_size=1
            )
        assert [result.request_id for result in recovered] == [prepared.request_id]

        events, quota, spend, lifecycle = await _terminal_accounting(
            factory, prepared.tenant_id
        )
        if started:
            _assert_settled_at_reservation(events, quota, spend)
        else:
            _assert_refunded(events, quota, spend)
        assert (lifecycle.status, lifecycle.terminal_error_code) == (
            "failed",
            "STALE_RESERVATION_RECOVERED",
        )
        assert not _ANSWER_SNAPSHOT_KEYS & lifecycle.lifecycle_metadata.keys()
    finally:
        await _drop_tenant(factory, prepared.tenant_id)


async def _parked_stream(factory, label: str, interval: float):
    """A started stream whose client read the first byte and then stopped reading."""

    coordinator, prepared = await _admitted_with_spend(factory, label, stream=True)
    usage = DurableUsageLifecycle(coordinator, factory)
    await usage.mark_provider_started(prepared)

    async def events():
        yield b'data: {"choices":[{"index":0,"delta":{"content":"Hello"}}]}\n\n'
        yield (
            b'data: {"choices":[{"index":0,"finish_reason":"stop"}],"usage":'
            b'{"prompt_tokens":50,"completion_tokens":900}}\n\ndata: [DONE]\n\n'
        )

    stream = ResponsePostprocessor(
        usage, heartbeat_interval_seconds=interval, output_hash_salt=None
    ).create_stream_session(prepared)
    stream.bind(events())
    await anext(stream)
    # The window set at the first byte has lapsed while the client holds the stream.
    async with factory.begin() as session:
        await session.execute(
            text(
                "UPDATE request_lifecycle SET reconciliation_due_at = :due "
                "WHERE organization_id = :organization_id"
            ),
            {"due": _LAPSED, "organization_id": prepared.tenant_id},
        )
    return prepared, stream


_LAPSED = datetime(2002, 1, 1, tzinfo=timezone.utc)


@pytest.mark.asyncio
async def test_a_stream_its_client_stops_reading_is_not_recovered_and_settles_its_usage(
    async_engine,
):
    factory = async_sessionmaker(async_engine, expire_on_commit=False)
    prepared, stream = await _parked_stream(factory, "slowreader", 0.02)
    try:
        await asyncio.sleep(0.3)
        async with factory.begin() as session:
            recovered = await DurableAccountingRepository().recover_stale(
                session, now=_LAPSED
            )
        assert prepared.request_id not in {result.request_id for result in recovered}

        _ = [chunk async for chunk in stream]

        events, _, _, lifecycle = await _terminal_accounting(
            factory, prepared.tenant_id
        )
        assert (lifecycle.status, lifecycle.terminal_error_code) == ("completed", None)
        settled = events["quota_settlement"]
        assert (
            settled.prompt_tokens,
            settled.completion_tokens,
            settled.estimated,
        ) == (
            50,
            900,
            False,
        )
        assert "quota_refund" not in events and "spend_refund" not in events
    finally:
        await _drop_tenant(factory, prepared.tenant_id)


@pytest.mark.asyncio
async def test_a_settlement_after_stale_recovery_is_counted_as_a_conflict(
    async_engine, caplog
):
    factory = async_sessionmaker(async_engine, expire_on_commit=False)
    prepared, stream = await _parked_stream(factory, "conflict", 3_600)
    conflicts = USAGE_SETTLEMENT_TOTAL.labels(status="conflict")
    before = conflicts._value.get()
    try:
        async with factory.begin() as session:
            recovered = await DurableAccountingRepository().recover_stale(
                session, now=_LAPSED
            )
        assert prepared.request_id in {result.request_id for result in recovered}

        with caplog.at_level(logging.ERROR):
            _ = [chunk async for chunk in stream]

        assert conflicts._value.get() == before + 1
        assert "Settlement hit an accounting conflict" in caplog.text
        _, _, _, lifecycle = await _terminal_accounting(factory, prepared.tenant_id)
        assert (lifecycle.status, lifecycle.terminal_error_code) == (
            "failed",
            "STALE_RESERVATION_RECOVERED",
        )
    finally:
        await _drop_tenant(factory, prepared.tenant_id)


def _quota_command(
    organization_id: UUID,
    api_key_id: UUID,
    tokens: int,
    policy: QuotaPolicySnapshot,
) -> QuotaReservationCommand:
    started_at = datetime.now(timezone.utc)
    return QuotaReservationCommand(
        tenant_id=organization_id,
        api_key_id=api_key_id,
        request_id=f"req_{uuid4().hex}",
        requested_model="gpt-5.6-luna",
        source_endpoint="chat.completions",
        started_at=started_at,
        reconciliation_due_at=started_at + timedelta(minutes=2),
        estimated_input_tokens=1,
        maximum_output_tokens=tokens - 1,
        policy=policy,
    )


async def _settle_exactly(
    factory, command: QuotaReservationCommand, cost_usd: Decimal | None
) -> None:
    """Settle a reservation at what it reserved, so settled counters equal reserved ones."""

    async with factory() as session:
        await DurableAccountingRepository().finalize(
            session,
            FinalizationCommand(
                tenant_id=command.tenant_id,
                request_id=command.request_id,
                quota_action=TerminalAction.SETTLE,
                spend_action=TerminalAction.NONE
                if cost_usd is None
                else TerminalAction.SETTLE,
                prompt_tokens=command.estimated_input_tokens,
                completion_tokens=command.maximum_output_tokens,
                actual_cost_usd=cost_usd or Decimal("0"),
                provider_model="gpt-5.6-luna",
                lifecycle_status="completed",
            ),
        )
        await session.commit()


async def _reserve(factory, reserve, refusal: type[Exception] | None) -> None:
    async with factory() as session:
        if refusal is None:
            await reserve(session)
            await session.commit()
            return
        with pytest.raises(refusal):
            await reserve(session)
        await session.rollback()


_UNCAPPED = QuotaPolicySnapshot("cap-test-quota", None, None, None)


@pytest.mark.asyncio
@pytest.mark.parametrize("first", ["in_flight", "settled"])
async def test_the_provider_spend_cap_counts_in_flight_settled_and_own_spend(
    async_engine, first
):
    factory = async_sessionmaker(async_engine, expire_on_commit=False)
    repository = DurableAccountingRepository()
    async with factory.begin() as setup:
        organization_id, _, api_key_id = await _create_tenant(setup, f"spend{first[0]}")
    spend = SpendPolicySnapshot(version="cap-test", monthly_limit_usd=Decimal("10"))

    def reserve(command: QuotaReservationCommand, cost_usd: str):
        async def run(session: AsyncSession) -> None:
            await repository.reserve_quota(session, command)
            await repository.reserve_provider_spend(
                session,
                SpendReservationCommand(
                    tenant_id=organization_id,
                    api_key_id=api_key_id,
                    request_id=command.request_id,
                    requested_model="gpt-5.6-luna",
                    provider="openai",
                    provider_model="gpt-5.6-luna",
                    estimated_cost_usd=Decimal(cost_usd),
                    pricing_metadata={"catalog_version": "cap-test"},
                    cache_status="miss",
                    audit_policy_mode="off",
                    policy=spend,
                ),
            )

        return run

    try:
        earlier = _quota_command(organization_id, api_key_id, 10, _UNCAPPED)
        await _reserve(factory, reserve(earlier, "6"), None)
        if first == "settled":
            await _settle_exactly(factory, earlier, Decimal("6"))
        # $6 more crosses $10; $4 more reaches it exactly.
        crossing = _quota_command(organization_id, api_key_id, 10, _UNCAPPED)
        await _reserve(factory, reserve(crossing, "6"), SpendLimitExceeded)
        reaching = _quota_command(organization_id, api_key_id, 10, _UNCAPPED)
        await _reserve(factory, reserve(reaching, "4"), None)
        await _reserve(
            factory,
            reserve(_quota_command(organization_id, api_key_id, 10, _UNCAPPED), "0.01"),
            SpendLimitExceeded,
        )
    finally:
        await _drop_tenant(factory, organization_id)


# Each step: tokens asked for, and whether the cap refuses them.
_QUOTA_STEPS = {
    "tokens": (
        QuotaPolicySnapshot("cap-test-quota", None, None, 100),
        ((41, True), (40, False), (1, True)),
    ),
    "requests": (
        QuotaPolicySnapshot("cap-test-quota", None, 1, None),
        ((10, True),),
    ),
}


@pytest.mark.asyncio
@pytest.mark.parametrize("first", ["in_flight", "settled"])
@pytest.mark.parametrize("scope", ["api_key", "organization"])
@pytest.mark.parametrize("limit", list(_QUOTA_STEPS))
async def test_the_monthly_quota_counts_in_flight_settled_and_own_usage(
    async_engine, first, scope, limit
):
    factory = async_sessionmaker(async_engine, expire_on_commit=False)
    repository = DurableAccountingRepository()
    async with factory.begin() as setup:
        organization_id, _, api_key_id = await _create_tenant(
            setup, f"quota{limit[0]}{scope[0]}{first[0]}"
        )
    capped, steps = _QUOTA_STEPS[limit]
    # The organization's first row starts from its keys' rows, then counts on its own.
    policy = (
        capped if scope == "api_key" else replace(_UNCAPPED, organization_policy=capped)
    )

    def reserve(tokens: int, quota: QuotaPolicySnapshot):
        command = _quota_command(organization_id, api_key_id, tokens, quota)

        async def run(session: AsyncSession) -> None:
            await repository.reserve_quota(session, command)

        return command, run

    try:
        earlier, run = reserve(60, _UNCAPPED if scope == "organization" else policy)
        await _reserve(factory, run, None)
        if first == "settled":
            await _settle_exactly(factory, earlier, None)
        for tokens, refused in steps:
            await _reserve(
                factory,
                reserve(tokens, policy)[1],
                QuotaLimitExceeded if refused else None,
            )
    finally:
        await _drop_tenant(factory, organization_id)


async def _reserved_command(prepared, *, material: str | None = None):
    if material is not None:
        await LoopDetectionService(SimpleNamespace(redis=None)).check_exact_repeat(
            str(prepared.tenant_id), material, limit=4, window_seconds=300
        )
    repository = SimpleNamespace(
        reserve_quota=AsyncMock(return_value=SimpleNamespace(replayed=False))
    )
    prepared.source_endpoint = "/v1/chat/completions"
    prepared.context.started_at = datetime.now(timezone.utc)
    prepared.policy = SimpleNamespace(team=None)
    await DurableAccountingCoordinator(
        repository=repository,
        policy_loader=SimpleNamespace(
            quota=AsyncMock(return_value=QuotaPolicySnapshot("v1", None, None, None))
        ),
    ).reserve_quota(
        prepared,
        AdmissionState(
            estimated_input_tokens=20,
            maximum_output_tokens=30,
            cost_center="untagged",
            tags=(),
        ),
        SimpleNamespace(commit=AsyncMock(), rollback=AsyncMock()),
    )
    return repository.reserve_quota.await_args.args[1]


@pytest.mark.asyncio
async def test_the_reservation_names_the_registry_deployment_only() -> None:
    prepared = _prepared()
    deployment_id = str(uuid4())
    prepared.target = ProviderTarget(
        deployment_id, "https://one.invalid", "one", "secret", 30, "1"
    )

    assert (await _reserved_command(prepared)).deployment_id == deployment_id
    prepared.target = None
    assert (await _reserved_command(prepared)).deployment_id is None


@pytest.mark.asyncio
async def test_the_repeat_digest_is_keyed_per_tenant_and_installation(
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "COMPLIANCE_HASH_SALT", "installation-key-one")
    prepared = _prepared()
    value = (await _reserved_command(prepared, material="same material")).repeat_digest

    assert value is not None and re.fullmatch(r"[0-9a-f]{64}", value)
    assert value != hashlib.sha256(b"same material").hexdigest()
    again = await _reserved_command(prepared, material="same material")
    assert again.repeat_digest == value
    other = await _reserved_command(prepared, material="other material")
    assert other.repeat_digest != value
    assert (await _reserved_command(prepared)).repeat_digest is None
    other_tenant = _prepared()
    assert (
        await _reserved_command(other_tenant, material="same material")
    ).repeat_digest not in {None, value}
    monkeypatch.setattr(settings, "COMPLIANCE_HASH_SALT", "installation-key-two")
    assert (
        await _reserved_command(prepared, material="same material")
    ).repeat_digest not in {None, value}


def test_the_repeat_digest_derivation_is_pinned() -> None:
    assert keyed_repeat_digest(
        b"k" * 32, "11111111-1111-1111-1111-111111111111", "a" * 64
    ) == ("9ce1858e4e008e90f5295b2135972c3b95ecde4bf58b70b1ed752128f7209cb5")


@pytest.mark.asyncio
async def test_the_detector_digest_reaches_the_reserved_row_in_one_task(
    db, test_api_key, caplog
) -> None:
    caplog.set_level(logging.DEBUG)
    request_id = f"req_repeat_digest_{uuid4().hex}"
    prepared = PreparedInference(
        context=GatewayContext(
            request_id=request_id,
            tenant_id=test_api_key.organization_id,
            actor_type="api_key",
            api_key_id=test_api_key.id,
            user_id=None,
            endpoint="/v1/chat/completions",
            started_at=datetime.now(timezone.utc),
            tier_policy=TierPolicy(
                rate_limit_rpm=60, rate_limit_tpm=None, monthly_token_limit=None
            ),
            privacy_policy=PrivacyPolicy(pii_mode="scrub"),
            audit_policy=AuditPolicy(mode="off"),
        ),
        payload={
            "model": "gpt-5.6-luna",
            "messages": [{"role": "user", "content": "repeat digest probe"}],
        },
        provider=ProviderId("openai"),
        protocol="chat",
        model="gpt-5.6-luna",
        stream=False,
        policy=RequestPolicyContext(rate_limit_key_hash="key-hash", tier="free"),
        pii_config=None,
    )
    detector = LoopDetectionService(
        SimpleNamespace(redis=SimpleNamespace(eval=AsyncMock(side_effect=OSError)))
    )

    @asynccontextmanager
    async def session_scope():
        yield db

    await AdmissionStage(
        SimpleNamespace(headers={}),
        DurableUsageLifecycle(DurableAccountingCoordinator(), session_scope),
        rate_limiter=SimpleNamespace(allow=AsyncMock(return_value=True)),
        loop_detector=detector,
        loop_repeat_limit=4,
        loop_window_seconds=300,
        cost_tag_max_length=64,
    ).run(prepared)

    lifecycle = await db.scalar(
        select(RequestLifecycle).where(RequestLifecycle.request_id == request_id)
    )
    detector_digest = detector.cache.redis.eval.await_args.args[2].split(":")[-1]
    hash_key = (settings.COMPLIANCE_HASH_SALT or settings.SECRET_KEY).encode("utf-8")
    assert lifecycle is not None
    assert lifecycle.lifecycle_metadata["repeat_digest"] == keyed_repeat_digest(
        hash_key, str(test_api_key.organization_id), detector_digest
    )
    assert lifecycle.lifecycle_metadata["deployment_id"] is None
    derived_key = hmac.new(
        hash_key, b"shim-repeat-digest-v1", hashlib.sha256
    ).hexdigest()
    assert "Repeat window failed open" in caplog.text
    assert detector_digest not in caplog.text
    assert derived_key not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "team_id", [UUID("00000000-0000-0000-0000-00000000ee12"), None]
)
async def test_reservation_records_the_keys_team_id(db, test_api_key, team_id) -> None:
    request_id = f"req_team_id_{uuid4().hex}"
    now = datetime.now(timezone.utc)

    await DurableAccountingRepository().reserve_quota(
        db,
        QuotaReservationCommand(
            tenant_id=test_api_key.organization_id,
            api_key_id=test_api_key.id,
            request_id=request_id,
            requested_model="gpt-5.6-luna",
            source_endpoint="chat.completions",
            started_at=now,
            reconciliation_due_at=now + timedelta(minutes=2),
            estimated_input_tokens=1,
            maximum_output_tokens=1,
            policy=QuotaPolicySnapshot("team-id", None, None, None, team_id=team_id),
        ),
    )

    lifecycle = await db.scalar(
        select(RequestLifecycle).where(RequestLifecycle.request_id == request_id)
    )
    reservation = await db.scalar(
        select(UsageLedger).where(
            UsageLedger.request_id == request_id,
            UsageLedger.event_type == "quota_reservation",
        )
    )
    await DurableAccountingRepository().finalize(
        db,
        FinalizationCommand(
            tenant_id=test_api_key.organization_id,
            request_id=request_id,
            quota_action=TerminalAction.SETTLE,
        ),
    )
    analytics = await db.scalar(
        select(OutboxEvent).where(
            OutboxEvent.aggregate_id == request_id,
            OutboxEvent.event_type == "analytics.request_completed",
        )
    )
    expected = str(team_id) if team_id is not None else None
    assert lifecycle is not None and reservation is not None and analytics is not None
    assert lifecycle.lifecycle_metadata["team_id"] == expected
    assert reservation.event_metadata["team_id"] == expected
    assert lifecycle.lifecycle_metadata["team"] is None
    projected = analytics_projection._projection_values(
        OutboxMessage.from_event(analytics)
    )
    assert projected["details"]["team_id"] == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("bulk", [{"distinct_values": 4, "threshold": 3}, None])
async def test_a_blocked_bulk_disclosure_writes_one_intent_beside_the_lifecycle(
    db, test_api_key, monkeypatch, bulk
) -> None:
    prepared = _prepared()
    prepared.tenant_id = test_api_key.organization_id
    prepared.api_key_id = test_api_key.id
    started_at = datetime.now(timezone.utc)
    prepared.context.started_at = started_at
    await DurableAccountingRepository().reserve_quota(
        db,
        QuotaReservationCommand(
            tenant_id=prepared.tenant_id,
            api_key_id=prepared.api_key_id,
            request_id=prepared.request_id,
            requested_model=prepared.model,
            source_endpoint="chat.completions",
            started_at=started_at,
            reconciliation_due_at=started_at + timedelta(minutes=2),
            estimated_input_tokens=20,
            maximum_output_tokens=30,
            policy=QuotaPolicySnapshot("test", None, None, None),
        ),
    )
    values = ["bulk.one@example.com", "bulk.two@example.com", "+90 532 000 00 00"]
    prepared.privacy = PrivacyOutcome(
        action=PrivacyAction.SCRUBBED,
        pii_detected=True,
        verification_map={
            "<EMAIL_ADDRESS_ff8d9811>": values[0],
            "<EMAIL_ADDRESS_ff8d9812>": values[1],
        },
        pii_entities={"EMAIL_ADDRESS": 2},
        monitored_entities={"PHONE_NUMBER": 1},
        blocked_entities={"SECRET": 1},
        bulk_disclosure=bulk,
    )
    prepared.record_verdict(
        "privacy.input", stage="privacy", outcome="deny", reason_code="SECRET_BLOCKED"
    )

    @asynccontextmanager
    async def session_scope():
        yield db

    usage = DurableUsageLifecycle(DurableAccountingCoordinator(), session_scope)
    for _ in range(2):
        await usage.record_privacy(prepared)
    await usage.fail(prepared, reason="request_aborted")
    await usage.record_response_privacy(
        prepared, {"response_entities": {"TR_NATIONAL_ID": 1}, "truncated": False}
    )

    lifecycle = (
        await db.execute(
            select(RequestLifecycle).where(
                RequestLifecycle.request_id == prepared.request_id
            )
        )
    ).scalar_one()
    intents = list(
        await db.scalars(
            select(OutboxEvent).where(
                OutboxEvent.organization_id == prepared.tenant_id,
                OutboxEvent.event_type == "privacy.bulk_disclosure",
            )
        )
    )
    assert lifecycle.lifecycle_metadata["bulk_disclosure"] == bulk
    if bulk is None:
        assert intents == []
        return
    [intent] = intents
    assert intent.idempotency_key == f"bulk_disclosure:{prepared.request_id}"
    assert (intent.aggregate_type, intent.aggregate_id) == (
        "request",
        prepared.request_id,
    )
    assert intent.payload["distinct_values"] == 4
    assert intent.payload["threshold"] == 3
    assert intent.payload["entity_counts"] == {
        "EMAIL_ADDRESS": 2,
        "PHONE_NUMBER": 1,
        "SECRET": 1,
    }
    assert intent.payload["api_key_id"] == str(test_api_key.id)
    encoded = json.dumps(intent.payload)
    assert not any(value in encoded for value in values)
    assert "<EMAIL_ADDRESS_" not in encoded

    event = (
        await db.execute(
            select(OutboxEvent).where(
                OutboxEvent.aggregate_id == prepared.request_id,
                OutboxEvent.event_type == "analytics.request_failed",
            )
        )
    ).scalar_one()
    monkeypatch.setattr(analytics_projection, "AsyncSessionLocal", session_scope)
    await analytics_projection.project_request(OutboxMessage.from_event(event))
    filters = dict(
        start=started_at - timedelta(minutes=1),
        end=None,
        status_filter=None,
        model=None,
        request_id=prepared.request_id,
        pii_detected=None,
        tag=None,
        cost_center=None,
        user=SimpleNamespace(
            id=uuid4(),
            kind="human",
            role="owner",
            custom_role_id=None,
            organization_id=prepared.tenant_id,
        ),
        session=db,
    )
    page = await management.activity.list_requests(**filters, limit=1, offset=0)
    exported = await management.activity.export_requests(**filters)
    rows = list(
        csv.DictReader(
            io.StringIO(
                b"".join([chunk async for chunk in exported.body_iterator]).decode(
                    "utf-8-sig"
                )
            )
        )
    )
    assert page.items[0].bulk_disclosure == bulk
    assert json.loads(rows[0]["bulk_disclosure"]) == bulk
    assert page.items[0].response_entities == {"TR_NATIONAL_ID": 1}
    assert json.loads(rows[0]["response_entities"]) == {"TR_NATIONAL_ID": 1}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "markers", [{"INSTRUCTION_OVERRIDE": 1}, {}, {"error": True}, None]
)
async def test_injection_markers_reach_the_lifecycle_the_request_list_and_csv(
    db, test_api_key, monkeypatch, markers
) -> None:
    prepared = _prepared()
    prepared.tenant_id = test_api_key.organization_id
    prepared.api_key_id = test_api_key.id
    started_at = datetime.now(timezone.utc)
    prepared.context.started_at = started_at
    await DurableAccountingRepository().reserve_quota(
        db,
        QuotaReservationCommand(
            tenant_id=prepared.tenant_id,
            api_key_id=prepared.api_key_id,
            request_id=prepared.request_id,
            requested_model=prepared.model,
            source_endpoint="chat.completions",
            started_at=started_at,
            reconciliation_due_at=started_at + timedelta(minutes=2),
            estimated_input_tokens=20,
            maximum_output_tokens=30,
            policy=QuotaPolicySnapshot("test", None, None, None),
        ),
    )
    prepared.privacy = PrivacyOutcome(
        action=PrivacyAction.DETECTED, pii_detected=False, injection_markers=markers
    )

    @asynccontextmanager
    async def session_scope():
        yield db

    usage = DurableUsageLifecycle(DurableAccountingCoordinator(), session_scope)
    await usage.record_privacy(prepared)
    await usage.fail(prepared, reason="request_aborted")

    lifecycle = (
        await db.execute(
            select(RequestLifecycle).where(
                RequestLifecycle.request_id == prepared.request_id
            )
        )
    ).scalar_one()
    assert lifecycle.lifecycle_metadata.get("injection_markers") == markers
    assert ("injection_markers" in lifecycle.lifecycle_metadata) == (
        markers is not None
    )
    event = (
        await db.execute(
            select(OutboxEvent).where(
                OutboxEvent.aggregate_id == prepared.request_id,
                OutboxEvent.event_type == "analytics.request_failed",
            )
        )
    ).scalar_one()
    monkeypatch.setattr(analytics_projection, "AsyncSessionLocal", session_scope)
    await analytics_projection.project_request(OutboxMessage.from_event(event))
    filters = dict(
        start=started_at - timedelta(minutes=1),
        end=None,
        status_filter=None,
        model=None,
        request_id=prepared.request_id,
        pii_detected=None,
        tag=None,
        cost_center=None,
        user=SimpleNamespace(
            id=uuid4(),
            kind="human",
            role="owner",
            custom_role_id=None,
            organization_id=prepared.tenant_id,
        ),
        session=db,
    )
    page = await management.activity.list_requests(**filters, limit=1, offset=0)
    exported = await management.activity.export_requests(**filters)
    [row] = csv.DictReader(
        io.StringIO(
            b"".join([chunk async for chunk in exported.body_iterator]).decode(
                "utf-8-sig"
            )
        )
    )
    assert page.items[0].injection_markers == markers
    assert (
        json.loads(row["injection_markers"]) if row["injection_markers"] else None
    ) == markers


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "media",
    [
        {
            "media_parts": {"image": 2, "pdf": 1},
            "media_unscanned": 3,
            "media_images": [[4000, 3000, 35000], [10, 20, 24]],
            "media_images_truncated": True,
            "documents": {
                "scanned": 1,
                "converted": 1,
                "native": 0,
                "unscannable": {"encrypted": 1},
            },
            "document_entities": {"EMAIL_ADDRESS": 1},
        },
        None,
    ],
)
async def test_media_records_reach_the_lifecycle_the_request_list_and_csv(
    db, test_api_key, monkeypatch, media
) -> None:
    prepared = _prepared()
    prepared.tenant_id = test_api_key.organization_id
    prepared.api_key_id = test_api_key.id
    started_at = datetime.now(timezone.utc)
    prepared.context.started_at = started_at
    await DurableAccountingRepository().reserve_quota(
        db,
        QuotaReservationCommand(
            tenant_id=prepared.tenant_id,
            api_key_id=prepared.api_key_id,
            request_id=prepared.request_id,
            requested_model=prepared.model,
            source_endpoint="chat.completions",
            started_at=started_at,
            reconciliation_due_at=started_at + timedelta(minutes=2),
            estimated_input_tokens=20,
            maximum_output_tokens=30,
            policy=QuotaPolicySnapshot("test", None, None, None),
        ),
    )
    prepared.privacy = PrivacyOutcome(
        action=PrivacyAction.DETECTED, pii_detected=False, media=media
    )

    @asynccontextmanager
    async def session_scope():
        yield db

    usage = DurableUsageLifecycle(DurableAccountingCoordinator(), session_scope)
    await usage.record_privacy(prepared)
    await usage.fail(prepared, reason="request_aborted")

    lifecycle = (
        await db.execute(
            select(RequestLifecycle).where(
                RequestLifecycle.request_id == prepared.request_id
            )
        )
    ).scalar_one()
    for key in ("media_parts", "media_unscanned", "media_images", "documents"):
        assert lifecycle.lifecycle_metadata.get(key) == (media or {}).get(key)
        assert (key in lifecycle.lifecycle_metadata) == (media is not None)
    event = (
        await db.execute(
            select(OutboxEvent).where(
                OutboxEvent.aggregate_id == prepared.request_id,
                OutboxEvent.event_type == "analytics.request_failed",
            )
        )
    ).scalar_one()
    monkeypatch.setattr(analytics_projection, "AsyncSessionLocal", session_scope)
    await analytics_projection.project_request(OutboxMessage.from_event(event))
    filters = dict(
        start=started_at - timedelta(minutes=1),
        end=None,
        status_filter=None,
        model=None,
        request_id=prepared.request_id,
        pii_detected=None,
        tag=None,
        cost_center=None,
        user=SimpleNamespace(
            id=uuid4(),
            kind="human",
            role="owner",
            custom_role_id=None,
            organization_id=prepared.tenant_id,
        ),
        session=db,
    )
    page = await management.activity.list_requests(**filters, limit=1, offset=0)
    exported = await management.activity.export_requests(**filters)
    [row] = csv.DictReader(
        io.StringIO(
            b"".join([chunk async for chunk in exported.body_iterator]).decode(
                "utf-8-sig"
            )
        )
    )
    item, expected = page.items[0], media or {}
    assert item.media_parts == expected.get("media_parts")
    assert item.media_unscanned == expected.get("media_unscanned")
    assert item.media_images == expected.get("media_images")
    assert item.media_images_truncated == expected.get("media_images_truncated")
    assert item.documents == expected.get("documents")
    assert item.document_entities == expected.get("document_entities")
    for key in ("documents", "document_entities"):
        assert (json.loads(row[key]) if row[key] else None) == expected.get(key)
    assert (json.loads(row["media_parts"]) if row["media_parts"] else None) == (
        expected.get("media_parts")
    )
    assert row["media_unscanned"] == str(expected.get("media_unscanned") or "")
    assert (json.loads(row["media_images"]) if row["media_images"] else None) == (
        expected.get("media_images")
    )
    assert row["media_images_truncated"] == (
        "True" if expected.get("media_images_truncated") else ""
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "applied", [({"id": "parameter_pin.temp_zero", "version": 3},), (), None]
)
async def test_settings_applied_reaches_the_lifecycle_the_request_list_and_csv(
    db, test_api_key, monkeypatch, applied
) -> None:
    prepared = _prepared()
    prepared.tenant_id = test_api_key.organization_id
    prepared.api_key_id = test_api_key.id
    started_at = datetime.now(timezone.utc)
    prepared.context.started_at = started_at
    await DurableAccountingRepository().reserve_quota(
        db,
        QuotaReservationCommand(
            tenant_id=prepared.tenant_id,
            api_key_id=prepared.api_key_id,
            request_id=prepared.request_id,
            requested_model=prepared.model,
            source_endpoint="chat.completions",
            started_at=started_at,
            reconciliation_due_at=started_at + timedelta(minutes=2),
            estimated_input_tokens=20,
            maximum_output_tokens=30,
            policy=QuotaPolicySnapshot("test", None, None, None),
        ),
    )
    prepared.privacy = PrivacyOutcome(action=PrivacyAction.DETECTED, pii_detected=False)
    prepared.settings_applied = applied
    expected = None if applied is None else list(applied)

    @asynccontextmanager
    async def session_scope():
        yield db

    usage = DurableUsageLifecycle(DurableAccountingCoordinator(), session_scope)
    await usage.record_privacy(prepared)
    await usage.fail(prepared, reason="request_aborted")

    lifecycle = (
        await db.execute(
            select(RequestLifecycle).where(
                RequestLifecycle.request_id == prepared.request_id
            )
        )
    ).scalar_one()
    assert lifecycle.lifecycle_metadata.get("settings_applied") == expected
    assert ("settings_applied" in lifecycle.lifecycle_metadata) == (applied is not None)
    event = (
        await db.execute(
            select(OutboxEvent).where(
                OutboxEvent.aggregate_id == prepared.request_id,
                OutboxEvent.event_type == "analytics.request_failed",
            )
        )
    ).scalar_one()
    monkeypatch.setattr(analytics_projection, "AsyncSessionLocal", session_scope)
    await analytics_projection.project_request(OutboxMessage.from_event(event))
    filters = dict(
        start=started_at - timedelta(minutes=1),
        end=None,
        status_filter=None,
        model=None,
        request_id=prepared.request_id,
        pii_detected=None,
        tag=None,
        cost_center=None,
        user=SimpleNamespace(
            id=uuid4(),
            kind="human",
            role="owner",
            custom_role_id=None,
            organization_id=prepared.tenant_id,
        ),
        session=db,
    )
    page = await management.activity.list_requests(**filters, limit=1, offset=0)
    exported = await management.activity.export_requests(**filters)
    [row] = csv.DictReader(
        io.StringIO(
            b"".join([chunk async for chunk in exported.body_iterator]).decode(
                "utf-8-sig"
            )
        )
    )
    assert page.items[0].settings_applied == expected
    assert (
        json.loads(row["settings_applied"]) if row["settings_applied"] else None
    ) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "applied",
    [
        (
            {
                "id": "json_compaction",
                "version": 1,
                "before_chars": 200,
                "after_chars": 120,
                "items": 2,
            },
        ),
        (),
        None,
    ],
)
async def test_transforms_applied_reaches_the_lifecycle_the_request_list_and_csv(
    db, test_api_key, monkeypatch, applied
) -> None:
    prepared = _prepared()
    prepared.tenant_id = test_api_key.organization_id
    prepared.api_key_id = test_api_key.id
    started_at = datetime.now(timezone.utc)
    prepared.context.started_at = started_at
    await DurableAccountingRepository().reserve_quota(
        db,
        QuotaReservationCommand(
            tenant_id=prepared.tenant_id,
            api_key_id=prepared.api_key_id,
            request_id=prepared.request_id,
            requested_model=prepared.model,
            source_endpoint="chat.completions",
            started_at=started_at,
            reconciliation_due_at=started_at + timedelta(minutes=2),
            estimated_input_tokens=20,
            maximum_output_tokens=30,
            policy=QuotaPolicySnapshot("test", None, None, None),
        ),
    )
    prepared.privacy = PrivacyOutcome(action=PrivacyAction.DETECTED, pii_detected=False)
    prepared.transforms_applied = applied
    expected = None if applied is None else list(applied)

    @asynccontextmanager
    async def session_scope():
        yield db

    usage = DurableUsageLifecycle(DurableAccountingCoordinator(), session_scope)
    await usage.record_privacy(prepared)
    await usage.fail(prepared, reason="request_aborted")

    lifecycle = (
        await db.execute(
            select(RequestLifecycle).where(
                RequestLifecycle.request_id == prepared.request_id
            )
        )
    ).scalar_one()
    assert lifecycle.lifecycle_metadata.get("transforms_applied") == expected
    assert ("transforms_applied" in lifecycle.lifecycle_metadata) == (
        applied is not None
    )
    event = (
        await db.execute(
            select(OutboxEvent).where(
                OutboxEvent.aggregate_id == prepared.request_id,
                OutboxEvent.event_type == "analytics.request_failed",
            )
        )
    ).scalar_one()
    monkeypatch.setattr(analytics_projection, "AsyncSessionLocal", session_scope)
    await analytics_projection.project_request(OutboxMessage.from_event(event))
    filters = dict(
        start=started_at - timedelta(minutes=1),
        end=None,
        status_filter=None,
        model=None,
        request_id=prepared.request_id,
        pii_detected=None,
        tag=None,
        cost_center=None,
        user=SimpleNamespace(
            id=uuid4(),
            kind="human",
            role="owner",
            custom_role_id=None,
            organization_id=prepared.tenant_id,
        ),
        session=db,
    )
    page = await management.activity.list_requests(**filters, limit=1, offset=0)
    exported = await management.activity.export_requests(**filters)
    [row] = csv.DictReader(
        io.StringIO(
            b"".join([chunk async for chunk in exported.body_iterator]).decode(
                "utf-8-sig"
            )
        )
    )
    assert page.items[0].transforms_applied == expected
    assert (
        json.loads(row["transforms_applied"]) if row["transforms_applied"] else None
    ) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("withheld", "markers"),
    [
        (frozenset({"TR_NATIONAL_ID"}), {"TR_NATIONAL_ID": 1}),
        (frozenset({"IBAN_CODE"}), {}),
        (frozenset(), None),
    ],
)
async def test_restore_withheld_counts_reach_the_lifecycle_the_request_list_and_csv(
    db, test_api_key, monkeypatch, withheld, markers
) -> None:
    prepared = _prepared()
    prepared.tenant_id = test_api_key.organization_id
    prepared.api_key_id = test_api_key.id
    started_at = datetime.now(timezone.utc)
    prepared.context.started_at = started_at
    await DurableAccountingRepository().reserve_quota(
        db,
        QuotaReservationCommand(
            tenant_id=prepared.tenant_id,
            api_key_id=prepared.api_key_id,
            request_id=prepared.request_id,
            requested_model=prepared.model,
            source_endpoint="chat.completions",
            started_at=started_at,
            reconciliation_due_at=started_at + timedelta(minutes=2),
            estimated_input_tokens=20,
            maximum_output_tokens=30,
            policy=QuotaPolicySnapshot("test", None, None, None),
        ),
    )
    prepared.privacy = PrivacyOutcome(
        action=PrivacyAction.SCRUBBED,
        pii_detected=True,
        verification_map={"<TR_NATIONAL_ID_ff8d9811>": "10000000146"},
        pii_entities={"TR_NATIONAL_ID": 1},
        restore_withheld=withheld,
    )

    @asynccontextmanager
    async def session_scope():
        yield db

    usage = DurableUsageLifecycle(DurableAccountingCoordinator(), session_scope)
    await usage.record_privacy(prepared)
    await usage.fail(prepared, reason="request_aborted")

    lifecycle = (
        await db.execute(
            select(RequestLifecycle).where(
                RequestLifecycle.request_id == prepared.request_id
            )
        )
    ).scalar_one()
    assert lifecycle.lifecycle_metadata.get("restore_withheld") == markers
    assert ("restore_withheld" in lifecycle.lifecycle_metadata) == (markers is not None)
    event = (
        await db.execute(
            select(OutboxEvent).where(
                OutboxEvent.aggregate_id == prepared.request_id,
                OutboxEvent.event_type == "analytics.request_failed",
            )
        )
    ).scalar_one()
    monkeypatch.setattr(analytics_projection, "AsyncSessionLocal", session_scope)
    await analytics_projection.project_request(OutboxMessage.from_event(event))
    filters = dict(
        start=started_at - timedelta(minutes=1),
        end=None,
        status_filter=None,
        model=None,
        request_id=prepared.request_id,
        pii_detected=None,
        tag=None,
        cost_center=None,
        user=SimpleNamespace(
            id=uuid4(),
            kind="human",
            role="owner",
            custom_role_id=None,
            organization_id=prepared.tenant_id,
        ),
        session=db,
    )
    page = await management.activity.list_requests(**filters, limit=1, offset=0)
    exported = await management.activity.export_requests(**filters)
    [row] = csv.DictReader(
        io.StringIO(
            b"".join([chunk async for chunk in exported.body_iterator]).decode(
                "utf-8-sig"
            )
        )
    )
    assert page.items[0].restore_withheld == markers
    assert (
        json.loads(row["restore_withheld"]) if row["restore_withheld"] else None
    ) == markers


@pytest.mark.asyncio
async def test_a_response_scan_updates_only_its_own_tenants_lifecycle(
    db, test_api_key
) -> None:
    prepared = _prepared()
    prepared.tenant_id = test_api_key.organization_id
    prepared.api_key_id = test_api_key.id
    started_at = datetime.now(timezone.utc)
    await DurableAccountingRepository().reserve_quota(
        db,
        QuotaReservationCommand(
            tenant_id=prepared.tenant_id,
            api_key_id=prepared.api_key_id,
            request_id=prepared.request_id,
            requested_model=prepared.model,
            source_endpoint="chat.completions",
            started_at=started_at,
            reconciliation_due_at=started_at + timedelta(minutes=2),
            estimated_input_tokens=20,
            maximum_output_tokens=30,
            policy=QuotaPolicySnapshot("test", None, None, None),
        ),
    )

    @asynccontextmanager
    async def session_scope():
        yield db

    usage = DurableUsageLifecycle(DurableAccountingCoordinator(), session_scope)
    stranger = _prepared()
    stranger.request_id = prepared.request_id
    await usage.record_response_privacy(
        prepared, {"response_entities": None, "error": True}
    )
    await usage.record_response_privacy(
        stranger, {"response_entities": {"EMAIL_ADDRESS": 9}, "truncated": False}
    )

    lifecycle = (
        await db.execute(
            select(RequestLifecycle).where(
                RequestLifecycle.request_id == prepared.request_id
            )
        )
    ).scalar_one()
    assert lifecycle.lifecycle_metadata["response_entities"] is None
    assert lifecycle.lifecycle_metadata["response_scan"] == {"error": True}


@pytest.mark.asyncio
async def test_an_anthropic_reservation_prices_input_at_the_one_hour_write_rate() -> (
    None
):
    repository = SimpleNamespace(
        reserve_provider_spend=AsyncMock(return_value=SimpleNamespace())
    )
    policy_loader = SimpleNamespace(
        spend=AsyncMock(
            return_value=SpendPolicySnapshot(version="spend-v1", monthly_limit_usd=None)
        )
    )
    session = SimpleNamespace(commit=AsyncMock(), rollback=AsyncMock())
    prepared = _prepared()
    prepared.provider = "anthropic"
    prepared.model = prepared.pricing_model = "claude-haiku-4-5"

    await DurableAccountingCoordinator(
        repository=repository, policy_loader=policy_loader
    ).reserve_spend(prepared, False, session)

    command = repository.reserve_provider_spend.await_args.args[1]
    # 20 input tokens at 2x the $1 base, 30 output tokens at $5.
    assert command.estimated_cost_usd == Decimal("0.00019")
    assert command.pricing_metadata["cache_write_1h_per_million"] == "2"


@pytest.mark.asyncio
async def test_finalization_passes_the_answer_facts_and_a_refund_records_none(
    db, test_api_key
) -> None:
    @asynccontextmanager
    async def session_scope():
        yield object()

    accounting = SimpleNamespace(finalize=AsyncMock())
    terminal = _terminal()
    terminal = replace(
        terminal,
        usage=replace(
            terminal.usage,
            provider_latency_ms=812,
            answer_characters=40,
            tool_call_names=("lookup",),
            reasoning_seen=True,
        ),
    )
    await DurableUsageLifecycle(accounting, session_scope).finalize(
        _prepared(), terminal
    )
    command = accounting.finalize.await_args.args[1]
    assert (
        command.provider_latency_ms,
        command.answer_characters,
        command.tool_call_names,
        command.reasoning_seen,
    ) == (812, 40, ("lookup",), True)

    repository = DurableAccountingRepository()
    request_id = f"req_refund_{uuid4().hex}"
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
            policy=QuotaPolicySnapshot("test", None, None, None),
        ),
    )
    await repository.finalize(
        db,
        FinalizationCommand(
            tenant_id=test_api_key.organization_id,
            request_id=request_id,
            quota_action=TerminalAction.REFUND,
            lifecycle_status="failed",
        ),
    )
    await db.flush()
    lifecycle = (
        await db.execute(
            select(RequestLifecycle).where(RequestLifecycle.request_id == request_id)
        )
    ).scalar_one()
    assert not {
        "provider_latency_ms",
        "answer_characters",
        "tool_call_names",
        "reasoning_seen",
    } & set(lifecycle.lifecycle_metadata)


@pytest.mark.asyncio
async def test_a_response_analysis_updates_only_its_own_tenants_lifecycle(
    db, test_api_key, caplog
) -> None:
    prepared = _prepared()
    prepared.tenant_id = test_api_key.organization_id
    prepared.api_key_id = test_api_key.id
    started_at = datetime.now(timezone.utc)
    await DurableAccountingRepository().reserve_quota(
        db,
        QuotaReservationCommand(
            tenant_id=prepared.tenant_id,
            api_key_id=prepared.api_key_id,
            request_id=prepared.request_id,
            requested_model=prepared.model,
            source_endpoint="chat.completions",
            started_at=started_at,
            reconciliation_due_at=started_at + timedelta(minutes=2),
            estimated_input_tokens=20,
            maximum_output_tokens=30,
            policy=QuotaPolicySnapshot("test", None, None, None),
        ),
    )

    @asynccontextmanager
    async def session_scope():
        yield db

    def lifecycle():
        return db.execute(
            select(RequestLifecycle)
            .where(RequestLifecycle.request_id == prepared.request_id)
            .execution_options(populate_existing=True)
        )

    reserved = dict((await lifecycle()).scalar_one().lifecycle_metadata)
    usage = DurableUsageLifecycle(DurableAccountingCoordinator(), session_scope)
    stranger = _prepared()
    stranger.request_id = prepared.request_id
    missing = _prepared()
    missing.tenant_id = prepared.tenant_id
    missing.request_id = f"req_missing_{uuid4().hex}"
    await usage.record_response_analysis(
        prepared, {"probe": {"n": 1}, "versions": {"probe": "1"}}
    )
    await usage.record_response_analysis(
        stranger, {"probe": {"n": 9}, "versions": {"probe": "1"}}
    )
    await usage.record_response_analysis(
        missing, {"probe": {"n": 2}, "versions": {"probe": "1"}}
    )

    metadata = (await lifecycle()).scalar_one().lifecycle_metadata
    assert metadata == {
        **reserved,
        "response_analysis": {"probe": {"n": 1}, "versions": {"probe": "1"}},
    }
    assert "Response analysis record failed" not in caplog.text


@pytest.mark.asyncio
async def test_a_failed_response_analysis_record_is_logged_and_dropped(caplog) -> None:
    @asynccontextmanager
    async def broken_scope():
        raise ConnectionError("database at private-host down")
        yield

    usage = DurableUsageLifecycle(DurableAccountingCoordinator(), broken_scope)

    await usage.record_response_analysis(_prepared(), {"versions": {}})

    assert "Response analysis record failed type=ConnectionError" in caplog.text
    assert "private-host" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("task_id", "trace_id"),
    [("task-42", "0af7651916cd43dd8448eb211c80319c"), (None, None)],
)
async def test_the_reservation_records_the_task_and_trace_ids(
    db, test_api_key, task_id, trace_id
) -> None:
    started_at = datetime.now(timezone.utc)
    request_id = f"req_{uuid4().hex}"
    await DurableAccountingRepository().reserve_quota(
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
            policy=QuotaPolicySnapshot("test", None, None, None),
            task_id=task_id,
            trace_id=trace_id,
            tool_call_repeats=2 if task_id else None,
            task_calls=3 if task_id else None,
        ),
    )

    lifecycle = (
        await db.execute(
            select(RequestLifecycle).where(RequestLifecycle.request_id == request_id)
        )
    ).scalar_one()
    metadata = lifecycle.lifecycle_metadata
    assert (metadata["task_id"], metadata["trace_id"]) == (task_id, trace_id)
    assert (metadata["tool_call_repeats"], metadata["task_calls"]) == (
        (2, 3) if task_id else (None, None)
    )
    assert metadata["inflight_duplicate_of"] is None


@pytest.mark.asyncio
async def test_a_shared_answer_settles_one_request_unit_without_tokens_or_spend(
    db, test_api_key
) -> None:
    from shim.gateway.pipeline.provider_execution import ProviderNonStream

    follower = _prepared()
    follower.tenant_id = test_api_key.organization_id
    follower.api_key_id = test_api_key.id
    leader_id = f"req_{uuid4().hex}"
    started_at = datetime.now(timezone.utc)
    await DurableAccountingRepository().reserve_quota(
        db,
        QuotaReservationCommand(
            tenant_id=follower.tenant_id,
            api_key_id=follower.api_key_id,
            request_id=follower.request_id,
            requested_model=follower.model,
            source_endpoint="chat.completions",
            started_at=started_at,
            reconciliation_due_at=started_at + timedelta(minutes=2),
            estimated_input_tokens=20,
            maximum_output_tokens=30,
            policy=QuotaPolicySnapshot("test", None, None, None),
            inflight_duplicate_of=leader_id,
        ),
    )

    @asynccontextmanager
    async def session_scope():
        yield db

    response = await ResponsePostprocessor(
        DurableUsageLifecycle(DurableAccountingCoordinator(), session_scope),
        heartbeat_interval_seconds=30,
        output_hash_salt=None,
    ).finalize_shared(
        follower,
        ProviderNonStream(
            payload={
                "id": "chatcmpl-1",
                "object": "chat.completion",
                "model": "gpt-5.6-luna",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "ok"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 100, "completion_tokens": 20},
            },
            request_id="upstream-1",
            latency_ms=12.0,
        ),
        leader_id,
    )

    lifecycle = await db.scalar(
        select(RequestLifecycle).where(
            RequestLifecycle.request_id == follower.request_id
        )
    )
    ledger = (
        await db.execute(
            select(
                UsageLedger.event_type,
                UsageLedger.request_count,
                UsageLedger.total_tokens,
                UsageLedger.cost_usd,
            ).where(UsageLedger.request_id == follower.request_id)
        )
    ).all()
    assert response is not None and response.headers["x-request-id"] == "upstream-1"
    assert (lifecycle.status, lifecycle.provider_model) == ("completed", "gpt-5.6-luna")
    metadata = lifecycle.lifecycle_metadata
    assert metadata["inflight_duplicate_of"] == leader_id
    assert metadata["inflight_share"] == {
        "leader_request_id": leader_id,
        "prompt_tokens": 100,
        "completion_tokens": 20,
        "avoided_cost_usd": str(
            compute_cost_usd("gpt-5.6-luna", 100, 20, provider="openai")
        ),
    }
    assert metadata["savings"] == {
        "version": 1,
        "measured": {
            "inflight_share": {
                "usd": f"{compute_cost_usd('gpt-5.6-luna', 100, 20, provider='openai'):.10f}",
                "tokens": 120,
            }
        },
    }
    assert ("inflight.share", "skip", "INFLIGHT_RESPONSE_SHARED") in {
        (verdict["rule_id"], verdict["outcome"], verdict["reason_code"])
        for verdict in metadata["policy_verdicts"]
    }
    assert sorted(ledger) == [
        ("quota_reservation", 1, 50, Decimal("0")),
        ("quota_settlement", 1, 0, Decimal("0")),
    ], "one request unit, no tokens, no spend row"


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", ["embeddings", "embed_content"])
async def test_an_embeddings_request_reserves_its_quota(protocol) -> None:
    repository = SimpleNamespace(
        reserve_quota=AsyncMock(return_value=SimpleNamespace(replayed=False))
    )
    policy_loader = SimpleNamespace(
        quota=AsyncMock(return_value=QuotaPolicySnapshot("quota-v1", None, None, None))
    )
    prepared = _prepared()
    prepared.protocol = protocol
    prepared.payload = {"model": "text-embedding-3-small", "input": "hello"}
    prepared.source_endpoint = "embeddings"
    prepared.context.started_at = datetime.now(timezone.utc)
    prepared.policy = SimpleNamespace(team=None)

    await DurableAccountingCoordinator(
        repository=repository, policy_loader=policy_loader
    ).reserve_quota(
        prepared,
        AdmissionState(
            estimated_input_tokens=20,
            maximum_output_tokens=0,
            cost_center="untagged",
            tags=(),
        ),
        SimpleNamespace(commit=AsyncMock(), rollback=AsyncMock()),
    )

    command = repository.reserve_quota.await_args.args[1]
    assert (command.maximum_output_tokens, command.system_prompt_hash) == (0, None)


@pytest.mark.asyncio
async def test_two_attempts_are_two_rows_each_with_its_own_cost(
    db, test_api_key, monkeypatch
) -> None:
    from shim.gateway.kernel.result import AttemptInfo

    @asynccontextmanager
    async def session_scope():
        yield db

    coordinator = DurableAccountingCoordinator()
    usage = DurableUsageLifecycle(coordinator, session_scope)
    started_at = datetime.now(timezone.utc)

    def attempt(number: int, group: str | None) -> SimpleNamespace:
        prepared = _prepared()
        prepared.tenant_id = test_api_key.organization_id
        prepared.api_key_id = test_api_key.id
        prepared.source_endpoint = "chat.completions"
        prepared.policy = SimpleNamespace(team=None)
        prepared.context.started_at = started_at
        prepared.admission.cost_center = "untagged"
        prepared.admission.tags = ()
        prepared.admission.repeat_chain_length = None
        prepared.privacy = PrivacyOutcome(
            action=PrivacyAction.DETECTED, pii_detected=False
        )
        if group is not None:
            prepared.attempt = AttemptInfo(
                group_id=group, number=number, reason="fallback", rule_id="spare"
            )
        return prepared

    first = attempt(1, None)
    second = attempt(2, first.request_id)
    for prepared in (first, second):
        await usage.admit(prepared, prepared.admission)
        await usage.record_privacy(prepared)
        await coordinator.reserve_spend(prepared, False, db)
    await usage.fail(first, reason="request_aborted")
    await coordinator.finalize(
        db,
        FinalizationCommand(
            tenant_id=second.tenant_id,
            request_id=second.request_id,
            quota_action=TerminalAction.SETTLE,
            spend_action=TerminalAction.SETTLE,
            prompt_tokens=20,
            completion_tokens=2,
            actual_cost_usd=Decimal("0.00002"),
            provider_model=second.pricing_model,
            lifecycle_status="completed",
        ),
    )

    rows = {
        row.request_id: row
        for row in (
            await db.scalars(
                select(RequestLifecycle).where(
                    RequestLifecycle.request_id.in_(
                        [first.request_id, second.request_id]
                    )
                )
            )
        ).all()
    }
    assert {key: row.status for key, row in rows.items()} == {
        first.request_id: "failed",
        second.request_id: "completed",
    }
    assert {
        key: value
        for key, value in rows[second.request_id].lifecycle_metadata.items()
        if key.startswith("attempt_")
    } == {
        "attempt_group_id": first.request_id,
        "attempt_number": 2,
        "attempt_reason": "fallback",
        "attempt_rule_id": "spare",
    }
    assert not any(
        key.startswith("attempt_") for key in rows[first.request_id].lifecycle_metadata
    )
    events = {
        (event.request_id, event.event_type)
        for event in (
            await db.scalars(
                select(UsageLedger).where(
                    UsageLedger.request_id.in_([first.request_id, second.request_id])
                )
            )
        ).all()
    }
    assert {
        (second.request_id, "spend_reservation"),
        (second.request_id, "spend_settlement"),
        (first.request_id, "spend_reservation"),
    } <= events
    assert (first.request_id, "spend_settlement") not in events

    monkeypatch.setattr(analytics_projection, "AsyncSessionLocal", session_scope)
    for event in (
        await db.scalars(
            select(OutboxEvent).where(
                OutboxEvent.aggregate_id.in_([first.request_id, second.request_id]),
                OutboxEvent.event_type.like("analytics.%"),
            )
        )
    ).all():
        await analytics_projection.project_request(OutboxMessage.from_event(event))
    filters = dict(
        start=started_at - timedelta(minutes=1),
        end=None,
        status_filter=None,
        model=None,
        request_id=None,
        pii_detected=None,
        tag=None,
        cost_center=None,
        attempt_group_id=first.request_id,
        user=SimpleNamespace(
            id=uuid4(),
            kind="human",
            role="owner",
            custom_role_id=None,
            organization_id=first.tenant_id,
        ),
        session=db,
    )
    page = await management.activity.list_requests(**filters, limit=10, offset=0)
    exported = await management.activity.export_requests(**filters)
    csv_rows = list(
        csv.DictReader(
            io.StringIO(
                b"".join([chunk async for chunk in exported.body_iterator]).decode(
                    "utf-8-sig"
                )
            )
        )
    )
    listed = {item.request_id: item for item in page.items}
    assert set(listed) == {first.request_id, second.request_id}
    assert (
        listed[second.request_id].attempt_group_id,
        listed[second.request_id].attempt_number,
        listed[second.request_id].attempt_reason,
        listed[second.request_id].attempt_rule_id,
    ) == (first.request_id, 2, "fallback", "spare")
    assert listed[first.request_id].attempt_group_id is None
    by_id = {row["request_id"]: row for row in csv_rows}
    assert by_id[second.request_id]["attempt_group_id"] == first.request_id
    assert by_id[second.request_id]["attempt_number"] == "2"
    assert by_id[first.request_id]["attempt_number"] == ""


@pytest.mark.asyncio
@pytest.mark.parametrize("first_answered", [False, True])
async def test_a_client_request_settles_one_request_unit_across_its_attempts(
    db, test_api_key, first_answered
) -> None:
    from shim.gateway.kernel.result import AttemptInfo

    @asynccontextmanager
    async def session_scope():
        yield db

    coordinator = DurableAccountingCoordinator()
    usage = DurableUsageLifecycle(coordinator, session_scope)

    def attempt(group: str | None) -> SimpleNamespace:
        prepared = _prepared()
        prepared.tenant_id = test_api_key.organization_id
        prepared.api_key_id = test_api_key.id
        prepared.source_endpoint = "chat.completions"
        prepared.policy = SimpleNamespace(team=None)
        prepared.context.started_at = datetime.now(timezone.utc)
        prepared.admission.cost_center = "untagged"
        prepared.admission.tags = ()
        prepared.admission.repeat_chain_length = None
        prepared.privacy = PrivacyOutcome(
            action=PrivacyAction.DETECTED, pii_detected=False
        )
        if group is not None:
            # As the kernel's next_attempt sets it.
            prepared.attempt = AttemptInfo(
                group_id=group,
                number=2,
                reason="format_retry" if first_answered else "fallback",
                rule_id="spare",
                counted=first_answered,
            )
        return prepared

    async def settle(prepared) -> None:
        await coordinator.finalize(
            db,
            FinalizationCommand(
                tenant_id=prepared.tenant_id,
                request_id=prepared.request_id,
                quota_action=TerminalAction.SETTLE,
                spend_action=TerminalAction.SETTLE,
                prompt_tokens=20,
                completion_tokens=2,
                actual_cost_usd=Decimal("0.00002"),
                provider_model=prepared.pricing_model,
                lifecycle_status="completed",
            ),
        )

    first = attempt(None)
    second = attempt(first.request_id)
    for prepared in (first, second):
        await usage.admit(prepared, prepared.admission)
        await usage.record_privacy(prepared)
        await coordinator.reserve_spend(prepared, False, db)
    if first_answered:
        await settle(first)
    else:
        await usage.fail(first, reason="request_aborted")
    await settle(second)

    monthly = (
        await db.scalars(
            select(QuotaPeriodUsage)
            .where(
                QuotaPeriodUsage.organization_id == test_api_key.organization_id,
                QuotaPeriodUsage.api_key_id == test_api_key.id,
                QuotaPeriodUsage.period_type == "monthly",
            )
            .execution_options(populate_existing=True)
        )
    ).one()
    assert (monthly.settled_requests, monthly.reserved_requests) == (1, 0)


@pytest.mark.asyncio
async def test_a_shadow_copy_is_its_own_row_with_no_request_unit(
    db, test_api_key, monkeypatch
) -> None:
    from shim.gateway.kernel.result import ShadowInfo

    @asynccontextmanager
    async def session_scope():
        yield db

    coordinator = DurableAccountingCoordinator()
    usage = DurableUsageLifecycle(coordinator, session_scope)
    started_at = datetime.now(timezone.utc)
    copy = _prepared()
    copy.tenant_id = test_api_key.organization_id
    copy.api_key_id = test_api_key.id
    copy.source_endpoint = "chat.completions"
    copy.policy = SimpleNamespace(team=None)
    copy.context.started_at = started_at
    copy.admission.cost_center = "untagged"
    # The caller's tag: its budget never sees the copy.
    copy.admission.tags = ("checkout",)
    copy.admission.repeat_chain_length = None
    copy.privacy = PrivacyOutcome(action=PrivacyAction.DETECTED, pii_detected=False)
    copy.shadow = ShadowInfo(of="req_primary", rule_id="change_test")

    await usage.admit(copy, copy.admission)
    await usage.record_privacy(copy)
    await coordinator.reserve_spend(copy, False, db)
    await coordinator.finalize(
        db,
        FinalizationCommand(
            tenant_id=copy.tenant_id,
            request_id=copy.request_id,
            quota_action=TerminalAction.SETTLE,
            spend_action=TerminalAction.SETTLE,
            prompt_tokens=20,
            completion_tokens=2,
            actual_cost_usd=Decimal("0.00002"),
            provider_model=copy.pricing_model,
            lifecycle_status="completed",
        ),
    )

    metadata = await db.scalar(
        select(RequestLifecycle.lifecycle_metadata).where(
            RequestLifecycle.request_id == copy.request_id
        )
    )
    assert (metadata["shadow_of"], metadata["shadow_rule_id"]) == (
        "req_primary",
        "change_test",
    )
    events = {
        event.event_type: event
        for event in (
            await db.scalars(
                select(UsageLedger).where(UsageLedger.request_id == copy.request_id)
            )
        ).all()
    }
    assert events["quota_reservation"].request_count == 0
    assert {"spend_reservation", "spend_settlement"} <= set(events)

    monkeypatch.setattr(analytics_projection, "AsyncSessionLocal", session_scope)
    event = (
        await db.execute(
            select(OutboxEvent).where(
                OutboxEvent.aggregate_id == copy.request_id,
                OutboxEvent.event_type.like("analytics.%"),
            )
        )
    ).scalar_one()
    await analytics_projection.project_request(OutboxMessage.from_event(event))
    filters = dict(
        start=started_at - timedelta(minutes=1),
        end=None,
        status_filter=None,
        model=None,
        request_id=copy.request_id,
        pii_detected=None,
        tag=None,
        cost_center=None,
        user=SimpleNamespace(
            id=uuid4(),
            kind="human",
            role="owner",
            custom_role_id=None,
            organization_id=copy.tenant_id,
        ),
        session=db,
    )
    page = await management.activity.list_requests(**filters, limit=1, offset=0)
    exported = await management.activity.export_requests(**filters)
    [row] = csv.DictReader(
        io.StringIO(
            b"".join([chunk async for chunk in exported.body_iterator]).decode(
                "utf-8-sig"
            )
        )
    )
    assert page.items[0].shadow_of == "req_primary"
    assert row["shadow_of"] == "req_primary"
    budgets = [
        await BudgetEvaluator().aggregate(
            db,
            SimpleNamespace(
                organization_id=copy.tenant_id, scope_type=scope, scope_value=value
            ),
            started_at - timedelta(minutes=1),
        )
        for scope, value in (("org", None), ("tag", "checkout"))
    ]
    assert [budget.cost_usd for budget in budgets] == [Decimal("0.00002"), 0]


@pytest.mark.asyncio
async def test_a_route_decision_is_stored_at_reservation_and_filters_the_list(
    db, test_api_key, monkeypatch
) -> None:
    @asynccontextmanager
    async def session_scope():
        yield db

    coordinator = DurableAccountingCoordinator()
    usage = DurableUsageLifecycle(coordinator, session_scope)
    started_at = datetime.now(timezone.utc)
    decision = {
        "rule_id": "cheap_start",
        "state": "monitor",
        "from": "strong",
        "to": "cheap",
        "reason": "max_start_chars",
        "conversation_id": "0123456789abcdef",
        "outcome": "would_route",
    }

    def request(route_decision: dict | None, pii: bool = False) -> SimpleNamespace:
        prepared = _prepared()
        prepared.tenant_id = test_api_key.organization_id
        prepared.api_key_id = test_api_key.id
        prepared.source_endpoint = "chat.completions"
        prepared.policy = SimpleNamespace(team=None)
        prepared.context.started_at = started_at
        prepared.admission.cost_center = "untagged"
        prepared.admission.tags = ()
        prepared.admission.repeat_chain_length = None
        prepared.privacy = PrivacyOutcome(
            action=PrivacyAction.DETECTED, pii_detected=pii
        )
        prepared.route_decision = route_decision
        return prepared

    # Refused before privacy: the reservation alone carries the decision.
    refused, plain, moved = request(decision), request(None), request(decision)
    personal = request(decision, pii=True)
    for prepared in (refused, plain, moved, personal):
        await usage.admit(prepared, prepared.admission)
    # A rule moved it again after privacy; the start decision stays under previous.
    moved.route_decision = {
        **decision,
        "state": "enforced",
        "reason": "fallback",
        "outcome": "routed",
        "previous": decision,
    }
    personal.route_decision = {**moved.route_decision}
    for prepared in (plain, moved, personal):
        await usage.record_privacy(prepared)
    for prepared in (refused, plain, moved, personal):
        await usage.fail(prepared, reason="request_aborted")
    rows = {
        row.request_id: row.lifecycle_metadata
        for row in (
            await db.scalars(
                select(RequestLifecycle).where(
                    RequestLifecycle.request_id.in_(
                        [
                            refused.request_id,
                            plain.request_id,
                            moved.request_id,
                            personal.request_id,
                        ]
                    )
                )
            )
        ).all()
    }
    # Refused before privacy: the first-turn digest is never written (night 3 M6).
    assert rows[refused.request_id]["route_decision"] == {
        **decision,
        "conversation_id": None,
    }
    assert "route_decision" not in rows[plain.request_id]
    assert rows[moved.request_id]["route_decision"]["previous"] == decision
    # A personal-data request keeps the decision without the first-turn digest.
    assert rows[personal.request_id]["route_decision"] == {
        **moved.route_decision,
        "conversation_id": None,
        "previous": {**decision, "conversation_id": None},
    }

    monkeypatch.setattr(analytics_projection, "AsyncSessionLocal", session_scope)
    for event in (
        await db.scalars(
            select(OutboxEvent).where(
                OutboxEvent.aggregate_id.in_(list(rows)),
                OutboxEvent.event_type.like("analytics.%"),
            )
        )
    ).all():
        await analytics_projection.project_request(OutboxMessage.from_event(event))
    filters = dict(
        start=started_at - timedelta(minutes=1),
        end=None,
        status_filter=None,
        model=None,
        request_id=None,
        pii_detected=None,
        tag=None,
        cost_center=None,
        user=SimpleNamespace(
            id=uuid4(),
            kind="human",
            role="owner",
            custom_role_id=None,
            organization_id=refused.tenant_id,
        ),
        session=db,
    )
    listed = {}
    for outcome in ("would_route", "routed", "target_unavailable"):
        page = await management.activity.list_requests(
            **filters, route_outcome=outcome, limit=10, offset=0
        )
        listed[outcome] = {item.request_id for item in page.items}
    exported = await management.activity.export_requests(
        **filters, route_outcome="would_route"
    )
    csv_rows = list(
        csv.DictReader(
            io.StringIO(
                b"".join([chunk async for chunk in exported.body_iterator]).decode(
                    "utf-8-sig"
                )
            )
        )
    )
    assert listed == {
        "would_route": {refused.request_id},
        "routed": {moved.request_id, personal.request_id},
        "target_unavailable": set(),
    }
    [row] = csv_rows
    assert json.loads(row["route_decision"]) == {**decision, "conversation_id": None}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "saved", [None, {"version": 1, "measured": {"image_downscale": {"bytes": 10}}}]
)
async def test_finalization_carries_the_savings_record(saved) -> None:
    @asynccontextmanager
    async def session_scope():
        yield object()

    accounting = SimpleNamespace(finalize=AsyncMock())
    terminal = _terminal()
    terminal = replace(terminal, usage=replace(terminal.usage, savings=saved))

    await DurableUsageLifecycle(accounting, session_scope).finalize(
        _prepared(), terminal
    )

    assert accounting.finalize.await_args.args[1].savings == saved
