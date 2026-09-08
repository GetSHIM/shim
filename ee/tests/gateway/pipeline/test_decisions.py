from datetime import datetime, timezone
from decimal import Decimal
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from uuid import uuid4
from fastapi import HTTPException
from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker

from shim.gateway.admission import LoopDetectionResult
from shim.gateway.contracts.context import AuditPolicy, TenantPolicy, TierPolicy
from shim.gateway.contracts.principal import AuthenticatedPrincipal
from shim.gateway.kernel.gateway_kernel import GatewayKernel
from shim.gateway.pipeline.authenticate import GatewayInvocation, GatewayRequestMetadata
from shim.gateway.pipeline.provider_execution import ProviderNonStream
from shim.gateway.request_policy import RequestPolicyContext, ResolvedRequestPolicy
from shim_enterprise.ai_act.audit_writer import write_audit_row
from shim_enterprise.ai_act.api import list_audit_logs
from shim_enterprise.ai_act.models import AIActAuditLog
from shim_enterprise.ai_act.verify import verify_chain
from shim_enterprise.billing.ledger import (
    QuotaLimitExceeded,
    QuotaPolicySnapshot,
    SpendLimitExceeded,
    SpendPolicySnapshot,
)
from shim_enterprise.billing.models import (
    AuditIntent,
    QuotaPeriodUsage,
    RequestLifecycle,
    SpendPeriodUsage,
    UsageLedger,
)
from shim_enterprise.tenants.models import ApiKey, Organization, User
from shim_enterprise.gateway.pipeline.audit_intent import AuditIntentPersistenceError
from shim_enterprise.gateway.pipeline.quota_reservation import (
    DurableAccountingCoordinator,
    DurableUsageLifecycle,
)
from shim_enterprise.outbox.handlers import append_audit_chain
from shim_enterprise.outbox.models import OutboxEvent
from shim_enterprise.outbox.publisher import OutboxMessage, OutboxWriter


@pytest_asyncio.fixture
async def decision_db(async_engine):
    factory = async_sessionmaker(async_engine, expire_on_commit=False, autoflush=False)
    tenant_id, user_id = uuid4(), uuid4()
    async with factory.begin() as setup:
        await setup.execute(
            text(
                "INSERT INTO tier_definitions (slug, name, rate_limit_rpm, rate_limit_tpm, monthly_request_limit, monthly_token_limit, features) VALUES ('free', 'Free', 60, 15000, 1000, 1000000, '{}') ON CONFLICT (slug) DO NOTHING"
            )
        )
        setup.add(
            Organization(
                id=tenant_id, name="Decision test", slug=f"decisions-{tenant_id}"
            )
        )
        await setup.flush()
        setup.add(
            User(id=user_id, organization_id=tenant_id, email=f"{user_id}@example.com")
        )
        await setup.flush()
        key = ApiKey(
            id=uuid4(),
            organization_id=tenant_id,
            user_id=user_id,
            key_hash=uuid4().hex,
            prefix="sk-decisions",
            tier="free",
            is_active=True,
        )
        setup.add(key)
    try:
        async with factory() as session:
            yield session, key
    finally:
        async with factory.begin() as cleanup:
            for model in (
                AIActAuditLog,
                AuditIntent,
                OutboxEvent,
                UsageLedger,
                RequestLifecycle,
                QuotaPeriodUsage,
                SpendPeriodUsage,
                ApiKey,
                User,
            ):
                await cleanup.execute(
                    delete(model).where(model.organization_id == tenant_id)
                )
            await cleanup.execute(
                delete(Organization).where(Organization.id == tenant_id)
            )


class Scrubber:
    def scrub(self, value, _config, **_kwargs):
        if "private@example.com" in value:
            return value.replace("private@example.com", "<EMAIL_ADDRESS_a1>"), {
                "<EMAIL_ADDRESS_a1>": "private@example.com"
            }
        return value, {}


def gateway(db, key, case, *, audit_mode="strict"):
    session_scope = async_sessionmaker(db.bind, expire_on_commit=False, autoflush=False)

    policy = ResolvedRequestPolicy(
        tenant_id=key.organization_id,
        tenant_policy=TenantPolicy(
            allowed_providers=("google",) if case == "provider" else (),
            require_zero_retention=case == "retention",
        ),
        tier_policy=TierPolicy(rate_limit_rpm=60),
        audit_policy=AuditPolicy(mode=audit_mode),
        request_policy=RequestPolicyContext("test-key-hash", "free"),
        pii_config={"EMAIL_ADDRESS": True},
    )
    usage = DurableUsageLifecycle(
        DurableAccountingCoordinator(
            policy_loader=SimpleNamespace(
                quota=AsyncMock(
                    return_value=QuotaPolicySnapshot(
                        "quota-v1", None, 0 if case == "quota" else 1000, 1000000
                    )
                ),
                spend=AsyncMock(
                    return_value=SpendPolicySnapshot(
                        "spend-v1", Decimal("0") if case == "spend" else None
                    )
                ),
            )
        ),
        session_scope,
    )

    async def execute(*, invocation, prepared, provider_start_callback):
        await provider_start_callback()
        assert "private@example.com" not in json.dumps(prepared.payload)
        return ProviderNonStream(
            payload={
                "model": prepared.model,
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "ok"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 2, "completion_tokens": 1},
            },
            request_id="provider-id",
        )

    execution = SimpleNamespace(
        pii_scrubber=Scrubber(), execute=AsyncMock(side_effect=execute)
    )
    kernel = GatewayKernel(
        {"openai": execution},
        chain_store=SimpleNamespace(),
        policy_resolver=SimpleNamespace(resolve=AsyncMock(return_value=policy)),
        rate_limiter=SimpleNamespace(allow=AsyncMock(return_value=case != "rate")),
        loop_detector=SimpleNamespace(
            check_exact_repeat=AsyncMock(return_value=LoopDetectionResult("SAFE", 1))
        ),
        loop_repeat_limit=3,
        loop_window_seconds=60,
        cost_tag_max_length=64,
        usage=usage,
    )
    model = "private@example.com" if case == "model" else "gpt-5.6-luna"
    content = (
        [{"type": "image_url", "image_url": {"url": "data:private"}}]
        if case == "privacy"
        else "private@example.com"
        if case == "mask"
        else "hello"
    )
    invocation = GatewayInvocation(
        principal=AuthenticatedPrincipal(
            actor_type="api_key",
            api_key_id=key.id,
            authenticated_at=datetime.now(timezone.utc),
        ),
        payload={
            "model": model,
            "messages": [{"role": "user", "content": content}],
            "max_completion_tokens": 4,
        },
        provider="openai",
        protocol="chat",
        model=model,
        stream=False,
        headers={"x-provider-key": "credential-sentinel"},
        provider_credential=None,
        metadata=GatewayRequestMetadata(endpoint="/v1/chat/completions"),
    )
    return kernel, invocation, execution


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("case", "rule"),
    [
        ("provider", "tenant.allowed_providers"),
        ("retention", "tenant.zero_retention_request"),
        ("model", "gateway.model_catalog"),
        ("rate", "rate.requests"),
        ("quota", "quota.requests_and_tokens"),
    ],
)
async def test_pre_admission_denial_is_durable_private_and_idempotent(
    decision_db, monkeypatch, case, rule
):
    db, test_api_key = decision_db
    kernel, invocation, execution = gateway(db, test_api_key, case)
    with pytest.raises((HTTPException, QuotaLimitExceeded)):
        await kernel._execute(invocation)
    execution.execute.assert_not_awaited()
    event = (
        await db.execute(
            select(OutboxEvent).where(
                OutboxEvent.organization_id == test_api_key.organization_id
            )
        )
    ).scalar_one()
    assert event.payload["actor"] is None
    assert event.payload["api_key_id"] == str(test_api_key.id)
    assert event.payload["extra"]["lifecycle_status"] == "rejected"
    assert event.payload["extra"]["admitted"] is False
    denied = next(
        verdict
        for verdict in event.payload["policy_verdicts"]
        if verdict["outcome"] == "deny"
    )
    assert denied["rule_id"] == rule
    assert denied["schema_version"] == denied["rule_version"] == 1
    assert denied["effective_at"] and denied["policy_version"]
    assert "private@example.com" not in json.dumps(event.payload)
    assert "credential-sentinel" not in json.dumps(event.payload)
    assert (
        not (
            await db.execute(
                select(UsageLedger).where(
                    UsageLedger.organization_id == test_api_key.organization_id
                )
            )
        )
        .scalars()
        .all()
    )
    assert (
        not (
            await db.execute(
                select(RequestLifecycle).where(
                    RequestLifecycle.organization_id == test_api_key.organization_id
                )
            )
        )
        .scalars()
        .all()
    )
    assert (
        len(
            (
                await db.execute(
                    select(AuditIntent).where(
                        AuditIntent.organization_id == test_api_key.organization_id
                    )
                )
            )
            .scalars()
            .all()
        )
        == 1
    )

    async def append(context):
        return await write_audit_row(context, db, deduplicate=True)

    monkeypatch.setattr(
        "shim_enterprise.ai_act.audit_writer.append_audit_row_deduplicated", append
    )
    message = OutboxMessage.from_event(event)
    await append_audit_chain(message)
    await append_audit_chain(message)
    verification = await verify_chain(db, test_api_key.organization_id)
    assert verification["ok"] is True
    assert verification["rows_checked"] == 1
    page = await list_audit_logs(
        request_id=event.aggregate_id,
        event_type=None,
        start=None,
        end=None,
        limit=50,
        offset=0,
        current_user=SimpleNamespace(organization_id=test_api_key.organization_id),
        session=db,
    )
    assert page.total == 1
    assert page.items[0].policy_verdicts == event.payload["policy_verdicts"]
    assert page.items[0].api_key_id == test_api_key.id
    assert page.items[0].actor is None
    assert page.items[0].actor_type == "api_key"
    assert page.items[0].lifecycle_status == "rejected"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("case", "expected_status", "expected_pii"),
    [
        ("allow", "completed", "allow"),
        ("mask", "completed", "mask"),
        ("privacy", "rejected", "deny"),
        ("spend", "rejected", "allow"),
    ],
)
async def test_admitted_decisions_survive_accounting_finalization(
    decision_db, case, expected_status, expected_pii
):
    db, test_api_key = decision_db
    kernel, invocation, execution = gateway(db, test_api_key, case)
    if expected_status == "rejected":
        with pytest.raises((HTTPException, SpendLimitExceeded)):
            await kernel._execute(invocation)
        execution.execute.assert_not_awaited()
    else:
        response = await kernel._execute(invocation)
        assert response.status_code == 200
        execution.execute.assert_awaited_once()
    lifecycle = (
        await db.execute(
            select(RequestLifecycle).where(
                RequestLifecycle.organization_id == test_api_key.organization_id
            )
        )
    ).scalar_one()
    event = (
        await db.execute(
            select(OutboxEvent).where(
                OutboxEvent.organization_id == test_api_key.organization_id,
                OutboxEvent.event_type == "audit.chain_append_requested",
            )
        )
    ).scalar_one()
    assert (
        lifecycle.status
        == event.payload["extra"]["lifecycle_status"]
        == expected_status
    )
    verdicts = {
        verdict["rule_id"]: verdict for verdict in event.payload["policy_verdicts"]
    }
    assert verdicts["quota.requests_and_tokens"]["policy_version"] == "quota-v1"
    assert verdicts["privacy.input"]["outcome"] == expected_pii
    if case != "privacy":
        assert verdicts["spend.provider_monthly"]["policy_version"] == "spend-v1"
        assert verdicts["spend.provider_monthly"]["outcome"] == (
            "deny" if case == "spend" else "allow"
        )
    assert event.payload["actor"] is None
    assert "private@example.com" not in json.dumps(event.payload)
    assert "credential-sentinel" not in json.dumps(event.payload)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["strict", "best_effort", "off"])
async def test_denial_audit_failure_obeys_mode_without_provider_execution(
    decision_db, monkeypatch, mode, caplog
):
    db, test_api_key = decision_db
    kernel, invocation, execution = gateway(db, test_api_key, "rate", audit_mode=mode)
    append = AsyncMock(side_effect=RuntimeError("private-audit-failure-sentinel"))
    monkeypatch.setattr(OutboxWriter, "append", append)
    with pytest.raises(
        AuditIntentPersistenceError if mode == "strict" else HTTPException
    ):
        await kernel._execute(invocation)
    execution.execute.assert_not_awaited()
    assert "private-audit-failure-sentinel" not in caplog.text
    if mode == "off":
        append.assert_not_awaited()
    else:
        append.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["strict", "best_effort"])
async def test_admitted_denial_outbox_failure_preserves_atomicity(
    decision_db, monkeypatch, mode, caplog
):
    db, key = decision_db
    kernel, invocation, execution = gateway(db, key, "privacy", audit_mode=mode)
    append = OutboxWriter.append

    async def fail_audit(writer, session, *, organization_id, values):
        if values["event_type"] == "audit.chain_append_requested":
            raise RuntimeError("private-audit-failure-sentinel")
        return await append(
            writer, session, organization_id=organization_id, values=values
        )

    monkeypatch.setattr(OutboxWriter, "append", fail_audit)
    with pytest.raises(
        AuditIntentPersistenceError if mode == "strict" else HTTPException
    ):
        await kernel._execute(invocation)
    execution.execute.assert_not_awaited()
    lifecycle = (
        await db.execute(
            select(RequestLifecycle).where(
                RequestLifecycle.organization_id == key.organization_id
            )
        )
    ).scalar_one()
    assert lifecycle.status == "accepted"
    assert lifecycle.reconciliation_due_at is not None
    assert lifecycle.reconciled_at is None
    ledger = (
        (
            await db.execute(
                select(UsageLedger).where(
                    UsageLedger.organization_id == key.organization_id
                )
            )
        )
        .scalars()
        .all()
    )
    assert [entry.event_type for entry in ledger] == ["quota_reservation"]
    assert "private-audit-failure-sentinel" not in caplog.text


@pytest.mark.asyncio
async def test_uncertain_admission_acknowledgement_reuses_durable_lifecycle(
    decision_db, monkeypatch
):
    db, key = decision_db
    kernel, invocation, execution = gateway(db, key, "allow")
    admit = kernel.usage.admit

    async def lost_ack(prepared, admission):
        await admit(prepared, admission)
        raise RuntimeError("lost-ack-private")

    monkeypatch.setattr(kernel.usage, "admit", lost_ack)
    with pytest.raises(RuntimeError, match="lost-ack-private"):
        await kernel._execute(invocation)
    execution.execute.assert_not_awaited()
    lifecycle = (
        await db.execute(
            select(RequestLifecycle).where(
                RequestLifecycle.organization_id == key.organization_id
            )
        )
    ).scalar_one()
    event = (
        await db.execute(
            select(OutboxEvent).where(
                OutboxEvent.organization_id == key.organization_id,
                OutboxEvent.event_type == "audit.chain_append_requested",
            )
        )
    ).scalar_one()
    assert lifecycle.status == event.payload["extra"]["lifecycle_status"] == "failed"
    assert (
        event.payload["policy_verdicts"][-1]["reason_code"] == "ADMISSION_UNAVAILABLE"
    )
    assert "lost-ack-private" not in json.dumps(event.payload)
    ledger = (
        (
            await db.execute(
                select(UsageLedger).where(
                    UsageLedger.organization_id == key.organization_id
                )
            )
        )
        .scalars()
        .all()
    )
    assert {entry.event_type for entry in ledger} == {
        "quota_reservation",
        "quota_refund",
    }
