from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import async_sessionmaker

from shim_enterprise.core.config import settings
from shim.gateway.contracts.ids import ApiKeyId, UserId
from shim_enterprise.gateway.contracts.enterprise_errors import (
    ScanLimitExceeded,
    ScanPersistenceError,
)
from shim.gateway.contracts.errors import ScanAnalysisError
from shim.gateway.contracts.inference import ScanInput
from shim.gateway.contracts.principal import AuthenticatedPrincipal
from shim_enterprise.billing.models import AuditIntent, RequestLifecycle
from shim_enterprise.outbox.models import OutboxEvent
from shim_enterprise.gateway.pipeline.audit_intent import AuditIntentRepository
from shim_enterprise.gateway.pipeline.scan_policy import ScanPolicyResolver
from shim_enterprise.observability.lifecycle import RequestLifecycleRepository
from shim_enterprise.gateway.kernel.scan_pipeline import ScanExecutionPipeline
from shim_enterprise.tenants.models import ApiKey, Organization, TierDefinition, User
from shim_enterprise.observability.enterprise_metrics import QUOTA_RESERVATION_TOTAL
from shim.observability.metrics import (
    PRIVACY_DETECTION_TOTAL,
    REQUESTS_TOTAL,
    bounded_label,
)


class StubScrubber:
    def __init__(
        self,
        entities: list[dict] | None = None,
        error: Exception | None = None,
        before_analyze: Callable[[], None] | None = None,
    ):
        self.entities = entities or []
        self.error = error
        self.before_analyze = before_analyze
        self.calls: list[str] = []

    def analyze(self, text: str, *, config: dict) -> list[dict]:
        self.calls.append(text)
        if self.before_analyze is not None:
            self.before_analyze()
        if self.error is not None:
            raise self.error
        return self.entities


def api_key_principal(api_key_id: uuid.UUID) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        actor_type="api_key",
        api_key_id=ApiKeyId(api_key_id),
        authenticated_at=datetime.now(timezone.utc),
    )


def user_principal(user_id: uuid.UUID) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        actor_type="user_jwt",
        user_id=UserId(user_id),
        authenticated_at=datetime.now(timezone.utc),
    )


@pytest.fixture(autouse=True)
def outbox_audit_mode(monkeypatch):
    monkeypatch.setattr(settings, "AI_ACT_AUDIT_ENABLED", True)


@pytest.mark.asyncio
async def test_success_persists_terminal_state_audit_outbox_without_raw_pii(
    db, test_api_key
) -> None:
    raw_text = "private-sentinel-person@example.com"
    scrubber = StubScrubber(
        [{"type": "EMAIL_ADDRESS", "score": 0.99, "start": 17, "end": 44}]
    )
    request_metric = REQUESTS_TOTAL.labels(
        endpoint="/v1/scan",
        status="success",
        tenant_tier=bounded_label("tenant_tier", test_api_key.tier),
    )
    privacy_metric = PRIVACY_DETECTION_TOTAL.labels(entity_type="EMAIL_ADDRESS")
    quota_metric = QUOTA_RESERVATION_TOTAL.labels(status="reserved")
    request_before = request_metric._value.get()
    privacy_before = privacy_metric._value.get()
    quota_before = quota_metric._value.get()

    result = await ScanExecutionPipeline(scrubber=scrubber).execute(
        ScanInput(text=raw_text, source="chatgpt"),
        api_key_principal(test_api_key.id),
        db,
    )

    lifecycle = (
        await db.execute(
            select(RequestLifecycle).where(
                RequestLifecycle.request_id == result.request_id
            )
        )
    ).scalar_one()
    intents = list(
        (
            await db.execute(
                select(AuditIntent).where(AuditIntent.request_id == result.request_id)
            )
        )
        .scalars()
        .all()
    )
    outbox = (
        await db.execute(
            select(OutboxEvent).where(OutboxEvent.aggregate_id == result.request_id)
        )
    ).scalar_one()

    assert lifecycle.organization_id == test_api_key.organization_id
    assert lifecycle.actor_type == "api_key"
    assert lifecycle.api_key_id == test_api_key.id
    assert lifecycle.user_id is None
    assert lifecycle.status == "completed"
    assert lifecycle.privacy_status == "detected"
    assert {intent.event_type for intent in intents} == {"preflight", "completion"}
    assert {intent.lifecycle_status for intent in intents} == {"accepted", "completed"}
    assert outbox.status == "pending"
    assert outbox.id == next(
        intent.outbox_event_id
        for intent in intents
        if intent.event_type == "completion"
    )
    persisted = json.dumps(
        {
            "lifecycle": lifecycle.lifecycle_metadata,
            "intents": [
                {
                    "input_hash": intent.input_hash,
                    "output_hash": intent.output_hash,
                    "pii_entities": intent.pii_entities,
                    "usage_summary": intent.usage_summary,
                }
                for intent in intents
            ],
            "outbox": outbox.payload,
        },
        default=str,
    )
    assert raw_text not in persisted
    assert "private-sentinel-person@example.com" not in persisted
    assert request_metric._value.get() == request_before + 1
    assert privacy_metric._value.get() == privacy_before + 1
    assert quota_metric._value.get() == quota_before + 1


@pytest.mark.asyncio
async def test_preflight_is_durable_before_privacy_analysis(
    db, test_api_key, monkeypatch
) -> None:
    commit = AsyncMock(wraps=db.commit)
    monkeypatch.setattr(db, "commit", commit)

    def assert_preflight_committed() -> None:
        assert commit.await_count == 1

    scrubber = StubScrubber(
        error=RuntimeError("privacy unavailable"),
        before_analyze=assert_preflight_committed,
    )

    with pytest.raises(ScanAnalysisError):
        await ScanExecutionPipeline(scrubber=scrubber).execute(
            ScanInput(text="private@example.com", source="unknown"),
            api_key_principal(test_api_key.id),
            db,
        )

    lifecycle = (
        await db.execute(
            select(RequestLifecycle).where(
                RequestLifecycle.api_key_id == test_api_key.id,
                RequestLifecycle.source_endpoint == "scan",
            )
        )
    ).scalar_one()
    intents = list(
        (
            await db.execute(
                select(AuditIntent).where(
                    AuditIntent.request_id == lifecycle.request_id
                )
            )
        )
        .scalars()
        .all()
    )
    outbox = (
        await db.execute(
            select(OutboxEvent).where(
                OutboxEvent.aggregate_id == lifecycle.request_id,
                OutboxEvent.event_type == "audit.chain_append_requested",
            )
        )
    ).scalar_one()
    assert scrubber.calls == ["private@example.com"]
    assert lifecycle.status == "internal_error"
    assert {intent.event_type for intent in intents} == {"preflight", "completion"}
    assert next(i for i in intents if i.event_type == "preflight").lifecycle_status == (
        "accepted"
    )
    assert outbox.payload["policy_verdicts"] == []


@pytest.mark.asyncio
async def test_empty_input_has_durable_lifecycle_without_consuming_usage(
    db, test_api_key
) -> None:
    scrubber = StubScrubber()
    kernel = ScanExecutionPipeline(scrubber=scrubber)

    result = await kernel.execute(
        ScanInput(text=" \n\t", source="gemini"),
        api_key_principal(test_api_key.id),
        db,
    )
    usage = await kernel.usage(api_key_principal(test_api_key.id), db)
    lifecycle = (
        await db.execute(
            select(RequestLifecycle).where(
                RequestLifecycle.request_id == result.request_id
            )
        )
    ).scalar_one()

    assert result.verdict == "clean"
    assert result.scan_count == 0
    assert usage.scan_count == 0
    assert lifecycle.status == "completed"
    assert lifecycle.lifecycle_metadata["scan_counted"] is False
    assert scrubber.calls == []


@pytest.mark.asyncio
async def test_usage_is_postgres_authoritative(db, test_api_key) -> None:
    kernel = ScanExecutionPipeline(scrubber=StubScrubber())

    await kernel.execute(
        ScanInput(text="one durable scan", source="unknown"),
        api_key_principal(test_api_key.id),
        db,
    )
    usage = await kernel.usage(api_key_principal(test_api_key.id), db)

    assert usage.scan_count == 1
    assert usage.scans_remaining == usage.scan_limit - 1


@pytest.mark.asyncio
async def test_unlimited_tier_tracks_usage_without_enforcing_a_cap(
    db, test_api_key
) -> None:
    await db.execute(
        update(TierDefinition)
        .where(TierDefinition.slug == test_api_key.tier)
        .values(features={"monthly_scan_limit": -1, "audit_policy_mode": "off"})
    )
    scrubber = StubScrubber()
    kernel = ScanExecutionPipeline(scrubber=scrubber)

    first = await kernel.execute(
        ScanInput(text="unlimited one", source="unknown"),
        api_key_principal(test_api_key.id),
        db,
    )
    second = await kernel.execute(
        ScanInput(text="unlimited two", source="unknown"),
        api_key_principal(test_api_key.id),
        db,
    )
    usage = await kernel.usage(api_key_principal(test_api_key.id), db)
    lifecycles = list(
        (
            await db.execute(
                select(RequestLifecycle).where(
                    RequestLifecycle.request_id.in_(
                        [str(first.request_id), str(second.request_id)]
                    )
                )
            )
        )
        .scalars()
        .all()
    )

    assert first.scan_count == 1
    assert second.scan_count == usage.scan_count == 2
    assert first.scan_limit == second.scan_limit == usage.scan_limit == -1
    assert first.scans_remaining == second.scans_remaining == -1
    assert usage.scans_remaining == -1
    assert len(lifecycles) == 2
    assert all(
        lifecycle.lifecycle_metadata["scan_counted"] is True for lifecycle in lifecycles
    )
    assert scrubber.calls == ["unlimited one", "unlimited two"]


@pytest.mark.asyncio
async def test_postgres_failure_stops_before_pii(db, test_api_key, monkeypatch) -> None:
    scrubber = StubScrubber()
    monkeypatch.setattr(
        RequestLifecycleRepository,
        "create",
        AsyncMock(side_effect=RuntimeError("postgres down")),
    )

    with pytest.raises(ScanPersistenceError):
        await ScanExecutionPipeline(scrubber=scrubber).execute(
            ScanInput(text="private@example.com", source="unknown"),
            api_key_principal(test_api_key.id),
            db,
        )

    assert scrubber.calls == []


@pytest.mark.parametrize("audit_mode", ["best_effort", "strict"])
@pytest.mark.asyncio
async def test_enabled_audit_preflight_failure_fails_closed_before_pii(
    db, test_api_key, monkeypatch, audit_mode
) -> None:
    await db.execute(
        update(TierDefinition)
        .where(TierDefinition.slug == test_api_key.tier)
        .values(features={"audit_policy_mode": audit_mode})
    )
    scrubber = StubScrubber()
    monkeypatch.setattr(
        AuditIntentRepository,
        "create",
        AsyncMock(side_effect=RuntimeError("audit store down")),
    )

    with pytest.raises(ScanPersistenceError):
        await ScanExecutionPipeline(scrubber=scrubber).execute(
            ScanInput(text="private@example.com", source="unknown"),
            api_key_principal(test_api_key.id),
            db,
        )

    assert scrubber.calls == []
    assert (
        await db.execute(
            select(RequestLifecycle).where(
                RequestLifecycle.api_key_id == test_api_key.id,
                RequestLifecycle.source_endpoint == "scan",
            )
        )
    ).scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_jwt_scan_retains_user_actor_and_current_tenant(
    db, test_org, test_user_with_org, test_tier
) -> None:
    test_org.tier = "managed"
    await db.flush()
    actor = await ScanPolicyResolver().resolve(
        user_principal(test_user_with_org.id),
        db,
    )
    result = await ScanExecutionPipeline(scrubber=StubScrubber()).execute(
        ScanInput(text="jwt scan", source="unknown"),
        user_principal(test_user_with_org.id),
        db,
    )
    lifecycle = (
        await db.execute(
            select(RequestLifecycle).where(
                RequestLifecycle.request_id == result.request_id
            )
        )
    ).scalar_one()

    assert lifecycle.organization_id == test_user_with_org.organization_id
    assert lifecycle.actor_type == "user_jwt"
    assert lifecycle.user_id == test_user_with_org.id
    assert lifecycle.api_key_id is None
    assert actor.tier == "managed"


@pytest.mark.asyncio
async def test_api_key_limit_is_shared_by_all_keys_owned_by_user(
    db, test_api_key
) -> None:
    await db.execute(
        update(TierDefinition)
        .where(TierDefinition.slug == test_api_key.tier)
        .values(features={"monthly_scan_limit": 1, "audit_policy_mode": "off"})
    )
    second_key = ApiKey(
        id=uuid.uuid4(),
        user_id=test_api_key.user_id,
        organization_id=test_api_key.organization_id,
        key_hash=uuid.uuid4().hex,
        prefix="sk-shim-second",
        tier=test_api_key.tier,
        is_active=True,
    )
    db.add(second_key)
    await db.flush()
    kernel = ScanExecutionPipeline(scrubber=StubScrubber())
    rejected_metric = QUOTA_RESERVATION_TOTAL.labels(status="rejected")
    rejected_before = rejected_metric._value.get()

    await kernel.execute(
        ScanInput(text="first key", source="unknown"),
        api_key_principal(test_api_key.id),
        db,
    )
    with pytest.raises(ScanLimitExceeded):
        await kernel.execute(
            ScanInput(text="second key", source="unknown"),
            api_key_principal(second_key.id),
            db,
        )
    assert rejected_metric._value.get() == rejected_before + 1


@pytest.mark.asyncio
async def test_concurrent_admission_cannot_exceed_tiny_limit(async_engine) -> None:
    session_factory = async_sessionmaker(async_engine, expire_on_commit=False)
    suffix = uuid.uuid4().hex
    organization_id = uuid.uuid4()
    user_id = uuid.uuid4()
    api_key_id = uuid.uuid4()
    tier_slug = f"scan-tiny-{suffix}"
    async with session_factory.begin() as setup:
        setup.add(
            TierDefinition(
                slug=tier_slug,
                name="Scan Tiny",
                rate_limit_rpm=60,
                rate_limit_tpm=15_000,
                monthly_request_limit=1_000,
                monthly_token_limit=1_000_000,
                features={"monthly_scan_limit": 1, "audit_policy_mode": "off"},
            )
        )
        setup.add(
            Organization(
                id=organization_id,
                name="Scan concurrency",
                slug=f"scan-concurrency-{suffix}",
            )
        )
        await setup.flush()
        setup.add(
            User(
                id=user_id,
                email=f"scan-concurrency-{suffix}@example.com",
                is_active=True,
                organization_id=organization_id,
            )
        )
        await setup.flush()
        setup.add(
            ApiKey(
                id=api_key_id,
                user_id=user_id,
                organization_id=organization_id,
                key_hash=suffix,
                prefix="sk-shim-concurr",
                tier=tier_slug,
                is_active=True,
            )
        )

    async def attempt(index: int) -> str:
        async with session_factory() as session:
            try:
                await ScanExecutionPipeline(scrubber=StubScrubber()).execute(
                    ScanInput(text=f"scan {index}", source="unknown"),
                    api_key_principal(api_key_id),
                    session,
                )
            except ScanLimitExceeded:
                return "rejected"
            return "accepted"

    try:
        outcomes = await asyncio.gather(*(attempt(index) for index in range(8)))
        async with session_factory() as verify:
            lifecycles = list(
                (
                    await verify.execute(
                        select(RequestLifecycle).where(
                            RequestLifecycle.organization_id == organization_id,
                            RequestLifecycle.source_endpoint == "scan",
                        )
                    )
                )
                .scalars()
                .all()
            )

        assert outcomes.count("accepted") == 1
        assert (
            sum(
                row.lifecycle_metadata.get("scan_counted") is True for row in lifecycles
            )
            == 1
        )
    finally:
        async with session_factory.begin() as cleanup:
            await cleanup.execute(
                delete(AuditIntent).where(
                    AuditIntent.organization_id == organization_id
                )
            )
            await cleanup.execute(
                delete(OutboxEvent).where(
                    OutboxEvent.organization_id == organization_id
                )
            )
            await cleanup.execute(
                delete(RequestLifecycle).where(
                    RequestLifecycle.organization_id == organization_id
                )
            )
            await cleanup.execute(delete(ApiKey).where(ApiKey.id == api_key_id))
            await cleanup.execute(delete(User).where(User.id == user_id))
            await cleanup.execute(
                delete(Organization).where(Organization.id == organization_id)
            )
            await cleanup.execute(
                delete(TierDefinition).where(TierDefinition.slug == tier_slug)
            )
