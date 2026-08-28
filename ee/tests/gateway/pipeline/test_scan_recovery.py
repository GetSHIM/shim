from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import async_sessionmaker

from shim_enterprise.core.config import settings
from shim.privacy.classification import content_ref
from shim.gateway.contracts.ids import RequestId, TenantId
from shim_enterprise.billing.models import AuditIntent, RequestLifecycle
from shim_enterprise.outbox.models import OutboxEvent
from shim_enterprise.gateway.pipeline.audit_intent import AuditIntentRepository
from shim_enterprise.observability.lifecycle import RequestLifecycleRepository
from shim_enterprise.gateway.pipeline.reconciliation import ScanReconciler
from shim_enterprise.tenants.models import ApiKey, Organization, TierDefinition, User


@pytest.mark.asyncio
async def test_stale_audited_scan_is_recovered_atomically_and_idempotently(
    async_engine,
) -> None:
    session_factory = async_sessionmaker(async_engine, expire_on_commit=False)
    suffix = uuid4().hex
    organization_id = uuid4()
    user_id = uuid4()
    api_key_id = uuid4()
    tier_slug = f"scan-recovery-{suffix}"
    raw_text = "recovery-private-person@example.com"
    request_id = RequestId(f"scan_recovery_{uuid4().hex}")
    recovery_now = datetime.now(timezone.utc)
    started_at = recovery_now - timedelta(minutes=10)
    async with session_factory.begin() as setup_session:
        setup_session.add(
            TierDefinition(
                slug=tier_slug,
                name="Scan Recovery",
                rate_limit_rpm=60,
                rate_limit_tpm=15_000,
                monthly_request_limit=1_000,
                monthly_token_limit=1_000_000,
                features={"audit_policy_mode": "best_effort"},
            )
        )
        setup_session.add(
            Organization(
                id=organization_id,
                name="Scan Recovery",
                slug=f"scan-recovery-{suffix}",
            )
        )
        await setup_session.flush()
        setup_session.add(
            User(
                id=user_id,
                email=f"scan-recovery-{suffix}@example.com",
                is_active=True,
                organization_id=organization_id,
            )
        )
        await setup_session.flush()
        setup_session.add(
            ApiKey(
                id=api_key_id,
                user_id=user_id,
                organization_id=organization_id,
                key_hash=suffix,
                prefix="sk-shim-recover",
                tier=tier_slug,
                is_active=True,
            )
        )
        await setup_session.flush()
        await RequestLifecycleRepository.create(
            setup_session,
            organization_id=TenantId(organization_id),
            values={
                "request_id": str(request_id),
                "actor_type": "api_key",
                "api_key_id": api_key_id,
                "user_id": None,
                "source_endpoint": "scan",
                "status": "accepted",
                "provider": None,
                "provider_model": None,
                "requested_model": None,
                "route_decision": None,
                "stream": False,
                "cache_status": "not_applicable",
                "privacy_status": "pending",
                "pii_detected": False,
                "started_at": started_at,
                "reconciliation_due_at": recovery_now - timedelta(seconds=1),
                "lifecycle_metadata": {
                    "audit_mode": "best_effort",
                    "scan_counted": True,
                    "scan_count_delta": 1,
                    "scan_source": "unknown",
                    "scan_subject_user_id": str(user_id),
                },
            },
        )
        await AuditIntentRepository.create(
            setup_session,
            organization_id=TenantId(organization_id),
            values={
                "request_id": str(request_id),
                "actor_type": "api_key",
                "api_key_id": api_key_id,
                "user_id": None,
                "event_type": "preflight",
                "audit_policy_mode": "best_effort",
                "input_hash": content_ref(
                    settings.COMPLIANCE_HASH_SALT or settings.SECRET_KEY,
                    raw_text,
                ),
                "output_hash": None,
                "pii_entities": {},
                "provider": None,
                "model": None,
                "usage_summary": {"scan_counted": 1},
                "lifecycle_status": "accepted",
            },
        )

    reconciler = ScanReconciler()
    try:
        async with session_factory.begin() as recovery_session:
            recovered = await reconciler.recover_stale(
                recovery_session,
                now=recovery_now,
                batch_size=10,
            )

        async with session_factory() as verification_session:
            lifecycle = (
                await verification_session.execute(
                    select(RequestLifecycle).where(
                        RequestLifecycle.request_id == str(request_id)
                    )
                )
            ).scalar_one()
            intents = list(
                (
                    await verification_session.execute(
                        select(AuditIntent).where(
                            AuditIntent.request_id == str(request_id)
                        )
                    )
                )
                .scalars()
                .all()
            )
            outbox = list(
                (
                    await verification_session.execute(
                        select(OutboxEvent).where(
                            OutboxEvent.aggregate_id == str(request_id)
                        )
                    )
                )
                .scalars()
                .all()
            )

        assert len(recovered) == 1
        assert lifecycle.status == "internal_error"
        assert lifecycle.reconciled_at == recovery_now
        assert lifecycle.reconciliation_due_at is None
        assert {intent.event_type for intent in intents} == {
            "preflight",
            "completion",
        }
        assert {event.event_type for event in outbox} == {
            "audit.chain_append_requested",
            "gateway.reconciliation",
        }
        audit_event = next(
            event
            for event in outbox
            if event.event_type == "audit.chain_append_requested"
        )
        assert audit_event.payload["policy_verdicts"] == []
        assert audit_event.payload["extra"]["lifecycle_status"] == "internal_error"
        assert raw_text not in json.dumps(audit_event.payload, default=str)

        async with session_factory.begin() as second_recovery_session:
            second_recovery = await reconciler.recover_stale(
                second_recovery_session,
                now=recovery_now + timedelta(seconds=1),
                batch_size=10,
            )
        assert second_recovery == ()
    finally:
        async with session_factory.begin() as cleanup_session:
            await cleanup_session.execute(
                delete(AuditIntent).where(
                    AuditIntent.organization_id == organization_id
                )
            )
            await cleanup_session.execute(
                delete(OutboxEvent).where(
                    OutboxEvent.organization_id == organization_id
                )
            )
            await cleanup_session.execute(
                delete(RequestLifecycle).where(
                    RequestLifecycle.organization_id == organization_id
                )
            )
            await cleanup_session.execute(delete(ApiKey).where(ApiKey.id == api_key_id))
            await cleanup_session.execute(delete(User).where(User.id == user_id))
            await cleanup_session.execute(
                delete(Organization).where(Organization.id == organization_id)
            )
            await cleanup_session.execute(
                delete(TierDefinition).where(TierDefinition.slug == tier_slug)
            )
