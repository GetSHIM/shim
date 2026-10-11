from __future__ import annotations

from datetime import datetime, timezone
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import shim_enterprise.core.database as database
from shim_enterprise.compliance.models import ComplianceForwardTarget
from shim_enterprise.outbox import handlers
from shim_enterprise.outbox.handlers import (
    APPROVAL_REQUESTED,
    COMPLIANCE_DELIVERY,
    _compliance_text,
    build_publisher,
)
from shim_enterprise.outbox.models import OutboxEvent
from shim_enterprise.outbox.publisher import OutboxMessage
from shim_enterprise.tenants.models import Organization


def _notice(tenant, approval_id: str) -> OutboxMessage:
    return OutboxMessage(
        id=uuid4(),
        organization_id=tenant,
        event_type=APPROVAL_REQUESTED,
        aggregate_type="request_approval",
        aggregate_id=approval_id,
        idempotency_key=f"request_approval:{approval_id}",
        payload={
            "organization_id": str(tenant),
            "approval_id": approval_id,
            "rule_ids": ["kasa"],
            "api_key_id": "key-1",
            "provider": "openai",
            "model": "gpt-5.6-luna",
            "expires_at": "2026-10-13T09:00:00+00:00",
            "occurred_at": "2026-10-12T09:00:00+00:00",
        },
        attempt_count=0,
        created_at=datetime.now(timezone.utc),
    )


@pytest.mark.parametrize("targets", [0, 2])
@pytest.mark.asyncio
async def test_one_delivery_per_forward_target_and_none_without(
    db, monkeypatch, targets: int
) -> None:
    tenant = uuid4()
    db.add(Organization(id=tenant, name="Notice", slug=f"notice-{uuid4().hex}"))
    await db.flush()
    db.add_all(
        ComplianceForwardTarget(
            organization_id=tenant,
            kind="slack",
            endpoint_origin="https://hooks.slack.com",
            secret_ref=f"fernet:v2:{index}",
            secret_backend="fernet",
            secret_version="v2",
            enabled=True,
        )
        for index in range(targets)
    )
    await db.flush()
    monkeypatch.setattr(
        database,
        "AsyncSessionLocal",
        async_sessionmaker(
            await db.connection(),
            class_=AsyncSession,
            expire_on_commit=False,
            join_transaction_mode="create_savepoint",
        ),
    )
    approval_id = str(uuid4())

    await build_publisher().publish(_notice(tenant, approval_id))
    # A retried handler appends nothing twice.
    await handlers.fan_out_request_approval(_notice(tenant, approval_id))

    deliveries = list(
        await db.scalars(
            select(OutboxEvent).where(
                OutboxEvent.organization_id == tenant,
                OutboxEvent.event_type == COMPLIANCE_DELIVERY,
            )
        )
    )
    body = {
        "source": "shim",
        "event_type": "tenant_policy",
        "kind": "request_approval_requested",
        **_notice(tenant, approval_id).payload,
        "review": f"/api/v1/management/approvals/{approval_id}",
    }
    assert len(deliveries) == targets
    for delivery in deliveries:
        assert delivery.idempotency_key.endswith(f":request_approval:{approval_id}")
        assert delivery.payload["body"] == body
    assert _compliance_text(body) == (
        "shim request waiting for approval: rule(s) kasa, key key-1, model "
        "gpt-5.6-luna; decide before 2026-10-13T09:00:00+00:00 at "
        f"/api/v1/management/approvals/{approval_id}"
    )


@pytest.mark.asyncio
async def test_the_email_subject(monkeypatch) -> None:
    tenant = uuid4()
    store = SimpleNamespace(
        get_secret=AsyncMock(
            return_value=json.dumps(
                {"kind": "email", "endpoint": "ops@example.com", "signing_secret": None}
            )
        )
    )
    emailed = AsyncMock()
    monkeypatch.setattr(handlers, "get_secret_store", lambda: store)
    monkeypatch.setattr(handlers, "_send_compliance_email", emailed)

    await handlers.deliver_compliance_event(
        OutboxMessage(
            id=uuid4(),
            organization_id=tenant,
            event_type=COMPLIANCE_DELIVERY,
            aggregate_type="organization",
            aggregate_id=str(tenant),
            idempotency_key="compliance:request-approval",
            payload={
                "organization_id": str(tenant),
                "connector_id": None,
                "target_id": str(uuid4()),
                "target_kind": "email",
                "secret_ref": "fernet:v2:target",
                "body": {"kind": "request_approval_requested", "rule_ids": ["kasa"]},
            },
            attempt_count=1,
            created_at=datetime.now(timezone.utc),
        )
    )

    assert emailed.await_args.kwargs["subject"] == "shim request waiting for approval"
