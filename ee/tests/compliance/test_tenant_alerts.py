from contextlib import asynccontextmanager
from datetime import datetime, timezone
from unittest.mock import AsyncMock
from uuid import uuid4

from fastapi import FastAPI
import httpx
import pytest
from sqlalchemy import select

import shim_enterprise.api.enterprise_deps as enterprise_deps
from shim_enterprise.api.v1.router import management_router
import shim_enterprise.compliance.api as compliance_api
from shim_enterprise.compliance.models import (
    ComplianceConnector,
    ComplianceForwardTarget,
)
from shim_enterprise.compliance.services.forwarder import (
    DELIVERY_EVENT,
    ComplianceForwarderService,
)
from shim_enterprise.core.database import get_db
from shim_enterprise.outbox import handlers
from shim_enterprise.outbox.models import OutboxEvent
from shim_enterprise.outbox.publisher import OutboxMessage
from shim_enterprise.tenants.models import Organization
from shim.gateway.contracts.ids import TenantId


def _target(organization_id, connector_id=None, *, enabled=True):
    return ComplianceForwardTarget(
        organization_id=organization_id,
        connector_id=connector_id,
        kind="slack",
        endpoint_origin="https://hooks.slack.com",
        secret_ref=f"fernet:v2:{uuid4().hex}",
        secret_backend="fernet",
        secret_version="v2",
        enabled=enabled,
    )


async def _deliveries(db, organization_id) -> list[OutboxEvent]:
    return list(
        await db.scalars(
            select(OutboxEvent).where(
                OutboxEvent.organization_id == organization_id,
                OutboxEvent.event_type == DELIVERY_EVENT,
            )
        )
    )


@pytest.mark.asyncio
async def test_tenant_without_a_connector_gets_one_delivery_per_enabled_target(
    db, test_org
) -> None:
    targets = [_target(test_org.id), _target(test_org.id)]
    db.add_all([*targets, _target(test_org.id, enabled=False)])
    await db.flush()
    service = ComplianceForwarderService()
    body = {"source": "shim", "kind": "test_alert"}

    for _ in range(2):
        queued = await service.send_tenant_alert(
            db, TenantId(test_org.id), body=body, delivery_key="test:1"
        )

    deliveries = await _deliveries(db, test_org.id)
    assert queued == 2
    assert sorted(event.payload["target_id"] for event in deliveries) == sorted(
        str(target.id) for target in targets
    )
    assert {
        (event.aggregate_type, event.aggregate_id, event.payload["connector_id"])
        for event in deliveries
    } == {("organization", str(test_org.id), None)}
    assert all(event.payload["body"] == body for event in deliveries)


@pytest.mark.asyncio
async def test_tenant_alerts_reach_connector_targets_once_and_findings_stay_scoped(
    db, test_org
) -> None:
    other = Organization(id=uuid4(), name="Other", slug=f"other-{uuid4().hex}")
    connector = ComplianceConnector(
        organization_id=test_org.id,
        provider="openai",
        secret_ref="fernet:v2:connector",
        secret_backend="fernet",
        secret_version="v2",
        masked_key="masked",
    )
    db.add_all([other, connector])
    await db.flush()
    connector_target = _target(test_org.id, connector.id)
    tenant_target = _target(test_org.id)
    db.add_all([connector_target, tenant_target, _target(other.id)])
    await db.flush()
    service = ComplianceForwarderService()

    await service.send_tenant_alert(
        db, TenantId(test_org.id), body={"kind": "test_alert"}, delivery_key="t:1"
    )
    await service.handle_run(
        db,
        connector,
        [{"severity": "high", "entity_type": "EMAIL_ADDRESS", "content_id": "c1"}],
    )

    deliveries = await _deliveries(db, test_org.id)
    alerts = [event for event in deliveries if event.payload["body"].get("kind")]
    findings = [event for event in deliveries if event not in alerts]
    assert sorted(event.payload["target_id"] for event in alerts) == sorted(
        [str(connector_target.id), str(tenant_target.id)]
    )
    assert [event.payload["target_id"] for event in findings] == [
        str(connector_target.id)
    ]
    assert findings[0].aggregate_type == "compliance_connector"
    assert await _deliveries(db, other.id) == []


@pytest.mark.asyncio
async def test_forward_targets_are_created_without_a_connector_and_tenant_scoped(
    monkeypatch: pytest.MonkeyPatch, db, test_user_with_org
) -> None:
    test_user_with_org.role = "admin"
    other = Organization(id=uuid4(), name="Other", slug=f"other-{uuid4().hex}")
    db.add(other)
    await db.flush()
    foreign = _target(other.id)
    db.add(foreign)
    await db.flush()
    monkeypatch.setattr(compliance_api, "assert_safe_forward_url", AsyncMock())
    application = FastAPI()
    application.include_router(management_router, prefix="/api/v1")
    application.dependency_overrides[enterprise_deps.get_current_user] = lambda: (
        test_user_with_org
    )
    application.dependency_overrides[get_db] = lambda: db

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="http://test"
    ) as client:
        created = await client.post(
            "/api/v1/compliance/forward-targets",
            json={"kind": "slack", "endpoint": "https://hooks.slack.com/services/x"},
        )
        unknown_connector = await client.post(
            f"/api/v1/compliance/forward-targets?connector_id={uuid4()}",
            json={"kind": "slack", "endpoint": "https://hooks.slack.com/services/x"},
        )
        listed = await client.get("/api/v1/compliance/forward-targets")
        foreign_patch = await client.patch(
            f"/api/v1/compliance/forward-targets/{foreign.id}", json={"enabled": False}
        )
        foreign_delete = await client.delete(
            f"/api/v1/compliance/forward-targets/{foreign.id}"
        )
        disabled = await client.patch(
            f"/api/v1/compliance/forward-targets/{created.json()['id']}",
            json={"enabled": False},
        )

    assert created.status_code == 201
    assert created.json()["connector_id"] is None
    assert unknown_connector.status_code == 404
    assert [item["id"] for item in listed.json()] == [created.json()["id"]]
    assert (foreign_patch.status_code, foreign_delete.status_code) == (404, 404)
    assert disabled.json()["enabled"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("enabled_targets", [2, 0])
async def test_a_bulk_disclosure_intent_fans_out_to_every_enabled_target(
    db, test_org, monkeypatch, enabled_targets
) -> None:
    db.add_all(
        [_target(test_org.id) for _ in range(enabled_targets)]
        + [_target(test_org.id, enabled=False)]
    )
    await db.flush()

    @asynccontextmanager
    async def session_scope():
        yield db

    monkeypatch.setattr(handlers, "AsyncSessionLocal", session_scope)
    monkeypatch.setattr(db, "commit", AsyncMock())
    message = OutboxMessage(
        id=uuid4(),
        organization_id=test_org.id,
        event_type=handlers.BULK_DISCLOSURE,
        aggregate_type="request",
        aggregate_id="req_bulk",
        idempotency_key="bulk_disclosure:req_bulk",
        payload={
            "organization_id": str(test_org.id),
            "request_id": "req_bulk",
            "api_key_id": None,
            "provider": "openai",
            "model": "gpt-5-nano",
            "distinct_values": 60,
            "threshold": 50,
            "entity_counts": {"EMAIL_ADDRESS": 60},
            "occurred_at": "2026-10-08T00:00:00+00:00",
        },
        attempt_count=0,
        created_at=datetime.now(timezone.utc),
    )

    for _ in range(2):
        await handlers.build_publisher().publish(message)

    deliveries = await _deliveries(db, test_org.id)
    assert len(deliveries) == enabled_targets
    for delivery in deliveries:
        body = delivery.payload["body"]
        assert body["kind"] == "bulk_disclosure"
        assert body["distinct_values"] == 60
        assert delivery.idempotency_key.endswith(":bulk_disclosure:req_bulk")
        assert handlers._compliance_text(body) == (
            "shim bulk disclosure: 60 distinct values (EMAIL_ADDRESS 60) in one "
            "request with API key None at 2026-10-08T00:00:00+00:00, threshold 50"
        )
