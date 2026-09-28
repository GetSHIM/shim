"""Cloud billing routes persist intents before the worker contacts Polar."""

import asyncio
import base64
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient, MockTransport, Request, Response
from polar_sdk import Polar, ResourceNotFound, ResourceNotFoundData, SDKError
from pydantic import ValidationError
import pytest
import pytest_asyncio
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from standardwebhooks import Webhook

from shim_enterprise.api.enterprise_deps import get_current_user
from shim_enterprise.core.config import settings
from shim_enterprise.core.database import get_db
from shim_enterprise.outbox.models import OutboxEvent
from shim_enterprise.outbox.publisher import OutboxMessage
from shim_enterprise.tenants.models import Organization, User
from shim_enterprise.tenants.plans import activate_organization_plan
from shim_enterprise.tenants.service import create_api_key
from shim_enterprise.billing.ledger import (
    DurableAccountingRepository,
    QuotaReservationCommand,
    QuotaPolicySnapshot,
    FinalizationCommand,
    TerminalAction,
)
from shim_enterprise.workers.outbox import OutboxLeaseRepository
from shim_cloud.activate import activate, require_activation
from shim_cloud import billing as billing_module
from shim_cloud import application as application_module
from shim_cloud import worker as worker_module
from shim_cloud.api import operation_view, router
from shim_cloud.billing import OPERATION_EVENT, SYNC_EVENT, request_operation
from shim_cloud.config import CloudSettings
from shim_cloud.models import BillingOperation
from shim_cloud.models import BillingActivation
from shim_cloud.polar import (
    POLAR_TIMEOUT_MS,
    CustomerSnapshot,
    SubscriptionSnapshot,
)

_WEBHOOK_SECRET = "whsec_" + base64.b64encode(b"cloud-billing-test-secret").decode()


@pytest_asyncio.fixture
async def session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(
        settings.DATABASE_URL,
        connect_args={"statement_cache_size": 0},
    )
    yield async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
    await engine.dispose()


def _config() -> CloudSettings:
    return CloudSettings(
        _env_file=None,
        CLOUD_BILLING_ENABLED=True,
        POLAR_ACCESS_TOKEN="test-polar-token",
        POLAR_WEBHOOK_SECRET=_WEBHOOK_SECRET,
        POLAR_ORGANIZATION_ID=uuid4(),
        POLAR_PRODUCTS={
            "managed:monthly": uuid4(),
            "agency:yearly": uuid4(),
        },
        CLOUD_DASHBOARD_URL="https://cloud.example",
    )


@pytest.mark.asyncio
async def test_activation_rejects_pending_usage_before_enabling_caps(session_factory):
    async with session_factory() as session:
        async with session.begin():
            organization_id, user_id = uuid4(), uuid4()
            organization = Organization(
                id=organization_id,
                name="Activation",
                slug=f"activation-{organization_id}",
            )
            session.add_all(
                [
                    organization,
                    User(
                        id=user_id,
                        organization_id=organization_id,
                        email=f"{user_id}@example.com",
                        role="owner",
                        is_active=True,
                        is_verified=True,
                    ),
                ]
            )
            await session.flush()
            _, key = await create_api_key(session, user_id=user_id, name="Activation")
            with pytest.raises(ValueError, match="draining old runtimes"):
                await require_activation(session)
            now = datetime.now(timezone.utc)
            request_id = f"req_activation_{uuid4().hex}"
            repository = DurableAccountingRepository()
            await repository.reserve_quota(
                session,
                QuotaReservationCommand(
                    tenant_id=organization_id,
                    api_key_id=key.id,
                    request_id=request_id,
                    requested_model="internal",
                    source_endpoint="chat.completions",
                    started_at=now,
                    reconciliation_due_at=now + timedelta(minutes=2),
                    estimated_input_tokens=2,
                    maximum_output_tokens=8,
                    policy=QuotaPolicySnapshot("disabled", None, None, None),
                ),
            )
            with pytest.raises(ValueError, match="reservations remain pending"):
                await activate(session)
            assert organization.quota_monthly_request_limit is None
            await repository.finalize(
                session,
                FinalizationCommand(
                    tenant_id=organization_id,
                    request_id=request_id,
                    quota_action=TerminalAction.REFUND,
                    lifecycle_status="failed",
                ),
            )
            await activate(session)
            await require_activation(session)
            await session.refresh(organization)
            assert organization.quota_monthly_request_limit == 1000
            assert organization.quota_monthly_token_limit == 1_000_000
            assert await session.get(BillingActivation, True) is not None
            await session.rollback()


@pytest.mark.asyncio
async def test_disabled_billing_has_no_capabilities_or_commerce_intents(
    session_factory,
):
    config = _config().model_copy(update={"CLOUD_BILLING_ENABLED": False})
    ids = await _workspace(session_factory)
    organization_id, owner_id, _, other_organization_id, _ = ids
    try:
        async with session_factory() as session:
            app = _app(
                config,
                session,
                {
                    "user": SimpleNamespace(
                        id=owner_id, organization_id=organization_id, role="owner"
                    )
                },
            )
            async with AsyncClient(
                transport=ASGITransport(app), base_url="http://test"
            ) as client:
                view = (await client.get("/api/v1/management/cloud-billing")).json()
                assert not any(
                    view[name]
                    for name in ("can_manage", "can_checkout", "can_open_portal")
                )
                assert view["products"] == []
                assert (
                    await client.post(
                        "/api/v1/management/cloud-billing/checkout",
                        json={
                            "request_id": str(uuid4()),
                            "plan": "managed",
                            "interval": "monthly",
                        },
                    )
                ).status_code == 503
                assert (
                    await client.post("/api/v1/webhooks/polar", content=b"ignored")
                ).status_code == 503
            assert (
                await session.scalar(
                    select(BillingOperation.id).where(
                        BillingOperation.organization_id == organization_id
                    )
                )
                is None
            )
            await billing_module.append_intent(
                session,
                organization_id,
                event_type=SYNC_EVENT,
                aggregate_id=str(organization_id),
                idempotency_key="disabled-test",
                payload={},
            )
            messages = await OutboxLeaseRepository((OPERATION_EVENT, SYNC_EVENT)).claim(
                session,
                worker_id="disabled",
                now=datetime.now(timezone.utc),
                lease_seconds=30,
                batch_size=100,
            )
            assert not any(
                message.organization_id == organization_id for message in messages
            )
            event = await session.scalar(
                select(OutboxEvent).where(
                    OutboxEvent.organization_id == organization_id
                )
            )
            assert event.status == "pending" and event.attempt_count == 0
            await session.rollback()
    finally:
        await _delete_workspace(
            session_factory, (organization_id, other_organization_id)
        )


@pytest.mark.asyncio
async def test_disabled_worker_skips_polar(monkeypatch):
    for name in CloudSettings.model_fields:
        monkeypatch.delenv(name, raising=False)
    config = CloudSettings(_env_file=None)
    assert config.CLOUD_BILLING_ENABLED is False
    assert config.POLAR_ORGANIZATION_ID is None
    assert config.POLAR_PRODUCTS == {}
    assert config.CLOUD_DASHBOARD_URL == ""
    assert (
        CloudSettings(_env_file=None, POLAR_ORGANIZATION_ID="").POLAR_ORGANIZATION_ID
        is None
    )
    monkeypatch.setattr(application_module, "create_enterprise_app", FastAPI)
    app = application_module.create_cloud_app(config)
    async with app.router.lifespan_context(app):
        assert app.state.cloud_settings is config
    run = AsyncMock()
    monkeypatch.setattr(worker_module, "CloudSettings", lambda: config)
    monkeypatch.setattr(worker_module, "run_outbox", run)
    monkeypatch.setattr(
        worker_module,
        "Polar",
        lambda **kwargs: pytest.fail("Disabled billing contacted Polar"),
    )
    await worker_module.main()
    run.assert_awaited_once()
    assert run.call_args.kwargs["repository"].excluded_event_types == (
        OPERATION_EVENT,
        SYNC_EVENT,
    )


@pytest.mark.asyncio
async def test_enabled_runtimes_require_activation(session_factory, monkeypatch):
    config = _config()
    monkeypatch.setattr(application_module, "create_enterprise_app", FastAPI)
    monkeypatch.setattr(application_module, "AsyncSessionLocal", session_factory)
    app = application_module.create_cloud_app(config)
    with pytest.raises(ValueError, match="draining old runtimes"):
        async with app.router.lifespan_context(app):
            pytest.fail("Unactivated gateway started")
    monkeypatch.setattr(worker_module, "CloudSettings", lambda: config)
    monkeypatch.setattr(worker_module, "AsyncSessionLocal", session_factory)
    monkeypatch.setattr(
        worker_module,
        "Polar",
        lambda **kwargs: pytest.fail("Unactivated worker contacted Polar"),
    )
    with pytest.raises(ValueError, match="draining old runtimes"):
        await worker_module.main()
    async with session_factory() as session:
        organization = Organization(
            name="Disabled authentication", slug=f"disabled-auth-{uuid4()}"
        )
        session.add(organization)
        await session.flush()
        user = SimpleNamespace(organization_id=organization.id)
        monkeypatch.setattr(
            application_module, "get_current_user", AsyncMock(return_value=user)
        )
        app.state.cloud_settings = config.model_copy(
            update={"CLOUD_BILLING_ENABLED": False}
        )
        assert (
            await application_module.cloud_user(SimpleNamespace(app=app), None, session)
            is user
        )
        await session.refresh(organization)
        assert organization.quota_monthly_request_limit is None
        assert organization.quota_monthly_token_limit is None
        await session.rollback()


async def _workspace(
    session_factory: async_sessionmaker[AsyncSession],
) -> tuple[UUID, UUID, UUID, UUID, UUID]:
    organization_id = uuid4()
    owner_id = uuid4()
    admin_id = uuid4()
    other_organization_id = uuid4()
    other_owner_id = uuid4()
    async with session_factory() as session:
        session.add_all(
            [
                Organization(
                    id=organization_id,
                    name="Cloud billing test",
                    slug=f"cloud-billing-{organization_id}",
                ),
                User(
                    id=owner_id,
                    organization_id=organization_id,
                    email=f"owner-{owner_id}@example.com",
                    role="owner",
                    is_active=True,
                    is_verified=True,
                ),
                User(
                    id=admin_id,
                    organization_id=organization_id,
                    email=f"admin-{admin_id}@example.com",
                    role="admin",
                    is_active=True,
                    is_verified=True,
                ),
                Organization(
                    id=other_organization_id,
                    name="Other cloud billing test",
                    slug=f"other-cloud-billing-{other_organization_id}",
                ),
                User(
                    id=other_owner_id,
                    organization_id=other_organization_id,
                    email=f"other-owner-{other_owner_id}@example.com",
                    role="owner",
                    is_active=True,
                    is_verified=True,
                ),
            ]
        )
        await session.commit()
    return organization_id, owner_id, admin_id, other_organization_id, other_owner_id


async def _delete_workspace(
    session_factory: async_sessionmaker[AsyncSession],
    organization_ids: tuple[UUID, ...],
) -> None:
    async with session_factory() as session:
        await session.execute(
            delete(BillingOperation).where(
                BillingOperation.organization_id.in_(organization_ids)
            )
        )
        await session.execute(
            delete(OutboxEvent).where(OutboxEvent.organization_id.in_(organization_ids))
        )
        await session.execute(
            delete(User).where(User.organization_id.in_(organization_ids))
        )
        await session.execute(
            delete(Organization).where(Organization.id.in_(organization_ids))
        )
        await session.commit()


def _app(
    config: CloudSettings,
    database: AsyncSession,
    current: dict[str, object],
) -> FastAPI:
    app = FastAPI()
    app.state.cloud_settings = config
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: current["user"]
    app.dependency_overrides[get_db] = lambda: database
    return app


def _signed_webhook(
    config: CloudSettings, event: dict[str, object], webhook_id: str
) -> tuple[bytes, dict[str, str]]:
    body = json.dumps(event, separators=(",", ":"), sort_keys=True).encode()
    timestamp = datetime.now(timezone.utc)
    signature = Webhook(config.POLAR_WEBHOOK_SECRET.get_secret_value()).sign(
        webhook_id, timestamp, body.decode()
    )
    return body, {
        "webhook-id": webhook_id,
        "webhook-signature": signature,
        "webhook-timestamp": str(int(timestamp.timestamp())),
    }


def _message(operation: BillingOperation) -> OutboxMessage:
    return OutboxMessage(
        id=uuid4(),
        organization_id=operation.organization_id,
        event_type=OPERATION_EVENT,
        aggregate_type="cloud_billing",
        aggregate_id=str(operation.id),
        idempotency_key=f"test:{operation.id}",
        payload={"operation_id": str(operation.id)},
        attempt_count=0,
        created_at=datetime.now(timezone.utc),
    )


@pytest.mark.asyncio
async def test_owner_checkout_is_durable_idempotent_and_tenant_scoped(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    config = _config()
    ids = await _workspace(session_factory)
    organization_id, owner_id, admin_id, other_organization_id, other_owner_id = ids
    request_id = uuid4()
    other_operation_id = uuid4()
    try:
        async with session_factory() as database:
            owner = SimpleNamespace(
                id=owner_id, organization_id=organization_id, role="owner"
            )
            admin = SimpleNamespace(
                id=admin_id, organization_id=organization_id, role="admin"
            )
            other_operation = BillingOperation(
                id=other_operation_id,
                organization_id=other_organization_id,
                created_by=other_owner_id,
                request_id=uuid4(),
                kind="checkout",
                product_id=str(config.POLAR_PRODUCTS["managed:monthly"]),
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=1),
            )
            database.add(other_operation)
            await database.commit()

            current = {"user": admin}
            app = _app(config, database, current)
            payload = {
                "request_id": str(request_id),
                "plan": "managed",
                "interval": "monthly",
            }
            async with AsyncClient(
                transport=ASGITransport(app), base_url="http://test"
            ) as client:
                status = await client.get("/api/v1/management/cloud-billing")
                assert status.status_code == 200
                assert status.json()["can_manage"] is False
                assert status.json()["can_checkout"] is False
                assert status.json()["can_open_portal"] is False
                assert (
                    await client.post(
                        "/api/v1/management/cloud-billing/checkout", json=payload
                    )
                ).status_code == 403

                current["user"] = owner
                capabilities = (
                    await client.get("/api/v1/management/cloud-billing")
                ).json()
                assert capabilities["can_checkout"] is True
                assert capabilities["can_open_portal"] is False
                first = await client.post(
                    "/api/v1/management/cloud-billing/checkout", json=payload
                )
                assert first.status_code == 202, first.text
                assert first.headers["cache-control"] == "no-store"
                assert first.json()["status"] == "pending"
                operation_id = UUID(first.json()["id"])

                repeated = await client.post(
                    "/api/v1/management/cloud-billing/checkout", json=payload
                )
                assert repeated.status_code == 202
                assert repeated.json()["id"] == str(operation_id)

                changed_intent = await client.post(
                    "/api/v1/management/cloud-billing/checkout",
                    json={**payload, "plan": "agency", "interval": "yearly"},
                )
                assert changed_intent.status_code == 409
                cross_organization = await client.get(
                    f"/api/v1/management/cloud-billing/operations/{other_operation_id}"
                )
                assert cross_organization.status_code == 404
                organization = await database.get(Organization, organization_id)
                assert organization is not None
                organization.tier = "managed"
                organization.billing_status = "active"
                organization.external_customer_id = str(uuid4())
                await database.commit()
                capabilities = (
                    await client.get("/api/v1/management/cloud-billing")
                ).json()
                assert capabilities["can_checkout"] is False
                assert capabilities["can_open_portal"] is True
                assert capabilities["products"] == []

            operations = list(
                (
                    await database.scalars(
                        select(BillingOperation).where(
                            BillingOperation.organization_id == organization_id
                        )
                    )
                ).all()
            )
            intents = list(
                (
                    await database.scalars(
                        select(OutboxEvent).where(
                            OutboxEvent.organization_id == organization_id,
                            OutboxEvent.event_type == OPERATION_EVENT,
                        )
                    )
                ).all()
            )
            assert [(operation.id, operation.status) for operation in operations] == [
                (operation_id, "pending")
            ]
            assert [intent.payload for intent in intents] == [
                {"operation_id": str(operation_id)}
            ]
    finally:
        await _delete_workspace(
            session_factory, (organization_id, other_organization_id)
        )


@pytest.mark.asyncio
async def test_concurrent_checkout_requests_commit_one_operation_and_intent(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    ids = await _workspace(session_factory)
    organization_id, owner_id, admin_id, other_organization_id, _ = ids
    start = asyncio.Event()

    async def request(request_id: UUID) -> str:
        await start.wait()
        async with session_factory() as session:
            try:
                operation = await request_operation(
                    session,
                    organization_id,
                    owner_id,
                    request_id=request_id,
                    kind="checkout",
                    product_id="product-managed",
                )
                await session.commit()
                return str(operation.id)
            except ValueError as exc:
                await session.rollback()
                return str(exc)

    try:
        tasks = [asyncio.create_task(request(uuid4())) for _ in range(2)]
        start.set()
        outcome = await asyncio.gather(*tasks)
        assert len(set(outcome)) == 1
        UUID(outcome[0])
        async with session_factory() as session:
            for user_id, product_id in (
                (owner_id, "product-agency"),
                (admin_id, "product-managed"),
            ):
                with pytest.raises(ValueError, match="checkout is already in progress"):
                    await request_operation(
                        session,
                        organization_id,
                        user_id,
                        request_id=uuid4(),
                        kind="checkout",
                        product_id=product_id,
                    )
            operations = list(
                (
                    await session.scalars(
                        select(BillingOperation).where(
                            BillingOperation.organization_id == organization_id
                        )
                    )
                ).all()
            )
            intents = list(
                (
                    await session.scalars(
                        select(OutboxEvent).where(
                            OutboxEvent.organization_id == organization_id,
                            OutboxEvent.event_type == OPERATION_EVENT,
                        )
                    )
                ).all()
            )
        assert len(operations) == len(intents) == 1
    finally:
        await _delete_workspace(
            session_factory, (organization_id, other_organization_id)
        )


@pytest.mark.asyncio
async def test_webhook_requires_a_body_bound_signature_and_customer_binding(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    config = _config()
    ids = await _workspace(session_factory)
    organization_id, owner_id, _, other_organization_id, _ = ids
    customer_id = uuid4()
    try:
        async with session_factory() as database:
            organization = await database.get(Organization, organization_id)
            owner = await database.get(User, owner_id)
            assert organization is not None and owner is not None
            organization.billing_source = "polar"
            organization.external_customer_id = str(customer_id)
            await database.commit()
            app = _app(config, database, {"user": owner})

            event = {
                "type": "customer.state_changed",
                "data": {
                    "id": str(customer_id),
                    "external_id": str(organization_id),
                    "organization_id": str(config.POLAR_ORGANIZATION_ID),
                },
            }
            body, headers = _signed_webhook(config, event, "delivery-1")
            async with AsyncClient(
                transport=ASGITransport(app), base_url="http://test"
            ) as client:
                assert (
                    await client.post(
                        "/api/v1/webhooks/polar", content=body, headers=headers
                    )
                ).status_code == 204
                assert (
                    await client.post(
                        "/api/v1/webhooks/polar", content=body, headers=headers
                    )
                ).status_code == 204

                altered_body = body + b" "
                assert (
                    await client.post(
                        "/api/v1/webhooks/polar", content=altered_body, headers=headers
                    )
                ).status_code == 403

                changed_event = {**event, "delivery_version": 2}
                changed_body, changed_headers = _signed_webhook(
                    config, changed_event, "delivery-1"
                )
                assert (
                    await client.post(
                        "/api/v1/webhooks/polar",
                        content=changed_body,
                        headers=changed_headers,
                    )
                ).status_code == 409

                merchant_event = {
                    **event,
                    "data": {**event["data"], "organization_id": str(uuid4())},
                }
                merchant_body, merchant_headers = _signed_webhook(
                    config, merchant_event, "merchant-mismatch"
                )
                assert (
                    await client.post(
                        "/api/v1/webhooks/polar",
                        content=merchant_body,
                        headers=merchant_headers,
                    )
                ).status_code == 403

                customer_event = {
                    **event,
                    "data": {**event["data"], "id": str(uuid4())},
                }
                customer_body, customer_headers = _signed_webhook(
                    config, customer_event, "customer-mismatch"
                )
                assert (
                    await client.post(
                        "/api/v1/webhooks/polar",
                        content=customer_body,
                        headers=customer_headers,
                    )
                ).status_code == 403

            intents = list(
                (
                    await database.scalars(
                        select(OutboxEvent).where(
                            OutboxEvent.organization_id == organization_id,
                            OutboxEvent.event_type == SYNC_EVENT,
                        )
                    )
                ).all()
            )
            assert len(intents) == 1
            assert intents[0].idempotency_key == "polar:webhook:delivery-1"
    finally:
        await _delete_workspace(
            session_factory, (organization_id, other_organization_id)
        )


@pytest.mark.asyncio
async def test_subscription_sync_enforces_review_expiry_and_operator_revision(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config()
    monkeypatch.setattr(billing_module, "AsyncSessionLocal", session_factory)
    ids = await _workspace(session_factory)
    organization_id, _, _, other_organization_id, _ = ids
    customer_id = "customer-1"
    known_product = str(config.POLAR_PRODUCTS["managed:monthly"])

    def state(*subscriptions: SubscriptionSnapshot) -> CustomerSnapshot:
        return CustomerSnapshot(
            id=customer_id,
            external_id=str(organization_id),
            organization_id=str(config.POLAR_ORGANIZATION_ID),
            subscriptions=subscriptions,
        )

    async def synchronize(snapshot: CustomerSnapshot) -> None:
        async def fetch(_client: object, _external_id: str) -> CustomerSnapshot:
            return snapshot

        monkeypatch.setattr(billing_module, "customer_state", fetch)
        await billing_module.synchronize_plan(object(), config, organization_id)

    try:
        async with session_factory() as session:
            organization = await session.get(Organization, organization_id)
            assert organization is not None
            organization.billing_source = "polar"
            organization.billing_revision = 1
            await session.commit()

        await synchronize(
            state(
                SubscriptionSnapshot(
                    id="subscription-1",
                    product_id=known_product,
                    status="active",
                    current_period_end=datetime.now(timezone.utc) + timedelta(days=30),
                    cancel_at_period_end=False,
                )
            )
        )
        async with session_factory() as session:
            current = await session.get(Organization, organization_id)
            assert current is not None
            assert (current.tier, current.billing_status, current.billing_source) == (
                "managed",
                "active",
                "polar",
            )

        with pytest.raises(ValueError, match="billing review"):
            await synchronize(
                state(
                    SubscriptionSnapshot(
                        id="subscription-unknown",
                        product_id="unmapped-product",
                        status="active",
                        current_period_end=datetime.now(timezone.utc)
                        + timedelta(days=30),
                        cancel_at_period_end=False,
                    )
                )
            )
        async with session_factory() as session:
            current = await session.get(Organization, organization_id)
            assert current is not None
            assert (current.tier, current.billing_status) == ("free", "review_required")

        with pytest.raises(ValueError, match="billing review"):
            await synchronize(
                state(
                    SubscriptionSnapshot(
                        id="subscription-first",
                        product_id=known_product,
                        status="active",
                        current_period_end=datetime.now(timezone.utc)
                        + timedelta(days=30),
                        cancel_at_period_end=False,
                    ),
                    SubscriptionSnapshot(
                        id="subscription-second",
                        product_id=known_product,
                        status="active",
                        current_period_end=datetime.now(timezone.utc)
                        + timedelta(days=30),
                        cancel_at_period_end=False,
                    ),
                )
            )

        await synchronize(
            state(
                SubscriptionSnapshot(
                    id="subscription-canceled",
                    product_id=known_product,
                    status="active",
                    current_period_end=datetime.now(timezone.utc)
                    - timedelta(seconds=1),
                    cancel_at_period_end=True,
                )
            )
        )
        async with session_factory() as session:
            current = await session.get(Organization, organization_id)
            assert current is not None
            assert (
                current.tier,
                current.billing_status,
                current.cancel_at_period_end,
            ) == (
                "free",
                "canceled",
                True,
            )

        fetched = asyncio.Event()
        continue_sync = asyncio.Event()
        active_state = state(
            SubscriptionSnapshot(
                id="subscription-2",
                product_id=known_product,
                status="active",
                current_period_end=datetime.now(timezone.utc) + timedelta(days=30),
                cancel_at_period_end=False,
            )
        )

        async def delayed_fetch(_client: object, _external_id: str) -> CustomerSnapshot:
            fetched.set()
            await continue_sync.wait()
            return active_state

        monkeypatch.setattr(billing_module, "customer_state", delayed_fetch)
        sync_task = asyncio.create_task(
            billing_module.synchronize_plan(object(), config, organization_id)
        )
        await fetched.wait()
        async with session_factory() as session:
            await activate_organization_plan(session, organization_id, "agency")
            await session.commit()
        continue_sync.set()
        with pytest.raises(ValueError, match="Billing revision changed"):
            await sync_task
        async with session_factory() as session:
            current = await session.get(Organization, organization_id)
            assert current is not None
            assert (current.tier, current.billing_source) == ("agency", "operator")
    finally:
        await _delete_workspace(
            session_factory, (organization_id, other_organization_id)
        )


@pytest.mark.asyncio
async def test_first_checkout_treats_polar_customer_404_as_no_customer(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config()
    monkeypatch.setattr(billing_module, "AsyncSessionLocal", session_factory)
    ids = await _workspace(session_factory)
    organization_id, owner_id, _, other_organization_id, _ = ids
    requests: list[Request] = []

    async def handler(request: Request) -> Response:
        requests.append(request)
        return Response(
            404,
            json={"detail": "customer not found", "error": "ResourceNotFound"},
            request=request,
        )

    http_client = AsyncClient(transport=MockTransport(handler))
    client = Polar(
        access_token="test-polar-token",
        async_client=http_client,
        retry_config=None,
        timeout_ms=POLAR_TIMEOUT_MS,
    )
    validate_catalog = AsyncMock()
    create_checkout = AsyncMock(return_value="https://checkout.example/session")
    monkeypatch.setattr(billing_module, "validate_catalog", validate_catalog)
    monkeypatch.setattr(billing_module, "checkout_url", create_checkout)
    try:
        async with session_factory() as session:
            organization = await session.get(Organization, organization_id)
            assert organization is not None
            organization.billing_source = "polar"
            operation = BillingOperation(
                organization_id=organization_id,
                created_by=owner_id,
                request_id=uuid4(),
                kind="checkout",
                product_id=str(config.POLAR_PRODUCTS["managed:monthly"]),
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
            )
            session.add(operation)
            await session.commit()

        await billing_module.deliver_operation(client, config, _message(operation))

        validate_catalog.assert_awaited_once()
        create_checkout.assert_awaited_once()
        assert [request.url.path for request in requests] == [
            f"/v1/customers/external/{organization_id}/state"
        ]
        async with session_factory() as session:
            completed = await session.get(BillingOperation, operation.id)
            assert completed is not None
            assert completed.status == "complete"
            assert completed.error is None
    finally:
        await http_client.aclose()
        await _delete_workspace(
            session_factory, (organization_id, other_organization_id)
        )


@pytest.mark.asyncio
async def test_worker_hides_vendor_error_bodies_on_sync_outage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config()
    secret = "polar-response-bearer-secret"
    failure = SDKError("Polar failure", Response(503, text=secret))

    async def unavailable(
        _client: object, _config: CloudSettings, _organization: UUID
    ) -> None:
        raise failure

    monkeypatch.setattr(worker_module, "synchronize_plan", unavailable)
    message = OutboxMessage(
        id=uuid4(),
        organization_id=uuid4(),
        event_type=SYNC_EVENT,
        aggregate_type="cloud_billing",
        aggregate_id="test",
        idempotency_key="test",
        payload={},
        attempt_count=0,
        created_at=datetime.now(timezone.utc),
    )
    with pytest.raises(ValueError, match="Polar state refresh failed") as error:
        await worker_module.sync_message(SimpleNamespace(), config, message)
    assert secret not in str(error.value)


@pytest.mark.asyncio
async def test_worker_hides_typed_polar_error_bodies_on_sync_outage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config()
    secret = "polar-resource-detail-secret"
    failure = ResourceNotFound(
        ResourceNotFoundData(detail=secret), Response(404, text=secret)
    )

    async def unavailable(
        _client: object, _config: CloudSettings, _organization: UUID
    ) -> None:
        raise failure

    monkeypatch.setattr(worker_module, "synchronize_plan", unavailable)
    message = OutboxMessage(
        id=uuid4(),
        organization_id=uuid4(),
        event_type=SYNC_EVENT,
        aggregate_type="cloud_billing",
        aggregate_id="test",
        idempotency_key="test",
        payload={},
        attempt_count=0,
        created_at=datetime.now(timezone.utc),
    )
    with pytest.raises(ValueError, match="Polar state refresh failed") as error:
        await worker_module.sync_message(SimpleNamespace(), config, message)
    assert secret not in str(error.value)


@pytest.mark.asyncio
async def test_worker_never_repeats_crashed_checkout_and_hides_expired_urls(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config()
    monkeypatch.setattr(billing_module, "AsyncSessionLocal", session_factory)
    ids = await _workspace(session_factory)
    organization_id, owner_id, _, other_organization_id, _ = ids
    checkout_url = "https://checkout.example/session-secret"
    try:
        async with session_factory() as session:
            organization = await session.get(Organization, organization_id)
            assert organization is not None
            organization.billing_source = "polar"
            crashed = BillingOperation(
                organization_id=organization_id,
                created_by=owner_id,
                request_id=uuid4(),
                kind="checkout",
                product_id=str(config.POLAR_PRODUCTS["managed:monthly"]),
                status="processing",
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=1),
            )
            pending = BillingOperation(
                organization_id=organization_id,
                created_by=owner_id,
                request_id=uuid4(),
                kind="checkout",
                product_id=str(config.POLAR_PRODUCTS["managed:monthly"]),
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=1),
            )
            session.add_all([crashed, pending])
            await session.commit()

        validate_catalog = AsyncMock()
        synchronize_plan = AsyncMock()
        create_checkout = AsyncMock(return_value=checkout_url)
        monkeypatch.setattr(billing_module, "validate_catalog", validate_catalog)
        monkeypatch.setattr(billing_module, "synchronize_plan", synchronize_plan)
        monkeypatch.setattr(billing_module, "checkout_url", create_checkout)

        await billing_module.deliver_operation(
            SimpleNamespace(), config, _message(crashed)
        )
        validate_catalog.assert_not_awaited()
        synchronize_plan.assert_not_awaited()
        create_checkout.assert_not_awaited()

        await billing_module.deliver_operation(
            SimpleNamespace(), config, _message(pending)
        )
        validate_catalog.assert_awaited_once()
        synchronize_plan.assert_awaited_once()
        create_checkout.assert_awaited_once()

        async with session_factory() as session:
            crashed_result = await session.get(BillingOperation, crashed.id)
            completed = await session.get(BillingOperation, pending.id)
            assert crashed_result is not None and completed is not None
            assert (crashed_result.status, crashed_result.error) == (
                "failed",
                "The billing request was interrupted. Please start a new request.",
            )
            assert completed.status == "complete"
            assert completed.result_ciphertext is not None
            assert checkout_url not in completed.result_ciphertext
            assert operation_view(completed).url == checkout_url
            completed.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            await session.commit()
            assert operation_view(completed).model_dump() == {
                "id": completed.id,
                "status": "expired",
                "url": None,
                "error": None,
            }
    finally:
        await _delete_workspace(
            session_factory, (organization_id, other_organization_id)
        )


@pytest.mark.asyncio
async def test_reconciliation_deduplicates_polar_intents_and_expires_results(
    session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config()
    frozen = datetime(2026, 9, 11, 12, tzinfo=timezone.utc)
    ids = await _workspace(session_factory)
    organization_id, owner_id, _, other_organization_id, _ = ids
    expired_operation_id = uuid4()

    class FrozenDateTime:
        @staticmethod
        def now(_timezone: timezone) -> datetime:
            return frozen

    synchronize_plan = AsyncMock()
    monkeypatch.setattr(worker_module, "AsyncSessionLocal", session_factory)
    monkeypatch.setattr(worker_module, "datetime", FrozenDateTime)
    monkeypatch.setattr(billing_module, "datetime", FrozenDateTime)
    monkeypatch.setattr(worker_module, "synchronize_plan", synchronize_plan)
    try:
        async with session_factory() as session:
            organization = await session.get(Organization, organization_id)
            operator_organization = await session.get(
                Organization, other_organization_id
            )
            assert organization is not None and operator_organization is not None
            organization.billing_source = "polar"
            operator_organization.billing_source = "operator"
            session.add(
                BillingOperation(
                    id=expired_operation_id,
                    organization_id=organization_id,
                    created_by=owner_id,
                    request_id=uuid4(),
                    kind="checkout",
                    product_id=str(config.POLAR_PRODUCTS["managed:monthly"]),
                    status="complete",
                    result_ciphertext=billing_module.result_cipher()
                    .encrypt(b"https://checkout.example/expired")
                    .decode(),
                    error="stale error",
                    expires_at=frozen - timedelta(seconds=1),
                )
            )
            await session.commit()

        await worker_module.enqueue_reconciliation(config)
        await worker_module.enqueue_reconciliation(config)

        synchronize_plan.assert_not_awaited()
        async with session_factory() as session:
            intents = list(
                (
                    await session.scalars(
                        select(OutboxEvent).where(
                            OutboxEvent.event_type == SYNC_EVENT,
                            OutboxEvent.organization_id.in_(
                                (organization_id, other_organization_id)
                            ),
                        )
                    )
                ).all()
            )
            expired = await session.get(BillingOperation, expired_operation_id)
            assert [
                (intent.organization_id, intent.idempotency_key) for intent in intents
            ] == [
                (
                    organization_id,
                    f"polar:reconcile:{int(frozen.timestamp()) // config.CLOUD_BILLING_RECONCILE_SECONDS}",
                )
            ]
            assert expired is not None
            assert (expired.status, expired.result_ciphertext, expired.error) == (
                "expired",
                None,
                None,
            )
    finally:
        await _delete_workspace(
            session_factory, (organization_id, other_organization_id)
        )


def test_invalid_configuration_does_not_print_credentials() -> None:
    values = _config().model_dump()
    values.update(POLAR_ACCESS_TOKEN="never-log-this", CLOUD_DASHBOARD_URL="ftp://bad")
    with pytest.raises(ValidationError) as error:
        CloudSettings(_env_file=None, **values)
    assert "never-log-this" not in str(error.value)
    assert "never-log-this" not in repr(error.value.errors())


@pytest.mark.parametrize(
    "name,value",
    [
        ("POLAR_ACCESS_TOKEN", ""),
        ("POLAR_WEBHOOK_SECRET", ""),
        ("POLAR_ORGANIZATION_ID", None),
        ("POLAR_PRODUCTS", {}),
        ("CLOUD_DASHBOARD_URL", ""),
    ],
)
def test_enabled_billing_requires_complete_configuration(name, value, monkeypatch):
    monkeypatch.delenv(name, raising=False)
    values = _config().model_dump()
    values[name] = value
    with pytest.raises(ValidationError):
        CloudSettings(_env_file=None, **values)


def test_configuration_requires_at_least_one_sellable_product(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("POLAR_PRODUCTS", raising=False)
    values = _config().model_dump()
    values.update(POLAR_PRODUCTS={})
    with pytest.raises(ValidationError):
        CloudSettings(_env_file=None, **values)


def test_configuration_rejects_duplicate_product_ids() -> None:
    values = _config().model_dump()
    shared = uuid4()
    values["POLAR_PRODUCTS"] = {
        "managed:monthly": shared,
        "agency:monthly": shared,
    }
    with pytest.raises(ValidationError):
        CloudSettings(_env_file=None, **values)


@pytest.mark.parametrize(
    "dashboard_url",
    ["ftp://bad.test", "https://bad.test/?q=1", "https://user:pass@bad.test"],
)
def test_configuration_rejects_non_origin_dashboard_urls(dashboard_url: str) -> None:
    values = _config().model_dump()
    values["CLOUD_DASHBOARD_URL"] = dashboard_url
    with pytest.raises(ValidationError):
        CloudSettings(_env_file=None, **values)


def test_production_billing_requires_an_https_dashboard() -> None:
    values = _config().model_dump()
    values.update(POLAR_SERVER="production", CLOUD_DASHBOARD_URL="http://bad.test")
    with pytest.raises(ValidationError):
        CloudSettings(_env_file=None, **values)
