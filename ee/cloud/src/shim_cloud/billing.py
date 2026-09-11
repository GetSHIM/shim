"""Committed commerce intents and verified entitlement synchronization."""

import base64
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from urllib.parse import urlsplit
from uuid import UUID

from cryptography.fernet import Fernet
from polar_sdk import Polar, PolarError
import httpx
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from shim.gateway.contracts.ids import TenantId
from shim_enterprise.core.config import settings
from shim_enterprise.core.database import AsyncSessionLocal
from shim_enterprise.outbox.publisher import OutboxMessage, OutboxWriter
from shim_enterprise.tenants.plans import (
    apply_billing_plan,
    billing_owner_email,
    claim_billing_source,
    organization_plan,
)
from shim_cloud.config import CloudSettings
from shim_cloud.models import BillingOperation
from shim_cloud.polar import checkout_url, customer_state, portal_url, validate_catalog

OPERATION_EVENT = "cloud.billing_operation"
SYNC_EVENT = "cloud.billing_sync"
OPERATION_LIFETIME = timedelta(minutes=10)


def result_cipher() -> Fernet:
    # Domain separation keeps these transient bearer URLs apart from other secrets.
    key = sha256(b"shim-cloud-billing-result\0" + settings.SECRET_KEY.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


async def append_intent(
    session: AsyncSession,
    organization_id: UUID,
    *,
    event_type: str,
    aggregate_id: str,
    idempotency_key: str,
    payload: dict[str, str],
) -> None:
    await OutboxWriter().append(
        session,
        organization_id=TenantId(organization_id),
        values={
            "event_type": event_type,
            "aggregate_type": "cloud_billing",
            "aggregate_id": aggregate_id,
            "idempotency_key": idempotency_key,
            "payload": payload,
            "next_attempt_at": datetime.now(timezone.utc),
        },
    )


async def request_operation(
    session: AsyncSession,
    organization_id: UUID,
    user_id: UUID,
    *,
    request_id: UUID,
    kind: str,
    product_id: str | None,
) -> BillingOperation:
    plan = await organization_plan(session, organization_id, lock=True)
    existing = await session.scalar(
        select(BillingOperation).where(
            BillingOperation.organization_id == organization_id,
            BillingOperation.request_id == request_id,
        )
    )
    if existing is not None:
        if (existing.kind, existing.product_id, existing.created_by) != (
            kind,
            product_id,
            user_id,
        ):
            raise ValueError("Request ID already belongs to another billing operation")
        return existing
    if kind == "checkout":
        plan = await claim_billing_source(session, organization_id, "polar")
        if plan.subscription_id is not None and plan.tier != "free":
            raise ValueError("Manage your existing subscription in the billing portal")
        active = await session.scalar(
            select(BillingOperation.id).where(
                BillingOperation.organization_id == organization_id,
                BillingOperation.kind == "checkout",
                BillingOperation.status.in_(("pending", "processing", "complete")),
                BillingOperation.expires_at > datetime.now(timezone.utc),
            )
        )
        if active is not None:
            raise ValueError(
                "A checkout is already in progress; resume it before starting another"
            )
    elif plan.source != "polar" or plan.customer_id is None:
        raise ValueError("This workspace does not have a cloud billing account")
    operation = BillingOperation(
        organization_id=organization_id,
        created_by=user_id,
        request_id=request_id,
        kind=kind,
        product_id=product_id,
        expires_at=datetime.now(timezone.utc) + OPERATION_LIFETIME,
    )
    session.add(operation)
    await session.flush()
    await append_intent(
        session,
        organization_id,
        event_type=OPERATION_EVENT,
        aggregate_id=str(operation.id),
        idempotency_key=f"polar:operation:{request_id}",
        payload={"operation_id": str(operation.id)},
    )
    return operation


async def synchronize_plan(
    client: Polar, config: CloudSettings, organization_id: UUID
) -> None:
    async with AsyncSessionLocal() as session:
        plan = await organization_plan(session, organization_id)
    if plan.source != "polar":
        return
    try:
        state = await customer_state(client, str(organization_id))
    except PolarError as exc:
        if exc.status_code == 404 and plan.customer_id is None and plan.tier == "free":
            return  # No customer exists until the first checkout is created.
        raise
    if (
        state.external_id != str(organization_id)
        or state.organization_id != str(config.POLAR_ORGANIZATION_ID)
        or plan.customer_id not in {None, state.id}
    ):
        raise ValueError("Polar customer binding mismatch")
    products = {
        str(value): key.split(":")[0] for key, value in config.POLAR_PRODUCTS.items()
    }
    subscription = next(iter(state.subscriptions), None)
    review_required = len(state.subscriptions) > 1 or (
        subscription is not None and subscription.product_id not in products
    )
    expired_cancellation = bool(
        subscription
        and subscription.cancel_at_period_end
        and subscription.current_period_end is not None
        and subscription.current_period_end <= datetime.now(timezone.utc)
    )
    entitled = bool(
        subscription
        and subscription.status in {"active", "trialing"}
        and not review_required
        and not expired_cancellation
    )
    async with AsyncSessionLocal() as session:
        applied = await apply_billing_plan(
            session,
            organization_id,
            expected_revision=plan.revision,
            source="polar",
            status="review_required"
            if review_required
            else (
                "canceled"
                if expired_cancellation
                else subscription.status
                if subscription
                else "free"
            ),
            tier=products[subscription.product_id]
            if entitled and subscription
            else "free",
            customer_id=state.id,
            subscription_id=subscription.id if subscription else None,
            product_id=subscription.product_id if subscription else None,
            current_period_end=subscription.current_period_end
            if subscription
            else None,
            cancel_at_period_end=subscription.cancel_at_period_end
            if subscription
            else False,
        )
        await session.commit()
    if not applied:
        # A competing update invalidates this network response. Outbox retries fetch anew.
        raise ValueError("Billing revision changed during synchronization")
    if review_required:
        raise ValueError("Polar subscription configuration requires billing review")


async def deliver_operation(
    client: Polar, config: CloudSettings, message: OutboxMessage
) -> None:
    operation_id = UUID(str(message.payload["operation_id"]))
    async with AsyncSessionLocal() as session:
        operation = await session.scalar(
            select(BillingOperation)
            .where(
                BillingOperation.id == operation_id,
                BillingOperation.organization_id == message.organization_id,
            )
            .with_for_update()
        )
        if operation is None or operation.status in {"complete", "failed", "expired"}:
            return
        if operation.expires_at <= datetime.now(timezone.utc):
            operation.status = "expired"
            await session.commit()
            return
        if operation.status == "processing":
            # Never repeat a checkout creation after an uncertain worker crash.
            operation.status = "failed"
            operation.error = (
                "The billing request was interrupted. Please start a new request."
            )
            await session.commit()
            return
        email = await billing_owner_email(
            session, operation.organization_id, operation.created_by
        )
        plan = await organization_plan(session, operation.organization_id)
        if email is None or plan.source != "polar":
            operation.status = "failed"
            operation.error = "Workspace billing permissions changed."
            await session.commit()
            return
        operation.status = "processing"
        await session.commit()
    try:
        if operation.kind == "checkout":
            selected_products = {
                key: value
                for key, value in config.POLAR_PRODUCTS.items()
                if str(value) == operation.product_id
            }
            if not selected_products:
                raise ValueError("This subscription option is no longer available")
            await validate_catalog(
                client,
                organization_id=str(config.POLAR_ORGANIZATION_ID),
                products=selected_products,
            )
            await synchronize_plan(client, config, operation.organization_id)
            async with AsyncSessionLocal() as session:
                current = await organization_plan(session, operation.organization_id)
            if (
                current.source != "polar"
                or current.tier != "free"
                or current.status == "review_required"
            ):
                raise ValueError(
                    "Manage your existing subscription in the billing portal"
                )
            assert operation.product_id is not None
            url = await checkout_url(
                client,
                external_id=str(operation.organization_id),
                email=email,
                product_id=operation.product_id,
                success_url=config.return_url + "?checkout=success",
                return_url=config.return_url,
                request_id=str(operation.id),
            )
        else:
            url = await portal_url(
                client,
                external_id=str(operation.organization_id),
                return_url=config.return_url,
            )
        destination = urlsplit(url)
        if (
            destination.scheme != "https"
            or not destination.hostname
            or destination.username
            or destination.password
        ):
            raise ValueError("Polar returned an invalid billing URL")
    except (PolarError, httpx.HTTPError, ValueError):
        # Vendor exceptions may contain customer data or bearer URLs; persist no details.
        async with AsyncSessionLocal() as session:
            await session.execute(
                update(BillingOperation)
                .where(BillingOperation.id == operation_id)
                .values(
                    status="failed",
                    error="Billing is temporarily unavailable. Please try again.",
                )
            )
            await session.commit()
        return
    async with AsyncSessionLocal() as session:
        await session.execute(
            update(BillingOperation)
            .where(
                BillingOperation.id == operation_id,
                BillingOperation.status == "processing",
            )
            .values(
                status="complete",
                result_ciphertext=result_cipher().encrypt(url.encode()).decode(),
            )
        )
        await session.commit()


async def expire_operations(session: AsyncSession) -> None:
    await session.execute(
        update(BillingOperation)
        .where(
            BillingOperation.expires_at <= datetime.now(timezone.utc),
            BillingOperation.status != "expired",
        )
        .values(status="expired", result_ciphertext=None, error=None)
    )
