"""Owner-scoped cloud billing routes and signed webhook intake."""

from datetime import datetime, timezone
from hashlib import sha256
from typing import Literal
from uuid import UUID

from cryptography.fernet import InvalidToken
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from standardwebhooks import Webhook
from standardwebhooks.webhooks import WebhookVerificationError

from shim_enterprise.api.enterprise_deps import get_current_user, get_org_owner
from shim_enterprise.core.database import get_db
from shim_enterprise.outbox.publisher import OutboxIdentityConflict
from shim_enterprise.tenants.models import User
from shim_enterprise.tenants.plans import organization_plan
from shim_cloud.billing import (
    SYNC_EVENT,
    append_intent,
    request_operation,
    result_cipher,
)
from shim_cloud.config import CloudSettings
from shim_cloud.models import BillingOperation

router = APIRouter(tags=["cloud billing"])


class ProductChoice(BaseModel):
    plan: Literal["managed", "agency"]
    interval: Literal["monthly", "yearly"]


class CloudBillingView(BaseModel):
    plan: str
    status: str
    source: str | None
    current_period_end: datetime | None
    cancel_at_period_end: bool
    can_manage: bool
    can_checkout: bool
    can_open_portal: bool
    products: list[ProductChoice]


class OperationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: UUID


class CheckoutRequest(OperationRequest):
    plan: Literal["managed", "agency"]
    interval: Literal["monthly", "yearly"]


class BillingOperationView(BaseModel):
    id: UUID
    status: Literal["pending", "processing", "complete", "failed", "expired"]
    url: str | None = None
    error: str | None = None


def cloud_settings(request: Request) -> CloudSettings:
    return request.app.state.cloud_settings


def operation_view(operation: BillingOperation) -> BillingOperationView:
    if operation.expires_at <= datetime.now(timezone.utc):
        return BillingOperationView(id=operation.id, status="expired")
    url = None
    if operation.result_ciphertext is not None and operation.status == "complete":
        try:
            url = result_cipher().decrypt(operation.result_ciphertext.encode()).decode()
        except InvalidToken:
            return BillingOperationView(id=operation.id, status="expired")
    return BillingOperationView.model_validate(
        {
            "id": operation.id,
            "status": operation.status,
            "url": url,
            "error": operation.error,
        }
    )


@router.get("/management/cloud-billing", response_model=CloudBillingView)
async def billing_status(
    response: Response,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
    config: CloudSettings = Depends(cloud_settings),
) -> CloudBillingView:
    response.headers["Cache-Control"] = "no-store"
    plan = await organization_plan(session, user.organization_id)
    manageable = user.role == "owner" and (
        plan.source == "polar" or (plan.source is None and plan.tier == "free")
    )
    can_checkout = (
        manageable and plan.tier == "free" and plan.status != "review_required"
    )
    return CloudBillingView(
        plan=plan.tier,
        status=plan.status,
        source=plan.source,
        current_period_end=plan.current_period_end,
        cancel_at_period_end=plan.cancel_at_period_end,
        can_manage=manageable,
        can_checkout=can_checkout,
        can_open_portal=manageable
        and plan.source == "polar"
        and plan.customer_id is not None,
        products=[
            ProductChoice.model_validate(
                dict(zip(("plan", "interval"), choice.split(":")))
            )
            for choice in sorted(config.POLAR_PRODUCTS)
        ]
        if can_checkout
        else [],
    )


@router.post(
    "/management/cloud-billing/checkout",
    response_model=BillingOperationView,
    status_code=202,
)
async def checkout(
    body: CheckoutRequest,
    response: Response,
    user: User = Depends(get_org_owner),
    session: AsyncSession = Depends(get_db),
    config: CloudSettings = Depends(cloud_settings),
) -> BillingOperationView:
    product_id = config.POLAR_PRODUCTS.get(f"{body.plan}:{body.interval}")
    if product_id is None:
        raise HTTPException(422, "This subscription option is unavailable")
    return await _request(body, response, user, session, "checkout", str(product_id))


@router.post(
    "/management/cloud-billing/portal",
    response_model=BillingOperationView,
    status_code=202,
)
async def portal(
    body: OperationRequest,
    response: Response,
    user: User = Depends(get_org_owner),
    session: AsyncSession = Depends(get_db),
) -> BillingOperationView:
    return await _request(body, response, user, session, "portal", None)


async def _request(
    body: OperationRequest,
    response: Response,
    user: User,
    session: AsyncSession,
    kind: str,
    product_id: str | None,
) -> BillingOperationView:
    response.headers["Cache-Control"] = "no-store"
    try:
        operation = await request_operation(
            session,
            user.organization_id,
            user.id,
            request_id=body.request_id,
            kind=kind,
            product_id=product_id,
        )
        await session.commit()
    except ValueError as exc:
        await session.rollback()
        raise HTTPException(409, str(exc)) from exc
    return operation_view(operation)


@router.get(
    "/management/cloud-billing/operations/{operation_id}",
    response_model=BillingOperationView,
)
async def operation_status(
    operation_id: UUID,
    response: Response,
    user: User = Depends(get_org_owner),
    session: AsyncSession = Depends(get_db),
) -> BillingOperationView:
    response.headers["Cache-Control"] = "no-store"
    operation = await session.scalar(
        select(BillingOperation).where(
            BillingOperation.id == operation_id,
            BillingOperation.organization_id == user.organization_id,
            BillingOperation.created_by == user.id,
        )
    )
    if operation is None:
        raise HTTPException(404, "Billing operation not found")
    return operation_view(operation)


class WebhookCustomer(BaseModel):
    id: UUID
    external_id: UUID | None = None
    organization_id: UUID


class CustomerStateEvent(BaseModel):
    type: Literal["customer.state_changed"]
    data: WebhookCustomer


@router.post("/webhooks/polar", status_code=204, response_class=Response)
async def polar_webhook(
    request: Request,
    session: AsyncSession = Depends(get_db),
    config: CloudSettings = Depends(cloud_settings),
) -> Response:
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > 256 * 1024:
            raise HTTPException(413, "Webhook payload too large")
    try:
        event = Webhook(config.POLAR_WEBHOOK_SECRET.get_secret_value()).verify(
            bytes(body), dict(request.headers)
        )
    except (WebhookVerificationError, ValueError):
        raise HTTPException(403, "Invalid webhook signature") from None
    if not isinstance(event, dict):
        raise HTTPException(422, "Invalid webhook payload")
    if event.get("type") != "customer.state_changed":
        return Response(status_code=204)
    try:
        parsed = CustomerStateEvent.model_validate(event)
    except ValidationError:
        raise HTTPException(422, "Invalid customer state event") from None
    if parsed.data.organization_id != config.POLAR_ORGANIZATION_ID:
        raise HTTPException(403, "Webhook merchant mismatch")
    if parsed.data.external_id is None:
        return Response(status_code=204)
    try:
        plan = await organization_plan(session, parsed.data.external_id)
    except ValueError:
        return Response(status_code=204)
    if plan.source != "polar":
        return Response(status_code=204)
    if plan.customer_id not in {None, str(parsed.data.id)}:
        raise HTTPException(403, "Webhook customer mismatch")
    webhook_id = request.headers["webhook-id"]
    if not 1 <= len(webhook_id) <= 200:
        raise HTTPException(422, "Invalid webhook identity")
    try:
        await append_intent(
            session,
            plan.organization_id,
            event_type=SYNC_EVENT,
            aggregate_id=str(plan.organization_id),
            idempotency_key=f"polar:webhook:{webhook_id}",
            payload={
                "customer_id": str(parsed.data.id),
                "digest": sha256(body).hexdigest(),
            },
        )
        await session.commit()
    except OutboxIdentityConflict:
        await session.rollback()
        raise HTTPException(409, "Webhook identity conflict") from None
    return Response(status_code=204)
