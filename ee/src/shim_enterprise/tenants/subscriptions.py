"""Organization billing state and Lemon Squeezy webhook processing."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import json
from typing import Any, Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import UUID, uuid4

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.core.config import settings
from shim_enterprise.tenants.models import (
    ApiKey,
    BillingWebhookReceipt,
    Organization,
    TierDefinition,
    User,
)

ACTIVE_BILLING_STATUSES = {"active", "on_trial"}
DEAD_BILLING_STATUSES = {"expired", "unpaid"}
KNOWN_EVENTS = {
    "subscription_created",
    "subscription_updated",
    "subscription_cancelled",
    "subscription_expired",
    "subscription_paused",
    "subscription_resumed",
}


def verify_lemonsqueezy_signature(
    payload: bytes,
    signature: str,
    secret: str,
) -> bool:
    if not signature or not secret:
        return False
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    try:
        return hmac.compare_digest(expected, signature)
    except TypeError:
        return False


def checkout_urls(
    organization_id: UUID,
    user_id: UUID,
) -> dict[str, dict[Literal["monthly", "yearly"], str]]:
    values: dict[
        str,
        dict[Literal["monthly", "yearly"], str | None],
    ] = {
        "managed": {
            "monthly": settings.LEMON_SQUEEZY_SOLO_PRO_MONTHLY_CHECKOUT_URL,
            "yearly": settings.LEMON_SQUEEZY_SOLO_PRO_YEARLY_CHECKOUT_URL,
        },
        "agency": {
            "monthly": settings.LEMON_SQUEEZY_AGENCY_MONTHLY_CHECKOUT_URL,
            "yearly": settings.LEMON_SQUEEZY_AGENCY_YEARLY_CHECKOUT_URL,
        },
    }
    return {
        tier: {
            period: _with_checkout_identity(url, organization_id, user_id)
            for period, url in urls.items()
            if url
        }
        for tier, urls in values.items()
        if any(urls.values())
    }


async def set_organization_tier(
    session: AsyncSession,
    organization: Organization,
    tier: str,
    *,
    status: str,
    source: str,
    event_at: datetime | None = None,
) -> None:
    if await session.get(TierDefinition, tier) is None:
        raise ValueError(f"Unknown tier: {tier}")
    organization.tier = tier
    organization.billing_status = status
    organization.billing_source = source
    organization.billing_event_at = event_at or datetime.now(timezone.utc)
    await session.flush()
    await session.execute(
        update(ApiKey)
        .where(
            ApiKey.organization_id == organization.id,
            ApiKey.is_active.is_(True),
        )
        .values(tier=tier)
    )


async def process_lemonsqueezy_webhook(
    session: AsyncSession,
    raw_body: bytes,
) -> str:
    try:
        payload = json.loads(raw_body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid JSON payload") from exc
    if not isinstance(payload, dict):
        raise ValueError("Invalid webhook payload")

    meta = payload.get("meta")
    data = payload.get("data")
    if not isinstance(meta, dict) or not isinstance(data, dict):
        raise ValueError("Invalid webhook payload")
    event_name = str(meta.get("event_name") or "")
    if event_name not in KNOWN_EVENTS:
        return "ignored"
    attributes = data.get("attributes")
    if not isinstance(attributes, dict):
        raise ValueError("Missing subscription attributes")
    event_at = _parse_datetime(attributes.get("updated_at"))
    if event_at is None:
        raise ValueError("Missing subscription update timestamp")

    external_subscription_id = str(data.get("id") or "").strip() or None
    organization = await _webhook_organization(
        session,
        meta,
        external_subscription_id,
    )
    digest = hashlib.sha256(raw_body).hexdigest()
    claimed = (
        await session.execute(
            insert(BillingWebhookReceipt)
            .values(
                id=uuid4(),
                organization_id=organization.id,
                payload_digest=digest,
                event_name=event_name,
                external_subscription_id=external_subscription_id,
                event_at=event_at,
            )
            .on_conflict_do_nothing(index_elements=["payload_digest"])
            .returning(BillingWebhookReceipt.id)
        )
    ).scalar_one_or_none()
    if claimed is None:
        return "duplicate"

    status = _event_status(event_name, attributes)
    if _is_stale(organization, event_at, status):
        await _mark_processed(session, digest)
        await session.commit()
        return "stale"

    variant_id = str(attributes.get("variant_id") or "").strip() or None
    if status in ACTIVE_BILLING_STATUSES:
        tier = _variant_tier(variant_id)
        if tier is None:
            raise ValueError("Unknown Lemon Squeezy variant")
        await set_organization_tier(
            session,
            organization,
            tier,
            status=status,
            source="lemonsqueezy",
            event_at=event_at,
        )
        organization.cancel_at_period_end = False
    elif status in DEAD_BILLING_STATUSES:
        await set_organization_tier(
            session,
            organization,
            "free",
            status=status,
            source="lemonsqueezy",
            event_at=event_at,
        )
        organization.cancel_at_period_end = False
    else:
        organization.billing_status = status
        organization.billing_source = "lemonsqueezy"
        organization.billing_event_at = event_at
        organization.cancel_at_period_end = status == "cancelled"

    organization.external_subscription_id = external_subscription_id
    organization.external_customer_id = _string_or_none(attributes.get("customer_id"))
    organization.billing_variant_id = variant_id
    organization.current_period_end = _parse_datetime(
        attributes.get("ends_at") or attributes.get("renews_at")
    )
    portal_url = _customer_portal_url(attributes)
    if portal_url is not None:
        organization.customer_portal_url = portal_url
    await _mark_processed(session, digest)
    await session.commit()
    return "processed"


async def _webhook_organization(
    session: AsyncSession,
    meta: dict[str, Any],
    external_subscription_id: str | None,
) -> Organization:
    custom_organization_id = _custom_organization_id(meta)
    if external_subscription_id is not None:
        organization = (
            await session.execute(
                select(Organization)
                .where(
                    Organization.external_subscription_id == external_subscription_id
                )
                .with_for_update(of=Organization)
            )
        ).scalar_one_or_none()
        if organization is not None:
            if (
                custom_organization_id is not None
                and custom_organization_id != organization.id
            ):
                raise ValueError("Subscription identity mismatch")
            return organization

    organization_id, user_id = _verified_checkout_identity(meta)
    organization = (
        await session.execute(
            select(Organization)
            .join(User, User.organization_id == Organization.id)
            .where(
                Organization.id == organization_id,
                User.id == user_id,
                User.role == "owner",
                User.is_active.is_(True),
            )
            .with_for_update(of=Organization)
        )
    ).scalar_one_or_none()
    if organization is None:
        raise LookupError("Organization not found")
    return organization


def _custom_organization_id(meta: dict[str, Any]) -> UUID | None:
    custom_data = meta.get("custom_data")
    if not isinstance(custom_data, dict) or not custom_data.get("organization_id"):
        return None
    try:
        return UUID(str(custom_data["organization_id"]))
    except ValueError as exc:
        raise ValueError("Invalid organization ID") from exc


def _verified_checkout_identity(meta: dict[str, Any]) -> tuple[UUID, UUID]:
    custom_data = meta.get("custom_data")
    if not isinstance(custom_data, dict):
        raise ValueError("Invalid checkout identity")
    try:
        organization_id = UUID(str(custom_data["organization_id"]))
        user_id = UUID(str(custom_data["user_id"]))
        signature = str(custom_data["checkout_signature"])
    except (KeyError, ValueError) as exc:
        raise ValueError("Invalid checkout identity") from exc
    expected = _checkout_signature(organization_id, user_id)
    if not hmac.compare_digest(expected, signature):
        raise ValueError("Invalid checkout identity")
    return organization_id, user_id


async def _mark_processed(session: AsyncSession, digest: str) -> None:
    await session.execute(
        update(BillingWebhookReceipt)
        .where(BillingWebhookReceipt.payload_digest == digest)
        .values(processed_at=datetime.now(timezone.utc))
    )


def _event_status(event_name: str, attributes: dict[str, Any]) -> str:
    if event_name == "subscription_cancelled":
        return "cancelled"
    if event_name == "subscription_expired":
        return "expired"
    if event_name == "subscription_paused":
        return "paused"
    if event_name == "subscription_resumed":
        return "active"
    status = str(attributes.get("status") or "").strip()
    if status not in ACTIVE_BILLING_STATUSES | DEAD_BILLING_STATUSES | {
        "cancelled",
        "past_due",
        "paused",
    }:
        raise ValueError("Unknown subscription status")
    return status


def _is_stale(
    organization: Organization,
    event_at: datetime,
    new_status: str,
) -> bool:
    previous = organization.billing_event_at
    if previous is None:
        return False
    previous = _aware(previous)
    event_at = _aware(event_at)
    if event_at != previous:
        return event_at < previous
    severity = {
        "active": 0,
        "on_trial": 0,
        "past_due": 1,
        "paused": 2,
        "cancelled": 3,
        "unpaid": 4,
        "expired": 5,
    }
    return severity.get(new_status, 0) < severity.get(
        organization.billing_status,
        0,
    )


def _variant_tier(variant_id: str | None) -> str | None:
    if variant_id is None:
        return None
    return {
        settings.LEMON_SQUEEZY_SOLO_PRO_MONTHLY_VARIANT_ID: "managed",
        settings.LEMON_SQUEEZY_SOLO_PRO_YEARLY_VARIANT_ID: "managed",
        settings.LEMON_SQUEEZY_AGENCY_MONTHLY_VARIANT_ID: "agency",
        settings.LEMON_SQUEEZY_AGENCY_YEARLY_VARIANT_ID: "agency",
    }.get(variant_id)


def _with_checkout_identity(
    url: str,
    organization_id: UUID,
    user_id: UUID,
) -> str:
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query["checkout[custom][organization_id]"] = str(organization_id)
    query["checkout[custom][user_id]"] = str(user_id)
    query["checkout[custom][checkout_signature]"] = _checkout_signature(
        organization_id,
        user_id,
    )
    return urlunsplit((*parts[:3], urlencode(query), parts.fragment))


def _checkout_signature(organization_id: UUID, user_id: UUID) -> str:
    identity = f"lemonsqueezy-checkout:v1:{organization_id}:{user_id}".encode()
    return hmac.new(settings.SECRET_KEY.encode(), identity, hashlib.sha256).hexdigest()


def _customer_portal_url(attributes: dict[str, Any]) -> str | None:
    urls = attributes.get("urls")
    if not isinstance(urls, dict):
        return None
    value = _string_or_none(urls.get("customer_portal"))
    if value is None:
        return None
    parts = urlsplit(value)
    hostname = (parts.hostname or "").casefold()
    if parts.scheme != "https" or not (
        hostname == "lemonsqueezy.com" or hostname.endswith(".lemonsqueezy.com")
    ):
        return None
    return value


def _parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return _aware(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except ValueError:
        return None


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _string_or_none(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
