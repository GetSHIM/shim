"""Small adapter around the pinned Polar SDK."""

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from polar_sdk import Polar, models

from shim_cloud.config import ProductKey

_FIXED_PRICE_TYPES = (
    models.ProductPriceFixed,
    models.LegacyRecurringProductPriceFixed,
)


@dataclass(frozen=True, slots=True)
class SubscriptionSnapshot:
    id: str
    product_id: str
    status: str
    current_period_end: datetime | None
    cancel_at_period_end: bool


@dataclass(frozen=True, slots=True)
class CustomerSnapshot:
    id: str
    external_id: str | None
    organization_id: str
    subscriptions: tuple[SubscriptionSnapshot, ...]


async def customer_state(client: Polar, external_id: str) -> CustomerSnapshot:
    state = await client.customers.get_state_external_async(
        external_id=external_id,
    )
    return CustomerSnapshot(
        id=state.id,
        external_id=state.external_id if isinstance(state.external_id, str) else None,
        organization_id=state.organization_id,
        subscriptions=tuple(
            SubscriptionSnapshot(
                id=subscription.id,
                product_id=subscription.product_id,
                status=subscription.status.value,
                current_period_end=subscription.current_period_end,
                cancel_at_period_end=subscription.cancel_at_period_end,
            )
            for subscription in state.active_subscriptions
        ),
    )


async def checkout_url(
    client: Polar,
    *,
    external_id: str,
    email: str,
    product_id: str,
    success_url: str,
    return_url: str,
    request_id: str,
) -> str:
    checkout = await client.checkouts.create_async(
        request={
            "products": [product_id],
            "external_customer_id": external_id,
            "customer_email": email,
            "success_url": success_url,
            "return_url": return_url,
            "metadata": {"shim_operation_id": request_id},
        },
    )
    return checkout.url


async def portal_url(client: Polar, *, external_id: str, return_url: str) -> str:
    session = await client.customer_sessions.create_async(
        request={
            "external_customer_id": external_id,
            "return_url": return_url,
        },
    )
    return session.customer_portal_url


async def validate_catalog(
    client: Polar, *, organization_id: str, products: dict[ProductKey, UUID]
) -> None:
    organization = await client.organizations.get_async(
        id=organization_id,
    )
    if organization.id != organization_id:
        raise ValueError("Polar organization binding mismatch")
    if organization.subscription_settings.allow_multiple_subscriptions:
        raise ValueError("Polar organization allows multiple subscriptions")

    for configured_key, configured_id in products.items():
        product_id = str(configured_id)
        product = await client.products.get_async(
            id=product_id,
        )
        if product.id != product_id or product.organization_id != organization_id:
            raise ValueError("Polar product merchant binding mismatch")
        _, separator, configured_interval = configured_key.rpartition(":")
        if not separator or configured_interval not in {"monthly", "yearly"}:
            raise ValueError("Polar product key must specify monthly or yearly")
        expected_interval = {
            "monthly": "month",
            "yearly": "year",
        }[configured_interval]
        if (
            product.is_archived
            or not product.is_recurring
            or product.recurring_interval is None
            or product.recurring_interval.value != expected_interval
            or product.recurring_interval_count != 1
            or product.meter_interval is not None
            or product.meter_interval_count is not None
        ):
            raise ValueError("Polar product is not a supported recurring plan")

        usable_prices = [price for price in product.prices if not price.is_archived]
        if (
            len(usable_prices) != 1
            or not isinstance(usable_prices[0], _FIXED_PRICE_TYPES)
            or usable_prices[0].price_currency.lower() != "usd"
        ):
            raise ValueError("Polar product must have exactly one fixed USD price")
