import json
from collections.abc import Awaitable, Callable
from uuid import UUID

import httpx
import pytest
from polar_sdk import Polar, SDKError

from shim_cloud.polar import (
    checkout_url,
    customer_state,
    portal_url,
    validate_catalog,
)

Handler = Callable[[httpx.Request], httpx.Response | Awaitable[httpx.Response]]
MONTHLY_PRODUCT_ID = "00000000-0000-0000-0000-000000000001"
YEARLY_PRODUCT_ID = "00000000-0000-0000-0000-000000000002"


def _subscription(subscription_id: str, product_id: str) -> dict[str, object]:
    return {
        "id": subscription_id,
        "created_at": "2026-09-01T00:00:00Z",
        "modified_at": None,
        "metadata": {},
        "status": "active",
        "amount": 1000,
        "currency": "usd",
        "recurring_interval": "month",
        "current_period_start": "2026-09-01T00:00:00Z",
        "current_period_end": "2026-10-01T00:00:00Z",
        "trial_start": None,
        "trial_end": None,
        "cancel_at_period_end": False,
        "canceled_at": None,
        "started_at": "2026-09-01T00:00:00Z",
        "ends_at": None,
        "product_id": product_id,
        "discount_id": None,
        "meters": [],
    }


def _customer_state(subscriptions: list[dict[str, object]]) -> dict[str, object]:
    return {
        "id": "customer-1",
        "created_at": "2026-09-01T00:00:00Z",
        "modified_at": None,
        "metadata": {},
        "email_verified": True,
        "name": "Workspace",
        "billing_name": None,
        "billing_address": None,
        "tax_id": None,
        "organization_id": "organization-1",
        "deleted_at": None,
        "avatar_url": None,
        "active_subscriptions": subscriptions,
        "granted_benefits": [],
        "active_meters": [],
        "email": "owner@example.com",
        "type": "team",
    }


async def _client(handler: Handler) -> tuple[Polar, httpx.AsyncClient]:
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return (
        Polar(
            access_token="test-token",
            async_client=http_client,
            retry_config=None,
            timeout_ms=10_000,
        ),
        http_client,
    )


def _organization(*, allow_multiple_subscriptions: bool = False) -> dict[str, object]:
    return {
        "id": "organization-1",
        "created_at": "2026-09-01T00:00:00Z",
        "modified_at": None,
        "name": "Shim",
        "slug": "shim",
        "avatar_url": None,
        "proration_behavior": "prorate",
        "allow_customer_updates": True,
        "email": "owner@example.com",
        "website": "https://example.com",
        "socials": [],
        "status": "active",
        "details_submitted_at": "2026-09-01T00:00:00Z",
        "sso_enforced": False,
        "default_presentment_currency": "usd",
        "default_tax_behavior": "location",
        "feature_settings": None,
        "subscription_settings": {
            "allow_multiple_subscriptions": allow_multiple_subscriptions,
            "proration_behavior": "prorate",
            "benefit_revocation_grace_period": 0,
            "prevent_trial_abuse": False,
            "allow_customer_updates": True,
        },
        "customer_email_settings": {
            key: False
            for key in (
                "order_confirmation",
                "subscription_cancellation",
                "subscription_confirmation",
                "subscription_cycled",
                "subscription_cycled_after_trial",
                "subscription_past_due",
                "subscription_paused",
                "subscription_resumed",
                "subscription_renewal_reminder",
                "subscription_revoked",
                "subscription_trial_conversion_reminder",
                "subscription_uncanceled",
                "subscription_updated",
            )
        },
        "customer_portal_settings": {
            "usage": {"show": True},
            "subscription": {
                "update_seats": False,
                "update_plan": False,
                "pause": False,
            },
            "customer": {"allow_email_change": False},
        },
        "account_id": "account-1",
        "payout_account_id": "payout-1",
        "capabilities": {
            key: True
            for key in (
                "checkout_payments",
                "subscription_renewals",
                "payouts",
                "refunds",
                "api_access",
                "dashboard_access",
            )
        },
        "country": "US",
    }


def _price(
    product_id: str,
    *,
    amount_type: str = "fixed",
    currency: str = "usd",
    archived: bool = False,
    price_id: str = "price-1",
) -> dict[str, object]:
    price: dict[str, object] = {
        "created_at": "2026-09-01T00:00:00Z",
        "modified_at": None,
        "id": price_id,
        "source": "catalog",
        "price_currency": currency,
        "tax_behavior": None,
        "is_archived": archived,
        "product_id": product_id,
        "amount_type": amount_type,
    }
    if amount_type == "fixed":
        price["price_amount"] = 1000
    elif amount_type == "custom":
        price.update(
            {"minimum_amount": 1000, "maximum_amount": 10000, "preset_amount": 1000}
        )
    elif amount_type == "metered_unit":
        price.update(
            {
                "unit_amount": "100",
                "cap_amount": None,
                "meter_id": "meter-1",
                "meter": {
                    "id": "meter-1",
                    "name": "API calls",
                    "unit": "scalar",
                    "custom_label": None,
                    "custom_multiplier": None,
                },
            }
        )
    return price


def _product(
    product_id: str = "product-1",
    *,
    organization_id: str = "organization-1",
    interval: str = "month",
    interval_count: int | None = 1,
    is_recurring: bool = True,
    is_archived: bool = False,
    meter_interval: str | None = None,
    meter_interval_count: int | None = None,
    prices: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "id": product_id,
        "created_at": "2026-09-01T00:00:00Z",
        "modified_at": None,
        "trial_interval": None,
        "trial_interval_count": None,
        "name": "Pro",
        "description": None,
        "visibility": "public",
        "recurring_interval": interval,
        "recurring_interval_count": interval_count,
        "meter_interval": meter_interval,
        "meter_interval_count": meter_interval_count,
        "is_recurring": is_recurring,
        "is_archived": is_archived,
        "organization_id": organization_id,
        "metadata": {},
        "prices": prices if prices is not None else [_price(product_id)],
        "benefits": [],
        "medias": [],
        "attached_custom_fields": [],
    }


async def _catalog_client(
    organization: dict[str, object], products: dict[str, dict[str, object]]
) -> tuple[Polar, httpx.AsyncClient, list[httpx.Request]]:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/v1/organizations/organization-1":
            return httpx.Response(200, json=organization, request=request)
        product_id = request.url.path.rsplit("/", 1)[-1]
        return httpx.Response(200, json=products[product_id], request=request)

    client, http_client = await _client(handler)
    return client, http_client, requests


@pytest.mark.asyncio
async def test_customer_state_maps_empty_and_multiple_subscriptions() -> None:
    requests: list[httpx.Request] = []
    payloads = (
        _customer_state([]),
        _customer_state(
            [
                _subscription("subscription-1", "product-monthly"),
                _subscription("subscription-2", "product-yearly"),
            ]
        ),
    )

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json=payloads[len(requests) - 1], request=request)

    client, http_client = await _client(handler)
    try:
        empty = await customer_state(client, "external-customer")
        multiple = await customer_state(client, "external-customer")
    finally:
        await http_client.aclose()

    assert empty.external_id is None
    assert empty.subscriptions == ()
    assert multiple.organization_id == "organization-1"
    assert [
        (item.id, item.product_id, item.status) for item in multiple.subscriptions
    ] == [
        ("subscription-1", "product-monthly", "active"),
        ("subscription-2", "product-yearly", "active"),
    ]
    assert [request.url.path for request in requests] == [
        "/v1/customers/external/external-customer/state",
        "/v1/customers/external/external-customer/state",
    ]


@pytest.mark.asyncio
async def test_checkout_url_uses_server_product_and_operation_metadata() -> None:
    requests: list[httpx.Request] = []
    response = {
        "id": "checkout-1",
        "created_at": "2026-09-01T00:00:00Z",
        "modified_at": None,
        "payment_processor": "stripe",
        "status": "open",
        "client_secret": "secret",
        "url": "https://checkout.polar.sh/checkout-1",
        "expires_at": "2026-09-01T01:00:00Z",
        "success_url": "https://app.example/success",
        "return_url": "https://app.example/return",
        "embed_origin": None,
        "amount": 1000,
        "discount_amount": 0,
        "net_amount": 1000,
        "tax_amount": 0,
        "tax_behavior": None,
        "total_amount": 1000,
        "currency": "usd",
        "allow_trial": False,
        "active_trial_interval": None,
        "active_trial_interval_count": None,
        "trial_end": None,
        "organization_id": "polar-organization",
        "product_id": "product-monthly",
        "product_price_id": None,
        "discount_id": None,
        "allow_discount_codes": False,
        "require_billing_address": False,
        "is_discount_applicable": False,
        "is_free_product_price": False,
        "is_payment_required": True,
        "is_payment_setup_required": False,
        "is_payment_form_required": True,
        "customer_id": "customer-1",
        "is_business_customer": False,
        "customer_name": None,
        "customer_email": "owner@example.com",
        "customer_ip_address": None,
        "customer_billing_name": None,
        "customer_billing_address": None,
        "customer_tax_id": None,
        "payment_processor_metadata": {},
        "billing_address_fields": {
            "country": "disabled",
            "state": "disabled",
            "city": "disabled",
            "postal_code": "disabled",
            "line1": "disabled",
            "line2": "disabled",
        },
        "trial_interval": None,
        "trial_interval_count": None,
        "metadata": {"shim_operation_id": "operation-1"},
        "external_customer_id": "external-customer",
        "products": [],
        "product": None,
        "product_price": None,
        "prices": None,
        "discount": None,
        "subscription_id": None,
        "attached_custom_fields": None,
        "customer_metadata": {},
        "custom_field_data": None,
    }

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(201, json=response, request=request)

    client, http_client = await _client(handler)
    try:
        url = await checkout_url(
            client,
            external_id="external-customer",
            email="owner@example.com",
            product_id="product-monthly",
            success_url="https://app.example/success",
            return_url="https://app.example/return",
            request_id="operation-1",
        )
    finally:
        await http_client.aclose()

    assert url == "https://checkout.polar.sh/checkout-1"
    assert requests[0].method == "POST"
    assert requests[0].url.path == "/v1/checkouts/"
    assert json.loads(requests[0].content) == {
        "allow_discount_codes": True,
        "allow_trial": True,
        "is_business_customer": False,
        "require_billing_address": False,
        "products": ["product-monthly"],
        "external_customer_id": "external-customer",
        "customer_email": "owner@example.com",
        "success_url": "https://app.example/success",
        "return_url": "https://app.example/return",
        "metadata": {"shim_operation_id": "operation-1"},
    }


@pytest.mark.asyncio
async def test_portal_url_uses_external_customer_and_return_url() -> None:
    requests: list[httpx.Request] = []
    response = {
        "created_at": "2026-09-01T00:00:00Z",
        "modified_at": None,
        "id": "session-1",
        "token": "session-token",
        "expires_at": "2026-09-01T01:00:00Z",
        "return_url": "https://app.example/subscription",
        "customer_portal_url": "https://polar.sh/portal/session-1",
        "customer_id": "customer-1",
        "customer": {
            "id": "customer-1",
            "created_at": "2026-09-01T00:00:00Z",
            "modified_at": None,
            "metadata": {},
            "email_verified": True,
            "name": "Workspace",
            "billing_name": None,
            "billing_address": None,
            "tax_id": None,
            "organization_id": "organization-1",
            "deleted_at": None,
            "avatar_url": None,
            "external_id": "external-customer",
            "email": "owner@example.com",
            "type": "team",
        },
    }

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(201, json=response, request=request)

    client, http_client = await _client(handler)
    try:
        url = await portal_url(
            client,
            external_id="external-customer",
            return_url="https://app.example/subscription",
        )
    finally:
        await http_client.aclose()

    assert url == "https://polar.sh/portal/session-1"
    assert requests[0].method == "POST"
    assert requests[0].url.path == "/v1/customer-sessions/"
    assert json.loads(requests[0].content) == {
        "external_customer_id": "external-customer",
        "return_url": "https://app.example/subscription",
    }


@pytest.mark.asyncio
async def test_customer_state_propagates_non_2xx_without_retry() -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(503, json={"detail": "unavailable"}, request=request)

    client, http_client = await _client(handler)
    try:
        with pytest.raises(SDKError):
            await customer_state(client, "external-customer")
    finally:
        await http_client.aclose()

    assert len(requests) == 1


@pytest.mark.asyncio
async def test_validate_catalog_accepts_supported_products() -> None:
    products = {
        MONTHLY_PRODUCT_ID: _product(MONTHLY_PRODUCT_ID, interval="month"),
        YEARLY_PRODUCT_ID: _product(YEARLY_PRODUCT_ID, interval="year"),
    }
    client, http_client, requests = await _catalog_client(_organization(), products)
    try:
        await validate_catalog(
            client,
            organization_id="organization-1",
            products={
                "managed:monthly": UUID(MONTHLY_PRODUCT_ID),
                "managed:yearly": UUID(YEARLY_PRODUCT_ID),
            },
        )
    finally:
        await http_client.aclose()

    assert [request.url.path for request in requests] == [
        "/v1/organizations/organization-1",
        "/v1/products/00000000-0000-0000-0000-000000000001",
        "/v1/products/00000000-0000-0000-0000-000000000002",
    ]


@pytest.mark.asyncio
async def test_validate_catalog_rejects_swapped_configured_intervals() -> None:
    products = {
        MONTHLY_PRODUCT_ID: _product(MONTHLY_PRODUCT_ID, interval="year"),
        YEARLY_PRODUCT_ID: _product(YEARLY_PRODUCT_ID, interval="month"),
    }
    client, http_client, _ = await _catalog_client(_organization(), products)
    try:
        with pytest.raises(ValueError, match="supported recurring plan"):
            await validate_catalog(
                client,
                organization_id="organization-1",
                products={
                    "managed:monthly": UUID(MONTHLY_PRODUCT_ID),
                    "managed:yearly": UUID(YEARLY_PRODUCT_ID),
                },
            )
    finally:
        await http_client.aclose()


@pytest.mark.asyncio
async def test_validate_catalog_rejects_multiple_subscriptions_setting() -> None:
    client, http_client, _ = await _catalog_client(
        _organization(allow_multiple_subscriptions=True), {}
    )
    try:
        with pytest.raises(ValueError, match="multiple subscriptions"):
            await validate_catalog(
                client,
                organization_id="organization-1",
                products={},
            )
    finally:
        await http_client.aclose()


@pytest.mark.parametrize(
    ("product", "message"),
    [
        (_product(organization_id="other-organization"), "merchant binding"),
        (_product(is_archived=True), "supported recurring plan"),
        (_product(is_recurring=False), "supported recurring plan"),
        (_product(interval="week"), "supported recurring plan"),
        (_product(interval_count=2), "supported recurring plan"),
        (
            _product(meter_interval="month", meter_interval_count=1),
            "supported recurring plan",
        ),
        (
            _product(prices=[_price("product-1", amount_type="custom")]),
            "fixed USD price",
        ),
        (
            _product(prices=[_price("product-1", amount_type="metered_unit")]),
            "fixed USD price",
        ),
        (
            _product(
                prices=[
                    _price("product-1"),
                    _price("product-1", price_id="price-2"),
                ]
            ),
            "fixed USD price",
        ),
        (
            _product(prices=[_price("product-1", currency="eur")]),
            "fixed USD price",
        ),
    ],
)
@pytest.mark.asyncio
async def test_validate_catalog_rejects_unsupported_product_catalog(
    product: dict[str, object], message: str
) -> None:
    product["id"] = MONTHLY_PRODUCT_ID
    product["organization_id"] = product.get("organization_id", "organization-1")
    for price in product["prices"]:
        assert isinstance(price, dict)
        price["product_id"] = MONTHLY_PRODUCT_ID
    client, http_client, _ = await _catalog_client(
        _organization(), {MONTHLY_PRODUCT_ID: product}
    )
    try:
        with pytest.raises(ValueError, match=message):
            await validate_catalog(
                client,
                organization_id="organization-1",
                products={"managed:monthly": UUID(MONTHLY_PRODUCT_ID)},
            )
    finally:
        await http_client.aclose()


@pytest.mark.asyncio
async def test_validate_catalog_does_not_retry_sdk_errors() -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(503, json={"detail": "unavailable"}, request=request)

    client, http_client = await _client(handler)
    try:
        with pytest.raises(SDKError):
            await validate_catalog(
                client,
                organization_id="organization-1",
                products={},
            )
    finally:
        await http_client.aclose()

    assert len(requests) == 1
