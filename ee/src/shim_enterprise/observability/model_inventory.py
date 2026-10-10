"""The model inventory: the registry and the traffic the gateway served, side by side."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from sqlalchemy import Text, and_, case, cast, column, func, not_, select, values
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.billing.models import RequestLifecycle
from shim_enterprise.gateway.pipeline.quota_reservation import (
    EPHEMERAL_BYOK_SPEND_POLICY_VERSION,
)
from shim_enterprise.tenants.models import ModelDeployment
from shim.billing.pricing import DEFAULT_PRICE_BOOK
from shim.gateway.kernel.result import UNSPECIFIED_PROVIDER_MODEL

MAX_INVENTORY_ITEMS = 500
# How readers see the Responses placeholder for a request that named no model.
UNSPECIFIED_MODEL = "model not specified"
# A catalog model the current price book no longer matches.
OTHER_MODEL = "other"


@dataclass(frozen=True, slots=True)
class InventoryItem:
    route: Literal["registry", "catalog"]
    registered: bool
    deployment_id: UUID | None
    alias: str | None
    provider: str | None
    model: str | None
    deployment_kind: str | None
    declared_version: str | None
    owner: str | None
    enabled: bool | None
    health: str | None
    requests: int
    first_seen: datetime | None
    last_seen: datetime | None
    api_keys: int
    teams: int
    byok_requests: int


@dataclass(frozen=True, slots=True)
class Inventory:
    items: list[InventoryItem]
    truncated: bool
    registry_deployments: int
    catalog_models: int
    requests: int
    byok_requests: int


def byok_request() -> Any:
    """A request that carried its own provider key past the provider spend limit."""
    return RequestLifecycle.lifecycle_metadata["policy_verdicts"].contains(
        [
            {
                "rule_id": "spend.provider_monthly",
                "policy_version": EPHEMERAL_BYOK_SPEND_POLICY_VERSION,
            }
        ]
    )


def shown_model(model: Any) -> Any:
    """A model name as readers see it: the Responses placeholder is not a model."""
    return case((model == UNSPECIFIED_PROVIDER_MODEL, UNSPECIFIED_MODEL), else_=model)


def registry_traffic(tenant_id: UUID) -> tuple[Any, Any]:
    """The lifecycle join and the registry deployment id (text) a request belongs to.

    The id is null for a catalog-routed request.
    """
    metadata = RequestLifecycle.lifecycle_metadata
    by_alias = (
        select(ModelDeployment.id, ModelDeployment.alias)
        .where(ModelDeployment.organization_id == tenant_id)
        .subquery("by_alias")
    )
    # Rows written before deployment ids were recorded fall back to the alias.
    joined = RequestLifecycle.__table__.outerjoin(
        by_alias,
        not_(metadata.has_key("deployment_id"))
        & metadata["deployment_kind"].as_string().is_distinct_from("unknown")
        & (RequestLifecycle.requested_model == by_alias.c.alias),
    )
    return joined, func.coalesce(
        metadata["deployment_id"].as_string(), cast(by_alias.c.id, Text)
    )


def catalog_request() -> Any:
    """A request no registry deployment served that reached spend reservation."""
    metadata = RequestLifecycle.lifecycle_metadata
    return and_(
        metadata["deployment_id"].as_string().is_(None),
        RequestLifecycle.provider.is_not(None),
        metadata["deployment_kind"].as_string() == "unknown",
    )


def catalog_models(*window: Any) -> Any:
    """Each catalog model name of the window and the price-book entry it matched.

    The name is caller text of any length; the entry is bounded by the book, so it
    is what inventories and findings key on.
    """
    book = values(
        column("provider", Text), column("entry", Text), name="price_book"
    ).data(
        [
            (provider, entry)
            for provider, prices in DEFAULT_PRICE_BOOK.provider_prices.items()
            for entry in prices
        ]
    )
    names = (
        select(RequestLifecycle.provider, RequestLifecycle.requested_model)
        .where(*window, catalog_request())
        .distinct()
        .cte("catalog_names")
    )
    name = func.lower(func.trim(names.c.requested_model))
    # The longest entry the name equals or extends with "-", as the gateway matched.
    entry = (
        select(book.c.entry)
        .where(
            book.c.provider == names.c.provider,
            (name == book.c.entry)
            | (func.left(name, func.length(book.c.entry) + 1) == book.c.entry + "-"),
        )
        .order_by(func.length(book.c.entry).desc())
        .limit(1)
        .scalar_subquery()
    )
    return select(
        names.c.provider,
        names.c.requested_model,
        case(
            (names.c.requested_model == UNSPECIFIED_PROVIDER_MODEL, UNSPECIFIED_MODEL),
            else_=func.coalesce(entry, OTHER_MODEL),
        ).label("model"),
    ).subquery("catalog_models")


def catalog_traffic(*window: Any) -> tuple[Any, Any]:
    """Catalog requests of the window joined to their bounded model name."""
    models = catalog_models(*window)
    return (
        RequestLifecycle.__table__.join(
            models,
            (models.c.provider == RequestLifecycle.provider)
            & (models.c.requested_model == RequestLifecycle.requested_model)
            & catalog_request(),
        ),
        models.c.model,
    )


async def catalog_model_names(
    session: AsyncSession, *, tenant_id: UUID, start_at: datetime, end_at: datetime
) -> list[str]:
    """The bounded names of the catalog models in traffic, as the inventory keys them."""
    models = catalog_models(*_window(tenant_id, start_at, end_at))
    return list(
        await session.scalars(
            select(models.c.model).distinct().order_by(models.c.model)
        )
    )


def _window(tenant_id: UUID, start_at: datetime, end_at: datetime) -> tuple[Any, ...]:
    return (
        RequestLifecycle.organization_id == tenant_id,
        RequestLifecycle.started_at >= start_at,
        RequestLifecycle.started_at < end_at,
    )


class ModelInventoryReadModel:
    async def read(
        self,
        session: AsyncSession,
        *,
        tenant_id: UUID,
        start_at: datetime,
        end_at: datetime,
    ) -> Inventory:
        deployments = (
            await session.scalars(
                select(ModelDeployment).where(
                    ModelDeployment.organization_id == tenant_id
                )
            )
        ).all()
        joined, target = registry_traffic(tenant_id)
        window = _window(tenant_id, start_at, end_at)
        catalog, model = catalog_traffic(*window)
        measures = (
            func.count().label("requests"),
            func.min(RequestLifecycle.started_at).label("first_seen"),
            func.max(RequestLifecycle.started_at).label("last_seen"),
            func.count(func.distinct(RequestLifecycle.api_key_id)).label("api_keys"),
            func.count(
                func.distinct(
                    RequestLifecycle.lifecycle_metadata["team_id"].as_string()
                )
            ).label("teams"),
            func.count().filter(byok_request()).label("byok_requests"),
        )
        registry = {
            row.deployment_id: row
            for row in await session.execute(
                select(target.label("deployment_id"), *measures)
                .select_from(joined)
                .where(*window, target.is_not(None))
                .group_by(target)
            )
        }
        catalog_rows = (
            await session.execute(
                select(RequestLifecycle.provider, model.label("model"), *measures)
                .select_from(catalog)
                .where(*window)
                .group_by(RequestLifecycle.provider, model)
            )
        ).all()
        registry_items = [
            InventoryItem(
                route="registry",
                registered=True,
                deployment_id=row.id,
                alias=row.alias,
                provider=row.provider,
                model=row.upstream_model,
                deployment_kind=row.deployment_kind,
                declared_version=row.declared_version,
                owner=row.owner,
                enabled=row.enabled,
                health=row.health,
                **_traffic(registry.get(str(row.id))),
            )
            for row in deployments
        ]
        catalog_items = [
            InventoryItem(
                route="catalog",
                registered=False,
                deployment_id=None,
                alias=None,
                provider=row.provider,
                model=row.model,
                deployment_kind=None,
                declared_version=None,
                owner=None,
                enabled=None,
                health=None,
                **_traffic(row),
            )
            for row in catalog_rows
        ]
        items = sorted(
            registry_items, key=lambda item: (-item.requests, item.alias or "")
        ) + sorted(catalog_items, key=lambda item: (-item.requests, item.model or ""))
        return Inventory(
            items=items[:MAX_INVENTORY_ITEMS],
            truncated=len(items) > MAX_INVENTORY_ITEMS,
            registry_deployments=len(registry_items),
            catalog_models=len(catalog_items),
            requests=sum(item.requests for item in items),
            byok_requests=sum(item.byok_requests for item in items),
        )


def _traffic(row: Any) -> dict[str, Any]:
    if row is None:
        return {
            "requests": 0,
            "first_seen": None,
            "last_seen": None,
            "api_keys": 0,
            "teams": 0,
            "byok_requests": 0,
        }
    return {
        "requests": row.requests,
        "first_seen": row.first_seen,
        "last_seen": row.last_seen,
        "api_keys": row.api_keys,
        "teams": row.teams,
        "byok_requests": row.byok_requests,
    }
