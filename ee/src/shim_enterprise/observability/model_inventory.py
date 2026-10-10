"""The model inventory: the registry and the traffic the gateway served, side by side."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from sqlalchemy import Text, and_, cast, func, not_, select
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.billing.models import RequestLifecycle
from shim_enterprise.gateway.pipeline.quota_reservation import (
    EPHEMERAL_BYOK_SPEND_POLICY_VERSION,
)
from shim_enterprise.tenants.models import ModelDeployment

MAX_INVENTORY_ITEMS = 500


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


def traffic_routes(tenant_id: UUID) -> tuple[Any, Any, Any]:
    """The lifecycle join, the deployment a request is attributed to, and the catalog test.

    The attributed id is text, null for a catalog-routed request.
    """
    metadata = RequestLifecycle.lifecycle_metadata
    kind = metadata["deployment_kind"].as_string()
    by_alias = (
        select(ModelDeployment.id, ModelDeployment.alias)
        .where(ModelDeployment.organization_id == tenant_id)
        .subquery("by_alias")
    )
    # Rows written before deployment ids were recorded fall back to the alias.
    joined = RequestLifecycle.__table__.outerjoin(
        by_alias,
        not_(metadata.has_key("deployment_id"))
        & kind.is_distinct_from("unknown")
        & (RequestLifecycle.requested_model == by_alias.c.alias),
    )
    target = func.coalesce(
        metadata["deployment_id"].as_string(), cast(by_alias.c.id, Text)
    )
    catalog = and_(
        target.is_(None), RequestLifecycle.provider.is_not(None), kind == "unknown"
    )
    return joined, target, catalog


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
        joined, target, catalog = traffic_routes(tenant_id)
        window = (
            RequestLifecycle.organization_id == tenant_id,
            RequestLifecycle.started_at >= start_at,
            RequestLifecycle.started_at < end_at,
        )
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
                select(
                    RequestLifecycle.provider,
                    RequestLifecycle.requested_model,
                    *measures,
                )
                .select_from(joined)
                .where(*window, catalog)
                .group_by(RequestLifecycle.provider, RequestLifecycle.requested_model)
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
                model=row.requested_model,
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
