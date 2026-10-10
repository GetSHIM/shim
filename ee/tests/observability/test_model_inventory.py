from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import event

from shim_enterprise.api.enterprise_deps import get_current_user
from shim_enterprise.api.v1.router import management_router
from shim_enterprise.billing.models import RequestLifecycle
from shim_enterprise.core.database import get_db
from shim_enterprise.gateway.pipeline.quota_reservation import (
    EPHEMERAL_BYOK_SPEND_POLICY_VERSION,
)
from shim_enterprise.observability import model_inventory
from shim_enterprise.observability.model_inventory import ModelInventoryReadModel
from shim_enterprise.tenants.models import (
    ApiKey,
    ModelDeployment,
    Organization,
    ProviderSecret,
    User,
)

NOW = datetime.now(timezone.utc)
BYOK = {
    "rule_id": "spend.provider_monthly",
    "policy_version": EPHEMERAL_BYOK_SPEND_POLICY_VERSION,
}


async def _tenant(db, role: str = "owner") -> tuple[User, ApiKey]:
    organization = Organization(
        id=uuid4(), name="Inventory", slug=f"inventory-{uuid4().hex}", tier="enterprise"
    )
    db.add(organization)
    await db.flush()
    user = User(
        id=uuid4(),
        organization_id=organization.id,
        email=f"inventory-{uuid4().hex}@example.com",
        role=role,
        is_active=True,
        is_verified=True,
    )
    db.add(user)
    await db.flush()
    key = ApiKey(
        id=uuid4(),
        organization_id=organization.id,
        user_id=user.id,
        key_hash=uuid4().hex,
        prefix="sk-shim-inv",
        tier="enterprise",
        is_active=True,
    )
    db.add(key)
    await db.flush()
    return user, key


async def _deployment(db, key: ApiKey, alias: str, *, enabled: bool = True):
    secret = ProviderSecret(
        id=uuid4(),
        organization_id=key.organization_id,
        provider="openai",
        secret_ref=f"reference-{uuid4().hex}",
        secret_backend="fernet",
        secret_version="v2",
        masked_key="masked",
    )
    db.add(secret)
    await db.flush()
    row = ModelDeployment(
        organization_id=key.organization_id,
        alias=alias,
        provider="openai",
        upstream_model="llama",
        base_url="https://a.internal/v1",
        provider_secret_id=secret.id,
        timeout_seconds=5,
        deployment_kind="internal",
        declared_version="v1",
        owner="Platform",
        enabled=enabled,
    )
    db.add(row)
    await db.flush()
    return row


def _row(
    db,
    key: ApiKey,
    model: str,
    started_at: datetime,
    *,
    provider: str | None = "openai",
    **metadata,
) -> None:
    db.add(
        RequestLifecycle(
            request_id=f"req_inventory_{uuid4().hex}",
            organization_id=key.organization_id,
            actor_type="api_key",
            api_key_id=key.id,
            source_endpoint="chat.completions",
            status="completed",
            provider=provider,
            requested_model=model,
            stream=False,
            started_at=started_at,
            lifecycle_metadata=metadata,
        )
    )


async def _seed(db) -> tuple[User, ApiKey, ModelDeployment, ModelDeployment]:
    user, key = await _tenant(db)
    _, other_key = await _tenant(db)
    served = await _deployment(db, key, "inv-served")
    idle = await _deployment(db, key, "inv-idle", enabled=False)
    first, last = NOW - timedelta(days=3), NOW - timedelta(hours=1)
    by_id = {"deployment_id": str(served.id), "deployment_kind": "internal"}
    _row(db, key, "inv-served", first, **by_id, team_id="t1")
    _row(db, key, "renamed-alias", last, **by_id, team_id="t2")
    _row(db, key, "inv-served", NOW - timedelta(days=2))
    catalog = {"deployment_id": None, "deployment_kind": "unknown"}
    _row(db, key, "gpt-5-mini", first, **catalog)
    _row(db, key, "gpt-5-mini", last, **catalog, policy_verdicts=[BYOK])
    _row(db, key, "claude-haiku-4-5", last, provider="anthropic", **catalog)
    _row(db, other_key, "gpt-5-mini", last, **catalog)
    _row(db, key, "gpt-5-mini", NOW - timedelta(days=40), **catalog)
    _row(db, key, "gpt-5-mini", last, provider=None, **catalog)
    await db.flush()
    return user, key, served, idle


@pytest.mark.asyncio
async def test_the_inventory_puts_registry_and_catalog_traffic_side_by_side(db) -> None:
    user, key, served, idle = await _seed(db)
    statements: list[str] = []
    connection = await db.connection()

    def count(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    event.listen(connection.sync_connection, "before_cursor_execute", count)
    try:
        inventory = await ModelInventoryReadModel().read(
            db,
            tenant_id=user.organization_id,
            start_at=NOW - timedelta(days=30),
            end_at=NOW,
        )
    finally:
        event.remove(connection.sync_connection, "before_cursor_execute", count)

    assert len(statements) <= 3
    items = {(item.route, item.alias or item.model): item for item in inventory.items}
    assert list(items) == [
        ("registry", "inv-served"),
        ("registry", "inv-idle"),
        ("catalog", "gpt-5-mini"),
        ("catalog", "claude-haiku-4-5"),
    ]
    registry = items["registry", "inv-served"]
    assert (registry.requests, registry.deployment_id, registry.model) == (
        3,
        served.id,
        "llama",
    )
    assert (registry.first_seen, registry.last_seen) == (
        NOW - timedelta(days=3),
        NOW - timedelta(hours=1),
    )
    assert (registry.api_keys, registry.teams, registry.byok_requests) == (1, 2, 0)
    unused = items["registry", "inv-idle"]
    assert (unused.requests, unused.enabled, unused.first_seen) == (0, False, None)
    catalog = items["catalog", "gpt-5-mini"]
    assert (catalog.registered, catalog.provider, catalog.requests) == (
        False,
        "openai",
        2,
    )
    assert (catalog.byok_requests, catalog.deployment_id, catalog.owner) == (
        1,
        None,
        None,
    )
    assert items["catalog", "claude-haiku-4-5"].provider == "anthropic"
    assert (inventory.registry_deployments, inventory.catalog_models) == (2, 2)
    assert (inventory.requests, inventory.byok_requests, inventory.truncated) == (
        6,
        1,
        False,
    )


@pytest.mark.asyncio
async def test_the_inventory_is_capped(db, monkeypatch) -> None:
    user, *_ = await _seed(db)
    monkeypatch.setattr(model_inventory, "MAX_INVENTORY_ITEMS", 3)

    inventory = await ModelInventoryReadModel().read(
        db,
        tenant_id=user.organization_id,
        start_at=NOW - timedelta(days=30),
        end_at=NOW,
    )

    assert (len(inventory.items), inventory.truncated) == (3, True)
    assert inventory.catalog_models == 2


def _app(db, user: User) -> FastAPI:
    app = FastAPI()
    app.include_router(management_router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_db] = lambda: db
    return app


@pytest.mark.asyncio
async def test_readers_read_the_inventory_within_thirty_one_days(db) -> None:
    owner, *_ = await _seed(db)
    member, _ = await _tenant(db, role="member")
    auditor, _ = await _tenant(db, role="auditor")

    async def get(user: User, **params) -> httpx.Response:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=_app(db, user)), base_url="http://test"
        ) as client:
            return await client.get("/api/v1/management/model-inventory", params=params)

    listed = await get(owner)
    too_long = await get(
        owner,
        start=(NOW - timedelta(days=40)).isoformat(),
        end=NOW.isoformat(),
    )

    assert listed.status_code == 200
    assert [item["route"] for item in listed.json()["items"]] == [
        "registry",
        "registry",
        "catalog",
        "catalog",
    ]
    assert listed.json()["byok_requests"] == 1
    assert too_long.status_code == 422
    assert (await get(auditor)).status_code == 200
    assert (await get(member)).status_code == 403


def test_the_byok_spend_version_has_one_literal() -> None:
    root = Path(__file__).resolve().parents[2] / "src" / "shim_enterprise"
    sources = [
        path
        for path in root.rglob("*.py")
        if EPHEMERAL_BYOK_SPEND_POLICY_VERSION in path.read_text()
    ]
    assert [path.name for path in sources] == ["quota_reservation.py"]
