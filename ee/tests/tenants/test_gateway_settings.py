from __future__ import annotations

from dataclasses import dataclass
import importlib.util
import inspect
import logging
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4

from alembic.migration import MigrationContext
from alembic.operations import Operations
from fastapi import FastAPI
import httpx
from pydantic import ValidationError
import pytest
from sqlalchemy import func, select, text

import shim_enterprise.tenants.gateway_settings as gateway_settings
import shim_enterprise.tenants.policy as policy_module
import shim_enterprise.api.enterprise_deps as enterprise_deps
from shim_enterprise.api.enterprise_deps import ADMIN_REQUIRED
from shim_enterprise.api.v1 import management
from shim_enterprise.api.v1.router import management_router
from shim_enterprise.core.database import get_db
from shim_enterprise.tenants.gateway_settings import (
    SETTING_DIRECTIONS,
    GatewaySettings,
    GatewaySettingsPatch,
    classify_change,
    stored_settings,
)
from shim_enterprise.tenants.models import (
    Organization,
    OrganizationGatewaySettings,
    User,
)


@dataclass(frozen=True)
class _Analyzer:
    name: str
    version: str = "1"

    def analyze(self, _ctx) -> None:
        return None


@pytest.fixture
def registry(monkeypatch):
    analyzers = (_Analyzer("shape"), _Analyzer("language"))
    names = frozenset(analyzer.name for analyzer in analyzers)
    monkeypatch.setattr(gateway_settings, "ANALYZERS", analyzers)
    monkeypatch.setattr(gateway_settings, "ANALYZER_NAMES", names)
    monkeypatch.setattr(management, "ANALYZERS", analyzers)
    return analyzers


class _DeletingCache:
    def __init__(self) -> None:
        self.deleted: list[str] = []

    async def delete(self, key: str) -> bool:
        self.deleted.append(key)
        return True


def _request(cache=None):
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(cache=cache)))


async def _admin(db, organization_id: UUID, role: str = "admin") -> User:
    user = User(
        id=uuid4(),
        email=f"gateway-settings-{uuid4().hex}@example.com",
        full_name="Gateway Settings Admin",
        is_active=True,
        is_verified=True,
        organization_id=organization_id,
        role=role,
    )
    db.add(user)
    await db.flush()
    return user


async def _rows(db, organization_id: UUID) -> int:
    return await db.scalar(
        select(func.count()).where(
            OrganizationGatewaySettings.organization_id == organization_id
        )
    )


@pytest.mark.asyncio
async def test_a_new_row_has_empty_settings_and_revision_zero(db, test_org) -> None:
    db.add(OrganizationGatewaySettings(organization_id=test_org.id))
    await db.flush()
    row = await db.get(OrganizationGatewaySettings, test_org.id)
    await db.refresh(row)

    assert (row.settings, row.revision, row.updated_by) == ({}, 0, None)


@pytest.mark.asyncio
async def test_get_without_a_row_gives_defaults_and_writes_nothing(
    db, test_user_with_org, registry
) -> None:
    view = await management.get_gateway_settings(test_user_with_org, db)

    assert view.settings == GatewaySettings()
    assert view.model_dump(mode="json") == {
        "settings": {
            "response_analysis": [],
            "four_eyes": "off",
            "finding_modes": {},
        },
        "revision": 0,
        "updated_at": None,
        "updated_by": None,
        "available_analyzers": ["shape", "language"],
        "unavailable": {},
    }
    assert await _rows(db, test_user_with_org.organization_id) == 0


@pytest.mark.asyncio
async def test_patch_round_trip_in_registry_order_with_audit(
    db, test_org, registry, audit_events
) -> None:
    admin = await _admin(db, test_org.id)
    cache = _DeletingCache()

    view = await management.update_gateway_settings(
        GatewaySettingsPatch(response_analysis=["language", "shape"]),
        _request(cache),
        admin,
        db,
    )
    again = await management.get_gateway_settings(admin, db)

    assert view.settings.response_analysis == ["shape", "language"]
    assert (view.revision, view.updated_by) == (1, admin.id)
    assert view.updated_at is not None
    assert again == view
    row = await db.get(OrganizationGatewaySettings, test_org.id)
    assert row.settings == {"response_analysis": ["shape", "language"]}
    assert cache.deleted == [f"config:gateway:{test_org.id}"]
    [event] = await audit_events(test_org.id)
    assert event["endpoint"] == "tenant.gateway_settings_updated"
    assert event["extra"]["before"] == {"response_analysis": []}
    assert event["extra"]["after"] == {"response_analysis": ["shape", "language"]}

    cleared = await management.update_gateway_settings(
        GatewaySettingsPatch(response_analysis=[]), _request(cache), admin, db
    )
    assert (cleared.revision, cleared.settings.response_analysis) == (2, [])
    assert row.settings == {}


@pytest.mark.asyncio
async def test_a_patch_that_changes_nothing_writes_nothing(
    db, test_org, registry, audit_events
) -> None:
    admin = await _admin(db, test_org.id)

    first = await management.update_gateway_settings(
        GatewaySettingsPatch(response_analysis=[]),
        _request(_DeletingCache()),
        admin,
        db,
    )
    assert first.revision == 0 and await _rows(db, test_org.id) == 0
    await management.update_gateway_settings(
        GatewaySettingsPatch(response_analysis=["shape"]), _request(), admin, db
    )
    same = await management.update_gateway_settings(
        GatewaySettingsPatch(response_analysis=["shape"]), _request(), admin, db
    )
    empty = await management.update_gateway_settings(
        GatewaySettingsPatch(), _request(), admin, db
    )

    assert (same.revision, empty.revision) == (1, 1)
    assert [event["endpoint"] for event in await audit_events(test_org.id)] == [
        "tenant.gateway_settings_updated"
    ]


@pytest.mark.parametrize(
    "body",
    [
        {"response_analysis": ["nope"]},
        {"response_analysis": ["shape", "shape"]},
        {"response_analysis": None},
        {"unknown": 1},
    ],
)
def test_a_patch_refuses_unknown_names_duplicates_nulls_and_fields(
    registry, body
) -> None:
    with pytest.raises(ValidationError):
        GatewaySettingsPatch.model_validate(body)


def test_the_routes_ask_settings_read_to_read_and_settings_write_to_write() -> None:
    guards = {
        (method, route.path): inspect.getclosurevars(dependency.call).nonlocals
        for route in management.router.routes
        if route.path.endswith("/gateway-settings")
        for method in route.methods
        for dependency in route.dependant.dependencies
        if dependency.call.__qualname__ == "require.<locals>.guard"
    }

    assert guards["GET", "/gateway-settings"] == {
        "permissions": ("settings.read",),
        "legacy_detail": None,
    }
    assert guards["PATCH", "/gateway-settings"] == {
        "permissions": ("settings.write",),
        "legacy_detail": ADMIN_REQUIRED,
    }


@pytest.mark.asyncio
async def test_a_relaxing_change_writes_the_relaxed_event(
    db, test_org, registry, audit_events, monkeypatch
) -> None:
    # A test-only direction stands in for a later PRD's relaxing field.
    monkeypatch.setitem(
        SETTING_DIRECTIONS, "response_analysis", lambda _b, _a: "relaxing"
    )
    admin = await _admin(db, test_org.id)

    await management.update_gateway_settings(
        GatewaySettingsPatch(response_analysis=["shape"]), _request(), admin, db
    )

    events = {event["endpoint"]: event for event in await audit_events(test_org.id)}
    assert set(events) == {
        "tenant.gateway_settings_updated",
        "tenant.gateway_protection_relaxed",
    }
    assert events["tenant.gateway_protection_relaxed"]["extra"]["relaxed"] == [
        "response_analysis"
    ]


def test_every_field_has_a_direction_and_changes_classify(
    registry, monkeypatch
) -> None:
    assert set(SETTING_DIRECTIONS) == set(GatewaySettings.model_fields)
    before, after = GatewaySettings(), GatewaySettings(response_analysis=["shape"])
    assert classify_change(before, after) == ("neutral", [])
    assert classify_change(before, before) == ("neutral", [])
    monkeypatch.setitem(
        SETTING_DIRECTIONS, "response_analysis", lambda _b, _a: "tightening"
    )
    assert classify_change(before, after) == ("tightening", [])


def test_a_stored_key_this_build_does_not_know_is_ignored_and_logged_once(
    caplog,
) -> None:
    caplog.set_level(logging.WARNING)
    key = f"future_{uuid4().hex[:8]}"

    assert stored_settings({key: True}) == GatewaySettings()
    assert stored_settings({key: False}) == GatewaySettings()
    assert caplog.text.count(f"name={key}") == 1


class _PolicyCache:
    def __init__(self, gateway: dict | None) -> None:
        self.gateway = gateway
        self.stored: dict | None = None
        self.gets = 0

    async def get_pii_config(self, _tenant_id: str) -> dict:
        self.gets += 1
        return {}

    async def get_gateway_settings(self, _tenant_id: str) -> dict | None:
        self.gets += 1
        return self.gateway

    async def set_gateway_settings(self, _tenant_id: str, value: dict) -> None:
        self.stored = value

    async def get_tier_definition(self, _slug: str) -> dict:
        return {"features": {}}


_KEY = SimpleNamespace(organization_id=UUID(int=7), tier="managed")


@pytest.mark.asyncio
async def test_an_invalid_stored_value_fails_closed(registry) -> None:
    service = policy_module.TenantPolicyService(
        _PolicyCache({"response_analysis": "shape"})
    )

    with pytest.raises(policy_module.TenantPolicyConfigurationError):
        await service.resolve(_KEY, session=None)


@pytest.mark.asyncio
async def test_a_cache_hit_reads_no_row(registry) -> None:
    cache = _PolicyCache({"response_analysis": ["language"]})

    resolved = await policy_module.TenantPolicyService(cache).resolve(
        _KEY, session=None
    )

    assert resolved.gateway_settings == GatewaySettings(response_analysis=["language"])
    assert cache.stored is None and cache.gets == 2


@pytest.mark.asyncio
async def test_a_miss_reads_the_row_and_a_missing_row_is_cached_empty(
    db, test_org, registry
) -> None:
    other = Organization(id=uuid4(), name="Other", slug=f"other-{uuid4().hex}")
    db.add(other)
    db.add(
        OrganizationGatewaySettings(
            organization_id=test_org.id, settings={"response_analysis": ["shape"]}
        )
    )
    await db.flush()
    service_hit = policy_module.TenantPolicyService(cache := _PolicyCache(None))
    service_missing = policy_module.TenantPolicyService(missing := _PolicyCache(None))

    found = await service_hit.resolve(
        SimpleNamespace(organization_id=test_org.id, tier="managed"), db
    )
    absent = await service_missing.resolve(
        SimpleNamespace(organization_id=other.id, tier="managed"), db
    )

    assert found.gateway_settings.response_analysis == ["shape"]
    assert cache.stored == {"response_analysis": ["shape"]}
    assert absent.gateway_settings == GatewaySettings() and missing.stored == {}


@pytest.mark.asyncio
async def test_one_tenants_patch_leaves_another_tenant_alone(
    db, test_org, registry
) -> None:
    other = Organization(id=uuid4(), name="Other", slug=f"other-{uuid4().hex}")
    db.add(other)
    await db.flush()
    admin, stranger = await _admin(db, test_org.id), await _admin(db, other.id)

    await management.update_gateway_settings(
        GatewaySettingsPatch(response_analysis=["shape"]), _request(), admin, db
    )

    untouched = await management.get_gateway_settings(stranger, db)
    assert (untouched.revision, untouched.settings) == (0, GatewaySettings())


@pytest.mark.asyncio
async def test_members_and_auditors_read_and_only_admins_write(
    db, test_org, registry
) -> None:
    user = await _admin(db, test_org.id)
    application = FastAPI()
    application.include_router(management_router, prefix="/api/v1")
    application.dependency_overrides[enterprise_deps.get_current_user] = lambda: user
    application.dependency_overrides[get_db] = lambda: db
    statuses = {}

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="http://test"
    ) as client:
        for role in ("member", "auditor", "admin"):
            user.role = role
            statuses[role] = (
                (await client.get("/api/v1/management/gateway-settings")).status_code,
                (
                    await client.patch(
                        "/api/v1/management/gateway-settings",
                        json={"response_analysis": ["shape"]},
                    )
                ).status_code,
            )

    assert statuses == {
        # settings.read, as for the privacy settings (E31's permission map).
        "member": (200, 403),
        "auditor": (200, 403),
        "admin": (200, 200),
    }
    assert await _rows(db, test_org.id) == 1


async def _migrate(db, step: str) -> None:
    path = (
        Path(__file__).resolve().parents[2]
        / "alembic"
        / "versions"
        / "24b8466be324_add_organization_gateway_settings.py"
    )
    spec = importlib.util.spec_from_file_location("gateway_settings_migration", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    def run(connection) -> None:
        with Operations.context(MigrationContext.configure(connection)):
            getattr(module, step)()

    await (await db.connection()).run_sync(run)


@pytest.mark.asyncio
async def test_the_migration_drops_and_recreates_the_table_with_its_defaults(
    db, test_org
) -> None:
    exists = text("SELECT to_regclass('organization_gateway_settings') IS NOT NULL")

    await _migrate(db, "downgrade")
    assert await db.scalar(exists) is False
    await _migrate(db, "upgrade")

    assert await db.scalar(exists) is True
    await db.execute(
        text(
            "INSERT INTO organization_gateway_settings (organization_id) VALUES (:org)"
        ),
        {"org": test_org.id},
    )
    row = (
        await db.execute(
            text(
                "SELECT settings, revision, updated_by FROM "
                "organization_gateway_settings WHERE organization_id = :org"
            ),
            {"org": test_org.id},
        )
    ).one()
    assert tuple(row) == ({}, 0, None)


@pytest.mark.asyncio
async def test_a_patch_keeps_keys_a_newer_build_wrote(db, test_org, registry) -> None:
    db.add(
        OrganizationGatewaySettings(
            organization_id=test_org.id, settings={"future_switch": True}
        )
    )
    await db.flush()
    admin = await _admin(db, test_org.id)

    await management.update_gateway_settings(
        GatewaySettingsPatch(response_analysis=["shape"]), _request(), admin, db
    )
    row = await db.get(OrganizationGatewaySettings, test_org.id)
    assert row.settings == {"future_switch": True, "response_analysis": ["shape"]}

    await management.update_gateway_settings(
        GatewaySettingsPatch(response_analysis=[]), _request(), admin, db
    )
    assert row.settings == {"future_switch": True}


def test_a_stored_analyzer_this_build_does_not_have_is_dropped_and_logged_once(
    registry, caplog
) -> None:
    caplog.set_level(logging.WARNING)
    retired = f"retired_{uuid4().hex[:8]}"

    assert stored_settings(
        {"response_analysis": ["language", retired, "shape"]}
    ) == GatewaySettings(response_analysis=["shape", "language"])
    assert stored_settings({"response_analysis": [retired]}) == GatewaySettings()
    assert caplog.text.count(f"name={retired}") == 1


@pytest.mark.asyncio
async def test_a_stored_analyzer_this_build_does_not_have_breaks_nothing(
    db, test_org, registry
) -> None:
    stored = {"response_analysis": ["shape", "retired"]}
    db.add(OrganizationGatewaySettings(organization_id=test_org.id, settings=stored))
    await db.flush()
    admin = await _admin(db, test_org.id)

    resolved = await policy_module.TenantPolicyService(_PolicyCache(stored)).resolve(
        SimpleNamespace(organization_id=test_org.id, tier="managed"), db
    )
    read = await management.get_gateway_settings(admin, db)
    same = await management.update_gateway_settings(
        GatewaySettingsPatch(response_analysis=["shape"]), _request(), admin, db
    )
    changed = await management.update_gateway_settings(
        GatewaySettingsPatch(response_analysis=["language"]), _request(), admin, db
    )

    assert resolved.gateway_settings.response_analysis == ["shape"]
    assert read.settings.response_analysis == ["shape"]
    assert (same.revision, changed.revision) == (0, 1)
    row = await db.get(OrganizationGatewaySettings, test_org.id)
    assert row.settings == {"response_analysis": ["language"]}
