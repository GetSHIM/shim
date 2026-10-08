from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import hmac
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import UUID

import pytest

import shim_enterprise.tenants.policy as policy_module
from shim.gateway.contracts.ids import ApiKeyId, ProviderId, TenantId
from shim.gateway.contracts.principal import AuthenticatedPrincipal
from shim_enterprise.tenants.models import ApiKey
from shim_enterprise.tenants.policy import (
    ResolvedTenantSettings,
    TenantRequestPolicyResolver,
)


class SessionContext:
    def __init__(self, session: object) -> None:
        self.session = session
        self.entered = False
        self.exited = False

    async def __aenter__(self) -> object:
        self.entered = True
        return self.session

    async def __aexit__(self, *_args: object) -> None:
        self.exited = True


@pytest.mark.asyncio
async def test_enterprise_policy_session_and_exact_values() -> None:
    api_key_id = UUID("22222222-2222-2222-2222-222222222222")
    tenant_id = UUID("11111111-1111-1111-1111-111111111111")
    api_key = ApiKey(
        id=api_key_id,
        organization_id=tenant_id,
        user_id=UUID("33333333-3333-3333-3333-333333333333"),
        key_hash="key-hash",
        prefix="shim_test",
        tier="managed",
        cost_center="engineering",
        team="platform",
    )
    query_result = SimpleNamespace(scalar_one_or_none=lambda: api_key)
    session = SimpleNamespace(execute=AsyncMock(return_value=query_result))
    context = SessionContext(session)
    session_factory = Mock(return_value=context)
    pii_config = {
        "block_email": False,
        "block_phone": True,
        "block_credit_card": True,
        "block_secrets": True,
        "block_pii_tr": True,
    }
    tier_definition = {
        "rate_limit_rpm": 120,
        "rate_limit_tpm": -1,
        "daily_request_limit": 20,
        "monthly_request_limit": 2_000,
        "monthly_token_limit": 3_000_000,
        "features": {
            "provider_policy": {
                "allowed_providers": ["openai"],
                "allowed_regions": ["eu"],
                "require_zero_retention": True,
            },
            "audit_policy": {"mode": "strict"},
        },
    }
    policy_service = SimpleNamespace(
        resolve=AsyncMock(
            return_value=ResolvedTenantSettings(
                tenant_id=tenant_id,
                pii_config=pii_config,
                tier_definition=tier_definition,
            )
        )
    )
    principal = AuthenticatedPrincipal(
        actor_type="api_key",
        api_key_id=ApiKeyId(api_key_id),
        authenticated_at=datetime(2026, 8, 27, tzinfo=UTC),
    )
    resolver = TenantRequestPolicyResolver(policy_service, session_factory)

    resolved = await resolver.resolve(principal)

    assert context.entered is True
    assert context.exited is True
    session_factory.assert_called_once_with()
    policy_service.resolve.assert_awaited_once_with(api_key, session)
    assert resolved.tenant_id == TenantId(tenant_id)
    assert resolved.tenant_policy.allowed_providers == (ProviderId("openai"),)
    assert resolved.tenant_policy.allowed_regions == ("eu",)
    assert resolved.tenant_policy.require_zero_retention is True
    assert resolved.tier_policy.rate_limit_rpm == 120
    assert resolved.tier_policy.rate_limit_tpm is None
    assert resolved.tier_policy.daily_request_limit == 20
    assert resolved.tier_policy.monthly_request_limit == 2_000
    assert resolved.tier_policy.monthly_token_limit == 3_000_000
    assert resolved.audit_policy.mode == "strict"
    assert resolved.request_policy.rate_limit_key_hash == "key-hash"
    assert resolved.request_policy.tier == "managed"
    assert resolved.request_policy.cost_center == "engineering"
    assert resolved.request_policy.team == "platform"
    assert resolved.pii_config == pii_config
    statement = str(session.execute.await_args.args[0])
    assert "api_keys.is_active IS true" in statement
    assert "api_keys.expires_at IS NULL" in statement
    assert "api_keys.expires_at >" in statement


@pytest.mark.asyncio
async def test_enterprise_policy_preserves_missing_tier_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api_key = SimpleNamespace(
        key_hash="key-hash",
        tier="managed",
        cost_center=None,
        team=None,
    )
    load_api_key = AsyncMock(return_value=api_key)
    monkeypatch.setattr(policy_module, "load_api_key_for_principal", load_api_key)
    monkeypatch.setattr(policy_module.settings, "AI_ACT_AUDIT_ENABLED", True)
    tenant_id = UUID("11111111-1111-1111-1111-111111111111")
    policy_service = SimpleNamespace(
        resolve=AsyncMock(
            return_value=ResolvedTenantSettings(
                tenant_id=tenant_id,
                pii_config=None,
                tier_definition=None,
            )
        )
    )
    session = object()
    context = SessionContext(session)
    resolver = TenantRequestPolicyResolver(
        policy_service,
        Mock(return_value=context),
    )
    principal = AuthenticatedPrincipal(
        actor_type="api_key",
        api_key_id=ApiKeyId(UUID("22222222-2222-2222-2222-222222222222")),
        authenticated_at=datetime(2026, 8, 27, tzinfo=UTC),
    )

    resolved = await resolver.resolve(principal)

    assert context.exited is True
    load_api_key.assert_awaited_once_with(principal, session)
    assert (
        resolved.tier_policy.rate_limit_rpm == policy_module.settings.DEFAULT_RPM_LIMIT
    )
    assert (
        resolved.tier_policy.rate_limit_tpm == policy_module.settings.DEFAULT_TPM_LIMIT
    )
    assert resolved.tier_policy.daily_request_limit is None
    assert resolved.tier_policy.monthly_request_limit == 1_000
    assert (
        resolved.tier_policy.monthly_token_limit
        == policy_module.settings.DEFAULT_MONTHLY_TOKEN_LIMIT
    )
    assert resolved.audit_policy.mode == "best_effort"
    assert resolved.tenant_policy.allowed_providers == ()
    assert resolved.pii_config is None


def test_enterprise_unlimited_mapping_preserves_existing_bool_semantics() -> None:
    assert policy_module._unlimited_as_none(True) is True


class _PolicyCache:
    def __init__(self, pii_config: dict | None) -> None:
        self.pii_config = pii_config
        self.stored: dict | None = None

    async def get_pii_config(self, _tenant_id: str) -> dict | None:
        return self.pii_config

    async def set_pii_config(self, _tenant_id: str, value: dict) -> None:
        self.stored = value

    async def get_tier_definition(self, _slug: str) -> dict:
        return {"features": {}}


_SWITCHES = {
    "block_email": True,
    "block_phone": False,
    "block_credit_card": True,
    "block_secrets": True,
    "block_pii_tr": True,
}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("cached", "entity_actions"),
    [
        (_SWITCHES, None),
        ({**_SWITCHES, "entity_actions": {}}, None),
        ({**_SWITCHES, "entity_actions": {"SECRET": "block"}}, {"SECRET": "block"}),
    ],
)
async def test_cached_privacy_settings_decode_old_and_new_values(
    cached, entity_actions
) -> None:
    api_key = SimpleNamespace(organization_id=UUID(int=1), tier="managed")
    service = policy_module.TenantPolicyService(_PolicyCache(cached))

    resolved = await service.resolve(api_key, session=None)

    assert resolved.pii_config == _SWITCHES
    assert resolved.entity_actions == entity_actions


@pytest.mark.asyncio
async def test_privacy_settings_are_cached_with_their_entity_actions() -> None:
    row = SimpleNamespace(
        **_SWITCHES,
        entity_actions={"EMAIL_ADDRESS": "monitor"},
        placeholder_mode="stable",
    )
    session = SimpleNamespace(
        execute=AsyncMock(return_value=SimpleNamespace(scalar_one_or_none=lambda: row))
    )
    cache = _PolicyCache(None)
    api_key = SimpleNamespace(organization_id=UUID(int=1), tier="managed")

    resolved = await policy_module.TenantPolicyService(cache).resolve(api_key, session)

    assert cache.stored == {
        **_SWITCHES,
        "entity_actions": {"EMAIL_ADDRESS": "monitor"},
        "placeholder_mode": "stable",
    }
    assert resolved.pii_config == _SWITCHES
    assert resolved.entity_actions == {"EMAIL_ADDRESS": "monitor"}
    assert resolved.placeholder_mode == "stable"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("cached", "mode"),
    [
        (_SWITCHES, "random"),
        ({**_SWITCHES, "placeholder_mode": "random"}, "random"),
        ({**_SWITCHES, "placeholder_mode": "stable"}, "stable"),
    ],
)
async def test_cached_placeholder_mode_stays_out_of_the_switches(cached, mode) -> None:
    api_key = SimpleNamespace(organization_id=UUID(int=1), tier="managed")

    resolved = await policy_module.TenantPolicyService(_PolicyCache(cached)).resolve(
        api_key, session=None
    )

    assert resolved.pii_config == _SWITCHES
    assert resolved.placeholder_mode == mode


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["random", "stable"])
async def test_only_stable_tenants_get_the_placeholder_root_key(
    monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    api_key = SimpleNamespace(
        key_hash="key-hash", tier="managed", cost_center=None, team=None
    )
    monkeypatch.setattr(
        policy_module, "load_api_key_for_principal", AsyncMock(return_value=api_key)
    )
    policy_service = SimpleNamespace(
        resolve=AsyncMock(
            return_value=ResolvedTenantSettings(
                tenant_id=UUID(int=1),
                pii_config=None,
                tier_definition=None,
                placeholder_mode=mode,
            )
        )
    )
    resolver = TenantRequestPolicyResolver(
        policy_service, Mock(return_value=SessionContext(object()))
    )

    resolved = await resolver.resolve(SimpleNamespace())

    root = hmac.new(
        policy_module.settings.SECRET_KEY.encode(),
        b"shim.placeholder.root.v1",
        hashlib.sha256,
    ).digest()
    if mode == "random":
        assert resolved.placeholder_key is None
        return
    assert resolved.placeholder_key is not None
    assert resolved.placeholder_key.get_secret_value() == root
    assert root.hex() not in repr(resolved) and repr(root) not in repr(resolved)
