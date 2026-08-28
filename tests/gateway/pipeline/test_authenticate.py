from dataclasses import fields
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID

import pytest
from fastapi import HTTPException

from shim.gateway.contracts.context import AuditPolicy, TenantPolicy, TierPolicy
from shim.gateway.contracts.ids import ProviderId, TenantId
from shim.gateway.contracts.principal import AuthenticatedPrincipal
from shim.gateway.pipeline.authenticate import (
    AuthenticateStage,
    GatewayInvocation,
    GatewayRequestMetadata,
    _zero_retention_requested,
)
from shim.gateway.request_policy import RequestPolicyContext, ResolvedRequestPolicy


@pytest.mark.asyncio
async def test_authenticate_uses_session_free_policy_values_only() -> None:
    api_key_id = UUID("22222222-2222-2222-2222-222222222222")
    tenant_id = UUID("11111111-1111-1111-1111-111111111111")
    resolved = ResolvedRequestPolicy(
        tenant_id=TenantId(tenant_id),
        tenant_policy=TenantPolicy(),
        tier_policy=TierPolicy(rate_limit_rpm=60, rate_limit_tpm=10_000),
        audit_policy=AuditPolicy(mode="best_effort"),
        request_policy=RequestPolicyContext(
            rate_limit_key_hash="key-hash",
            tier="managed",
            cost_center="engineering",
            team="platform",
        ),
        pii_config=None,
    )
    policy_resolver = SimpleNamespace(
        resolve=AsyncMock(
            return_value=resolved,
        )
    )
    principal = AuthenticatedPrincipal(
        actor_type="api_key",
        api_key_id=api_key_id,
        user_id=None,
        authenticated_at=datetime(2026, 8, 27, tzinfo=UTC),
    )
    invocation = GatewayInvocation(
        principal=principal,
        payload={"model": "gpt-5.6-luna", "messages": []},
        provider="openai",
        protocol="chat",
        model="gpt-5.6-luna",
        stream=False,
        headers={},
        provider_credential=None,
        metadata=GatewayRequestMetadata(endpoint="/v1/chat/completions"),
    )

    prepared = await AuthenticateStage(policy_resolver).run(invocation)

    assert prepared.policy == RequestPolicyContext(
        rate_limit_key_hash="key-hash",
        tier="managed",
        cost_center="engineering",
        team="platform",
    )
    assert all(
        value is None or isinstance(value, str)
        for value in (
            prepared.policy.rate_limit_key_hash,
            prepared.policy.tier,
            prepared.policy.cost_center,
            prepared.policy.team,
        )
    )
    assert all(field.name != "db" for field in fields(prepared))
    assert not hasattr(invocation, "db")
    assert not hasattr(prepared, "api_key")
    assert not hasattr(prepared, "db")
    assert not hasattr(prepared.policy, "__dict__")
    policy_resolver.resolve.assert_awaited_once_with(principal)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tenant_policy", "provider", "payload", "expected_code"),
    [
        (
            TenantPolicy(allowed_providers=(ProviderId("openai"),)),
            "google",
            {},
            "PROVIDER_NOT_ALLOWED",
        ),
        (
            TenantPolicy(require_zero_retention=True),
            "openai",
            {"store": True},
            "ZERO_RETENTION_REQUIRED",
        ),
    ],
)
async def test_authenticate_preserves_tenant_request_restrictions(
    tenant_policy: TenantPolicy,
    provider: str,
    payload: dict,
    expected_code: str,
) -> None:
    api_key_id = UUID("22222222-2222-2222-2222-222222222222")
    principal = AuthenticatedPrincipal(
        actor_type="api_key",
        api_key_id=api_key_id,
        authenticated_at=datetime(2026, 8, 27, tzinfo=UTC),
    )
    resolver = SimpleNamespace(
        resolve=AsyncMock(
            return_value=ResolvedRequestPolicy(
                tenant_id=TenantId(UUID("11111111-1111-1111-1111-111111111111")),
                tenant_policy=tenant_policy,
                tier_policy=TierPolicy(),
                audit_policy=AuditPolicy(mode="best_effort"),
                request_policy=RequestPolicyContext("key-hash", "managed"),
                pii_config=None,
            )
        )
    )
    invocation = GatewayInvocation(
        principal=principal,
        payload=payload,
        provider=provider,
        protocol="generate_content" if provider == "google" else "chat",
        model="test-model",
        stream=False,
        headers={},
        provider_credential=None,
        metadata=GatewayRequestMetadata(endpoint="/test"),
    )

    with pytest.raises(HTTPException) as error:
        await AuthenticateStage(resolver).run(invocation)

    assert error.value.detail["code"] == expected_code


@pytest.mark.parametrize(
    ("provider", "protocol", "payload", "allowed"),
    [
        ("openai", "chat", {"store": False}, True),
        (
            "openai",
            "chat",
            {"store": False, "prompt_cache_retention": "24h"},
            False,
        ),
        ("openai", "chat", {"store": False, "modalities": ["audio"]}, False),
        (
            "openai",
            "responses",
            {"store": False, "conversation": "conv_1"},
            False,
        ),
        ("google", "generate_content", {"store": False}, True),
        (
            "google",
            "generate_content",
            {"store": False, "cachedContent": "cachedContents/1"},
            False,
        ),
        ("google", "generate_content", {"store": False, "tools": [{}]}, False),
        ("anthropic", "messages", {"store": False}, False),
    ],
)
def test_zero_retention_rejects_provider_features_that_retain_data(
    provider: str,
    protocol: str,
    payload: dict,
    allowed: bool,
) -> None:
    invocation = SimpleNamespace(
        provider=provider,
        protocol=protocol,
        payload=payload,
    )

    assert _zero_retention_requested(invocation) is allowed
