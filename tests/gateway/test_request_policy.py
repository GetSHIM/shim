from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256
from typing import get_type_hints
from uuid import UUID

import pytest
from fastapi import HTTPException
from pydantic import SecretStr

import shim.gateway.local_auth as local_auth_module
import shim.gateway.kernel.result as kernel_result
import shim.gateway.request_policy as request_policy_module
from shim.gateway.contracts.ids import ApiKeyId
from shim.gateway.contracts.principal import AuthenticatedPrincipal
from shim.gateway.kernel.result import PreparedInference
from shim.gateway.local_auth import (
    LOCAL_API_KEY_ID,
    LOCAL_TENANT_ID,
    LocalAuthenticator,
)
from shim.gateway.request_policy import LocalRequestPolicyResolver


LOCAL_KEY = "local-gateway-key"


@pytest.mark.asyncio
async def test_local_identity_and_policy_do_not_depend_on_key_rotation() -> None:
    first_authenticator = LocalAuthenticator(SecretStr(LOCAL_KEY))
    second_key = "rotated-local-gateway-key"
    second_authenticator = LocalAuthenticator(SecretStr(second_key))

    first = first_authenticator.authenticate({"x-shim-key": LOCAL_KEY})
    second = second_authenticator.authenticate({"x-shim-key": second_key})
    resolver = LocalRequestPolicyResolver(rate_limit_rpm=60, rate_limit_tpm=10_000)
    first_policy = await resolver.resolve(first)
    second_policy = await resolver.resolve(second)

    assert first.api_key_id == second.api_key_id == LOCAL_API_KEY_ID
    assert first_policy.tenant_id == second_policy.tenant_id == LOCAL_TENANT_ID
    assert LOCAL_API_KEY_ID.version == LOCAL_TENANT_ID.version == 5
    assert first_policy.request_policy == second_policy.request_policy
    assert (
        first_policy.request_policy.rate_limit_key_hash
        == sha256(str(LOCAL_API_KEY_ID).encode()).hexdigest()
    )
    assert first_policy.request_policy.tier == "local"
    assert first_policy.tier_policy.rate_limit_rpm == 60
    assert first_policy.tier_policy.rate_limit_tpm == 10_000
    assert first_policy.tier_policy.daily_request_limit is None
    assert first_policy.tier_policy.monthly_request_limit is None
    assert first_policy.tier_policy.monthly_token_limit is None
    assert first_policy.tenant_policy.allowed_providers == ()
    assert first_policy.tenant_policy.allowed_regions == ()
    assert first_policy.tenant_policy.require_zero_retention is False
    assert first_policy.audit_policy.mode == "off"
    assert first_policy.pii_config == {
        "block_email": True,
        "block_phone": True,
        "block_credit_card": True,
        "block_secrets": True,
        "block_pii_tr": True,
    }
    for secret in (LOCAL_KEY, second_key):
        assert secret not in repr(first_authenticator)
        assert secret not in repr(second_authenticator)
        assert secret not in repr(first)
        assert secret not in repr(first_policy)


@pytest.mark.asyncio
async def test_local_policy_rejects_nonlocal_principals() -> None:
    principal = AuthenticatedPrincipal(
        actor_type="api_key",
        api_key_id=ApiKeyId(UUID("22222222-2222-2222-2222-222222222222")),
        authenticated_at=datetime(2026, 8, 27, tzinfo=UTC),
    )

    with pytest.raises(ValueError, match="local API-key principal"):
        await LocalRequestPolicyResolver(
            rate_limit_rpm=60,
            rate_limit_tpm=10_000,
        ).resolve(principal)


def test_request_policy_context_has_no_legacy_kernel_export() -> None:
    assert not hasattr(kernel_result, "RequestPolicyContext")
    assert (
        get_type_hints(PreparedInference)["policy"]
        is request_policy_module.RequestPolicyContext
    )


def test_open_local_auth_ignores_sdk_placeholder_credentials() -> None:
    principal = LocalAuthenticator(None).authenticate(
        {
            "Authorization": "Bearer openai-sdk-placeholder",
            "x-shim-key": "shim-sdk-placeholder",
        }
    )

    assert principal.api_key_id == LOCAL_API_KEY_ID


def test_configured_local_auth_accepts_bearer_key() -> None:
    principal = LocalAuthenticator(SecretStr(LOCAL_KEY)).authenticate(
        {"Authorization": f"Bearer {LOCAL_KEY}"}
    )

    assert principal.api_key_id == LOCAL_API_KEY_ID


def test_provider_only_headers_never_authenticate_the_local_gateway() -> None:
    authenticator = LocalAuthenticator(SecretStr(LOCAL_KEY))

    with pytest.raises(HTTPException) as error:
        authenticator.authenticate(
            {
                "x-openai-api-key": LOCAL_KEY,
                "x-goog-api-key": LOCAL_KEY,
                "x-provider-key": LOCAL_KEY,
            }
        )

    assert error.value.status_code == 401
    assert error.value.detail == "Missing API Key"


def test_local_auth_compares_fixed_length_digests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    compared: list[tuple[bytes, bytes]] = []
    compare_digest = local_auth_module.secrets.compare_digest

    def spy(left: bytes, right: bytes) -> bool:
        compared.append((left, right))
        return compare_digest(left, right)

    monkeypatch.setattr(local_auth_module.secrets, "compare_digest", spy)

    LocalAuthenticator(SecretStr(LOCAL_KEY)).authenticate({"x-shim-key": LOCAL_KEY})

    assert len(compared) == 1
    assert tuple(map(len, compared[0])) == (32, 32)


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"x-shim-key": "wrong-local-gateway-key"},
        {"Authorization": "Basic local-gateway-key"},
    ],
)
def test_configured_local_auth_rejects_missing_or_invalid_key(
    headers: dict[str, str],
) -> None:
    with pytest.raises(HTTPException) as error:
        LocalAuthenticator(SecretStr(LOCAL_KEY)).authenticate(headers)

    assert error.value.status_code == 401


@pytest.mark.parametrize(
    ("headers", "accept_anthropic_key", "allowed"),
    [
        (
            {
                "x-shim-key": LOCAL_KEY,
                "Authorization": "Bearer wrong-local-gateway-key",
            },
            False,
            True,
        ),
        (
            {
                "x-shim-key": "wrong-local-gateway-key",
                "Authorization": f"Bearer {LOCAL_KEY}",
            },
            False,
            False,
        ),
        (
            {
                "Authorization": "Bearer wrong-local-gateway-key",
                "x-api-key": LOCAL_KEY,
            },
            True,
            False,
        ),
        ({"x-api-key": LOCAL_KEY}, True, True),
        ({"x-api-key": LOCAL_KEY}, False, False),
    ],
)
def test_local_auth_uses_strict_first_present_precedence(
    headers: dict[str, str],
    accept_anthropic_key: bool,
    allowed: bool,
) -> None:
    authenticator = LocalAuthenticator(SecretStr(LOCAL_KEY))

    if allowed:
        assert (
            authenticator.authenticate(
                headers,
                accept_anthropic_key=accept_anthropic_key,
            ).api_key_id
            == LOCAL_API_KEY_ID
        )
    else:
        with pytest.raises(HTTPException) as error:
            authenticator.authenticate(
                headers,
                accept_anthropic_key=accept_anthropic_key,
            )
        assert error.value.status_code == 401
