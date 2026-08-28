from __future__ import annotations

import json
import pickle
from uuid import UUID

import pytest

from shim.gateway.contracts.ids import TenantId
from shim.secrets.credentials import (
    EnvironmentProviderCredentialResolver,
    EphemeralProviderCredential,
    extract_provider_credential,
)


TENANT_ID = TenantId(UUID("11111111-1111-1111-1111-111111111111"))


def test_empty_provider_credential_is_rejected() -> None:
    with pytest.raises(ValueError, match="credential is required"):
        EphemeralProviderCredential("openai", "")


def test_provider_credential_is_removed_into_one_use_envelope() -> None:
    headers, credential = extract_provider_credential(
        {
            "x-provider-key": "tenant-provider-secret",
            "x-openai-api-key": "tenant-openai-secret",
            "x-shim-tag": "engineering",
        },
        "openai",
    )

    assert headers == {"x-shim-tag": "engineering"}
    assert credential is not None
    assert "tenant-provider-secret" not in repr(credential)
    assert credential.available() is True
    with pytest.raises(TypeError):
        json.dumps(credential)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(credential)
    assert credential.consume() == "tenant-provider-secret"
    assert credential.available() is False
    assert credential.consume() is None


def test_empty_high_priority_provider_credential_does_not_fall_through() -> None:
    with pytest.raises(ValueError, match="credential is required"):
        extract_provider_credential(
            {
                "x-provider-key": "",
                "x-openai-api-key": "lower-priority-secret",
            },
            "openai",
        )


def test_anthropic_gateway_api_key_is_not_provider_credential() -> None:
    headers, credential = extract_provider_credential(
        {
            "x-api-key": "shim-key",
            "anthropic-version": "2023-06-01",
        },
        "anthropic",
    )

    assert headers == {"anthropic-version": "2023-06-01"}
    assert credential is None


@pytest.mark.parametrize(
    "gateway_header",
    [
        {"x-shim-key": "same-key"},
        {"Authorization": "Bearer same-key"},
    ],
)
def test_matching_anthropic_and_gateway_keys_are_not_byok(
    gateway_header: dict[str, str],
) -> None:
    headers, credential = extract_provider_credential(
        {**gateway_header, "x-api-key": "same-key", "x-shim-tag": "engineering"},
        "anthropic",
    )

    assert headers == {"x-shim-tag": "engineering"}
    assert credential is None


def test_anthropic_byok_requires_the_unambiguous_provider_header() -> None:
    headers, credential = extract_provider_credential(
        {
            "Authorization": "Bearer shim-key",
            "x-api-key": "other-gateway-key",
            "x-provider-key": "anthropic-key",
        },
        "anthropic",
    )

    assert headers == {}
    assert credential is not None
    assert credential.consume() == "anthropic-key"


def test_all_credential_headers_are_removed_before_invocation() -> None:
    headers, credential = extract_provider_credential(
        {
            "Authorization": "Bearer shim-key",
            "X-Shim-Key": "shim-key",
            "x-provider-key": "explicit-provider-key",
            "x-api-key": "anthropic-key",
            "x-openai-api-key": "openai-key",
            "x-goog-api-key": "google-key",
            "x-shim-tag": "engineering",
        },
        "anthropic",
    )

    assert headers == {"x-shim-tag": "engineering"}
    assert credential is not None
    assert credential.consume() == "explicit-provider-key"


@pytest.mark.parametrize(
    ("provider", "header"),
    [
        ("openai", "x-openai-api-key"),
        ("google", "x-goog-api-key"),
    ],
)
def test_native_provider_headers_are_one_use_and_never_forwarded(
    provider: str,
    header: str,
) -> None:
    headers, credential = extract_provider_credential(
        {header: "tenant-provider-secret", "x-shim-tag": "engineering"},
        provider,
    )

    assert headers == {"x-shim-tag": "engineering"}
    assert credential is not None
    assert credential.consume() == "tenant-provider-secret"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("provider", "variable"),
    [
        ("openai", "OPENAI_API_KEY"),
        ("anthropic", "ANTHROPIC_API_KEY"),
        ("google", "GOOGLE_API_KEY"),
    ],
)
async def test_environment_resolver_uses_the_selected_provider_key(
    provider: str,
    variable: str,
) -> None:
    resolver = EnvironmentProviderCredentialResolver(
        provider,
        {variable: "environment-provider-key"},
    )

    assert await resolver.resolve(TENANT_ID, None) == "environment-provider-key"


@pytest.mark.asyncio
async def test_environment_resolver_reads_the_process_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "process-provider-key")

    resolver = EnvironmentProviderCredentialResolver("anthropic")

    assert await resolver.resolve(TENANT_ID, None) == "process-provider-key"


@pytest.mark.asyncio
async def test_invocation_credential_precedes_the_environment() -> None:
    credential = EphemeralProviderCredential("openai", "invocation-provider-key")
    resolver = EnvironmentProviderCredentialResolver(
        "openai",
        {"OPENAI_API_KEY": "environment-provider-key"},
    )

    assert await resolver.resolve(TENANT_ID, credential) == "invocation-provider-key"
    assert credential.available() is False


@pytest.mark.asyncio
async def test_environment_resolver_returns_none_without_a_key() -> None:
    resolver = EnvironmentProviderCredentialResolver("openai", {})

    assert await resolver.resolve(TENANT_ID, None) is None


@pytest.mark.asyncio
async def test_provider_mismatch_does_not_consume_the_credential() -> None:
    credential = EphemeralProviderCredential("google", "google-provider-key")
    resolver = EnvironmentProviderCredentialResolver("openai", {})

    with pytest.raises(ValueError, match="does not match"):
        await resolver.resolve(TENANT_ID, credential)
    assert credential.available() is True
