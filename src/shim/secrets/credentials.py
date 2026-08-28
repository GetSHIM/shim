"""Invocation-scoped provider credentials and local resolution."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Never, Protocol

from shim.gateway.contracts.ids import TenantId


_PROVIDER_CREDENTIAL_HEADERS = {
    "openai": "x-openai-api-key",
    "anthropic": "x-api-key",
    "google": "x-goog-api-key",
}
_PROVIDER_ENVIRONMENT_VARIABLES = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "google": "GOOGLE_API_KEY",
}
_CREDENTIAL_HEADERS = frozenset(
    {
        *_PROVIDER_CREDENTIAL_HEADERS.values(),
        "authorization",
        "x-provider-key",
        "x-shim-key",
    }
)


class EphemeralProviderCredential:
    """One-use secret with idempotent defensive cleanup."""

    __slots__ = ("provider", "_key")

    def __init__(self, provider: str, key: str) -> None:
        if provider not in _PROVIDER_CREDENTIAL_HEADERS:
            raise ValueError("unsupported provider credential")
        if not key:
            raise ValueError("provider credential is required")
        self.provider = provider
        self._key: str | None = key

    def consume(self) -> str | None:
        value = self._key
        self.clear()
        return value

    def available(self) -> bool:
        return self._key is not None

    def clear(self) -> None:
        self._key = None

    def __repr__(self) -> str:
        return f"EphemeralProviderCredential(provider={self.provider!r}, <redacted>)"

    def __reduce__(self) -> Never:
        raise TypeError("provider credential envelopes cannot be serialized")


class ProviderCredentialResolver(Protocol):
    async def resolve(
        self,
        tenant_id: TenantId,
        credential: EphemeralProviderCredential | None,
    ) -> str | None: ...


class EnvironmentProviderCredentialResolver:
    """Resolve an invocation credential before the provider environment key."""

    __slots__ = ("provider", "_environment")

    def __init__(
        self,
        provider: str,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        if provider not in _PROVIDER_ENVIRONMENT_VARIABLES:
            raise ValueError("unsupported provider credential")
        self.provider = provider
        self._environment = os.environ if environment is None else environment

    async def resolve(
        self,
        tenant_id: TenantId,
        credential: EphemeralProviderCredential | None,
    ) -> str | None:
        del tenant_id
        if credential is not None and credential.provider != self.provider:
            raise ValueError("credential does not match the selected provider")
        injected = credential.consume() if credential is not None else None
        if injected:
            return injected
        return (
            self._environment.get(_PROVIDER_ENVIRONMENT_VARIABLES[self.provider])
            or None
        )


def extract_provider_credential(
    headers: Mapping[str, str],
    provider: str,
) -> tuple[dict[str, str], EphemeralProviderCredential | None]:
    try:
        provider_header = _PROVIDER_CREDENTIAL_HEADERS[provider]
    except KeyError:
        raise ValueError("unsupported provider credential") from None
    folded_headers = {key.casefold(): value for key, value in headers.items()}
    if "x-provider-key" in folded_headers:
        credential = folded_headers["x-provider-key"]
    elif provider != "anthropic" and provider_header in folded_headers:
        credential = folded_headers[provider_header]
    else:
        credential = None
    sanitized = {
        key: value
        for key, value in headers.items()
        if key.casefold() not in _CREDENTIAL_HEADERS
    }
    return (
        sanitized,
        (
            EphemeralProviderCredential(provider, credential)
            if credential is not None
            else None
        ),
    )
