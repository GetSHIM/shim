"""Optional authentication for the single-user community gateway."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from hashlib import sha256
import secrets
from uuid import NAMESPACE_URL, uuid5

from pydantic import SecretStr

from shim.gateway.auth import authentication_error, select_gateway_credential
from shim.gateway.contracts.ids import ApiKeyId, TenantId
from shim.gateway.contracts.principal import AuthenticatedPrincipal


LOCAL_TENANT_ID = TenantId(uuid5(NAMESPACE_URL, "shim/community/local-tenant"))
LOCAL_API_KEY_ID = ApiKeyId(uuid5(NAMESPACE_URL, "shim/community/local-api-key"))


class LocalAuthenticator:
    """Authenticate one optional local key without retaining its plaintext."""

    __slots__ = ("_expected_digest",)

    def __init__(self, configured_key: SecretStr | None) -> None:
        self._expected_digest = (
            sha256(configured_key.get_secret_value().encode()).digest()
            if configured_key is not None
            else None
        )

    def authenticate(
        self,
        headers: Mapping[str, str],
        *,
        accept_anthropic_key: bool = False,
    ) -> AuthenticatedPrincipal:
        return self._resolve(
            select_gateway_credential(
                headers,
                accept_anthropic_key=accept_anthropic_key,
            )
        )

    async def resolve(self, candidate: str | None) -> AuthenticatedPrincipal:
        return self._resolve(candidate)

    def _resolve(self, candidate: str | None) -> AuthenticatedPrincipal:
        if self._expected_digest is not None:
            if candidate is None:
                raise authentication_error("Missing API Key")
            if not secrets.compare_digest(
                self._expected_digest,
                sha256(candidate.encode()).digest(),
            ):
                raise authentication_error("Invalid API Key")
        return AuthenticatedPrincipal(
            actor_type="api_key",
            api_key_id=LOCAL_API_KEY_ID,
            authenticated_at=datetime.now(timezone.utc),
        )
