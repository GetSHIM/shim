"""Azure OpenAI credentials: an Azure key, or a Microsoft Entra ID client-credential token.

Tokens come from Entra's client-credentials grant over the gateway's shared HTTP client,
so no `azure-identity` dependency is needed.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from collections.abc import Callable, Hashable
import logging
import re
import time
from uuid import UUID

import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from shim.gateway.contracts.ids import TenantId
from shim.gateway.pipeline.provider_execution import ProviderCallError
from shim.secrets.credentials import EphemeralProviderCredential

logger = logging.getLogger(__name__)

DEFAULT_SCOPE = "https://cognitiveservices.azure.com/.default"
# A token is renewed once fewer seconds than this remain.
REFRESH_MARGIN_SECONDS = 300
_ENTRA_ERROR = re.compile(r"[a-z_]{1,64}")


class EntraClientCredential(BaseModel):
    """An Entra app registration's client secret, for the client-credentials grant."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tenant: str = Field(pattern=r"^[A-Za-z0-9.-]{1,128}$")
    client_id: UUID
    client_secret: SecretStr = Field(min_length=1, max_length=1_024)
    scope: str = Field(
        default=DEFAULT_SCOPE, max_length=256, pattern=r"^https://\S+/\.default$"
    )


class EntraTokenCache:
    """Tokens by key, renewed 300 seconds before expiry, one request per key at a time."""

    def __init__(
        self,
        http_client: httpx.AsyncClient,
        *,
        authority_host: str,
        provider: str = "openai",
        max_entries: int = 1_024,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.http_client = http_client
        self.authority_host = authority_host.rstrip("/")
        self.provider = provider
        self.max_entries = max_entries
        self.clock = clock
        self.tokens: OrderedDict[Hashable, tuple[str, float]] = OrderedDict()
        self.locks: dict[Hashable, asyncio.Lock] = {}

    def _cached(self, key: Hashable) -> str | None:
        found = self.tokens.get(key)
        if found is None or found[1] - self.clock() <= REFRESH_MARGIN_SECONDS:
            return None
        self.tokens.move_to_end(key)
        return found[0]

    async def token(self, key: Hashable, credential: EntraClientCredential) -> str:
        if (token := self._cached(key)) is not None:
            return token
        try:
            async with self.locks.setdefault(key, asyncio.Lock()):
                if (token := self._cached(key)) is not None:
                    return token
                token, expires_in = await self._request(credential)
                self.tokens[key] = (token, self.clock() + expires_in)
                self.tokens.move_to_end(key)
                while len(self.tokens) > self.max_entries:
                    self.tokens.popitem(last=False)
                return token
        finally:
            self.locks.pop(key, None)

    async def _request(self, credential: EntraClientCredential) -> tuple[str, int]:
        unavailable = ProviderCallError(
            503, "PROVIDER_UNAVAILABLE", True, provider=self.provider
        )
        try:
            response = await self.http_client.post(
                f"{self.authority_host}/{credential.tenant}/oauth2/v2.0/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": str(credential.client_id),
                    "client_secret": credential.client_secret.get_secret_value(),
                    "scope": credential.scope,
                },
                timeout=10,
            )
        except (httpx.TransportError, TimeoutError) as error:
            logger.warning("Entra token request failed type=%s", type(error).__name__)
            raise unavailable from None
        try:
            body = response.json()
        except ValueError:
            body = None
        error = body.get("error") if isinstance(body, dict) else None
        if response.status_code != 200:
            # Never the secret, the token or Entra's error_description.
            logger.warning(
                "Entra token request failed status=%s error=%s",
                response.status_code,
                error
                if isinstance(error, str) and _ENTRA_ERROR.fullmatch(error)
                else None,
            )
            if response.status_code in {400, 401}:
                raise ProviderCallError(
                    401,
                    "INVALID_PROVIDER_CREDENTIAL",
                    False,
                    provider=self.provider,
                    message="Microsoft Entra ID refused the configured client credential.",
                )
            raise unavailable
        token = body.get("access_token") if isinstance(body, dict) else None
        token_type = body.get("token_type") if isinstance(body, dict) else None
        expires_in = body.get("expires_in") if isinstance(body, dict) else None
        if (
            not isinstance(token, str)
            or not isinstance(token_type, str)
            or token_type.casefold() != "bearer"
            or not isinstance(expires_in, int)
            or isinstance(expires_in, bool)
            or not 60 <= expires_in <= 86_400
        ):
            logger.warning("Entra token response was malformed")
            raise unavailable
        return token, expires_in


class AzureCredentialResolver:
    """An invocation's own key first, then the configured Azure key, else an Entra token."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        entra: tuple[EntraTokenCache, EntraClientCredential] | None = None,
    ) -> None:
        self.api_key = api_key
        self.entra = entra

    async def resolve(
        self,
        tenant_id: TenantId,
        credential: EphemeralProviderCredential | None,
        *,
        reference: str | None = None,
    ) -> str | None:
        del tenant_id
        if reference is not None:
            raise ValueError("local credentials do not support managed references")
        if credential is not None and credential.provider != "openai":
            raise ValueError("credential does not match the selected provider")
        if credential is not None and (injected := credential.consume()):
            return injected
        if self.api_key:
            return self.api_key
        if self.entra is not None:
            cache, client = self.entra
            return await cache.token("community", client)
        return None
