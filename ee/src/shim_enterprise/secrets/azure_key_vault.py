"""Version-pinned Azure Key Vault implementation."""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import os
import re
from typing import Any, cast
from urllib.parse import urlparse
from uuid import uuid4

from shim.gateway.contracts.ids import SecretRef, TenantId
from shim_enterprise.secrets.store import (
    AZURE_V1_PREFIX,
    decode_envelope,
    encode_envelope,
    parse_secret_ref,
    validate_write,
)


class AzureKeyVaultStore:
    backend = "azure"

    def __init__(self, *, vault_url: str | None = None, client: Any | None = None):
        self._vault_url = (vault_url or os.getenv("AZURE_KEY_VAULT_URL") or "").rstrip(
            "/"
        )
        self._client = client
        if not self._vault_url:
            raise ValueError("AZURE_KEY_VAULT_URL is required for the Azure backend")

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                identity = importlib.import_module("azure.identity")
                secrets = importlib.import_module("azure.keyvault.secrets")
            except ImportError as exc:
                raise RuntimeError(
                    "The Azure secret backend requires azure-identity and azure-keyvault-secrets"
                ) from exc
            self._client = secrets.SecretClient(
                vault_url=self._vault_url,
                credential=identity.DefaultAzureCredential(),
            )
        return self._client

    @staticmethod
    def _name_version(locator: str) -> tuple[str, str]:
        path = urlparse(locator).path.strip("/").split("/")
        if len(path) != 3 or path[0] != "secrets":
            raise ValueError("Invalid Azure Key Vault secret reference")
        return path[1], path[2]

    async def _read(
        self,
        tenant_id: TenantId,
        secret_ref: SecretRef,
        expected_purpose: str | None,
    ) -> tuple[dict[str, Any], str]:
        parsed = parse_secret_ref(secret_ref)
        if parsed.backend != self.backend or not parsed.locator.startswith(
            f"{self._vault_url}/secrets/"
        ):
            raise ValueError("Not an Azure Key Vault reference for this vault")
        name, version = self._name_version(parsed.locator)
        response = await asyncio.to_thread(
            self._get_client().get_secret,
            name,
            version,
        )
        return decode_envelope(response.value, tenant_id, expected_purpose), name

    async def put_secret(
        self,
        tenant_id: TenantId,
        purpose: str,
        plaintext: str,
        metadata: dict[str, Any] | None = None,
    ) -> SecretRef:
        validate_write(tenant_id, purpose, plaintext)
        purpose_slug = re.sub(r"[^a-z0-9-]", "-", purpose.lower())[:35]
        tenant_hash = hashlib.sha256(str(tenant_id).encode()).hexdigest()[:10]
        name = f"shim-{tenant_hash}-{purpose_slug or 'secret'}-{uuid4().hex}"
        response = await asyncio.to_thread(
            self._get_client().set_secret,
            name,
            encode_envelope(tenant_id, purpose, plaintext, metadata),
        )
        locator = str(response.id)
        secret_ref = SecretRef(f"{AZURE_V1_PREFIX}{locator}")
        parse_secret_ref(secret_ref)
        return secret_ref

    async def get_secret(
        self,
        tenant_id: TenantId,
        secret_ref: SecretRef,
        *,
        expected_purpose: str | None = None,
    ) -> str:
        envelope, _ = await self._read(tenant_id, secret_ref, expected_purpose)
        return cast(str, envelope["plaintext"])

    async def rotate_secret(
        self,
        tenant_id: TenantId,
        secret_ref: SecretRef,
        new_plaintext: str,
        *,
        expected_purpose: str | None = None,
    ) -> SecretRef:
        if not new_plaintext:
            raise ValueError("Cannot store an empty secret")
        envelope, _ = await self._read(tenant_id, secret_ref, expected_purpose)
        return await self.put_secret(
            tenant_id,
            cast(str, envelope["purpose"]),
            new_plaintext,
            cast(dict[str, Any], envelope["metadata"]),
        )

    async def delete_secret(
        self,
        tenant_id: TenantId,
        secret_ref: SecretRef,
        *,
        expected_purpose: str | None = None,
    ) -> None:
        _, name = await self._read(tenant_id, secret_ref, expected_purpose)
        poller = await asyncio.to_thread(self._get_client().begin_delete_secret, name)
        await asyncio.to_thread(poller.wait)
