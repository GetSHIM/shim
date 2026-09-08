"""Vault KV v2 with tenant-bound envelopes and immutable version references."""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx

from shim.gateway.contracts.ids import SecretRef, TenantId
from shim_enterprise.core.config import settings
from shim_enterprise.secrets.store import (
    VAULT_V1_PREFIX,
    decode_envelope,
    encode_envelope,
    parse_secret_ref,
    validate_write,
)


class VaultSecretStore:
    backend = "vault"

    def __init__(self, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._transport = transport

    async def _call(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        if not settings.VAULT_ADDR or not settings.VAULT_TOKEN_FILE:
            raise ValueError("Vault address and token file are required")
        # Vault Agent renews/replaces the token atomically; never cache its contents.
        token = (
            await asyncio.to_thread(Path(settings.VAULT_TOKEN_FILE).read_text)
        ).strip()
        if not token or "\n" in token or "\r" in token:
            raise ValueError("Invalid Vault token file")
        headers = {"X-Vault-Token": token}
        if settings.VAULT_NAMESPACE:
            headers["X-Vault-Namespace"] = settings.VAULT_NAMESPACE
        async with httpx.AsyncClient(
            base_url=settings.VAULT_ADDR.rstrip("/") + "/v1/",
            timeout=10,
            follow_redirects=False,
            transport=self._transport,
        ) as client:
            response = await client.request(method, path, headers=headers, **kwargs)
        response.raise_for_status()
        return response.json() if response.content else {}

    @staticmethod
    def _path(tenant_id: TenantId) -> str:
        tenant_hash = hashlib.sha256(str(tenant_id).encode()).hexdigest()
        return f"{settings.VAULT_KV_MOUNT}/shim/{tenant_hash}/"

    async def _read(
        self, tenant_id: TenantId, secret_ref: SecretRef, purpose: str | None
    ) -> tuple[dict[str, Any], str, str]:
        parsed = parse_secret_ref(secret_ref)
        if parsed.backend != self.backend or not parsed.locator.startswith(
            self._path(tenant_id)
        ):
            raise ValueError("Vault reference does not belong to this tenant/backend")
        mount, path = parsed.locator.split("/", 1)
        result = await self._call(
            "GET", f"{mount}/data/{path}", params={"version": parsed.version}
        )
        envelope = decode_envelope(
            result["data"]["data"]["envelope"], tenant_id, purpose
        )
        return envelope, f"{mount}/destroy/{path}", parsed.version

    async def put_secret(
        self,
        tenant_id: TenantId,
        purpose: str,
        plaintext: str,
        metadata: dict[str, Any] | None = None,
    ) -> SecretRef:
        validate_write(tenant_id, purpose, plaintext)
        locator = self._path(tenant_id) + uuid4().hex
        mount, path = locator.split("/", 1)
        result = await self._call(
            "POST",
            f"{mount}/data/{path}",
            json={
                "options": {"cas": 0},
                "data": {
                    "envelope": encode_envelope(tenant_id, purpose, plaintext, metadata)
                },
            },
        )
        reference = SecretRef(f"{VAULT_V1_PREFIX}{locator}@{result['data']['version']}")
        parse_secret_ref(reference)
        return reference

    async def get_secret(
        self,
        tenant_id: TenantId,
        secret_ref: SecretRef,
        *,
        expected_purpose: str | None = None,
    ) -> str:
        envelope, _, _ = await self._read(tenant_id, secret_ref, expected_purpose)
        return envelope["plaintext"]

    async def rotate_secret(
        self,
        tenant_id: TenantId,
        secret_ref: SecretRef,
        new_plaintext: str,
        *,
        expected_purpose: str | None = None,
    ) -> SecretRef:
        envelope, _, _ = await self._read(tenant_id, secret_ref, expected_purpose)
        # A new path preserves the old reference until the DB/outbox commits rotation.
        return await self.put_secret(
            tenant_id, envelope["purpose"], new_plaintext, envelope["metadata"]
        )

    async def delete_secret(
        self,
        tenant_id: TenantId,
        secret_ref: SecretRef,
        *,
        expected_purpose: str | None = None,
    ) -> None:
        _, path, version = await self._read(tenant_id, secret_ref, expected_purpose)
        await self._call("PUT", path, json={"versions": [int(version)]})
