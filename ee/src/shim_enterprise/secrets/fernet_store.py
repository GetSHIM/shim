"""Local encrypted implementation of the canonical SecretStore port."""

from __future__ import annotations

from typing import Any, cast

from cryptography.fernet import Fernet

from shim_enterprise.core.config import settings
from shim.gateway.contracts.ids import SecretRef, TenantId
from shim_enterprise.secrets.store import (
    FERNET_V2_PREFIX,
    decode_envelope,
    encode_envelope,
    parse_secret_ref,
    validate_write,
)


class FernetSecretStore:
    backend = "fernet"

    @staticmethod
    def _cipher() -> Fernet:
        if not settings.ENCRYPTION_KEY:
            raise RuntimeError("ENCRYPTION_KEY is required for the Fernet secret store")
        return Fernet(settings.ENCRYPTION_KEY.encode())

    def _decrypt(self, value: str) -> str:
        return self._cipher().decrypt(value.encode()).decode()

    async def put_secret(
        self,
        tenant_id: TenantId,
        purpose: str,
        plaintext: str,
        metadata: dict[str, Any] | None = None,
    ) -> SecretRef:
        validate_write(tenant_id, purpose, plaintext)
        payload = encode_envelope(tenant_id, purpose, plaintext, metadata)
        encrypted = self._cipher().encrypt(payload.encode()).decode()
        return SecretRef(FERNET_V2_PREFIX + encrypted)

    async def get_secret(
        self,
        tenant_id: TenantId,
        secret_ref: SecretRef,
        *,
        expected_purpose: str | None = None,
    ) -> str:
        parsed = parse_secret_ref(secret_ref)
        if parsed.backend != self.backend:
            raise ValueError("Secret reference uses a different backend")
        envelope = decode_envelope(
            self._decrypt(parsed.locator), tenant_id, expected_purpose
        )
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
        parsed = parse_secret_ref(secret_ref)
        if parsed.backend != self.backend:
            raise ValueError("Secret reference uses a different backend")
        envelope = decode_envelope(
            self._decrypt(parsed.locator), tenant_id, expected_purpose
        )
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
        parsed = parse_secret_ref(secret_ref)
        if parsed.backend != self.backend:
            raise ValueError("Secret reference uses a different backend")
        decode_envelope(self._decrypt(parsed.locator), tenant_id, expected_purpose)
