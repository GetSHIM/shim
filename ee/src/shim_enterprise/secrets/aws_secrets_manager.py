"""Version-pinned AWS Secrets Manager implementation."""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import os
import re
from typing import Any, cast
from uuid import uuid4

from shim.gateway.contracts.ids import SecretRef, TenantId
from shim_enterprise.secrets.store import (
    AWS_V1_PREFIX,
    decode_envelope,
    encode_envelope,
    parse_secret_ref,
    validate_write,
)


class AWSSecretsManagerStore:
    backend = "aws"

    def __init__(self, *, client: Any | None = None, region_name: str | None = None):
        self._client = client
        self._region_name = region_name or os.getenv("AWS_REGION")

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                boto3 = importlib.import_module("boto3")
            except ImportError as exc:
                raise RuntimeError("The AWS secret backend requires boto3") from exc
            self._client = boto3.client(
                "secretsmanager",
                **({"region_name": self._region_name} if self._region_name else {}),
            )
        return self._client

    async def _call(self, method_name: str, **kwargs: Any) -> Any:
        method = getattr(self._get_client(), method_name)
        return await asyncio.to_thread(method, **kwargs)

    async def _read(
        self,
        tenant_id: TenantId,
        secret_ref: SecretRef,
        expected_purpose: str | None,
    ) -> tuple[dict[str, Any], str]:
        parsed = parse_secret_ref(secret_ref)
        if parsed.backend != self.backend:
            raise ValueError("Secret reference uses a different backend")
        response = await self._call(
            "get_secret_value",
            SecretId=parsed.locator,
            VersionId=parsed.version,
        )
        serialized = response.get("SecretString")
        if not isinstance(serialized, str):
            raise ValueError("AWS secret payload must be a string")
        return decode_envelope(serialized, tenant_id, expected_purpose), parsed.locator

    async def put_secret(
        self,
        tenant_id: TenantId,
        purpose: str,
        plaintext: str,
        metadata: dict[str, Any] | None = None,
    ) -> SecretRef:
        validate_write(tenant_id, purpose, plaintext)
        purpose_slug = re.sub(r"[^a-z0-9/_+=.@-]", "-", purpose.lower())[:40]
        tenant_hash = hashlib.sha256(str(tenant_id).encode()).hexdigest()[:12]
        name = f"shim/{tenant_hash}/{purpose_slug or 'secret'}/{uuid4().hex}"
        response = await self._call(
            "create_secret",
            Name=name,
            SecretString=encode_envelope(tenant_id, purpose, plaintext, metadata),
        )
        secret_id = str(response.get("ARN") or name)
        version_id = str(response["VersionId"])
        return SecretRef(f"{AWS_V1_PREFIX}{secret_id}@{version_id}")

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
        _, secret_id = await self._read(tenant_id, secret_ref, expected_purpose)
        await self._call(
            "delete_secret",
            SecretId=secret_id,
            ForceDeleteWithoutRecovery=True,
        )
