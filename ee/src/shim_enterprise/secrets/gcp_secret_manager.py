"""Version-pinned Google Cloud Secret Manager implementation."""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import logging
import os
import re
from typing import Any, cast
from uuid import uuid4

from shim.gateway.contracts.ids import SecretRef, TenantId
from shim_enterprise.secrets.store import (
    GCP_V1_PREFIX,
    ParsedSecretRef,
    decode_envelope,
    encode_envelope,
    parse_secret_ref,
    validate_write,
)

logger = logging.getLogger(__name__)


class GCPSecretManagerStore:
    backend = "gcp"

    def __init__(
        self, project_id: str | None = None, client: Any | None = None
    ) -> None:
        self._project_id = (
            project_id
            or os.getenv("GOOGLE_CLOUD_PROJECT")
            or os.getenv("GCP_PROJECT_ID")
        )
        self._client = client
        if not self._project_id:
            raise ValueError(
                "GOOGLE_CLOUD_PROJECT or GCP_PROJECT_ID is required for the GCP secret backend"
            )

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                module = importlib.import_module("google.cloud.secretmanager")
            except ImportError as exc:
                raise RuntimeError(
                    "The GCP secret backend requires google-cloud-secret-manager"
                ) from exc
            self._client = module.SecretManagerServiceClient()
        return self._client

    def _resource_name(self, parsed: ParsedSecretRef) -> str:
        if parsed.backend != "gcp":
            raise ValueError("Not a GCP Secret Manager reference")
        project, resource = parsed.locator.removeprefix("projects/").split("/", 1)
        # Secret Manager canonicalizes project IDs to numeric project numbers.
        if project != self._project_id and not project.isdecimal():
            raise ValueError("Not a GCP Secret Manager reference")
        return f"projects/{self._project_id}/{resource}"

    @staticmethod
    def _version_ref(version_name: str, secret_name: str) -> SecretRef:
        if not version_name.startswith(f"{secret_name}/versions/"):
            raise ValueError("GCP returned a version outside the created secret")
        secret_ref = SecretRef(f"{GCP_V1_PREFIX}{version_name}")
        parse_secret_ref(secret_ref)
        return secret_ref

    @staticmethod
    def _secret_name(resource_name: str) -> str:
        if "/versions/" not in resource_name:
            raise ValueError("GCP secret reference must identify a version")
        return resource_name.split("/versions/", 1)[0]

    async def _call(self, method_name: str, request: dict[str, Any]) -> Any:
        method = getattr(self._get_client(), method_name)
        return await asyncio.to_thread(method, request=request)

    async def _read_envelope(
        self,
        tenant_id: TenantId,
        secret_ref: SecretRef,
        expected_purpose: str | None = None,
    ) -> tuple[dict[str, Any], str]:
        resource_name = self._resource_name(parse_secret_ref(secret_ref))
        response = await self._call("access_secret_version", {"name": resource_name})
        data = response.payload.data
        serialized = data.decode("utf-8") if isinstance(data, bytes) else str(data)
        return decode_envelope(serialized, tenant_id, expected_purpose), resource_name

    async def put_secret(
        self,
        tenant_id: TenantId,
        purpose: str,
        plaintext: str,
        metadata: dict[str, Any] | None = None,
    ) -> SecretRef:
        validate_write(tenant_id, purpose, plaintext)
        purpose_slug = re.sub(r"[^a-z0-9_-]", "-", purpose.lower()).strip("-")
        tenant_hash = hashlib.sha256(str(tenant_id).encode()).hexdigest()[:12]
        secret_id = (
            f"shim-tenant-{purpose_slug[:40] or 'secret'}-{tenant_hash}-{uuid4().hex}"
        )
        parent = f"projects/{self._project_id}"
        created = await self._call(
            "create_secret",
            {
                "parent": parent,
                "secret_id": secret_id,
                "secret": {"replication": {"automatic": {}}},
            },
        )
        secret_name = getattr(created, "name", f"{parent}/secrets/{secret_id}")
        payload = encode_envelope(tenant_id, purpose, plaintext, metadata).encode()
        try:
            version = await self._call(
                "add_secret_version",
                {"parent": secret_name, "payload": {"data": payload}},
            )
        except Exception:
            try:
                await self._call("delete_secret", {"name": secret_name})
            except Exception:
                logger.warning("GCP secret cleanup failed after version creation error")
            raise
        return self._version_ref(version.name, secret_name)

    async def get_secret(
        self,
        tenant_id: TenantId,
        secret_ref: SecretRef,
        *,
        expected_purpose: str | None = None,
    ) -> str:
        envelope, _ = await self._read_envelope(tenant_id, secret_ref, expected_purpose)
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
        envelope, _ = await self._read_envelope(tenant_id, secret_ref, expected_purpose)
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
        _, resource_name = await self._read_envelope(
            tenant_id, secret_ref, expected_purpose
        )
        await self._call("delete_secret", {"name": self._secret_name(resource_name)})
