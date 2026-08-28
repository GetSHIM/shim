"""Tenant-aware secret-store port and versioned reference grammar."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Protocol

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from shim_enterprise.core.config import settings
from shim_enterprise.core.errors import ConfigurationError
from shim.gateway.contracts.ids import SecretRef, TenantId
from shim.secrets.credentials import EphemeralProviderCredential

FERNET_V2_PREFIX = "fernet:v2:"
GCP_V1_PREFIX = "gcpsm:v1:"
AWS_V1_PREFIX = "awssm:v1:"
AZURE_V1_PREFIX = "azurekv:v1:"


@dataclass(frozen=True, slots=True)
class ParsedSecretRef:
    backend: str
    version: str
    locator: str
    format_version: str


def parse_secret_ref(secret_ref: SecretRef | str) -> ParsedSecretRef:
    """Parse only canonical, version-pinned secret references."""

    value = str(secret_ref)
    if value.startswith(FERNET_V2_PREFIX):
        locator = value[len(FERNET_V2_PREFIX) :]
        if not locator:
            raise ValueError("Fernet secret reference has no encrypted payload")
        return ParsedSecretRef("fernet", "v2", locator, "v2")
    if value.startswith(GCP_V1_PREFIX):
        locator = value[len(GCP_V1_PREFIX) :]
        match = re.fullmatch(
            r"projects/[^/]+/secrets/[^/]+/versions/([1-9][0-9]*)",
            locator,
        )
        if match is None:
            raise ValueError("GCP secret reference must pin a numeric version")
        return ParsedSecretRef("gcp", match.group(1), locator, "v1")
    if value.startswith(AWS_V1_PREFIX):
        locator = value[len(AWS_V1_PREFIX) :]
        secret_id, separator, version_id = locator.rpartition("@")
        if not separator or not secret_id or not version_id:
            raise ValueError("AWS secret reference must pin a version id")
        return ParsedSecretRef("aws", version_id, secret_id, "v1")
    if value.startswith(AZURE_V1_PREFIX):
        locator = value[len(AZURE_V1_PREFIX) :]
        if not re.fullmatch(r"https://[^/]+/secrets/[^/]+/[A-Za-z0-9-]+", locator):
            raise ValueError("Azure secret reference must pin a version")
        return ParsedSecretRef("azure", locator.rsplit("/", 1)[-1], locator, "v1")
    raise ValueError("Unsupported secret reference")


class SecretStore(Protocol):
    backend: str

    async def put_secret(
        self,
        tenant_id: TenantId,
        purpose: str,
        plaintext: str,
        metadata: dict[str, Any] | None = None,
    ) -> SecretRef: ...

    async def get_secret(
        self,
        tenant_id: TenantId,
        secret_ref: SecretRef,
        *,
        expected_purpose: str | None = None,
    ) -> str: ...

    async def rotate_secret(
        self,
        tenant_id: TenantId,
        secret_ref: SecretRef,
        new_plaintext: str,
        *,
        expected_purpose: str | None = None,
    ) -> SecretRef: ...

    async def delete_secret(
        self,
        tenant_id: TenantId,
        secret_ref: SecretRef,
        *,
        expected_purpose: str | None = None,
    ) -> None: ...


def validate_write(tenant_id: TenantId, purpose: str, plaintext: str) -> None:
    if not str(tenant_id):
        raise ValueError("tenant_id is required")
    if not purpose.strip():
        raise ValueError("purpose is required")
    if not plaintext:
        raise ValueError("Cannot store an empty secret")


def encode_envelope(
    tenant_id: TenantId,
    purpose: str,
    plaintext: str,
    metadata: dict[str, Any] | None,
) -> str:
    return json.dumps(
        {
            "metadata": metadata or {},
            "plaintext": plaintext,
            "purpose": purpose,
            "tenant_id": str(tenant_id),
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def decode_envelope(
    serialized: str,
    tenant_id: TenantId,
    expected_purpose: str | None = None,
) -> dict[str, Any]:
    try:
        envelope = json.loads(serialized)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid secret payload") from exc
    if not isinstance(envelope, dict) or envelope.get("tenant_id") != str(tenant_id):
        raise ValueError("Secret reference does not belong to this tenant")
    if not isinstance(envelope.get("purpose"), str) or not isinstance(
        envelope.get("plaintext"), str
    ):
        raise ValueError("Invalid secret payload")
    if expected_purpose is not None and envelope["purpose"] != expected_purpose:
        raise ValueError("Secret reference has the wrong purpose")
    if not isinstance(envelope.get("metadata", {}), dict):
        raise ValueError("Invalid secret metadata")
    return envelope


_store_singleton: SecretStore | None = None


def get_secret_store() -> SecretStore:
    """Construct the configured canonical backend exactly once."""

    global _store_singleton
    if _store_singleton is None:
        if settings.SECRET_BACKEND == "fernet":
            from shim_enterprise.secrets.fernet_store import FernetSecretStore

            _store_singleton = FernetSecretStore()
        elif settings.SECRET_BACKEND == "gcp_secret_manager":
            from shim_enterprise.secrets.gcp_secret_manager import GCPSecretManagerStore

            _store_singleton = GCPSecretManagerStore()
        elif settings.SECRET_BACKEND == "aws_secrets_manager":
            from shim_enterprise.secrets.aws_secrets_manager import (
                AWSSecretsManagerStore,
            )

            _store_singleton = AWSSecretsManagerStore()
        elif settings.SECRET_BACKEND == "azure_key_vault":
            from shim_enterprise.secrets.azure_key_vault import AzureKeyVaultStore

            _store_singleton = AzureKeyVaultStore()
        else:
            raise ConfigurationError(
                f"Unknown SECRET_BACKEND: {settings.SECRET_BACKEND!r}"
            )
    return _store_singleton


class ManagedProviderCredentialResolver:
    """Resolve one invocation credential or a tenant-managed secret."""

    def __init__(
        self,
        provider: str,
        store: SecretStore,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        if provider not in {"openai", "anthropic", "google"}:
            raise ValueError("unsupported provider credential")
        self.provider = provider
        self.store = store
        self.session_factory = session_factory

    async def resolve(
        self,
        tenant_id: TenantId,
        credential: EphemeralProviderCredential | None,
    ) -> str | None:
        if credential is not None and credential.provider != self.provider:
            raise ValueError("credential does not match the selected provider")
        injected = credential.consume() if credential is not None else None
        if injected:
            return injected

        from shim_enterprise.tenants.models import ProviderSecret

        async with self.session_factory() as session:
            row = (
                (
                    await session.execute(
                        select(ProviderSecret)
                        .where(
                            ProviderSecret.organization_id == tenant_id,
                            ProviderSecret.provider == self.provider,
                        )
                        .order_by(
                            desc(ProviderSecret.created_at), desc(ProviderSecret.id)
                        )
                        .limit(1)
                    )
                )
                .scalars()
                .first()
            )
            secret_ref = SecretRef(row.secret_ref) if row is not None else None
        if secret_ref is None:
            return None
        return await self.store.get_secret(
            tenant_id,
            secret_ref,
            expected_purpose=f"provider:{self.provider}:api-key",
        )
