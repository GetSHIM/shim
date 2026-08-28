"""Encrypted tenant-bound PII mappings for Responses continuations."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping

from cryptography.fernet import Fernet

from shim_enterprise.cache.redis_index import CacheService
from shim_enterprise.core.config import settings
from shim.gateway.contracts.ids import TenantId
from shim.privacy.continuation import PrivacyContinuationUnavailableError


class RedisPrivacyContinuationStore:
    def __init__(
        self,
        cache: CacheService,
        *,
        encryption_key: str | None = None,
        ttl_seconds: int | None = None,
    ) -> None:
        key = encryption_key or settings.ENCRYPTION_KEY
        if not key:
            raise PrivacyContinuationUnavailableError()
        self._cache = cache
        self._cipher = Fernet(key.encode())
        self._ttl_seconds = ttl_seconds or settings.PRIVACY_CHAIN_TTL_SECONDS

    async def ensure_available(self) -> None:
        client = self._cache.redis
        if client is None:
            raise PrivacyContinuationUnavailableError()
        try:
            await client.ping()
        except Exception as exc:
            raise PrivacyContinuationUnavailableError() from exc

    async def load(
        self,
        tenant_id: TenantId,
        response_id: str,
    ) -> dict[str, str] | None:
        client = self._cache.redis
        if client is None:
            raise PrivacyContinuationUnavailableError()
        try:
            encrypted = await client.get(self._key(tenant_id, response_id))
            if encrypted is None:
                return None
            raw = self._cipher.decrypt(encrypted.encode()).decode()
            payload = json.loads(raw)
            if payload.get("tenant_id") != str(tenant_id):
                raise PrivacyContinuationUnavailableError()
            mapping = payload.get("mapping")
            if not isinstance(mapping, dict) or not all(
                isinstance(key, str) and isinstance(value, str)
                for key, value in mapping.items()
            ):
                raise PrivacyContinuationUnavailableError()
            return mapping
        except PrivacyContinuationUnavailableError:
            raise
        except Exception as exc:
            raise PrivacyContinuationUnavailableError() from exc

    async def save(
        self,
        tenant_id: TenantId,
        response_id: str,
        mapping: Mapping[str, str],
    ) -> None:
        if not mapping:
            return
        client = self._cache.redis
        if client is None:
            raise PrivacyContinuationUnavailableError()
        payload = json.dumps(
            {"tenant_id": str(tenant_id), "mapping": dict(mapping)},
            sort_keys=True,
            separators=(",", ":"),
        )
        encrypted = self._cipher.encrypt(payload.encode()).decode()
        try:
            await client.set(
                self._key(tenant_id, response_id),
                encrypted,
                ex=self._ttl_seconds,
            )
        except Exception as exc:
            raise PrivacyContinuationUnavailableError() from exc

    @staticmethod
    def _key(tenant_id: TenantId, response_id: str) -> str:
        digest = hmac.new(
            settings.SECRET_KEY.encode(),
            f"{tenant_id}:{response_id}".encode(),
            hashlib.sha256,
        ).hexdigest()
        return f"privacy:response-chain:{digest}"
