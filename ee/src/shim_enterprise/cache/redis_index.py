"""Shared Redis connection and bounded configuration-cache operations."""

from __future__ import annotations

import json
import logging
from typing import Any

import redis.asyncio as redis

from shim_enterprise.core.config import settings


logger = logging.getLogger(__name__)


class CacheService:
    def __init__(self) -> None:
        self.redis: Any | None = None

    async def connect(self) -> None:
        if self.redis is not None:
            return
        client = redis.from_url(
            str(settings.REDIS_URL),
            encoding="utf-8",
            decode_responses=True,
        )
        try:
            await client.ping()
        except BaseException:
            await client.aclose()
            raise
        self.redis = client

    async def close(self) -> None:
        client, self.redis = self.redis, None
        if client is not None:
            await client.aclose()

    async def get(self, key: str) -> Any | None:
        if self.redis is None:
            return None
        try:
            value = await self.redis.get(key)
        except Exception as exc:
            logger.warning("Redis cache read failed type=%s", type(exc).__name__)
            return None
        if value is None:
            return None
        if not isinstance(value, str):
            return value
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value

    async def set(self, key: str, value: Any, expire: int = 3600) -> None:
        if self.redis is None:
            return
        encoded = value if isinstance(value, (str, bytes)) else json.dumps(value)
        try:
            await self.redis.set(key, encoded, ex=expire)
        except Exception as exc:
            logger.warning("Redis cache write failed type=%s", type(exc).__name__)

    async def delete(self, key: str) -> bool:
        if self.redis is None:
            return False
        try:
            return bool(await self.redis.delete(key))
        except Exception as exc:
            logger.warning("Redis cache delete failed type=%s", type(exc).__name__)
            return False


class CacheManager:
    """Namespaced, short-lived cache for tenant configuration read models."""

    def __init__(self, cache: CacheService) -> None:
        self.cache = cache

    async def get_pii_config(self, tenant_id: str) -> dict[str, Any] | None:
        return _mapping(await self.cache.get(f"config:pii:{tenant_id}"))

    async def set_pii_config(self, tenant_id: str, config: dict[str, Any]) -> None:
        await self.cache.set(f"config:pii:{tenant_id}", config, expire=300)

    async def invalidate_pii_config(self, tenant_id: str) -> None:
        await self.cache.delete(f"config:pii:{tenant_id}")

    async def get_tier_definition(self, slug: str) -> dict[str, Any] | None:
        return _mapping(await self.cache.get(f"config:tier:{slug}"))

    async def set_tier_definition(self, slug: str, value: dict[str, Any]) -> None:
        await self.cache.set(f"config:tier:{slug}", value, expire=3600)


def _mapping(value: Any) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None
