"""Bounded Redis pacing for compliance-provider worker traffic."""

from __future__ import annotations

import asyncio
import logging
import time

from redis.exceptions import RedisError

from shim_enterprise.cache.redis_index import CacheService


logger = logging.getLogger(__name__)
WINDOW_SECONDS = 60
ACQUIRE_LUA = """
local current = tonumber(redis.call('GET', KEYS[1]) or '0')
if current >= tonumber(ARGV[1]) then
    return {0, redis.call('TTL', KEYS[1])}
end
current = redis.call('INCR', KEYS[1])
if current == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[2])
end
return {1, redis.call('TTL', KEYS[1])}
"""


class ComplianceRateLimitTimeout(TimeoutError):
    """No provider request slot became available within one fixed window."""


class ComplianceRateLimiter:
    def __init__(
        self,
        limit_per_minute: int,
        connector_key: str,
        *,
        cache: CacheService,
    ) -> None:
        if limit_per_minute < 1 or not connector_key:
            raise ValueError("rate-limit inputs must be positive and non-empty")
        self.limit = limit_per_minute
        self.key = f"compliance:rate:{connector_key}"
        self.cache = cache

    async def acquire(self) -> None:
        redis = self.cache.redis
        if redis is None:
            return
        deadline = time.monotonic() + WINDOW_SECONDS
        while True:
            try:
                allowed, ttl = await redis.eval(
                    ACQUIRE_LUA,
                    1,
                    self.key,
                    self.limit,
                    WINDOW_SECONDS,
                )
            except (OSError, RedisError) as exc:
                logger.warning(
                    "Compliance rate limiter unavailable type=%s",
                    type(exc).__name__,
                )
                return
            if int(allowed) == 1:
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ComplianceRateLimitTimeout(
                    "compliance provider rate-limit wait expired"
                )
            await asyncio.sleep(min(max(float(ttl), 0.05), remaining))
