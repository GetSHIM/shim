"""Best-effort Redis burst windows used before durable quota admission."""

from __future__ import annotations

import logging

from shim_enterprise.cache.redis_index import CacheService


logger = logging.getLogger(__name__)

_INCREMENT_WINDOW = """
local value = redis.call('INCRBY', KEYS[1], ARGV[1])
local ttl = redis.call('TTL', KEYS[1])
if ttl < 0 then
    redis.call('EXPIRE', KEYS[1], ARGV[2])
end
return value
"""


class BurstRateLimiter:
    """Apply non-authoritative fixed windows without persisting billing truth."""

    def __init__(self, cache: CacheService) -> None:
        self.cache = cache

    async def allow(
        self,
        key: str,
        *,
        limit: int,
        window_seconds: int,
        amount: int = 1,
    ) -> bool:
        _validate_window(key, limit, window_seconds, amount)
        redis = self.cache.redis
        if redis is None:
            logger.warning(
                "Burst window unavailable; durable quota remains authoritative"
            )
            return True
        try:
            value = await redis.eval(
                _INCREMENT_WINDOW,
                1,
                f"burst:{key}",
                amount,
                window_seconds,
            )
        except Exception as exc:
            logger.error("Burst window failed open type=%s", type(exc).__name__)
            return True
        return int(value) <= limit


def _validate_window(
    key: str,
    limit: int,
    window_seconds: int,
    amount: int,
) -> None:
    if not key.strip():
        raise ValueError("burst-window key cannot be empty")
    if limit < 1 or window_seconds < 1 or amount < 1:
        raise ValueError("burst-window bounds must be positive")
