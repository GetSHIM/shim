"""Best-effort exact-repeat admission using a bounded Redis window."""

from __future__ import annotations

import hashlib
import logging

from shim_enterprise.cache.redis_index import CacheService
from shim.gateway.admission import LoopDetectionResult


logger = logging.getLogger(__name__)

_INCREMENT_WINDOW = """
local value = redis.call('INCR', KEYS[1])
local ttl = redis.call('TTL', KEYS[1])
if ttl < 0 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return value
"""


class LoopDetectionService:
    """Count only prompt digests; raw prompt material never enters Redis."""

    def __init__(self, cache: CacheService) -> None:
        self.cache = cache

    async def check_exact_repeat(
        self,
        organization_id: str,
        prompt: str,
        *,
        limit: int,
        window_seconds: int,
    ) -> LoopDetectionResult:
        if not organization_id.strip():
            raise ValueError("repeat window requires a tenant identity")
        if limit < 2 or window_seconds < 1:
            raise ValueError("repeat window bounds are invalid")
        if not prompt:
            return LoopDetectionResult("SAFE", 0)
        digest = hashlib.sha256(prompt.encode()).hexdigest()
        key = f"loop:{organization_id}:{digest}"
        redis = self.cache.redis
        if redis is None:
            logger.warning("Repeat window unavailable; admission continues")
            return LoopDetectionResult("SAFE", 0)
        try:
            count = int(
                await redis.eval(
                    _INCREMENT_WINDOW,
                    1,
                    key,
                    window_seconds,
                )
            )
        except Exception as exc:
            logger.error("Repeat window failed open type=%s", type(exc).__name__)
            return LoopDetectionResult("SAFE", 0)
        status = "BLOCKED" if count > limit else "WARNING" if count == limit else "SAFE"
        return LoopDetectionResult(status, count)
