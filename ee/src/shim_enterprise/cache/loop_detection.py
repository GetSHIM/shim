"""Best-effort exact-repeat admission using a bounded Redis window."""

from __future__ import annotations

from contextvars import ContextVar
import hashlib
import logging

from shim_enterprise.cache.redis_index import CacheService
from shim.gateway.admission import LoopDetectionResult


logger = logging.getLogger(__name__)

# With a second key, the agent-loop turn is counted in the same round trip.
_INCREMENT_WINDOW = """
local counts = {}
for index, key in ipairs(KEYS) do
    counts[index] = redis.call('INCR', key)
    if redis.call('TTL', key) < 0 then
        redis.call('EXPIRE', key, ARGV[1])
    end
end
if #KEYS == 1 then
    return counts[1]
end
return counts
"""

# Carries the digest to the quota reservation in the same task without a core contract.
_REPEAT_DIGEST: ContextVar[tuple[str, str] | None] = ContextVar(
    "_REPEAT_DIGEST", default=None
)


def take_repeat_digest(organization_id: str) -> str | None:
    stored = _REPEAT_DIGEST.get()
    _REPEAT_DIGEST.set(None)
    if stored is None or stored[0] != organization_id:
        return None
    return stored[1]


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
        turn_key: str | None = None,
    ) -> LoopDetectionResult:
        if not organization_id.strip():
            raise ValueError("repeat window requires a tenant identity")
        if limit < 2 or window_seconds < 1:
            raise ValueError("repeat window bounds are invalid")
        if not prompt:
            _REPEAT_DIGEST.set(None)
            return LoopDetectionResult("SAFE", 0)
        digest = hashlib.sha256(prompt.encode()).hexdigest()
        _REPEAT_DIGEST.set((organization_id, digest))
        key = f"loop:{organization_id}:{digest}"
        redis = self.cache.redis
        if redis is None:
            logger.warning("Repeat window unavailable; admission continues")
            return LoopDetectionResult("SAFE", 0)
        keys = [key, *([f"turn:{organization_id}:{turn_key}"] if turn_key else [])]
        try:
            counted = await redis.eval(
                _INCREMENT_WINDOW, len(keys), *keys, window_seconds
            )
            count, turns = (
                (int(counted[0]), int(counted[1]))
                if isinstance(counted, list)
                else (int(counted), 0)
            )
        except Exception as exc:
            logger.error("Repeat window failed open type=%s", type(exc).__name__)
            return LoopDetectionResult("SAFE", 0)
        status = "BLOCKED" if count > limit else "WARNING" if count == limit else "SAFE"
        return LoopDetectionResult(status, count, turns)
