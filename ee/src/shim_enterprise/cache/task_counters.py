"""Calls and settled cost per agent task in Redis; raw task ids never enter it."""

from __future__ import annotations

import logging

from shim.gateway.admission import TaskAdmission
from shim_enterprise.cache.redis_index import CacheService

logger = logging.getLogger(__name__)

# Refuses without counting; the hash expires a window after the task's first write.
_ADMIT = """
local calls = tonumber(redis.call('HGET', KEYS[1], 'calls') or '0')
local cost = tonumber(redis.call('HGET', KEYS[1], 'cost_micro_usd') or '0')
local max_calls = tonumber(ARGV[1])
local max_cost = tonumber(ARGV[2])
if (max_calls >= 0 and calls + 1 > max_calls) or (max_cost >= 0 and cost >= max_cost) then
    return {calls, cost, 0}
end
redis.call('HINCRBY', KEYS[1], 'calls', 1)
if redis.call('TTL', KEYS[1]) < 0 then
    redis.call('EXPIRE', KEYS[1], ARGV[3])
end
return {calls + 1, cost, 1}
"""
_RELEASE = """
if tonumber(redis.call('HGET', KEYS[1], 'calls') or '0') > 0 then
    redis.call('HINCRBY', KEYS[1], 'calls', -1)
end
return 1
"""
_ADD_COST = """
redis.call('HINCRBY', KEYS[1], 'cost_micro_usd', ARGV[1])
if redis.call('TTL', KEYS[1]) < 0 then
    redis.call('EXPIRE', KEYS[1], ARGV[2])
end
return 1
"""


class RedisTaskCounter:
    """Fails open, as the repeat window does: a counter error never refuses a call."""

    def __init__(self, cache: CacheService) -> None:
        self.cache = cache

    async def admit_call(
        self,
        tenant_id: str,
        task_key: str,
        *,
        max_calls: int | None,
        max_cost_micro_usd: int | None,
        window_seconds: int,
    ) -> TaskAdmission:
        redis = self.cache.redis
        try:
            if redis is None:
                raise ConnectionError("redis unavailable")
            calls, cost, allowed = await redis.eval(
                _ADMIT,
                1,
                f"task:{tenant_id}:{task_key}",
                -1 if max_calls is None else max_calls,
                -1 if max_cost_micro_usd is None else max_cost_micro_usd,
                window_seconds,
            )
        except Exception as exc:
            logger.error("Task counter failed open type=%s", type(exc).__name__)
            return TaskAdmission(0, 0, allowed=True, unavailable=True)
        return TaskAdmission(int(calls), int(cost), allowed=bool(int(allowed)))

    async def add_cost(
        self, tenant_id: str, task_key: str, *, micro_usd: int, window_seconds: int
    ) -> None:
        redis = self.cache.redis
        try:
            if redis is None:
                raise ConnectionError("redis unavailable")
            await redis.eval(
                _ADD_COST, 1, f"task:{tenant_id}:{task_key}", micro_usd, window_seconds
            )
        except Exception as exc:
            logger.error("Task cost not recorded type=%s", type(exc).__name__)

    async def release_call(self, tenant_id: str, task_key: str) -> None:
        redis = self.cache.redis
        try:
            if redis is None:
                raise ConnectionError("redis unavailable")
            await redis.eval(_RELEASE, 1, f"task:{tenant_id}:{task_key}")
        except Exception as exc:
            logger.error("Task call not given back type=%s", type(exc).__name__)
