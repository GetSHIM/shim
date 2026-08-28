"""Redis-backed provider circuit state for enterprise composition."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import re
import time
from typing import Any, Protocol

from redis.exceptions import RedisError

from shim.core.circuit_breaker import validate_circuit_limits


_PROVIDER_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_RECORD_FAILURE_LUA = """
local failures = redis.call('INCR', KEYS[1])
redis.call('EXPIRE', KEYS[1], ARGV[1])
if failures >= tonumber(ARGV[2]) then
    redis.call('SET', KEYS[2], 'open', 'EX', ARGV[1])
    redis.call('SET', KEYS[3], ARGV[3], 'EX', ARGV[1])
end
redis.call('DEL', KEYS[4])
return failures
"""


class RedisResource(Protocol):
    """Structural port exposing an optional asynchronous Redis client."""

    redis: Any | None


@dataclass(frozen=True, slots=True)
class CircuitState:
    failures: int
    open_until: float

    @property
    def is_open(self) -> bool:
        return self.open_until > 0


class RedisCircuitBreaker:
    """Fail-open Redis circuit with a single half-open probe lease."""

    def __init__(
        self,
        provider_id: str,
        *,
        failure_threshold: int = 5,
        recovery_seconds: int = 60,
        cache: RedisResource | None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        normalized = provider_id.strip().casefold()
        if not _PROVIDER_ID.fullmatch(normalized):
            raise ValueError("provider_id is invalid")
        validate_circuit_limits(failure_threshold, recovery_seconds)
        self.provider_id = normalized
        self.failure_threshold = failure_threshold
        self.recovery_seconds = recovery_seconds
        self.cache = cache
        self.clock = clock

    @property
    def _redis(self) -> Any | None:
        return self.cache.redis if self.cache is not None else None

    @property
    def _keys(self) -> tuple[str, str, str, str]:
        prefix = f"circuit:{self.provider_id}"
        return (
            f"{prefix}:failures",
            f"{prefix}:state",
            f"{prefix}:open_until",
            f"{prefix}:probe",
        )

    async def state(self) -> CircuitState:
        redis = self._redis
        if redis is None:
            return CircuitState(failures=0, open_until=0)
        failures_key, state_key, open_until_key, _probe_key = self._keys
        try:
            values = await redis.mget(failures_key, state_key, open_until_key)
            failures = int(values[0] or 0)
            is_open = _decode(values[1]) == "open"
            open_until = float(values[2] or 0) if is_open else 0
        except (TypeError, ValueError, OSError, RedisError):
            return CircuitState(failures=0, open_until=0)
        return CircuitState(failures=failures, open_until=open_until)

    async def is_available(self) -> bool:
        """Return whether another provider call may start."""

        state = await self.state()
        return not state.is_open or self.clock() >= state.open_until

    async def acquire_call(self) -> bool:
        """Acquire the sole recovery probe when an open window has elapsed."""

        redis = self._redis
        if redis is None:
            return True
        state = await self.state()
        if not state.is_open:
            return True
        if self.clock() < state.open_until:
            return False
        probe_key = self._keys[3]
        try:
            return bool(
                await redis.set(
                    probe_key,
                    "1",
                    nx=True,
                    ex=self.recovery_seconds,
                )
            )
        except (OSError, RedisError):
            return True

    async def record_success(self) -> None:
        redis = self._redis
        if redis is None:
            return
        try:
            await redis.delete(*self._keys)
        except (OSError, RedisError):
            return

    async def release_probe(self) -> None:
        """Release an unconsumed half-open probe without changing health state."""

        redis = self._redis
        if redis is None:
            return
        try:
            await redis.delete(self._keys[3])
        except (OSError, RedisError):
            return

    async def record_failure(self) -> None:
        redis = self._redis
        if redis is None:
            return
        failures_key, state_key, open_until_key, probe_key = self._keys
        open_until = self.clock() + self.recovery_seconds
        try:
            await redis.eval(
                _RECORD_FAILURE_LUA,
                4,
                failures_key,
                state_key,
                open_until_key,
                probe_key,
                self.recovery_seconds * 2,
                self.failure_threshold,
                open_until,
            )
        except (OSError, RedisError):
            return


def _decode(value: Any) -> str:
    return value.decode() if isinstance(value, bytes) else str(value or "")
