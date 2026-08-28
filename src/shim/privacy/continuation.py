"""Public privacy-continuation state contract and local implementation."""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Mapping
from time import monotonic
from typing import Protocol

from shim.gateway.contracts.ids import TenantId


class PrivacyContinuationUnavailableError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("privacy continuation state is unavailable")


class PrivacyContinuationStore(Protocol):
    async def ensure_available(self) -> None: ...

    async def load(
        self,
        tenant_id: TenantId,
        response_id: str,
    ) -> dict[str, str] | None: ...

    async def save(
        self,
        tenant_id: TenantId,
        response_id: str,
        mapping: Mapping[str, str],
    ) -> None: ...


class InMemoryPrivacyContinuationStore:
    """Bounded process-local continuation state for the community gateway."""

    def __init__(self, *, ttl_seconds: int, max_entries: int) -> None:
        if ttl_seconds <= 0 or max_entries <= 0:
            raise ValueError("privacy continuation limits must be positive")
        self._ttl_seconds = ttl_seconds
        self._max_entries = max_entries
        self._entries: OrderedDict[
            tuple[TenantId, str], tuple[float, dict[str, str]]
        ] = OrderedDict()

    async def ensure_available(self) -> None:
        return None

    async def load(
        self,
        tenant_id: TenantId,
        response_id: str,
    ) -> dict[str, str]:
        now = monotonic()
        self._discard_expired(now)
        entry = self._entries.get((tenant_id, response_id))
        if entry is None:
            raise PrivacyContinuationUnavailableError()
        return dict(entry[1])

    async def save(
        self,
        tenant_id: TenantId,
        response_id: str,
        mapping: Mapping[str, str],
    ) -> None:
        now = monotonic()
        self._discard_expired(now)
        key = (tenant_id, response_id)
        self._entries.pop(key, None)
        self._entries[key] = (now + self._ttl_seconds, dict(mapping))
        while len(self._entries) > self._max_entries:
            self._entries.popitem(last=False)

    def _discard_expired(self, now: float) -> None:
        while self._entries:
            _, (expires_at, _) = next(iter(self._entries.items()))
            if expires_at > now:
                return
            self._entries.popitem(last=False)
