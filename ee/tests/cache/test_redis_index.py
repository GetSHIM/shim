from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from shim_enterprise.cache.redis_index import CacheService


@pytest.mark.asyncio
async def test_configuration_cache_fails_open_on_redis_errors() -> None:
    failure = ConnectionError("redis unavailable")
    cache = CacheService()
    cache.redis = SimpleNamespace(
        get=AsyncMock(side_effect=failure),
        set=AsyncMock(side_effect=failure),
        delete=AsyncMock(side_effect=failure),
    )

    assert await cache.get("key") is None
    await cache.set("key", {"value": 1})
    assert await cache.delete("key") is False
