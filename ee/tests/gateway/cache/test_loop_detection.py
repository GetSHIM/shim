from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from shim_enterprise.cache.loop_detection import LoopDetectionService
from shim_enterprise.cache.redis_index import CacheService


@pytest.mark.asyncio
async def test_cache_connect_closes_client_when_ping_fails() -> None:
    cache = object.__new__(CacheService)
    cache.redis = None
    client = SimpleNamespace(
        ping=AsyncMock(side_effect=ConnectionError("unavailable")),
        aclose=AsyncMock(),
    )

    with (
        patch("shim_enterprise.cache.redis_index.redis.from_url", return_value=client),
        pytest.raises(ConnectionError, match="unavailable"),
    ):
        await cache.connect()

    client.aclose.assert_awaited_once_with()
    assert cache.redis is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("count", "status"),
    [(1, "SAFE"), (4, "WARNING"), (5, "BLOCKED")],
)
async def test_repeat_window_has_bounded_typed_outcomes(
    count: int,
    status: str,
) -> None:
    redis = SimpleNamespace(eval=AsyncMock(return_value=count))
    detector = LoopDetectionService(SimpleNamespace(redis=redis))

    result = await detector.check_exact_repeat(
        "tenant-1",
        "normalized prompt",
        limit=4,
        window_seconds=300,
    )

    assert result.status == status
    assert result.chain_length == count
    arguments = redis.eval.await_args.args
    assert arguments[1] == 1
    assert arguments[2].startswith("loop:tenant-1:")
    assert "normalized prompt" not in arguments[2]
    assert arguments[3] == 300


@pytest.mark.asyncio
async def test_repeat_window_fails_open_without_redis() -> None:
    detector = LoopDetectionService(SimpleNamespace(redis=None))

    result = await detector.check_exact_repeat(
        "tenant-1",
        "normalized prompt",
        limit=4,
        window_seconds=300,
    )

    assert result.status == "SAFE"
    assert result.chain_length == 0


@pytest.mark.asyncio
async def test_repeat_window_fails_open_on_backend_error() -> None:
    redis = SimpleNamespace(eval=AsyncMock(side_effect=ConnectionError))
    detector = LoopDetectionService(SimpleNamespace(redis=redis))

    result = await detector.check_exact_repeat(
        "tenant-1",
        "normalized prompt",
        limit=4,
        window_seconds=300,
    )

    assert result.status == "SAFE"
    assert result.chain_length == 0
