from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from shim_enterprise.cache.task_counters import RedisTaskCounter


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("reply", "calls", "allowed"), [([3, 0, 1], 3, True), ([2, 900, 0], 2, False)]
)
async def test_a_call_is_admitted_or_refused_by_one_script(
    reply, calls, allowed
) -> None:
    redis = SimpleNamespace(eval=AsyncMock(return_value=reply))

    admitted = await RedisTaskCounter(SimpleNamespace(redis=redis)).admit_call(
        "org-1", "key-1", max_calls=None, max_cost_micro_usd=900, window_seconds=600
    )

    assert (admitted.calls, admitted.allowed, admitted.unavailable) == (
        calls,
        allowed,
        False,
    )
    assert redis.eval.await_args.args[1:] == (1, "task:org-1:key-1", -1, 900, 600)


@pytest.mark.asyncio
async def test_cost_is_added_to_the_same_hash() -> None:
    redis = SimpleNamespace(eval=AsyncMock(return_value=1))

    await RedisTaskCounter(SimpleNamespace(redis=redis)).add_cost(
        "org-1", "key-1", micro_usd=250, window_seconds=600
    )

    assert redis.eval.await_args.args[1:] == (1, "task:org-1:key-1", 250, 600)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "redis", [None, SimpleNamespace(eval=AsyncMock(side_effect=ConnectionError()))]
)
async def test_an_unavailable_counter_admits_and_says_so(redis) -> None:
    counter = RedisTaskCounter(SimpleNamespace(redis=redis))

    admitted = await counter.admit_call(
        "org-1", "key-1", max_calls=1, max_cost_micro_usd=None, window_seconds=60
    )
    await counter.add_cost("org-1", "key-1", micro_usd=1, window_seconds=60)

    assert (admitted.allowed, admitted.unavailable) == (True, True)
