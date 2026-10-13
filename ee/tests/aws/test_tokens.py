from __future__ import annotations

import asyncio
import base64
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import SecretStr

from shim_enterprise.aws.sigv4 import AwsCredentials
from shim_enterprise.aws.tokens import BedrockTokenCache

NOW = datetime(2026, 10, 8, 12, 0, tzinfo=timezone.utc)


def _loader(calls: list[int], expires_at: datetime | None = None, delay: float = 0):
    async def load() -> AwsCredentials:
        calls.append(1)
        await asyncio.sleep(delay)
        return AwsCredentials(
            f"AKIA{len(calls):016d}", SecretStr("0" * 40), expires_at=expires_at
        )

    return load


@pytest.mark.asyncio
async def test_a_token_is_reused_until_five_minutes_before_it_expires() -> None:
    cache, calls = BedrockTokenCache(), []
    key = ("tenant", "secret", "v2", "eu-central-1", None)

    first = await cache.token(key, "eu-central-1", _loader(calls), now=NOW)
    reused = await cache.token(
        key, "eu-central-1", _loader(calls), now=NOW + timedelta(minutes=54)
    )
    renewed = await cache.token(
        key, "eu-central-1", _loader(calls), now=NOW + timedelta(minutes=55)
    )

    assert first == reused != renewed
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_a_short_lived_credential_shortens_the_token() -> None:
    cache, calls = BedrockTokenCache(), []

    token = await cache.token(
        "k", "eu-central-1", _loader(calls, NOW + timedelta(minutes=10)), now=NOW
    )
    url = base64.b64decode(token.removeprefix("bedrock-api-key-")).decode()

    assert "X-Amz-Expires=540&" in url
    with pytest.raises(ValueError):
        await BedrockTokenCache().token(
            "k", "eu-central-1", _loader(calls, NOW + timedelta(seconds=30)), now=NOW
        )


@pytest.mark.asyncio
async def test_concurrent_misses_share_one_store_read() -> None:
    cache, calls = BedrockTokenCache(), []

    tokens = await asyncio.gather(
        *(
            cache.token("k", "eu-central-1", _loader(calls, delay=0.05), now=NOW)
            for _ in range(5)
        )
    )

    assert len(set(tokens)) == 1
    assert calls == [1]


@pytest.mark.asyncio
async def test_the_least_recently_used_token_is_evicted() -> None:
    cache, calls = BedrockTokenCache(max_entries=2), []

    for key in ("a", "b"):
        await cache.token(key, "eu-central-1", _loader(calls), now=NOW)
    await cache.token("a", "eu-central-1", _loader(calls), now=NOW)
    await cache.token("c", "eu-central-1", _loader(calls), now=NOW)
    await cache.token("a", "eu-central-1", _loader(calls), now=NOW)
    await cache.token("b", "eu-central-1", _loader(calls), now=NOW)

    # a, b, c minted; a hit; b was evicted by c and minted again.
    assert len(calls) == 4


@pytest.mark.asyncio
async def test_a_rotation_or_another_region_is_another_token() -> None:
    cache, calls = BedrockTokenCache(), []

    tokens = {
        await cache.token(
            ("t", "s", version, region, None), region, _loader(calls), now=NOW
        )
        for version, region in (
            ("v1", "eu-central-1"),
            ("v2", "eu-central-1"),
            ("v1", "us-east-1"),
        )
    }

    assert len(tokens) == 3
