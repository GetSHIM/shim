"""Short-lived AWS material, minted on a miss and reused until close to expiry."""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Hashable
from datetime import datetime, timedelta, timezone

from shim_enterprise.aws.sigv4 import AwsCredentials, bedrock_bearer_token

TOKEN_SECONDS = 3_600
# Replaced while this much life remains, so nothing expires on the way.
RENEW_BEFORE = timedelta(seconds=300)
# A token never outlives the credential that signed it.
CREDENTIAL_MARGIN = timedelta(seconds=60)
MAX_ENTRIES = 4_096


class ExpiringCache[T]:
    """One live value per key; concurrent misses for a key share one mint, and the
    least recently used entry goes above `max_entries`."""

    def __init__(self, max_entries: int = MAX_ENTRIES) -> None:
        self.max_entries = max_entries
        self._values: OrderedDict[Hashable, tuple[T, datetime]] = OrderedDict()
        self._minting: dict[Hashable, asyncio.Future[T]] = {}

    async def get(
        self,
        key: Hashable,
        mint: Callable[[], Awaitable[tuple[T, datetime]]],
        *,
        now: datetime,
    ) -> T:
        cached = self._values.get(key)
        if cached is not None and cached[1] - now > RENEW_BEFORE:
            self._values.move_to_end(key)
            return cached[0]
        if (pending := self._minting.get(key)) is not None:
            try:
                return await asyncio.shield(pending)
            except asyncio.CancelledError:
                task = asyncio.current_task()
                if not pending.cancelled() or (task and task.cancelling()):
                    raise
                # The minting request went away (its client left): mint here.
                return await self.get(key, mint, now=now)
        future: asyncio.Future[T] = asyncio.get_running_loop().create_future()
        self._minting[key] = future
        try:
            value, expires_at = await mint()
            self._values[key] = (value, expires_at)
            self._values.move_to_end(key)
            while len(self._values) > self.max_entries:
                self._values.popitem(last=False)
            future.set_result(value)
            return value
        except Exception as error:
            future.set_exception(error)
            # Waiters see the error; nobody else needs to retrieve it.
            future.exception()
            raise
        except BaseException:
            future.cancel()
            raise
        finally:
            del self._minting[key]


class BedrockTokenCache:
    """Per (tenant, secret, secret reference, region, session tag), one live Bedrock key.

    Minting is local: no AWS call happens on the request path, and the credentials
    are loaded only on a miss.
    """

    def __init__(self, max_entries: int = MAX_ENTRIES) -> None:
        self._cache: ExpiringCache[str] = ExpiringCache(max_entries)

    async def token(
        self,
        key: Hashable,
        region: str,
        load: Callable[[], Awaitable[AwsCredentials]],
        *,
        now: datetime | None = None,
    ) -> str:
        at = now or datetime.now(timezone.utc)

        async def mint() -> tuple[str, datetime]:
            credentials = await load()
            seconds = TOKEN_SECONDS
            if credentials.expires_at is not None:
                left = credentials.expires_at - CREDENTIAL_MARGIN - at
                seconds = min(seconds, int(left.total_seconds()))
            if seconds < 1:
                raise ValueError("the credential expires too soon to sign a token")
            token = bedrock_bearer_token(
                credentials, region=region, now=at, expires_seconds=seconds
            )
            return token, at + timedelta(seconds=seconds)

        return await self._cache.get(key, mint, now=at)
