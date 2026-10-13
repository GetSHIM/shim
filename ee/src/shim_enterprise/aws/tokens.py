"""Short-term Bedrock API keys, minted locally and reused until close to expiry."""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Hashable
from datetime import datetime, timedelta, timezone

from shim_enterprise.aws.sigv4 import AwsCredentials, bedrock_bearer_token

TOKEN_SECONDS = 3_600
# A token is replaced while this much of its life remains, so no request carries one
# that expires on the way.
RENEW_BEFORE = timedelta(seconds=300)
# A token never outlives the credential that signed it.
CREDENTIAL_MARGIN = timedelta(seconds=60)
MAX_ENTRIES = 4_096


class BedrockTokenCache:
    """Per (tenant, secret, secret version, region, session tag), one live token.

    Minting is local: no AWS call happens on the request path. Concurrent misses for
    one key share one mint, and the secret store is read only on a miss.
    """

    def __init__(self, max_entries: int = MAX_ENTRIES) -> None:
        self.max_entries = max_entries
        self._tokens: OrderedDict[Hashable, tuple[str, datetime]] = OrderedDict()
        self._minting: dict[Hashable, asyncio.Future[str]] = {}

    async def token(
        self,
        key: Hashable,
        region: str,
        load: Callable[[], Awaitable[AwsCredentials]],
        *,
        now: datetime | None = None,
    ) -> str:
        now = now or datetime.now(timezone.utc)
        cached = self._tokens.get(key)
        if cached is not None and cached[1] - now > RENEW_BEFORE:
            self._tokens.move_to_end(key)
            return cached[0]
        if (pending := self._minting.get(key)) is not None:
            return await asyncio.shield(pending)
        future: asyncio.Future[str] = asyncio.get_running_loop().create_future()
        self._minting[key] = future
        try:
            credentials = await load()
            seconds = TOKEN_SECONDS
            if credentials.expires_at is not None:
                left = credentials.expires_at - CREDENTIAL_MARGIN - now
                seconds = min(seconds, int(left.total_seconds()))
            if seconds < 1:
                raise ValueError("the credential expires too soon to sign a token")
            token = bedrock_bearer_token(
                credentials, region=region, now=now, expires_seconds=seconds
            )
            self._tokens[key] = (token, now + timedelta(seconds=seconds))
            self._tokens.move_to_end(key)
            while len(self._tokens) > self.max_entries:
                self._tokens.popitem(last=False)
            future.set_result(token)
            return token
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
