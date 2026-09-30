import asyncio
import time
from types import SimpleNamespace
from uuid import uuid4

from cryptography.fernet import Fernet
from fastapi import HTTPException
import pytest

from shim.gateway.contracts.ids import TenantId
from shim_enterprise.billing.quota import BurstRateLimiter
from shim_enterprise.cache.circuit_breaker import RedisCircuitBreaker
from shim_enterprise.cache.loop_detection import LoopDetectionService
from shim_enterprise.cache.redis_index import CacheService
from shim_enterprise.compliance.ratelimit import ACQUIRE_LUA
from shim_enterprise.compliance.services.ingest import UNLOCK_LUA
from shim_enterprise.privacy.chain_store import RedisPrivacyContinuationStore
from shim_enterprise.tenants import oidc


@pytest.mark.asyncio
async def test_actual_coordination_ttls_atomic_scripts_sessions_and_privacy():
    cache = CacheService()
    await cache.connect()
    identifier = uuid4().hex
    try:
        client = cache.redis
        assert client is not None
        info = await client.info("server")
        assert info.get("redis_version")
        key = "compatibility:" + identifier
        assert await client.set(key, "first", ex=30, nx=True)
        assert not await client.set(key, "second", ex=30, nx=True)
        assert await client.set(key, "second", ex=30, xx=True)
        assert 0 < await client.ttl(key) <= 30
        assert await client.getdel(key) == "second" and await client.get(key) is None
        lock = client.lock(key + ":lock", timeout=30, blocking=False)
        competitor = client.lock(key + ":lock", timeout=30, blocking=False)
        assert await lock.acquire() and not await competitor.acquire()
        await lock.release()
        assert await competitor.acquire()
        await competitor.release()
        assert await client.eval(ACQUIRE_LUA, 1, key + ":pacing", 1, 30) == [1, 30]
        assert (await client.eval(ACQUIRE_LUA, 1, key + ":pacing", 1, 30))[0] == 0
        assert await client.set(key + ":connector", "owner", nx=True, ex=30)
        assert await client.eval(UNLOCK_LUA, 1, key + ":connector", "foreign") == 0
        assert await client.eval(UNLOCK_LUA, 1, key + ":connector", "owner") == 1
        limiter = BurstRateLimiter(cache)
        allowed = await asyncio.gather(
            *(limiter.allow(identifier, limit=3, window_seconds=30) for _ in range(5))
        )
        assert sum(allowed) == 3
        repeat = LoopDetectionService(cache)
        assert (
            await repeat.check_exact_repeat(
                identifier, "synthetic", limit=2, window_seconds=30
            )
        ).status == "SAFE"
        assert (
            await repeat.check_exact_repeat(
                identifier, "synthetic", limit=2, window_seconds=30
            )
        ).status == "WARNING"
        assert (
            await repeat.check_exact_repeat(
                identifier, "synthetic", limit=2, window_seconds=30
            )
        ).status == "BLOCKED"
        clock = [1000.0]
        circuit = RedisCircuitBreaker(
            "compatibility-" + identifier,
            failure_threshold=2,
            recovery_seconds=30,
            cache=cache,
            clock=lambda: clock[0],
        )
        await circuit.record_failure()
        await circuit.record_failure()
        assert not await circuit.is_available()
        clock[0] += 31
        assert await circuit.acquire_call() and not await circuit.acquire_call()
        await circuit.record_success()
        assert await circuit.is_available()
        privacy = RedisPrivacyContinuationStore(
            cache, encryption_key=Fernet.generate_key().decode(), ttl_seconds=30
        )
        tenant = TenantId(uuid4())
        await privacy.save(tenant, identifier, {"synthetic": "masked"})
        assert await privacy.load(tenant, identifier) == {"synthetic": "masked"}
        assert await privacy.load(TenantId(uuid4()), identifier) is None
        session_id = identifier
        request = SimpleNamespace(
            app=SimpleNamespace(state=SimpleNamespace(cache=cache))
        )
        session_key = oidc._session_key(session_id)
        data = {
            "expires_at": time.time() + 30,
            "private": "synthetic-token",
        }
        await oidc._save_session(request, session_key, data, create=True)
        assert "synthetic-token" not in await client.get(session_key)
        await oidc._save_session(request, session_key, data)
        await client.delete(session_key)
        with pytest.raises(HTTPException, match="revoked"):
            await oidc._save_session(request, session_key, data)
    finally:
        await cache.close()
