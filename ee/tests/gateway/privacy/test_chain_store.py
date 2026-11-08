from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock
from uuid import UUID

import pytest
from cryptography.fernet import Fernet
from fastapi import HTTPException

from shim.gateway.contracts.context import (
    AuditPolicy,
    GatewayContext,
    PrivacyPolicy,
    TierPolicy,
)
from shim.gateway.contracts.ids import ApiKeyId, ProviderId, RequestId, TenantId
from shim.gateway.contracts.principal import AuthenticatedPrincipal
from shim.gateway.kernel.result import PreparedInference
from shim.gateway.pipeline.authenticate import GatewayRequestMetadata
from shim.gateway.pipeline.privacy import PrivacyStage
from shim.gateway.request_policy import RequestPolicyContext
from shim_enterprise.privacy.chain_store import RedisPrivacyContinuationStore
from shim.privacy.continuation import PrivacyContinuationUnavailableError
from shim.services.gateway.service import GatewayService


class FakeRedis:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.expirations: dict[str, int] = {}

    async def ping(self) -> bool:
        return True

    async def get(self, key: str) -> str | None:
        return self.values.get(key)

    async def set(self, key: str, value: str, *, ex: int) -> None:
        self.values[key] = value
        self.expirations[key] = ex


@pytest.mark.asyncio
async def test_mapping_is_encrypted_tenant_bound_and_ttl_limited() -> None:
    redis = FakeRedis()
    store = RedisPrivacyContinuationStore(
        SimpleNamespace(redis=redis),
        encryption_key=Fernet.generate_key().decode(),
        ttl_seconds=123,
    )
    tenant = TenantId(UUID("11111111-1111-1111-1111-111111111111"))
    other_tenant = TenantId(UUID("33333333-3333-3333-3333-333333333333"))
    mapping = {"<EMAIL_ADDRESS_ff8d9819>": "alice@example.com"}

    await store.save(tenant, "resp_empty", {})
    await store.save(tenant, "resp_same", mapping)

    assert await store.load(tenant, "resp_empty") == {}
    assert await store.load(tenant, "resp_same") == mapping
    for absent in ((tenant, "resp_absent"), (other_tenant, "resp_same")):
        with pytest.raises(PrivacyContinuationUnavailableError):
            await store.load(*absent)
    assert set(redis.expirations.values()) == {123}
    serialized = "".join(redis.values.values())
    assert "alice@example.com" not in serialized
    assert "EMAIL_ADDRESS" not in serialized

    redis.values[store._key(other_tenant, "resp_empty")] = redis.values[
        store._key(tenant, "resp_empty")
    ]
    with pytest.raises(PrivacyContinuationUnavailableError):
        await store.load(other_tenant, "resp_empty")

    redis.values.clear()
    with pytest.raises(PrivacyContinuationUnavailableError):
        await store.load(tenant, "resp_same")


class FailingRedis(FakeRedis):
    async def set(self, key: str, value: str, *, ex: int) -> None:
        raise ConnectionError("redis unavailable")


@pytest.mark.asyncio
@pytest.mark.parametrize("redis", [None, FailingRedis()])
async def test_an_empty_marker_is_best_effort_and_a_mapping_is_not(redis) -> None:
    store = RedisPrivacyContinuationStore(
        SimpleNamespace(redis=redis),
        encryption_key=Fernet.generate_key().decode(),
        ttl_seconds=60,
    )
    tenant = TenantId(UUID("11111111-1111-1111-1111-111111111111"))

    await store.save(tenant, "resp_empty", {})
    with pytest.raises(PrivacyContinuationUnavailableError):
        await store.save(
            tenant, "resp_mapping", {"<EMAIL_ADDRESS_ff8d9819>": "alice@example.com"}
        )


@pytest.mark.asyncio
async def test_unavailable_or_corrupt_state_fails_closed_without_plaintext() -> None:
    key = Fernet.generate_key().decode()
    unavailable = RedisPrivacyContinuationStore(
        SimpleNamespace(redis=None), encryption_key=key, ttl_seconds=60
    )

    with pytest.raises(PrivacyContinuationUnavailableError) as error:
        await unavailable.load(
            TenantId(UUID("11111111-1111-1111-1111-111111111111")), "resp_1"
        )
    assert "resp_1" not in str(error.value)

    redis = FakeRedis()
    store = RedisPrivacyContinuationStore(
        SimpleNamespace(redis=redis), encryption_key=key, ttl_seconds=60
    )
    tenant = TenantId(UUID("11111111-1111-1111-1111-111111111111"))
    redis.values[store._key(tenant, "resp_1")] = "not-a-token"
    with pytest.raises(PrivacyContinuationUnavailableError):
        await store.load(
            TenantId(UUID("11111111-1111-1111-1111-111111111111")), "resp_1"
        )


@pytest.mark.asyncio
async def test_gateway_service_maps_continuation_failure_to_fixed_safe_error() -> None:
    kernel = SimpleNamespace(
        execute=AsyncMock(side_effect=PrivacyContinuationUnavailableError())
    )
    service = GatewayService(kernel)  # type: ignore[arg-type]
    principal = AuthenticatedPrincipal(
        actor_type="api_key",
        api_key_id=UUID("22222222-2222-2222-2222-222222222222"),
        user_id=None,
        authenticated_at=datetime(2026, 7, 22, tzinfo=UTC),
    )

    with pytest.raises(HTTPException) as error:
        await service.dispatch_inference(
            payload={},
            provider="openai",
            protocol="responses",
            model="gpt-5.6-luna",
            stream=False,
            headers={},
            provider_credential=None,
            principal=principal,
            request_metadata=GatewayRequestMetadata(endpoint="/v1/responses"),
        )

    assert error.value.status_code == 503
    assert error.value.detail == {
        "code": "PRIVACY_STATE_UNAVAILABLE",
        "message": "Privacy continuation state is unavailable.",
    }


@pytest.mark.asyncio
async def test_gateway_service_preserves_unknown_failures() -> None:
    failure = RuntimeError("unknown failure")
    service = GatewayService(  # type: ignore[arg-type]
        SimpleNamespace(execute=AsyncMock(side_effect=failure))
    )

    with pytest.raises(RuntimeError) as error:
        await service.dispatch_inference(
            payload={},
            provider="openai",
            protocol="responses",
            model="gpt-5.6-luna",
            stream=False,
            headers={},
            provider_credential=None,
            principal=cast(Any, object()),
            request_metadata=GatewayRequestMetadata(endpoint="/v1/responses"),
        )

    assert error.value is failure


def _continuation(tenant: TenantId, previous: str) -> PreparedInference:
    context = GatewayContext(
        request_id=RequestId("req_chain"),
        tenant_id=tenant,
        actor_type="api_key",
        api_key_id=ApiKeyId(UUID("22222222-2222-2222-2222-222222222222")),
        user_id=None,
        endpoint="/v1/responses",
        started_at=datetime(2026, 10, 8, tzinfo=UTC),
        tier_policy=TierPolicy(),
        privacy_policy=PrivacyPolicy(pii_mode="scrub"),
        audit_policy=AuditPolicy(mode="best_effort"),
    )
    return PreparedInference(
        context=context,
        payload={"previous_response_id": previous, "input": "must not be inspected"},
        provider=ProviderId("openai"),
        protocol="responses",
        model="gpt-5.6-luna",
        stream=False,
        policy=RequestPolicyContext(rate_limit_key_hash="key-hash", tier="managed"),
        pii_config=None,
    )


@pytest.mark.asyncio
async def test_a_lost_marker_stops_the_turn_before_anything_is_scrubbed() -> None:
    scrubbed: list[str] = []

    class RecordingScrubber:
        def scrub(self, text: str, *args, **kwargs) -> tuple[str, dict[str, str]]:
            scrubbed.append(text)
            return text, {}

    redis = FakeRedis()
    key = Fernet.generate_key().decode()
    store = RedisPrivacyContinuationStore(
        SimpleNamespace(redis=redis), encryption_key=key, ttl_seconds=60
    )
    tenant = TenantId(UUID("11111111-1111-1111-1111-111111111111"))
    other_tenant = TenantId(UUID("33333333-3333-3333-3333-333333333333"))
    await store.save(tenant, "resp_empty", {})
    stage = PrivacyStage(RecordingScrubber(), store)  # type: ignore[arg-type]

    await stage.run(_continuation(tenant, "resp_empty"))
    assert scrubbed
    scrubbed.clear()
    down = PrivacyStage(
        RecordingScrubber(),  # type: ignore[arg-type]
        RedisPrivacyContinuationStore(
            SimpleNamespace(redis=None), encryption_key=key, ttl_seconds=60
        ),
    )
    for running, prepared in (
        (stage, _continuation(tenant, "resp_lost")),
        (stage, _continuation(other_tenant, "resp_empty")),
        (down, _continuation(tenant, "resp_empty")),
    ):
        with pytest.raises(PrivacyContinuationUnavailableError):
            await running.run(prepared)
    assert scrubbed == []
