from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from threading import get_ident
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID

from prometheus_client import REGISTRY
import pytest

import shim.privacy.continuation as continuation_module
from shim.gateway.contracts.context import (
    AuditPolicy,
    GatewayContext,
    PrivacyPolicy,
    TierPolicy,
)
from shim.gateway.contracts.ids import ApiKeyId, ProviderId, RequestId, TenantId
from shim.gateway.kernel.result import PreparedInference
from shim.gateway.pipeline.privacy import PrivacyStage
from shim.gateway.request_policy import RequestPolicyContext
from shim.privacy.continuation import (
    InMemoryPrivacyContinuationStore,
    PrivacyContinuationUnavailableError,
)
from shim.privacy.pii_scrubber import PIIScrubberService
from shim.privacy.policies import effective_entity_actions


DEFAULT_ACTIONS = effective_entity_actions()


def _tenant(value: str) -> TenantId:
    return TenantId(UUID(value))


def _prepared(payload: dict) -> PreparedInference:
    context = GatewayContext(
        request_id=RequestId("req_chain"),
        tenant_id=_tenant("11111111-1111-1111-1111-111111111111"),
        actor_type="api_key",
        api_key_id=ApiKeyId(UUID("22222222-2222-2222-2222-222222222222")),
        user_id=None,
        endpoint="/v1/responses",
        started_at=datetime(2026, 7, 22, tzinfo=UTC),
        tier_policy=TierPolicy(),
        privacy_policy=PrivacyPolicy(pii_mode="scrub"),
        audit_policy=AuditPolicy(mode="best_effort"),
    )
    return PreparedInference(
        context=context,
        payload=payload,
        provider=ProviderId("openai"),
        protocol="responses",
        model="gpt-5.6-luna",
        stream=False,
        policy=RequestPolicyContext(rate_limit_key_hash="key-hash", tier="managed"),
        pii_config=None,
    )


@pytest.mark.parametrize(
    ("ttl_seconds", "max_entries"),
    ((0, 1), (1, 0)),
)
def test_in_memory_limits_must_be_positive(
    ttl_seconds: int,
    max_entries: int,
) -> None:
    with pytest.raises(ValueError, match="limits must be positive"):
        InMemoryPrivacyContinuationStore(
            ttl_seconds=ttl_seconds,
            max_entries=max_entries,
        )


@pytest.mark.asyncio
async def test_in_memory_state_is_tenant_bound_defensive_and_bounded() -> None:
    store = InMemoryPrivacyContinuationStore(ttl_seconds=60, max_entries=2)
    tenant = _tenant("11111111-1111-1111-1111-111111111111")
    other_tenant = _tenant("33333333-3333-3333-3333-333333333333")
    source = {"<EMAIL_ADDRESS_ff8d9819>": "alice@example.com"}
    expected = dict(source)

    await store.save(tenant, "resp_same", source)
    source.clear()
    loaded = await store.load(tenant, "resp_same")
    loaded.clear()
    assert await store.load(tenant, "resp_same") == expected

    await store.save(other_tenant, "resp_same", {})
    assert await store.load(other_tenant, "resp_same") == {}
    await store.save(tenant, "resp_new", {})

    with pytest.raises(PrivacyContinuationUnavailableError):
        await store.load(tenant, "resp_same")
    assert await store.load(other_tenant, "resp_same") == {}


@pytest.mark.asyncio
async def test_in_memory_state_expires_and_missing_references_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = [10.0]
    monkeypatch.setattr(continuation_module, "monotonic", lambda: now[0])
    store = InMemoryPrivacyContinuationStore(ttl_seconds=2, max_entries=1)
    tenant = _tenant("11111111-1111-1111-1111-111111111111")

    with pytest.raises(PrivacyContinuationUnavailableError) as error:
        await store.load(tenant, "resp_missing")
    assert str(error.value) == "privacy continuation state is unavailable"
    assert "resp_missing" not in str(error.value)

    await store.save(tenant, "resp_expiring", {})
    now[0] = 12.0
    with pytest.raises(PrivacyContinuationUnavailableError):
        await store.load(tenant, "resp_expiring")


@pytest.mark.asyncio
async def test_stage_accepts_empty_marker_and_rejects_unknown_parent_first() -> None:
    calls: list[str] = []

    class RecordingScrubber:
        def scrub(self, text: str, *args, **kwargs) -> tuple[str, dict[str, str]]:
            calls.append(text)
            return text, {}

    store = InMemoryPrivacyContinuationStore(ttl_seconds=60, max_entries=1)
    known = _prepared(
        {
            "previous_response_id": "resp_known",
            "input": "safe text",
        }
    )
    await store.save(known.tenant_id, "resp_known", {})
    stage = PrivacyStage(RecordingScrubber(), store)  # type: ignore[arg-type]

    await stage.run(known)
    calls_after_known = len(calls)
    with pytest.raises(PrivacyContinuationUnavailableError):
        await stage.run(
            _prepared(
                {
                    "previous_response_id": "resp_unknown",
                    "input": "must not be inspected",
                }
            )
        )

    assert calls_after_known > 0
    assert len(calls) == calls_after_known


@pytest.mark.asyncio
async def test_previous_response_mapping_is_loaded_and_merged_before_sdk() -> None:
    scrubber = PIIScrubberService()
    parent_placeholder, parent_map = scrubber.scrub(
        "parent@example.com", DEFAULT_ACTIONS
    )
    prepared = _prepared(
        {
            "model": "gpt-5.6-luna",
            "previous_response_id": "resp_parent",
            "input": "parent@example.com and new@example.com",
        }
    )
    continuation_store = SimpleNamespace(
        load=AsyncMock(return_value=parent_map),
        ensure_available=AsyncMock(),
    )

    result = await PrivacyStage(scrubber, continuation_store).run(prepared)

    assert result.privacy is not None
    assert parent_placeholder in result.privacy.verification_map
    assert parent_placeholder in result.payload["input"]
    assert "parent@example.com" in result.privacy.verification_map.values()
    assert "new@example.com" in result.privacy.verification_map.values()
    assert "new@example.com" not in str(result.payload)
    continuation_store.load.assert_awaited_once_with(prepared.tenant_id, "resp_parent")
    continuation_store.ensure_available.assert_awaited_once()


@pytest.mark.asyncio
async def test_privacy_stage_runs_scrubbing_off_the_event_loop() -> None:
    worker_threads: set[int] = set()

    class RecordingScrubber:
        def scrub(self, text: str, *args, **kwargs) -> tuple[str, dict[str, str]]:
            worker_threads.add(get_ident())
            return text, {}

    prepared = _prepared({"model": "gpt-5.6-luna", "input": "safe text"})
    continuation_store = SimpleNamespace(
        load=AsyncMock(),
        ensure_available=AsyncMock(),
    )

    await PrivacyStage(RecordingScrubber(), continuation_store).run(  # type: ignore[arg-type]
        prepared
    )

    assert worker_threads
    assert get_ident() not in worker_threads


@pytest.mark.asyncio
async def test_a_tailed_placeholder_is_counted_once() -> None:
    prepared = replace(
        _prepared({"input": "4111 1111 1111 1111 and 4111 1111 1111 1111"}),
        entity_actions={"CREDIT_CARD": "mask_last4"},
    )
    continuation_store = SimpleNamespace(load=AsyncMock(), ensure_available=AsyncMock())

    result = await PrivacyStage(PIIScrubberService(), continuation_store).run(prepared)

    assert result.privacy is not None
    assert dict(result.privacy.pii_entities) == {"CREDIT_CARD": 1}


@pytest.mark.asyncio
async def test_a_continuation_counts_only_values_first_seen_in_this_request() -> None:
    scrubber = PIIScrubberService()
    _, parent_map = scrubber.scrub("parent@example.com", DEFAULT_ACTIONS)
    continuation_store = SimpleNamespace(
        load=AsyncMock(return_value=parent_map), ensure_available=AsyncMock()
    )
    stage = PrivacyStage(scrubber, continuation_store)

    repeated = await stage.run(
        _prepared({"previous_response_id": "resp_parent", "input": "Thanks"})
    )
    extended = await stage.run(
        _prepared(
            {
                "previous_response_id": "resp_parent",
                "input": "parent@example.com and new@example.com",
            }
        )
    )

    assert repeated.privacy is not None and extended.privacy is not None
    assert dict(repeated.privacy.pii_entities) == {}
    assert repeated.privacy.pii_detected is True
    assert repeated.privacy.verification_map == parent_map
    assert dict(extended.privacy.pii_entities) == {"EMAIL_ADDRESS": 1}
    assert len(extended.privacy.verification_map) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("threshold", "bulk"),
    [
        (5, None),
        (4, {"distinct_values": 4, "threshold": 4}),
        (2, {"distinct_values": 4, "threshold": 2}),
        (None, None),
    ],
)
async def test_bulk_disclosure_counts_distinct_new_values_of_every_action(
    threshold, bulk
) -> None:
    scrubber = PIIScrubberService()
    _, parent_map = scrubber.scrub("parent@example.com", DEFAULT_ACTIONS)
    stage = PrivacyStage(
        scrubber,
        SimpleNamespace(
            load=AsyncMock(return_value=parent_map), ensure_available=AsyncMock()
        ),
    )
    prepared = replace(
        _prepared(
            {
                "previous_response_id": "resp_parent",
                "input": "parent@example.com one@example.com one@example.com "
                "two@example.com +90 532 000 00 00 key sk-proj-" + "0" * 32,
            }
        ),
        entity_actions={"PHONE_NUMBER": "monitor", "SECRET": "block"},
        bulk_threshold=threshold,
    )
    before = (
        REGISTRY.get_sample_value(
            "shim_privacy_bulk_disclosures_total", {"provider": "openai"}
        )
        or 0
    )

    result = await stage.run(prepared)

    assert result.privacy is not None
    assert result.privacy.bulk_disclosure == bulk
    verdicts = [v for v in result.policy_verdicts if v.rule_id == "privacy.bulk"]
    assert [(v.outcome, v.reason_code) for v in verdicts] == (
        [("allow", "BULK_DISCLOSURE")] if bulk else []
    )
    after = (
        REGISTRY.get_sample_value(
            "shim_privacy_bulk_disclosures_total", {"provider": "openai"}
        )
        or 0
    )
    assert after - before == (1 if bulk else 0)
