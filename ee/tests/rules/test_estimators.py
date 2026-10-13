"""Preview estimators for destination rules and request caps, on seeded records."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace
from typing import get_args
from uuid import uuid4

import pytest

from ee.tests.rules.test_preview import _preview, _tenant
from shim.gateway.kernel.result import PreparedInference
from shim.rules import Rule, RuleScope
from shim_enterprise.billing.models import RequestLifecycle, UsageLedger
from shim_enterprise.rules import estimators
from shim_enterprise.rules.preview import PREVIEW_ESTIMATORS
from shim_enterprise.tenants.models import ApiKey, OrganizationPIIConfig

END = datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc)
START = END - timedelta(days=7)
TCKN = "10000000146"


def _destination(entity_types=("TR_NATIONAL_ID",), **scope) -> Rule:
    return Rule.model_validate(
        {
            "id": "tckn",
            "name": "TCKN stays inside",
            "kind": "destination",
            "action": "mask",
            "state": "enforced",
            "scope": scope or {"deployment_kinds": ["external"]},
            "match": {"entity_types": list(entity_types)},
        }
    )


def _limit(scope: dict | None = None, **match) -> Rule:
    return Rule.model_validate(
        {
            "id": "caps",
            "name": "Request caps",
            "kind": "request_limit",
            "action": "block",
            "state": "enforced",
            "scope": scope or {},
            "match": match,
        }
    )


async def _seed(
    db,
    key: ApiKey,
    *,
    at: datetime = END - timedelta(hours=1),
    endpoint: str = "chat.completions",
    model: str = "bulut",
    reached: str | None = "gpt-5-nano",
    reserved: int | None = None,
    **metadata,
) -> str:
    request_id = f"req_estimate_{uuid4().hex}"
    db.add(
        RequestLifecycle(
            request_id=request_id,
            organization_id=key.organization_id,
            actor_type="api_key",
            api_key_id=key.id,
            source_endpoint=endpoint,
            status="completed",
            requested_model=model,
            provider_model=reached,
            stream=False,
            started_at=at,
            lifecycle_metadata={"deployment_kind": "external", **metadata},
        )
    )
    if reserved is not None:
        await db.flush()
        db.add(
            UsageLedger(
                request_id=request_id,
                organization_id=key.organization_id,
                api_key_id=key.id,
                requested_model=model,
                created_at=at,
                event_type="quota_reservation",
                idempotency_key=f"request:{request_id}:quota:reservation",
                prompt_tokens=reserved,
                completion_tokens=0,
                total_tokens=reserved,
            )
        )
    await db.flush()
    return request_id


async def _count(db, key: ApiKey, rule: Rule):
    estimator = PREVIEW_ESTIMATORS[rule.kind]
    return await estimator(db, key.organization_id, rule, START, END)


def test_both_kinds_are_registered_and_endpoints_map_as_the_kernel_does() -> None:
    protocols = get_args(RuleScope.model_fields["endpoints"].annotation)[0]
    kernel = PreparedInference.source_endpoint.fget

    assert PREVIEW_ESTIMATORS["destination"] is estimators.estimate_destination
    assert PREVIEW_ESTIMATORS["request_limit"] is estimators.estimate_request_limit
    assert estimators.ENDPOINT_SOURCE == {
        protocol: kernel(SimpleNamespace(protocol=protocol, payload={}))
        for protocol in get_args(protocols)
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(("days", "unlocks"), [(7, True), (6, False)])
async def test_a_destination_preview_counts_from_metadata(db, days, unlocks) -> None:
    owner, key = await _tenant(db)
    await _seed(
        db, key, at=datetime.now(timezone.utc), pii_entities={"TR_NATIONAL_ID": 1}
    )

    preview = await _preview(
        db,
        owner,
        {
            "id": "tckn",
            "name": "TCKN stays inside",
            "kind": "destination",
            "action": "mask",
            "state": "enforced",
            "scope": {"deployment_kinds": ["external"]},
            "match": {"entity_types": ["TR_NATIONAL_ID"]},
        },
        days,
    )

    body = preview.json()
    assert preview.status_code == 200, preview.text
    assert (body["basis"], body["requests"], body["window"]["covered_days"]) == (
        "metadata",
        1,
        days,
    )
    assert body["enforce_on_create"] is unlocks


@pytest.mark.asyncio
async def test_each_scope_list_alone_and_combined(db) -> None:
    owner, key = await _tenant(db)
    team = str(uuid4())
    other = ApiKey(
        id=uuid4(),
        organization_id=key.organization_id,
        user_id=owner.id,
        key_hash=uuid4().hex,
        prefix="sk-shim-oth",
        tier="enterprise",
        is_active=True,
    )
    db.add(other)
    found = {"pii_entities": {"TR_NATIONAL_ID": 1}}
    await _seed(db, key, team_id=team, tags=["bank", "retail"], **found)
    await _seed(db, other, reached="claude-sonnet-4-5-20250929", **found)
    await _seed(db, key, deployment_kind="unknown", endpoint="messages", **found)
    await _seed(db, key, deployment_kind="internal", endpoint="responses", **found)

    async def counted(**scope) -> int:
        return (await _count(db, key, _destination(**scope)))["requests"]

    assert await counted(api_key_ids=[str(other.id)]) == 1
    assert await counted(team_ids=[team]) == 1
    assert await counted(tags=["retail", "other"]) == 1
    # The reached model, its date suffix stripped, case folded; never the alias.
    assert await counted(models=["Claude-Sonnet-4-5"]) == 1
    assert await counted(models=["bulut"]) == 0
    assert await counted(deployment_kinds=["external"]) == 3
    assert await counted(deployment_kinds=["internal"]) == 1
    assert await counted(endpoints=["messages", "responses"]) == 2
    assert await counted(api_key_ids=[str(key.id)], deployment_kinds=["external"]) == 2
    assert await counted(team_ids=[team], endpoints=["messages"]) == 0


@pytest.mark.asyncio
async def test_a_count_tokens_scope_counts_zero_with_its_note(db) -> None:
    _, key = await _tenant(db)
    await _seed(db, key, pii_entities={"TR_NATIONAL_ID": 1})

    counted = await _count(db, key, _destination(endpoints=["count_tokens"]))
    capped = await _count(
        db, key, _limit({"endpoints": ["count_tokens"]}, max_input_bytes=1024)
    )

    assert (counted["requests"], counted["note"]) == (0, estimators.COUNT_TOKENS_NOTE)
    assert (capped["requests"], capped["note"]) == (0, estimators.COUNT_TOKENS_NOTE)


@pytest.mark.asyncio
async def test_destination_counts_detected_types_once_inside_the_window(db) -> None:
    _, key = await _tenant(db)
    await _seed(db, key, pii_entities={"TR_NATIONAL_ID": 2})
    await _seed(db, key, monitored_entities={"IBAN_CODE": 1})
    await _seed(
        db, key, pii_entities={"TR_NATIONAL_ID": 1}, monitored_entities={"IBAN_CODE": 1}
    )
    await _seed(db, key, blocked_entities={"TR_NATIONAL_ID": 1})
    await _seed(db, key, pii_entities={"EMAIL_ADDRESS": 1})
    await _seed(db, key, at=END, pii_entities={"TR_NATIONAL_ID": 1})
    await _seed(
        db, key, at=START - timedelta(seconds=1), pii_entities={"TR_NATIONAL_ID": 1}
    )

    counted = await _count(db, key, _destination(("TR_NATIONAL_ID", "IBAN_CODE")))

    assert counted["requests"] == 3
    assert counted["note"] is None
    assert counted["by_scope"]["models"] == [{"model": "bulut", "requests": 3}]
    assert counted["by_scope"]["api_keys"] == [{"id": str(key.id), "requests": 3}]


@pytest.mark.asyncio
async def test_a_type_off_in_the_base_config_is_named_never_a_value(db) -> None:
    _, key = await _tenant(db)
    db.add(
        OrganizationPIIConfig(
            organization_id=key.organization_id,
            entity_actions={"TR_NATIONAL_ID": "off"},
        )
    )
    await _seed(db, key, pii_entities={"IBAN_CODE": 1}, sample=TCKN)

    counted = await _count(db, key, _destination(("TR_NATIONAL_ID", "IBAN_CODE")))

    assert counted["requests"] == 1
    assert counted["note"].startswith("types TR_NATIONAL_ID have base action off")
    assert TCKN not in json.dumps(counted)


@pytest.mark.asyncio
async def test_by_scope_keeps_the_20_largest_models(db) -> None:
    _, key = await _tenant(db)
    for index in range(22):
        for _ in range(1 + (index == 0)):
            await _seed(db, key, model=f"m{index:02}", pii_entities={"IBAN_CODE": 1})

    counted = await _count(db, key, _destination(("IBAN_CODE",)))

    models = counted["by_scope"]["models"]
    assert counted["requests"] == 23
    assert len(models) == 20
    assert models[0] == {"model": "m00", "requests": 2}


@pytest.mark.asyncio
async def test_the_byte_cap_reads_the_reservation_and_leaves_media_out(db) -> None:
    _, key = await _tenant(db)
    await _seed(db, key, reserved=2048)
    await _seed(db, key, reserved=2049)
    await _seed(db, key, reserved=9000, media_parts=1)
    await _seed(db, key)

    counted = await _count(db, key, _limit(max_input_bytes=2048))

    assert counted["requests"] == 1
    assert counted["note"] == "1 requests with media parts not counted"


@pytest.mark.asyncio
async def test_the_price_tier_counts_the_settled_warning(db) -> None:
    _, key = await _tenant(db)
    await _seed(db, key, warnings=["LARGE_CONTEXT_PRICE"])
    await _seed(db, key, warnings=["TRUNCATED"])
    await _seed(db, key)

    counted = await _count(db, key, _limit(below_price_tier=True))

    assert counted["requests"] == 1
    assert counted["note"] == estimators.PRICE_TIER_NOTE


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("cap", "field"),
    [
        ("max_tools", "tool_count"),
        ("max_documents", "document_count"),
        ("max_history", "message_count"),
    ],
)
async def test_each_shape_cap_counts_above_it(db, cap, field) -> None:
    _, key = await _tenant(db)
    for value in (5, 6, "7"):
        await _seed(db, key, response_analysis={"shape": {field: value}})
    await _seed(db, key)

    counted = await _count(db, key, _limit(**{cap: 5}))

    # 5 is at the cap, "7" is not a number; the unshaped row is not counted.
    assert counted["requests"] == 1
    assert counted["note"] == (
        "tools, documents and history counted on 3 of 4 requests that carry "
        f"shape analysis; {estimators.SHAPE_DEFINITIONS_NOTE}"
    )


@pytest.mark.asyncio
async def test_shape_caps_without_shape_rows_start_in_monitor(db) -> None:
    _, key = await _tenant(db)
    await _seed(db, key, reserved=4096)
    await _seed(
        db,
        key,
        at=START - timedelta(hours=1),
        response_analysis={"shape": {"tool_count": 9}},
    )

    assert await _count(db, key, _limit(max_tools=5)) is None
    assert (await _count(db, key, _limit(max_input_bytes=2048)))["requests"] == 1


@pytest.mark.asyncio
async def test_two_caps_count_a_row_crossing_either_once(db) -> None:
    _, key = await _tenant(db)
    await _seed(db, key, reserved=4096, response_analysis={"shape": {"tool_count": 9}})
    await _seed(db, key, reserved=4096, response_analysis={"shape": {"tool_count": 1}})
    await _seed(db, key, reserved=100, response_analysis={"shape": {"tool_count": 9}})
    await _seed(db, key, reserved=100, response_analysis={"shape": {"tool_count": 1}})

    counted = await _count(db, key, _limit(max_tools=5, max_input_bytes=2048))

    assert counted["requests"] == 3
