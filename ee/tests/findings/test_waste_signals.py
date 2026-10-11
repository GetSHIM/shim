from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import event, select

from shim.jsonschema_subset import check
from shim_enterprise.billing.models import RequestLifecycle
from shim_enterprise.findings import service
from shim_enterprise.findings.models import Finding
from shim_enterprise.observability.analytics_projection import RequestLog
from shim_enterprise.tenants.models import ApiKey, Organization, User

NOW = datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc)
SCHEMA = json.loads(
    (Path(__file__).parents[3] / "docs" / "schemas" / "finding-v1.json").read_text()
)


def _shape(**values) -> dict:
    return {
        "message_count": 4,
        "history_chars": 2_000,
        "largest_part_chars": 1_000,
        "tool_count": 0,
        "tool_definition_chars": 0,
        "tools_offered": [],
        "tools_order_digest": "0" * 64,
        "tools_set_digest": "0" * 64,
        **values,
    }


def _add(
    db,
    key: ApiKey,
    shape: dict | None,
    *,
    calls: list[str] | None = None,
    started_at: datetime = NOW - timedelta(hours=1),
    prompt_tokens: int | None = None,
    cached: int | None = None,
) -> str:
    request_id = f"req_waste_{uuid4().hex}"
    db.add(
        RequestLifecycle(
            request_id=request_id,
            organization_id=key.organization_id,
            actor_type="api_key",
            api_key_id=key.id,
            source_endpoint="messages",
            status="completed",
            provider="anthropic",
            requested_model="claude-haiku-5-5",
            stream=False,
            started_at=started_at,
            lifecycle_metadata={
                "tool_call_names": calls or [],
                **(
                    {"response_analysis": {"shape": shape}} if shape is not None else {}
                ),
            },
        )
    )
    if prompt_tokens is not None:
        db.add(
            RequestLog(
                request_id=request_id,
                api_key_id=key.id,
                organization_id=key.organization_id,
                prompt_tokens=prompt_tokens,
                details={} if cached is None else {"cached_input_tokens": cached},
            )
        )
    return request_id


async def _run(db, key: ApiKey, rule) -> list[service.Detection]:
    await db.flush()
    return await rule(db, key.organization_id, NOW)


async def _other_key(db) -> ApiKey:
    organization = Organization(
        id=uuid4(), name="Other", slug=f"waste-{uuid4().hex}", tier="enterprise"
    )
    db.add(organization)
    await db.flush()
    owner = User(
        id=uuid4(),
        organization_id=organization.id,
        email=f"waste-{uuid4().hex}@example.com",
        role="owner",
        is_active=True,
        is_verified=True,
    )
    db.add(owner)
    await db.flush()
    key = ApiKey(
        id=uuid4(),
        organization_id=organization.id,
        user_id=owner.id,
        key_hash=uuid4().hex,
        prefix="sk-shim-was",
        tier="enterprise",
        is_active=True,
    )
    db.add(key)
    await db.flush()
    return key


def _valid(detection: service.Detection, key: ApiKey) -> None:
    spec = service.RULES[detection.rule_id]
    finding = service.finding_from_row(
        Finding(
            id=uuid4(),
            organization_id=key.organization_id,
            rule_id=detection.rule_id,
            rule_version=1,
            subject_key=detection.subject_key,
            subject=detection.subject,
            title=spec.TITLE,
            summary="",
            severity_id=spec.SEVERITY_ID,
            status_id=1,
            first_seen_at=NOW,
            last_seen_at=NOW,
            occurrences=1,
            evidence=detection.evidence,
            impact=detection.impact,
            remediation={"text": "", "doc": ""},
            source="gateway",
        )
    )
    assert check(finding.model_dump(mode="json"), SCHEMA).valid is None
    assert finding.impact.tokens == (detection.impact or {}).get("tokens")


@pytest.fixture(autouse=True)
def fresh_dead_tools_due(monkeypatch):
    monkeypatch.setattr(service, "_dead_tools_due", {})


@pytest.mark.parametrize(
    ("field", "limit", "measured"),
    [
        ("tool_definition_chars", 40_000, "tool_definitions_median"),
        ("message_count", 100, "history_messages_median"),
        ("history_chars", 200_000, "history_chars_median"),
        ("largest_part_chars", 100_000, "large_part_median"),
    ],
)
@pytest.mark.asyncio
async def test_each_part_fires_at_its_median_limit_and_not_below(
    db, test_api_key, field: str, limit: int, measured: str
) -> None:
    other = await _other_key(db)
    for _ in range(20):
        _add(db, test_api_key, _shape(**{field: limit}))
        _add(db, other, _shape(**{field: limit - 1}))

    [detection] = await _run(db, test_api_key, service._oversized_parts)
    below = await _run(db, other, service._oversized_parts)

    assert detection.evidence[measured] == limit
    assert (detection.evidence["analysed_requests"], detection.impact["requests"]) == (
        20,
        20,
    )
    assert below == []
    _valid(detection, test_api_key)


@pytest.mark.asyncio
async def test_several_kinds_join_one_finding_with_a_token_estimate(
    db, test_api_key
) -> None:
    for index in range(21):
        _add(
            db,
            test_api_key,
            _shape(tool_definition_chars=50_000, largest_part_chars=120_000 + index),
        )
    # Not judged: rows without the shape record, and 19 rows are too few elsewhere.
    for _ in range(5):
        _add(db, test_api_key, None)

    [detection] = await _run(db, test_api_key, service._oversized_parts)

    assert detection.evidence["crossed_kinds"] == 2
    assert detection.evidence["tokens_estimated"] is True
    assert detection.impact["requests"] == 21
    assert (
        detection.impact["tokens"]
        == (21 * 50_000 + sum(120_000 + index for index in range(21))) // 4
    )
    assert len(detection.evidence["request_ids"]) == 20


@pytest.mark.asyncio
async def test_fewer_than_20_requests_never_fire(db, test_api_key) -> None:
    for _ in range(19):
        _add(db, test_api_key, _shape(tool_definition_chars=90_000))

    assert await _run(db, test_api_key, service._oversized_parts) == []


@pytest.mark.asyncio
async def test_a_tool_offered_often_and_never_called_is_dead(db, test_api_key) -> None:
    for index in range(50):
        offered = ["lookup", "create", "web_search"] + (
            ["delete"] if index < 30 else []
        )
        offered += ["rare"] if index < 10 else []
        calls = ["lookup"] if index == 0 else ["web_search_call"] if index == 1 else []
        _add(
            db,
            test_api_key,
            _shape(tool_count=len(offered), tools_offered=offered),
            calls=calls,
        )

    [detection] = await _run(db, test_api_key, service._dead_tools)

    assert detection.evidence["tools"] == [
        {"name": "create", "offered": 50},
        {"name": "delete", "offered": 30},
    ]
    assert (
        detection.evidence["offering_requests"],
        detection.evidence["dead_tools"],
    ) == (50, 2)
    assert detection.impact["requests"] == 50
    _valid(detection, test_api_key)


@pytest.mark.asyncio
async def test_no_dead_tools_without_any_tool_call_or_below_50_requests(
    db, test_api_key
) -> None:
    other = await _other_key(db)
    for _ in range(50):
        _add(db, test_api_key, _shape(tool_count=1, tools_offered=["create"]))
    for index in range(49):
        _add(
            db,
            other,
            _shape(tool_count=1, tools_offered=["create"]),
            calls=["x"] if index == 0 else None,
        )

    assert await _run(db, test_api_key, service._dead_tools) == []
    assert await _run(db, other, service._dead_tools) == []


@pytest.mark.asyncio
async def test_dead_tools_list_20_names_cut_to_64_characters(db, test_api_key) -> None:
    tools = [f"t{index:02d}_" + "x" * 80 for index in range(25)]
    for index in range(50):
        _add(
            db,
            test_api_key,
            _shape(tool_count=25, tools_offered=tools),
            calls=["used"] if index == 0 else None,
        )

    [detection] = await _run(db, test_api_key, service._dead_tools)

    names = [item["name"] for item in detection.evidence["tools"]]
    assert len(names) == 20
    assert all(len(name) == 64 for name in names)


@pytest.mark.asyncio
async def test_dead_tools_run_once_a_day_per_organization(db, test_api_key) -> None:
    for index in range(50):
        _add(
            db,
            test_api_key,
            _shape(tool_count=1, tools_offered=["create"]),
            calls=["used"] if index == 0 else None,
        )
    await db.flush()
    connection = await db.connection()
    sent: list[str] = []

    def capture(_conn, _cursor, statement, *_args) -> None:
        sent.append(statement)

    event.listen(connection.sync_connection, "before_cursor_execute", capture)
    try:
        first = await service._dead_tools(db, test_api_key.organization_id, NOW)
        statements = len(sent)
        again = await service._dead_tools(
            db, test_api_key.organization_id, NOW + timedelta(hours=23)
        )
        within = len(sent)
        later = await service._dead_tools(
            db, test_api_key.organization_id, NOW + timedelta(hours=24)
        )
    finally:
        event.remove(connection.sync_connection, "before_cursor_execute", capture)

    assert len(first) == 1 and again == [] and len(later) == 1
    assert statements == within
    assert len(sent) > within


def _orders(
    db, key, orders: list[str], *, cached=None, prompt_tokens=2_000, digest="1" * 64
):
    for order in orders:
        _add(
            db,
            key,
            _shape(tool_count=3, tools_set_digest=digest, tools_order_digest=order),
            prompt_tokens=prompt_tokens,
            cached=cached,
        )


@pytest.mark.asyncio
async def test_two_orders_without_cache_reads_churn(db, test_api_key) -> None:
    _orders(db, test_api_key, ["a" * 64, "b" * 64] * 10, cached=0)
    # A second set in one fixed order stays out of the finding.
    _orders(db, test_api_key, ["c" * 64] * 20, digest="2" * 64)

    [detection] = await _run(db, test_api_key, service._cache_order_churn)

    assert detection.evidence["tool_sets"] == 1
    assert detection.evidence["orders"] == 2
    assert detection.evidence["sets"][0]["requests_per_order"] == [10, 10]
    assert detection.evidence["sets"][0]["providers"] == ["anthropic"]
    assert detection.impact["requests"] == 20
    _valid(detection, test_api_key)


@pytest.mark.parametrize(
    ("orders", "cached", "prompt_tokens"),
    [
        (["a" * 64] * 17 + ["b" * 64] * 3, None, 2_000),
        (["a" * 64, "b" * 64] * 10, 600, 2_000),
        (["a" * 64, "b" * 64] * 10, None, 1_000),
    ],
)
@pytest.mark.asyncio
async def test_one_dominant_order_cache_reads_or_small_prompts_do_not_churn(
    db, test_api_key, orders, cached, prompt_tokens
) -> None:
    if cached is None:
        _orders(db, test_api_key, orders, prompt_tokens=prompt_tokens)
    else:
        # Cache reads on 12 of 20 rows.
        _orders(
            db, test_api_key, orders[:12], cached=cached, prompt_tokens=prompt_tokens
        )
        _orders(db, test_api_key, orders[12:], cached=0, prompt_tokens=prompt_tokens)

    assert await _run(db, test_api_key, service._cache_order_churn) == []


@pytest.mark.asyncio
async def test_rows_without_a_cache_field_count_as_misses(db, test_api_key) -> None:
    _orders(db, test_api_key, ["a" * 64, "b" * 64] * 10)

    [detection] = await _run(db, test_api_key, service._cache_order_churn)

    assert detection.evidence["cache_read_share"] == "0.0000"


@pytest.mark.asyncio
async def test_the_worker_raises_the_three_in_observe_and_only_for_shape_rows(
    db, test_api_key
) -> None:
    other = await _other_key(db)
    for index in range(50):
        offered = ["lookup", "create"]
        shape = _shape(
            tool_count=2,
            tools_offered=offered,
            tool_definition_chars=45_000,
            tools_order_digest=("a" if index % 2 else "b") * 64,
            tools_set_digest="1" * 64,
        )
        _add(
            db,
            test_api_key,
            shape,
            calls=["lookup"] if index == 0 else None,
            prompt_tokens=2_000,
        )
        _add(
            db,
            other,
            None,
            calls=["lookup"] if index == 0 else None,
            prompt_tokens=2_000,
        )
    await db.flush()

    await service.evaluate_organization(db, test_api_key.organization_id, now=NOW)
    await service.evaluate_organization(db, other.organization_id, now=NOW)
    rows = list(
        await db.scalars(
            select(Finding).where(
                Finding.organization_id.in_(
                    [test_api_key.organization_id, other.organization_id]
                )
            )
        )
    )

    assert {(row.organization_id, row.rule_id) for row in rows} == {
        (test_api_key.organization_id, service.OVERSIZED_PARTS),
        (test_api_key.organization_id, service.DEAD_TOOLS),
        (test_api_key.organization_id, service.CACHE_ORDER_CHURN),
    }
    for row in rows:
        spec = service.RULES[row.rule_id]
        assert (spec.MAX_MODE, spec.ACTION_KIND) == ("observe", None)
        assert (
            check(service.finding_from_row(row).model_dump(mode="json"), SCHEMA).valid
            is None
        )
