"""The live check strategy on a marked scope, with a stand-in kernel and real rows."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
import time
from types import MethodType, SimpleNamespace
from uuid import UUID, uuid4

from fastapi import HTTPException
from fastapi.responses import JSONResponse
import pytest
from sqlalchemy import select

from ee.tests.gateway.test_attempts import _deployment, origins  # noqa: F401
from ee.tests.observability.test_tasks import _request, _tenant
from ee.tests.rules.test_rules_resource import MANAGEMENT, _call
from shim.gateway.kernel.result import PreparedInference
from shim.rules.model import RuleMatch
from shim_enterprise.billing.models import RequestLifecycle
from shim_enterprise.semantic import live
from shim_enterprise.semantic.call import CHECK_TAG
from shim_enterprise.semantic.live import SemanticPreCheck, counter_key
from shim_enterprise.semantic.models import OrganizationSemanticQuestions
from shim_enterprise.tenants.gateway_settings import (
    GatewaySettings,
    SemanticCheckSettings,
)

pytestmark = pytest.mark.usefixtures("origins")
TEXT = "Satın alacağımız şirketin adı"
CHECK_KEY = UUID("00000000-0000-4000-8000-00000000000a")
OTHER_KEY = UUID("00000000-0000-4000-8000-00000000000b")
QUESTION = {
    "id": "atlas",
    "text": "The request discusses Project Atlas.",
    "examples": [],
}


class _Redis:
    def __init__(self, error: bool = False) -> None:
        self.values: dict[str, int] = {}
        self.error = error

    async def incr(self, key):
        if self.error:
            raise ConnectionError("down")
        self.values[key] = self.values.get(key, 0) + 1
        return self.values[key]

    async def expire(self, key, seconds):
        return True


class _Kernel:
    def __init__(self, mode: str = "match", delay: float = 0) -> None:
        self.mode = mode
        self.delay = delay
        self.calls = 0
        self.cancelled = False

    async def execute(self, invocation):
        self.calls += 1
        try:
            await asyncio.sleep(self.delay)
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        if self.mode == "blocked":
            raise HTTPException(400, detail={"code": "RULE_BLOCKED"})
        if self.mode == "down":
            return JSONResponse({"error": {}}, status_code=503)
        answer = (
            "not json"
            if self.mode == "bad"
            else json.dumps(
                {"matches": [{"question_id": "atlas", "match": self.mode == "match"}]}
            )
        )
        return JSONResponse(
            {"choices": [{"index": 0, "message": {"content": answer}}]},
            headers={"x-shim-request-id": "req_check_1"},
        )


class _Untouchable:
    @property
    def redis(self):
        pytest.fail("Redis was read")


def _no_session():
    pytest.fail("a session was opened")


def _factory(db):
    @asynccontextmanager
    async def session():
        yield db

    return session


def _prepared(check: dict | None, **values) -> SimpleNamespace:
    prepared = SimpleNamespace(
        tenant_gateway_settings=None
        if check is None
        else GatewaySettings(
            semantic_check=SemanticCheckSettings.model_validate(check)
        ),
        protocol=values.pop("protocol", "chat"),
        admission=SimpleNamespace(tags=values.pop("tags", ("hukuk",))),
        api_key_id=values.pop("api_key_id", None),
        model=values.pop("model", "asistan"),
        tenant_id=values.pop("tenant_id", None),
        deployment_kind=values.pop("deployment_kind", "internal"),
        privacy=SimpleNamespace(pii_detected=values.pop("pii_detected", False)),
        rule_matches=values.pop("rule_matches", []),
        rules=None,
        payload={"messages": [{"role": "user", "content": TEXT}]},
        request_id=values.pop("request_id", "req_marked"),
        warnings=[],
        **values,
    )
    prepared.warn = MethodType(PreparedInference.warn, prepared)
    return prepared


def _check(key, **values) -> dict:
    return {
        "enabled": True,
        "scope": {"tags": ["hukuk"]},
        "model": "kontrol",
        "api_key_id": str(key.id),
        "warn_header": True,
        **values,
    }


async def _setup(
    db, check_kind: str = "internal", check_url: str = "https://a.internal/v1"
):
    user, key, check_key = await _tenant(db)
    await _deployment(
        db, key, "kontrol", deployment_kind=check_kind, base_url=check_url
    )
    db.add(
        OrganizationSemanticQuestions(
            organization_id=user.organization_id, revision=3, questions=[QUESTION]
        )
    )
    request_id = _request(db, key, None)
    await db.flush()
    return user, key, check_key, request_id


async def _record(db, request_id) -> dict | None:
    row = await db.scalar(
        select(RequestLifecycle)
        .where(RequestLifecycle.request_id == request_id)
        .execution_options(populate_existing=True)
    )
    return row.lifecycle_metadata.get("semantic_check")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("check", "values"),
    [
        (None, {}),
        ({"enabled": False}, {}),
        ({}, {"tags": ("other",)}),
        ({"scope": {"models": ["asistan"]}}, {"model": "other"}),
        ({"scope": {"api_key_ids": [OTHER_KEY]}}, {}),
        ({"endpoints": ["messages"]}, {}),
        ({}, {"tags": ("hukuk", CHECK_TAG), "api_key_id": CHECK_KEY}),
        ({}, {"api_key_id": CHECK_KEY}),
    ],
)
async def test_out_of_scope_requests_cost_nothing(check, values) -> None:
    strategy = SemanticPreCheck(_no_session, _Untouchable())  # type: ignore[arg-type]
    strategy.kernel = None
    if check is not None and check != {"enabled": False}:
        check = _check(SimpleNamespace(id=CHECK_KEY), **check)
    prepared = _prepared(check, **values)

    assert await strategy.after_privacy(prepared) is None
    assert prepared.warnings == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mode", "outcome", "warned"),
    [
        ("match", "matched", True),
        ("clear", "clear", False),
        ("bad", "invalid_answer", False),
        ("down", "failed", False),
        ("blocked", "failed", False),
    ],
)
async def test_each_outcome_is_recorded_and_only_a_match_warns(
    db, mode, outcome, warned
) -> None:
    user, _, check_key, request_id = await _setup(db)
    strategy = SemanticPreCheck(_factory(db), SimpleNamespace(redis=_Redis()))
    strategy.kernel = _Kernel(mode)
    prepared = _prepared(
        _check(check_key), tenant_id=user.organization_id, request_id=request_id
    )

    assert await strategy.after_privacy(prepared) is None

    assert prepared.warnings == (["SEMANTIC_WARN"] if warned else [])
    record = await _record(db, request_id)
    assert record["outcome"] == outcome
    assert record["prompt_version"] == "semantic-v1"
    assert isinstance(record["latency_ms"], int)
    if mode != "blocked":
        assert record["questions_revision"] == 3
    assert TEXT not in json.dumps(record)
    if mode == "match":
        assert (record["matched"], record["check_request_id"]) == (
            ["atlas"],
            "req_check_1",
        )


@pytest.mark.asyncio
async def test_a_match_without_the_header_switch_is_only_recorded(db) -> None:
    user, _, check_key, request_id = await _setup(db)
    strategy = SemanticPreCheck(_factory(db), SimpleNamespace(redis=_Redis()))
    strategy.kernel = _Kernel("match")
    prepared = _prepared(
        _check(check_key, warn_header=False),
        tenant_id=user.organization_id,
        request_id=request_id,
    )

    await strategy.after_privacy(prepared)

    assert prepared.warnings == []
    assert (await _record(db, request_id))["outcome"] == "matched"


@pytest.mark.asyncio
async def test_a_slow_check_is_cancelled_at_the_timeout(db) -> None:
    user, _, check_key, request_id = await _setup(db)
    kernel = _Kernel("match", delay=5)
    strategy = SemanticPreCheck(_factory(db), SimpleNamespace(redis=_Redis()))
    strategy.kernel = kernel
    prepared = _prepared(
        _check(check_key, timeout_ms=500),
        tenant_id=user.organization_id,
        request_id=request_id,
    )

    started = time.monotonic()
    await strategy.after_privacy(prepared)

    assert time.monotonic() - started < 0.5 + 0.1
    assert kernel.cancelled
    assert (await _record(db, request_id))["outcome"] == "timeout"
    assert prepared.warnings == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("detected", "outcome"),
    [
        ({"pii_detected": True}, "skipped_guard"),
        (
            {
                "rule_matches": [
                    RuleMatch(
                        rule_id="falcon",
                        kind="term",
                        action="monitor",
                        state="monitor",
                        count=1,
                    )
                ]
            },
            "skipped_guard",
        ),
        ({}, "matched"),
    ],
)
@pytest.mark.parametrize(
    ("check_kind", "check_url"),
    [
        ("external", "https://a.internal/v1"),
        # Labelled internal, but outside the operator's internal origins.
        ("internal", "https://b.internal/v1"),
    ],
)
async def test_an_internal_request_reaches_an_external_check_model_only_when_clean(
    db, detected, outcome, check_kind, check_url
) -> None:
    user, _, check_key, request_id = await _setup(db, check_kind, check_url)
    strategy = SemanticPreCheck(_factory(db), SimpleNamespace(redis=_Redis()))
    strategy.kernel = _Kernel("match")

    await strategy.after_privacy(
        _prepared(
            _check(check_key),
            tenant_id=user.organization_id,
            request_id=request_id,
            **detected,
        )
    )

    assert (await _record(db, request_id))["outcome"] == outcome


@pytest.mark.asyncio
async def test_a_slow_database_counts_toward_the_timeout(db) -> None:
    user, _, check_key, request_id = await _setup(db)
    opened = []

    @asynccontextmanager
    async def slow():
        # The first session (the target and question reads) hangs; the record does not.
        opened.append(1)
        if len(opened) == 1:
            await asyncio.sleep(5)
        yield db

    strategy = SemanticPreCheck(slow, SimpleNamespace(redis=_Redis()))
    strategy.kernel = _Kernel("match")
    prepared = _prepared(
        _check(check_key, timeout_ms=500),
        tenant_id=user.organization_id,
        request_id=request_id,
    )

    started = time.monotonic()
    await strategy.after_privacy(prepared)

    assert time.monotonic() - started < 0.5 + 0.1
    assert (await _record(db, request_id))["outcome"] == "timeout"


@pytest.mark.asyncio
async def test_the_daily_cap_counts_and_a_counter_error_skips(db) -> None:
    user, _, check_key, request_id = await _setup(db)
    redis = _Redis()
    strategy = SemanticPreCheck(_factory(db), SimpleNamespace(redis=redis))
    strategy.kernel = _Kernel("clear")
    outcomes = []
    for _ in range(3):
        await strategy.after_privacy(
            _prepared(
                _check(check_key, max_checks_per_day=2),
                tenant_id=user.organization_id,
                request_id=request_id,
            )
        )
        outcomes.append((await _record(db, request_id))["outcome"])
    broken = SemanticPreCheck(_factory(db), SimpleNamespace(redis=_Redis(error=True)))
    broken.kernel = _Kernel("clear")
    await broken.after_privacy(
        _prepared(
            _check(check_key), tenant_id=user.organization_id, request_id=request_id
        )
    )

    assert outcomes == ["clear", "clear", "skipped_cap"]
    assert list(redis.values) == [
        counter_key(user.organization_id, datetime.now(timezone.utc))
    ]
    assert (await _record(db, request_id))["outcome"] == "skipped_cap"


@pytest.mark.asyncio
async def test_questions_are_cached_a_minute_and_the_cache_is_bounded(
    db, monkeypatch
) -> None:
    user, _, _, _ = await _setup(db)
    strategy = SemanticPreCheck(_factory(db), None)
    clock = [1_000.0]
    monkeypatch.setattr(live, "monotonic", lambda: clock[0])

    first = await strategy._questions(db, user.organization_id)
    row = await db.get(OrganizationSemanticQuestions, user.organization_id)
    row.questions, row.revision = [], 4
    await db.flush()
    cached = await strategy._questions(db, user.organization_id)
    clock[0] += 61
    fresh = await strategy._questions(db, user.organization_id)
    for index in range(1_100):
        strategy.questions[index] = (clock[0], 0, [])
        strategy.questions.move_to_end(index)
    await strategy._questions(db, uuid4())

    assert first == cached == (3, [QUESTION])
    assert fresh == (4, [])
    assert len(strategy.questions) == 1_024


@pytest.mark.asyncio
async def test_a_failure_inside_the_strategy_never_reaches_the_request(db) -> None:
    user, _, check_key, request_id = await _setup(db)

    @asynccontextmanager
    async def broken():
        raise RuntimeError("database down")
        yield

    strategy = SemanticPreCheck(broken, SimpleNamespace(redis=_Redis()))
    strategy.kernel = _Kernel("match")

    assert (
        await strategy.after_privacy(
            _prepared(
                _check(check_key), tenant_id=user.organization_id, request_id=request_id
            )
        )
        is None
    )


class _Counter:
    def __init__(self, value) -> None:
        self.value = value

    async def get(self, key):
        return self.value


@pytest.mark.asyncio
async def test_the_read_counts_outcomes_latency_and_cost_of_its_own_tenant(db) -> None:
    user, key, check_key, _ = await _setup(db)
    other, other_key, _ = await _tenant(db)
    now = datetime.now(timezone.utc)
    check_ids = [
        _request(db, check_key, None, cost="0.002", started_at=now) for _ in range(2)
    ]
    for latency, outcome, check_id in [
        (100, "matched", check_ids[0]),
        (300, "clear", check_ids[1]),
        (3_000, "timeout", None),
    ]:
        _request(
            db,
            key,
            None,
            settled=False,
            started_at=now,
            semantic_check={
                "outcome": outcome,
                "latency_ms": latency,
                "check_request_id": check_id,
            },
        )
    _request(
        db,
        other_key,
        None,
        settled=False,
        started_at=now,
        semantic_check={"outcome": "matched", "latency_ms": 9},
    )
    await db.flush()
    path = f"{MANAGEMENT}/semantic-check"

    read = await _call(
        db, user, "GET", path, cache=SimpleNamespace(redis=_Counter(b"7"))
    )
    unread = await _call(db, user, "GET", path)
    user.role = "member"
    member = await _call(db, user, "GET", path)

    body = read.json()
    assert read.status_code == 200, read.text
    assert (body["enabled"], body["checks_today"], body["max_checks_per_day"]) == (
        False,
        7,
        1_000,
    )
    assert {k: v for k, v in body["outcomes"].items() if v} == {
        "matched": 1,
        "clear": 1,
        "timeout": 1,
    }
    assert body["latency_ms_p50"] == 300
    assert Decimal(body["cost_usd"]) == Decimal("0.004")
    assert Decimal(body["cost_usd_per_check"]) == Decimal("0.002")
    assert unread.json()["checks_today"] is None
    assert member.status_code == 403


@pytest.mark.asyncio
async def test_the_finding_counts_matched_checks_per_key_in_a_day(db) -> None:
    from shim_enterprise.findings import service

    user, key, _, _ = await _setup(db)
    now = datetime.now(timezone.utc)
    ids = [
        _request(
            db,
            key,
            None,
            settled=False,
            started_at=now - timedelta(hours=hours),
            semantic_check={"outcome": outcome, "matched": matched},
        )
        for hours, outcome, matched in [
            (1, "matched", ["atlas"]),
            (2, "matched", ["atlas", "orion"]),
            (3, "clear", []),
            (4, "skipped_cap", None),
            # Older than the window: not counted.
            (25, "matched", ["atlas"]),
        ]
    ]
    await db.flush()

    [found] = await service._semantic_check_matches(db, user.organization_id, now)

    assert found.subject == {"api_key_id": str(key.id)}
    assert found.evidence == {
        "window_hours": 24,
        "matched_requests": 2,
        "checked_requests": 3,
        "questions_matched": 2,
        "request_ids": [ids[1], ids[0]],
    }
    assert service.RULES[service.SEMANTIC_CHECK_MATCH].MAX_MODE == "observe"
