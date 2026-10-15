"""The change-test sender: which requests are copied, the caps, and the comparison."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
from types import SimpleNamespace

import pytest
from prometheus_client import REGISTRY
from sqlalchemy import select

from ee.tests.gateway.test_attempts import _deployment, origins  # noqa: F401
from ee.tests.observability.test_tasks import _request, _tenant
from shim.gateway.kernel.shadow import ShadowObservation, ShadowSelection
from shim.gateway.pipeline.analysis import AnalysisToolCall
from shim.rules import validate_rule_set
from shim_enterprise.billing.models import RequestLifecycle
from shim_enterprise.gateway import change_test
from shim_enterprise.gateway.change_test import ChangeTestSender, counter_key, sampled
from shim_enterprise.rules.estimators import change_test_estimate, estimate_change_test
from shim_enterprise.tenants.models import ModelDeployment

pytestmark = pytest.mark.usefixtures("origins")
NOW = datetime.now(timezone.utc)
STARTS = (NOW - timedelta(days=1)).replace(microsecond=0)
ENDS = STARTS + timedelta(days=7)
SCHEMA = {
    "type": "json_schema",
    "json_schema": {
        "name": "answer",
        "schema": {
            "type": "object",
            "properties": {"total": {"type": "integer"}},
            "required": ["total"],
        },
    },
}


def _shadow(rule_id: str = "llama4_degisiklik", state: str = "enforced", **match):
    return {
        "id": rule_id,
        "name": "Llama 4 change test",
        "kind": "route",
        "action": "route",
        "state": state,
        "scope": match.pop("scope", {}),
        "match": {
            "on": "shadow",
            "from": "kurum-llama",
            "to": "kurum-llama-4",
            "share_percent": 100,
            "starts_at": STARTS.isoformat(),
            "ends_at": ENDS.isoformat(),
            "max_requests": 1000,
            "max_cost_usd": "50",
            **match,
        },
    }


def _prepared(*rules: dict, request_id: str = "req_1", tags=(), **values):
    return SimpleNamespace(
        rules=validate_rule_set({"revision": 1, "rules": list(rules)})
        if rules
        else None,
        model="kurum-llama",
        request_id=request_id,
        admission=SimpleNamespace(tags=tags),
        deployment_kind="internal",
        api_key_id=None,
        tenant_id=values.pop("tenant_id", "00000000-0000-4000-8000-000000000001"),
        policy=SimpleNamespace(team_id=None),
        protocol="chat",
        pricing_model="kurum-llama-upstream",
        provider="openai",
        **values,
    )


class _Untouchable:
    redis = property(lambda self: pytest.fail("Redis was read"))


def _no_session():
    pytest.fail("a session was opened")


def _skips(reason: str) -> float:
    return (
        REGISTRY.get_sample_value("shim_change_test_skips_total", {"reason": reason})
        or 0
    )


def test_without_an_enforced_shadow_rule_select_does_nothing() -> None:
    sender = ChangeTestSender(_no_session, _Untouchable())  # type: ignore[arg-type]
    assert sender.select(_prepared()) is None
    assert sender.select(_prepared(_shadow(state="monitor"))) is None


@pytest.mark.parametrize(
    ("rules", "values", "selected"),
    [
        ((_shadow(),), {}, "llama4_degisiklik"),
        ((_shadow(**{"from": "other"}),), {}, None),
        ((_shadow(scope={"tags": ["mobil"]}),), {}, None),
        (
            (_shadow(scope={"tags": ["mobil"]}),),
            {"tags": ("mobil",)},
            "llama4_degisiklik",
        ),
        ((_shadow(starts_at=(NOW + timedelta(hours=1)).isoformat()),), {}, None),
        ((_shadow(ends_at=(NOW - timedelta(seconds=1)).isoformat()),), {}, None),
        ((_shadow("first"), _shadow("second", to="x")), {}, "first"),
    ],
)
def test_select_takes_the_first_test_in_scope_and_window(
    rules, values, selected
) -> None:
    sender = ChangeTestSender(_no_session, _Untouchable())  # type: ignore[arg-type]

    selection = sender.select(_prepared(*rules, **values))

    assert (selection.rule_id if selection else None) == selected
    if selection is not None:
        assert selection.keep_answer is True


def test_an_ended_test_is_not_selected() -> None:
    sender = ChangeTestSender(_no_session, _Untouchable())  # type: ignore[arg-type]
    sender.ended.add(("llama4_degisiklik", STARTS))

    assert sender.select(_prepared(_shadow())) is None


def test_sampling_is_pinned_and_close_to_the_share() -> None:
    assert sampled("llama4_degisiklik", "req_fixed", 10) is False
    assert sampled("llama4_degisiklik", "req_fixed", 70) is True
    picked = sum(sampled("r", f"req_{index}", 10) for index in range(10_000))
    assert 900 <= picked <= 1_100
    assert sum(sampled("r", f"req_{index}", 0.1) for index in range(10_000)) < 30
    assert all(sampled("r", f"req_{index}", 100) for index in range(1_000))


class _Redis:
    def __init__(self, values=None, error=False) -> None:
        self.values = dict(values or {})
        self.error = error
        self.floats: list[tuple[str, float]] = []

    def _check(self):
        if self.error:
            raise ConnectionError("down")

    async def exists(self, key):
        self._check()
        return int(key in self.values)

    async def set(self, key, value, nx=False, ex=None):
        self._check()
        if nx and key in self.values:
            return None
        self.values[key] = str(value)
        return True

    async def incr(self, key):
        self._check()
        self.values[key] = str(int(self.values.get(key, 0)) + 1)
        return int(self.values[key])

    async def get(self, key):
        self._check()
        return self.values.get(key)

    async def incrbyfloat(self, key, amount):
        self.floats.append((key, amount))


def _factory(db):
    @asynccontextmanager
    async def session():
        yield db

    return session


async def _candidate_setup(db, **match):
    user, key, _ = await _tenant(db)
    await _deployment(db, key, "kurum-llama")
    await _deployment(db, key, "kurum-llama-4")
    prepared = _prepared(_shadow(**match), tenant_id=user.organization_id)
    prepared.api_key_id = key.id
    return user, key, prepared


@pytest.mark.asyncio
async def test_copies_stop_at_max_requests_counting_from_the_ledger(
    db,
) -> None:
    user, key, prepared = await _candidate_setup(db, max_requests=3)
    # One copy of this test already settled before the counter existed.
    _request(
        db,
        key,
        None,
        cost="0.010",
        started_at=STARTS + timedelta(hours=1),
        shadow_rule_id="llama4_degisiklik",
    )
    await db.flush()
    redis = _Redis()
    sender = ChangeTestSender(_factory(db), SimpleNamespace(redis=redis))
    selection = ShadowSelection("llama4_degisiklik", "kurum-llama-4", True)
    before = _skips("cap_requests")

    answers = []
    for index in range(3):
        answers.append(await sender.candidate(prepared, selection))
        if answers[-1] is not None:
            # Sent: the copy counts, after the core guards let it through.
            await sender.compare(
                prepared,
                selection,
                _observation("req_primary", "a"),
                _observation(f"req_copy_{index}", "b", cost=None),
            )

    assert [answer is not None for answer in answers] == [True, True, False]
    key_name = counter_key(user.organization_id, "llama4_degisiklik", STARTS)
    assert Decimal(redis.values[f"{key_name}:usd"]) == Decimal("0.010")
    assert answers[0].provider_target.upstream_model == "kurum-llama-4-upstream"
    assert _skips("cap_requests") == before + 1
    assert ("llama4_degisiklik", STARTS) in sender.ended


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("redis", "rule", "allowed", "reason"),
    [
        ("spent", {}, None, "cap_cost"),
        (None, {}, None, "counter_unavailable"),
        ("error", {}, None, "counter_unavailable"),
        ("ok", {}, ["kurum-llama"], "target_not_allowed"),
        ("ok", {"disabled": True}, None, "target_unavailable"),
    ],
)
async def test_every_reason_for_no_copy_is_counted(
    db,
    redis,
    rule,
    allowed,
    reason,  # noqa: F811
) -> None:
    user, key, prepared = await _candidate_setup(db)
    if allowed is not None:
        key.allowed_models = allowed
    if rule.get("disabled"):
        row = await db.scalar(
            select(ModelDeployment).where(
                ModelDeployment.organization_id == user.organization_id,
                ModelDeployment.alias == "kurum-llama-4",
            )
        )
        row.enabled = False
    await db.flush()
    key_name = counter_key(user.organization_id, "llama4_degisiklik", STARTS)
    fake = {
        "spent": _Redis({f"{key_name}:n": "0", f"{key_name}:usd": "50"}),
        "error": _Redis(error=True),
        "ok": _Redis(),
        None: None,
    }[redis]
    sender = ChangeTestSender(_factory(db), SimpleNamespace(redis=fake))
    before = _skips(reason)

    answer = await sender.candidate(
        prepared, ShadowSelection("llama4_degisiklik", "kurum-llama-4", True)
    )

    assert answer is None
    assert _skips(reason) == before + 1
    if reason.startswith("target"):
        # A copy that cannot be sent takes nothing from the caps.
        assert fake.values == {}


def _observation(
    request_id: str,
    text: str | None,
    *,
    outcome: str | None = "complete",
    status: str = "completed",
    cost: str | None = "0.0004",
    truncated: bool = False,
    tool_calls=(),
) -> ShadowObservation:
    return ShadowObservation(
        request_id=request_id,
        status=status,
        completion_outcome=outcome,
        answer_text=text,
        prompt_tokens=310,
        completion_tokens=98,
        cost_usd=None if cost is None else Decimal(cost),
        provider_latency_ms=820,
        ttft_ms=None,
        error_code=None if text is not None else "PROVIDER_UNAVAILABLE",
        tool_calls=tool_calls,
        answer_truncated=truncated,
    )


async def _compare(
    db, primary_text, shadow_kwargs, *, analysis=(), pii=False, payload=None
):
    user, key, _ = await _tenant(db)
    copy_id = _request(
        db, key, None, shadow_of="req_primary", shadow_rule_id="llama4_degisiklik"
    )
    await db.flush()
    redis = _Redis()
    sender = ChangeTestSender(_factory(db), SimpleNamespace(redis=redis))
    prepared = _prepared(
        _shadow(),
        tenant_id=user.organization_id,
        pre_band_payload=payload
        or {
            "model": "kurum-llama",
            "messages": [{"role": "user", "content": "total?"}],
            "response_format": SCHEMA,
        },
        response_analysis=tuple(analysis),
        privacy=SimpleNamespace(pii_detected=pii),
    )
    await sender.compare(
        prepared,
        ShadowSelection("llama4_degisiklik", "kurum-llama-4", True),
        _observation("req_primary", primary_text),
        _observation(copy_id, **shadow_kwargs),
    )
    row = await db.scalar(
        select(RequestLifecycle)
        .where(RequestLifecycle.request_id == copy_id)
        .execution_options(populate_existing=True)
    )
    return row.lifecycle_metadata, redis, user


@pytest.mark.asyncio
async def test_a_valid_primary_and_an_invalid_candidate_are_recorded_without_text(
    db,
) -> None:
    primary, candidate = '{"total": 4}', '{"total": "dört bin"}'

    metadata, redis, user = await _compare(
        db, primary, {"text": candidate}, analysis=("language", "refusal")
    )

    record = metadata["shadow_comparison"]
    assert record["rule_id"] == "llama4_degisiklik"
    assert record["schema_expected"] == "json_schema"
    assert (record["primary"]["schema_valid"], record["candidate"]["schema_valid"]) == (
        True,
        False,
    )
    assert record["primary"]["answer_chars"] == len(primary)
    assert record["candidate"]["language"] is not None
    assert record["candidate"]["soft_refusal"] is False
    assert record["candidate"]["cost_usd"] == "0.0004"
    stored = json.dumps(metadata)
    assert "dört bin" not in stored and '"total": 4' not in stored
    # The other keys of the row are untouched.
    assert metadata["shadow_rule_id"] == "llama4_degisiklik"
    assert metadata["completion_outcome"] == "complete"
    assert redis.floats == [
        (
            f"{counter_key(user.organization_id, 'llama4_degisiklik', STARTS)}:usd",
            0.0004,
        )
    ]


@pytest.mark.asyncio
async def test_only_the_tenants_analyzers_run_beside_schema(db) -> None:
    metadata, _, _ = await _compare(db, '{"total": 4}', {"text": '{"total": 5}'})

    side = metadata["shadow_comparison"]["candidate"]
    assert (side["schema_valid"], side["language"], side["soft_refusal"]) == (
        True,
        None,
        None,
    )


@pytest.mark.asyncio
async def test_a_failed_copy_and_a_truncated_answer_leave_their_fields_null(db) -> None:
    failed, _, _ = await _compare(
        db, '{"total": 4}', {"text": None, "outcome": None, "status": "provider_error"}
    )
    truncated, _, _ = await _compare(
        db, '{"total": 4}', {"text": '{"total": 4', "truncated": True}
    )

    side = failed["shadow_comparison"]["candidate"]
    assert (side["outcome"], side["schema_valid"], side["answer_chars"]) == (
        "failed",
        None,
        None,
    )
    assert side["error_code"] == "PROVIDER_UNAVAILABLE"
    cut = truncated["shadow_comparison"]["candidate"]
    assert (cut["schema_valid"], cut["answer_truncated"]) == (None, True)


@pytest.mark.asyncio
async def test_tool_arguments_are_checked_against_the_tool_schema(db) -> None:
    payload = {
        "model": "kurum-llama",
        "messages": [{"role": "user", "content": "add"}],
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "add",
                    "parameters": {
                        "type": "object",
                        "properties": {"a": {"type": "integer"}},
                        "required": ["a"],
                    },
                },
            }
        ],
    }

    metadata, _, _ = await _compare(
        db,
        "",
        {"text": "", "tool_calls": (AnalysisToolCall("add", '{"a": "x"}'),)},
        payload=payload,
    )

    record = metadata["shadow_comparison"]
    assert record["candidate"]["schema_valid"] is False
    assert '"a": "x"' not in json.dumps(metadata)


@pytest.mark.asyncio
async def test_after_a_request_with_personal_data_no_answer_is_analysed(db) -> None:
    metadata, _, _ = await _compare(
        db, '{"total": 4}', {"text": '{"total": "x"}'}, pii=True
    )

    record = metadata["shadow_comparison"]
    assert record["schema_expected"] is None
    assert record["candidate"]["schema_valid"] is None
    assert record["candidate"]["answer_chars"] == len('{"total": "x"}')


@pytest.mark.asyncio
async def test_a_failing_write_is_counted_and_swallowed(db, monkeypatch) -> None:
    async def broken(*args, **kwargs):
        raise RuntimeError("database down")

    monkeypatch.setattr(change_test.RequestLifecycleRepository, "update", broken)
    before = (
        REGISTRY.get_sample_value(
            "shim_change_test_comparisons_total", {"result": "failed"}
        )
        or 0
    )

    await _compare(db, '{"total": 4}', {"text": '{"total": 4}'})

    assert (
        REGISTRY.get_sample_value(
            "shim_change_test_comparisons_total", {"result": "failed"}
        )
        == before + 1
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("priced", [True, False])
async def test_the_estimate_counts_the_share_and_prices_it_at_the_candidate(
    db,
    priced,  # noqa: F811
) -> None:
    user, key, _ = await _tenant(db)
    await _deployment(
        db,
        key,
        "kurum-llama-4",
        **(
            {
                "input_price_per_million": Decimal("1"),
                "output_price_per_million": Decimal("2"),
            }
            if priced
            else {}
        ),
    )
    for _ in range(10):
        _request(
            db,
            key,
            None,
            model="kurum-llama",
            started_at=NOW - timedelta(hours=1),
            prompt_tokens=1_000,
            completion_tokens=500,
        )
    await db.flush()
    rule = validate_rule_set(
        {"revision": 1, "rules": [_shadow(share_percent=50, max_requests=4)]}
    ).rules[0]

    estimate = await change_test_estimate(
        db, user.organization_id, rule, NOW - timedelta(days=7), NOW
    )
    preview = await estimate_change_test(
        db, user.organization_id, rule, NOW - timedelta(days=7), NOW
    )

    assert (estimate["requests"], estimate["would_copy"]) == (10, 4)
    assert preview["requests"] == 4
    if priced:
        # Half of 10,000 prompt and 5,000 completion tokens at 1 and 2 USD a million.
        assert Decimal(estimate["extra_cost_usd"]) == Decimal("0.01")
        assert preview["note"] == "estimated extra cost USD 0.010000"
    else:
        assert (estimate["extra_cost_usd"], estimate["priced"]) == (None, False)
        assert preview["note"] == "candidate unpriced"
