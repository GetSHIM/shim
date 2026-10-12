from __future__ import annotations

from collections.abc import Iterator
import copy
from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
import json
from typing import Any
from uuid import UUID

from pydantic import SecretBytes
import pytest

from shim.gateway.contracts.context import (
    AuditPolicy,
    GatewayContext,
    PrivacyPolicy,
    TierPolicy,
)
from shim.gateway.contracts.ids import ApiKeyId, ProviderId, RequestId, TenantId
from shim.gateway.kernel.result import (
    AdmissionState,
    PreparedInference,
    ProviderTarget,
)
from shim.gateway.pipeline.settings_band import (
    STEPS,
    SettingsBandStage,
    pins_in_scope,
)
from shim.gateway.request_policy import BandSettings, RequestPolicyContext
from shim.privacy.policies import PrivacyAction, PrivacyOutcome
from shim.rules import RuleSet, validate_rule_set

_CONTENT_FIELDS = (
    "messages",
    "input",
    "contents",
    "system",
    "systemInstruction",
    "instructions",
)


def _strings(value: object, path: tuple[object, ...] = ()) -> Iterator[tuple]:
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _strings(item, (*path, key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _strings(item, (*path, index))


def assert_content_untouched(before: dict[str, Any], after: dict[str, Any]) -> None:
    """No band step changes a string of the conversation or of a tool description."""

    for field in _CONTENT_FIELDS:
        assert list(_strings(before.get(field))) == list(_strings(after.get(field)))
    descriptions = [
        [text for path, text in _strings(payload.get("tools")) if "description" in path]
        for payload in (before, after)
    ]
    assert descriptions[0] == descriptions[1]


_PROVIDERS = {
    "chat": "openai",
    "responses": "openai",
    "messages": "anthropic",
    "count_tokens": "anthropic",
    "generate_content": "google",
}
_PAYLOADS: dict[str, dict[str, Any]] = {
    "chat": {
        "model": "gpt-5-nano",
        "messages": [{"role": "user", "content": "temperature 0.7 please"}],
        "tools": [{"type": "function", "function": {"name": "f", "description": "d"}}],
    },
    "responses": {"model": "gpt-5-nano", "instructions": "be brief", "input": "hi"},
    "messages": {
        "model": "claude-sonnet-4-6",
        "max_tokens": 16,
        "system": "be brief",
        "messages": [{"role": "user", "content": "hi"}],
    },
    "count_tokens": {
        "model": "claude-sonnet-4-6",
        "messages": [{"role": "user", "content": "hi"}],
    },
    "generate_content": {
        "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
        "generationConfig": {"maxOutputTokens": 16},
    },
}


def _rules(*rules: dict[str, Any]) -> RuleSet:
    return validate_rule_set(
        {
            "revision": 7,
            "rules": [
                {
                    "id": "pin",
                    "name": "n",
                    "kind": "parameter_pin",
                    "action": "set",
                    "state": "enforced",
                    "match": {"parameter": "temperature", "value": 0},
                    **rule,
                }
                for rule in rules or ({},)
            ],
        }
    )


def _prepared(protocol: str, rules: RuleSet, **fields: Any) -> PreparedInference:
    context = GatewayContext(
        request_id=RequestId("req_band"),
        tenant_id=TenantId(UUID("11111111-1111-1111-1111-111111111111")),
        actor_type="api_key",
        api_key_id=ApiKeyId(UUID("22222222-2222-2222-2222-222222222222")),
        user_id=None,
        endpoint="/v1/chat/completions",
        started_at=datetime(2026, 10, 12, tzinfo=UTC),
        tier_policy=TierPolicy(rate_limit_rpm=60),
        privacy_policy=PrivacyPolicy(pii_mode="scrub"),
        audit_policy=AuditPolicy(mode="best_effort"),
    )
    payload = copy.deepcopy(_PAYLOADS[protocol])
    payload.update(fields)
    return PreparedInference(
        context=context,
        payload=payload,
        provider=ProviderId(_PROVIDERS[protocol]),
        protocol=protocol,  # type: ignore[arg-type]
        model=payload.get("model", "gemini-3.5-flash"),
        stream=False,
        policy=RequestPolicyContext(rate_limit_key_hash="h", tier="t"),
        pii_config=None,
        admission=AdmissionState(
            estimated_input_tokens=1,
            maximum_output_tokens=16,
            cost_center="untagged",
            tags=(),
        ),
        rules=rules,
    )


async def _run(prepared: PreparedInference):
    before = copy.deepcopy(prepared.payload)
    banded, blocked = await SettingsBandStage(pins_in_scope(prepared)).run(prepared)
    assert prepared.payload == before, "the band never changes the payload it got"
    assert_content_untouched(before, banded.payload)
    verdicts = {
        verdict.rule_id: (verdict.stage, verdict.outcome, verdict.reason_code)
        for verdict in banded.policy_verdicts
    }
    return banded, blocked, verdicts


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("protocol", "parameter", "value", "fields", "expected"),
    [
        ("chat", "temperature", 0, {"temperature": 0.7}, {"temperature": 0}),
        ("chat", "seed", 42, {}, {"seed": 42}),
        ("chat", "reasoning_effort", "low", {}, {"reasoning_effort": "low"}),
        ("responses", "temperature", 0, {}, {"temperature": 0}),
        (
            "responses",
            "reasoning_effort",
            "minimal",
            {"reasoning": {"summary": "auto"}},
            {"reasoning": {"summary": "auto", "effort": "minimal"}},
        ),
        (
            "responses",
            "reasoning_effort",
            "high",
            {"reasoning": None},
            {"reasoning": {"effort": "high"}},
        ),
        ("messages", "top_k", 40, {"top_k": 5}, {"top_k": 40}),
        ("messages", "top_p", 0.9, {}, {"top_p": 0.9}),
        (
            "generate_content",
            "temperature",
            0,
            {},
            {"generationConfig": {"maxOutputTokens": 16, "temperature": 0}},
        ),
        (
            "generate_content",
            "seed",
            7,
            {"generationConfig": {"seed": 1, "topK": 3}},
            {"generationConfig": {"seed": 7, "topK": 3}},
        ),
    ],
)
async def test_an_enforced_set_writes_the_value_where_the_protocol_keeps_it(
    protocol, parameter, value, fields, expected
) -> None:
    rules = _rules({"match": {"parameter": parameter, "value": value}})

    banded, blocked, verdicts = await _run(_prepared(protocol, rules, **fields))

    assert blocked is None
    assert {key: banded.payload[key] for key in expected} == expected
    assert banded.settings_applied == ({"id": "parameter_pin.pin", "version": 7},)
    assert verdicts["rule.pin"] == ("settings", "allow", "RULE_SET")
    assert [(m.rule_id, m.count) for m in banded.rule_matches] == [("pin", 1)]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("sent", "matches"),
    [(0, False), (0.0, False), (0.7, True), (None, True), ("0", True), (False, True)],
)
async def test_a_pin_matches_when_the_value_is_absent_or_differs(sent, matches) -> None:
    fields = {} if sent is None else {"temperature": sent}
    prepared = _prepared("chat", _rules(), **fields)

    banded, _, verdicts = await _run(prepared)

    assert bool(banded.rule_matches) is matches
    assert ("rule.pin" in verdicts) is matches
    assert banded.settings_applied == (
        ({"id": "parameter_pin.pin", "version": 7},) if matches else ()
    )
    if not matches:
        assert banded.payload is prepared.payload


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("rule", "reason"),
    [
        ({"state": "monitor"}, "RULE_WOULD_SET"),
        ({"state": "monitor", "action": "block"}, "RULE_WOULD_BLOCK"),
        ({"action": "monitor"}, "RULE_MONITORED"),
        ({"action": "warn"}, "RULE_WARN"),
    ],
)
async def test_monitor_warn_and_monitor_state_change_nothing(rule, reason) -> None:
    prepared = _prepared("chat", _rules(rule), temperature=0.7)

    banded, blocked, verdicts = await _run(prepared)

    assert blocked is None and banded.payload is prepared.payload
    assert banded.settings_applied == ()
    assert verdicts["rule.pin"] == ("settings", "allow", reason)
    assert banded.warnings == (["RULE_WARN"] if reason == "RULE_WARN" else [])


@pytest.mark.asyncio
async def test_an_enforced_block_returns_its_rule_and_applies_nothing() -> None:
    rules = _rules(
        {"id": "seed_set", "match": {"parameter": "seed", "value": 1}},
        {"id": "temp_block", "action": "block"},
    )

    banded, blocked, verdicts = await _run(_prepared("chat", rules, temperature=0.7))

    assert blocked == "temp_block"
    assert banded.payload == _prepared("chat", rules, temperature=0.7).payload
    assert banded.settings_applied == ()
    assert verdicts["rule.temp_block"] == ("settings", "deny", "RULE_BLOCKED")


@pytest.mark.asyncio
async def test_the_lowest_enforced_pin_wins_and_shadows_the_others() -> None:
    rules = _rules(
        {"id": "b_zero", "action": "block"},
        {"id": "a_half", "match": {"parameter": "temperature", "value": 0.5}},
        {
            "id": "c_watch",
            "state": "monitor",
            "match": {"parameter": "temperature", "value": 1},
        },
    )

    banded, blocked, verdicts = await _run(_prepared("chat", rules, temperature=0.7))

    assert blocked is None and banded.payload["temperature"] == 0.5
    assert verdicts["rule.a_half"] == ("settings", "allow", "RULE_SET")
    assert verdicts["rule.b_zero"] == ("settings", "skip", "RULE_PIN_SHADOWED")
    assert verdicts["rule.c_watch"] == ("settings", "allow", "RULE_WOULD_SET")
    assert [m.rule_id for m in banded.rule_matches] == ["a_half", "c_watch"]


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["enabled", "adaptive"])
async def test_thinking_requests_skip_temperature_and_top_k_pins(kind) -> None:
    rules = _rules(
        {"id": "temp"},
        {"id": "topk", "match": {"parameter": "top_k", "value": 5}},
        {"id": "topp", "match": {"parameter": "top_p", "value": 0.95}},
    )
    thinking = {"type": kind, **({"budget_tokens": 1024} if kind == "enabled" else {})}
    prepared = _prepared("messages", rules, thinking=thinking, temperature=1)

    banded, blocked, verdicts = await _run(prepared)

    assert blocked is None
    assert banded.payload["temperature"] == 1 and "top_k" not in banded.payload
    assert banded.payload["top_p"] == 0.95
    assert verdicts["rule.temp"] == ("settings", "skip", "RULE_PIN_INCOMPATIBLE")
    assert verdicts["rule.topk"] == ("settings", "skip", "RULE_PIN_INCOMPATIBLE")
    assert banded.settings_applied == ({"id": "parameter_pin.topp", "version": 7},)


@pytest.mark.asyncio
async def test_disabled_thinking_takes_the_pin() -> None:
    prepared = _prepared("messages", _rules(), thinking={"type": "disabled"})

    banded, _, verdicts = await _run(prepared)

    assert banded.payload["temperature"] == 0
    assert verdicts["rule.pin"] == ("settings", "allow", "RULE_SET")


def test_only_pins_in_scope_whose_parameter_the_protocol_has_run() -> None:
    rules = _rules(
        {"id": "seed", "match": {"parameter": "seed", "value": 1}},
        {"id": "other_model", "scope": {"models": ["gpt-5"]}},
        {"id": "temp"},
    )

    assert [rule.id for rule in pins_in_scope(_prepared("responses", rules))] == [
        "temp"
    ]
    assert pins_in_scope(_prepared("count_tokens", rules)) == []
    assert pins_in_scope(_prepared("chat", RuleSet(revision=1, rules=()))) == []


@pytest.mark.asyncio
async def test_the_span_counts_applied_steps_and_the_record_is_json() -> None:
    stage = SettingsBandStage([])
    banded, _ = await stage.run(_prepared("chat", _rules(), temperature=0.7))
    assert stage.trace_metadata((banded, None)) == {"settings_applied": 0}

    rules = _rules()
    stage = SettingsBandStage(pins_in_scope(_prepared("chat", rules)))
    banded, _ = await stage.run(_prepared("chat", rules, temperature=0.7))
    assert stage.trace_metadata((banded, None)) == {"settings_applied": 1}
    assert json.loads(json.dumps(banded.settings_applied)) == [
        {"id": "parameter_pin.pin", "version": 7}
    ]


# Provider cache steps (S54).


def _cached(
    protocol: str,
    *,
    band: dict[str, Any],
    key: str = "22222222-2222-2222-2222-222222222222",
    **fields: Any,
) -> PreparedInference:
    prepared = _prepared(protocol, None, **fields)
    return replace(
        prepared,
        band=BandSettings(**band),
        context=prepared.context.model_copy(update={"api_key_id": ApiKeyId(UUID(key))}),
    )


async def _band(prepared: PreparedInference) -> PreparedInference:
    before = copy.deepcopy(prepared.payload)
    banded, blocked = await SettingsBandStage([]).run(prepared)
    assert blocked is None and prepared.payload == before
    assert_content_untouched(before, banded.payload)
    return banded


_BREAKPOINT = {"type": "ephemeral"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("ttl", "marker"),
    [("5m", {"type": "ephemeral"}), ("1h", {"type": "ephemeral", "ttl": "1h"})],
)
async def test_auto_cache_adds_one_top_level_breakpoint(ttl, marker) -> None:
    prepared = _cached("messages", band={"anthropic_auto_cache": ttl})

    banded = await _band(prepared)

    assert banded.payload == {**prepared.payload, "cache_control": marker}
    assert banded.settings_applied == ({"id": "anthropic_auto_cache", "version": 1},)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fields",
    [
        {"cache_control": _BREAKPOINT},
        {"system": [{"type": "text", "text": "s", "cache_control": _BREAKPOINT}]},
        {"tools": [{"name": "t", "input_schema": {}, "cache_control": _BREAKPOINT}]},
        {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "x", "cache_control": _BREAKPOINT}
                    ],
                }
            ]
        },
        {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "t1",
                            "content": [
                                {
                                    "type": "text",
                                    "text": "x",
                                    "cache_control": _BREAKPOINT,
                                }
                            ],
                        }
                    ],
                }
            ]
        },
    ],
)
async def test_a_client_breakpoint_anywhere_keeps_full_control(fields) -> None:
    prepared = _cached("messages", band={"anthropic_auto_cache": "5m"}, **fields)

    banded = await _band(prepared)

    assert banded.payload is prepared.payload and banded.settings_applied == ()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("placeholder_key", "mapping", "applied"),
    [
        (None, {"<EMAIL_ADDRESS_a1>": "a@example.com"}, False),
        (None, {}, True),
        (SecretBytes(b"k" * 32), {"<EMAIL_ADDRESS_a1>": "a@example.com"}, True),
    ],
)
async def test_random_placeholders_with_a_detection_skip_auto_cache(
    placeholder_key, mapping, applied
) -> None:
    prepared = replace(
        _cached("messages", band={"anthropic_auto_cache": "5m"}),
        placeholder_key=placeholder_key,
        privacy=PrivacyOutcome(
            action=PrivacyAction.SCRUBBED if mapping else PrivacyAction.DETECTED,
            pii_detected=bool(mapping),
            verification_map=mapping,
        ),
    )

    banded = await _band(prepared)

    assert ("cache_control" in banded.payload) is applied


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", ["generate_content", "chat"])
async def test_auto_cache_touches_messages_only(protocol) -> None:
    prepared = _cached(protocol, band={"anthropic_auto_cache": "5m"})

    banded = await _band(prepared)

    assert banded.payload is prepared.payload and banded.settings_applied == ()


def test_token_counting_never_runs_a_band_step() -> None:
    assert all("count_tokens" not in protocols for _, _, protocols, _ in STEPS)
    assert [step[0] for step in STEPS] == [
        "anthropic_auto_cache",
        "openai_prompt_cache_key",
    ]


_TARGET = ProviderTarget(
    deployment_id="d",
    base_url="https://models.internal.test/v1",
    upstream_model="m",
    credential_reference="c",
    timeout_seconds=30,
    declared_version="1",
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("target", "listed", "applied"),
    [(None, (), True), (_TARGET, (), False), (_TARGET, ("claude-sonnet-4-6",), True)],
)
async def test_registry_targets_take_the_steps_only_when_listed(
    target, listed, applied
) -> None:
    band = {
        "anthropic_auto_cache": "5m",
        "openai_prompt_cache_key": "key",
        "provider_cache_deployments": listed,
    }
    messages = replace(_cached("messages", band=band), target=target)
    chat = replace(
        _cached("chat", band={**band, "provider_cache_deployments": ()}), target=target
    )

    assert ("cache_control" in (await _band(messages)).payload) is applied
    assert ("prompt_cache_key" in (await _band(chat)).payload) is (target is None)


def _key(prepared: PreparedInference) -> str:
    return prepared.payload["prompt_cache_key"]


_OTHER_KEY = "33333333-3333-3333-3333-333333333333"


@pytest.mark.asyncio
async def test_the_prompt_cache_key_follows_the_prefix_and_the_scope() -> None:
    system = [{"role": "system", "content": "be brief"}]
    chat = {
        "messages": [*system, {"role": "user", "content": "one"}],
    }

    first = await _band(
        _cached("chat", band={"openai_prompt_cache_key": "key"}, **chat)
    )
    material = "\x1f".join(
        (
            "shim.prompt_cache_key.v1",
            "11111111-1111-1111-1111-111111111111",
            "22222222-2222-2222-2222-222222222222",
            "gpt-5-nano",
            sha256(
                json.dumps(
                    {"messages": system, "tools": first.payload["tools"]},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest(),
        )
    )
    assert _key(first) == "shim-" + sha256(material.encode()).hexdigest()[:32]
    assert first.settings_applied == ({"id": "openai_prompt_cache_key", "version": 1},)

    later_turn = await _band(
        _cached(
            "chat",
            band={"openai_prompt_cache_key": "key"},
            messages=[*system, {"role": "user", "content": "two"}],
        )
    )
    other_key = await _band(
        _cached("chat", band={"openai_prompt_cache_key": "key"}, key=_OTHER_KEY, **chat)
    )
    tenant_wide = [
        _key(
            await _band(
                _cached(
                    "chat", band={"openai_prompt_cache_key": "tenant"}, key=key, **chat
                )
            )
        )
        for key in ("22222222-2222-2222-2222-222222222222", _OTHER_KEY)
    ]
    other_prefix = await _band(
        _cached(
            "chat",
            band={"openai_prompt_cache_key": "key"},
            messages=[
                {"role": "developer", "content": "be long"},
                {"role": "user", "content": "one"},
            ],
        )
    )

    assert _key(later_turn) == _key(first)
    assert _key(other_key) != _key(first)
    assert tenant_wide[0] == tenant_wide[1] != _key(first)
    assert _key(other_prefix) != _key(first)


@pytest.mark.asyncio
async def test_responses_keys_read_instructions_and_leading_input_items() -> None:
    band = {"openai_prompt_cache_key": "key"}
    base = await _band(_cached("responses", band=band))
    other = await _band(_cached("responses", band=band, instructions="be long"))
    leading = await _band(
        _cached(
            "responses",
            band=band,
            input=[
                {"role": "developer", "content": "rules"},
                {"role": "user", "content": "hi"},
            ],
        )
    )

    assert _key(base).startswith("shim-") and len(_key(base)) == 37
    assert len({_key(base), _key(other), _key(leading)}) == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("sent", ["client-key", "<EMAIL_ADDRESS_a1>"])
async def test_a_client_prompt_cache_key_is_left_as_privacy_left_it(sent) -> None:
    prepared = _cached(
        "chat", band={"openai_prompt_cache_key": "key"}, prompt_cache_key=sent
    )

    banded = await _band(prepared)

    assert banded.payload is prepared.payload and banded.settings_applied == ()
