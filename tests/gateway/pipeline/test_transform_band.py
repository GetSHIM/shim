from __future__ import annotations

import copy
from datetime import UTC, datetime
import json
import subprocess
import sys
from typing import Any
from uuid import UUID

import pytest

import shim.gateway.pipeline.transform_band as transform_band
from shim.gateway.contracts.context import (
    AuditPolicy,
    GatewayContext,
    PrivacyPolicy,
    TierPolicy,
)
from shim.gateway.contracts.ids import ApiKeyId, ProviderId, RequestId, TenantId
from shim.gateway.kernel.result import PreparedInference
from shim.gateway.pipeline.transform_band import (
    JSON_COMPACTION_MAX_CHARS,
    TransformBandStage,
    compact_json,
)
from shim.gateway.request_policy import BandSettings, RequestPolicyContext


# shim-cli@ac64452 src/shim_cli/events/diet.py:14-66, verbatim: the reference.
_WHITESPACE = " \t\r\n"
_STRUCTURAL = "{}[]:,"


def reference_compact_json(text: str) -> str:
    if not text or text[0] not in "{[":
        return text
    out = []
    index = 0
    length = len(text)
    while index < length:
        character = text[index]
        if character == '"':
            end = _string_end(text, index)
            if end is None:
                return text
            out.append(text[index:end])
            index = end
            continue
        if character in _WHITESPACE:
            index += 1
            continue
        if character not in _STRUCTURAL and not _is_literal_start(character):
            return text
        out.append(character)
        index += 1
    compacted = "".join(out)
    if not _same_value(text, compacted):
        return text
    return compacted


def _is_literal_start(character: str) -> bool:
    return character.isalnum() or character in "+-."


def _string_end(text: str, start: int) -> int | None:
    index = start + 1
    length = len(text)
    while index < length:
        character = text[index]
        if character == "\\":
            index += 2
            continue
        if character == '"':
            return index + 1
        index += 1
    return None


def _same_value(original: str, compacted: str) -> bool:
    import json

    try:
        return json.loads(original) == json.loads(compacted)
    except (ValueError, RecursionError):
        return False


# At least 64 characters, by indenting inside the outer brackets.
def _pad(text: str) -> str:
    return text[0] + " " * max(0, 64 - len(text)) + text[1:]


VECTORS = [
    (_pad('{"a": 1.10, "b": 1e5, "c": -0, "d": 12345678901234567890}'), True),
    (_pad('{"s": "keep  these\\tspaces", "q": "a \\" quote", "b": "\\\\ end"}'), True),
    (_pad('{"k": 1, "k": 2,   "z": [1,  2]}'), True),
    (json.dumps({"rows": [{"id": n, "ok": True} for n in range(5)]}, indent=2), True),
    (" " + json.dumps({"a": list(range(30))}, indent=2), False),
    ("not json " * 10, False),
    ('{"a": [1, 2, 3' + " " * 64, False),
    # Python's json parses NaN to one shared float, so both sides compare equal and
    # the literal survives byte for byte, as in shim-cli.
    (_pad('{"a": NaN,  "b": 1}'), True),
    ("[" * 100_000 + "]" * 100_000, False),
    (_pad('{"a":1}').replace(" ", ""), False),
]


@pytest.mark.parametrize(("text", "changes"), VECTORS, ids=range(len(VECTORS)))
def test_compaction_matches_shim_cli_and_is_lossless(text, changes) -> None:
    result = compact_json(text)

    assert (result != text) is changes
    assert result == reference_compact_json(text)
    if changes:
        assert json.loads(result) == json.loads(text)
        assert compact_json(result) == result


def test_number_literals_strings_and_duplicate_keys_survive_byte_for_byte() -> None:
    text = _pad('{"n": 1.10,  "e": 1e5, "z": -0, "s": "a  b\\"c", "n": 2}')

    assert compact_json(text) == '{"n":1.10,"e":1e5,"z":-0,"s":"a  b\\"c","n":2}'


def test_the_length_bounds() -> None:
    def sized(length: int) -> str:
        return "[" + " " * (length - 3) + "1]"

    assert compact_json(sized(63)) == sized(63)
    assert compact_json(sized(64)) == "[1]"
    assert compact_json(sized(JSON_COMPACTION_MAX_CHARS + 1)) == sized(
        JSON_COMPACTION_MAX_CHARS + 1
    )


def test_the_output_is_the_same_in_another_process() -> None:
    text = VECTORS[3][0]
    script = (
        "import sys; from shim.gateway.pipeline.transform_band import compact_json; "
        "sys.stdout.write(compact_json(sys.stdin.read()))"
    )

    other = subprocess.run(
        [sys.executable, "-c", script],
        input=text,
        capture_output=True,
        text=True,
        check=True,
    )

    assert other.stdout == compact_json(text)


_INDENTED = json.dumps(
    {"rows": [{"id": n, "name": f"row {n}"} for n in range(4)]}, indent=2
)
_SMALL = json.dumps(
    {"rows": [{"id": n, "name": f"row {n}"} for n in range(4)]}, separators=(",", ":")
)


def _prepared(protocol: str, payload: dict[str, Any]) -> PreparedInference:
    return PreparedInference(
        context=GatewayContext(
            request_id=RequestId("req_transform"),
            tenant_id=TenantId(UUID("11111111-1111-1111-1111-111111111111")),
            actor_type="api_key",
            api_key_id=ApiKeyId(UUID("22222222-2222-2222-2222-222222222222")),
            user_id=None,
            endpoint="/v1/chat/completions",
            started_at=datetime(2026, 10, 13, tzinfo=UTC),
            tier_policy=TierPolicy(rate_limit_rpm=60),
            privacy_policy=PrivacyPolicy(pii_mode="scrub"),
            audit_policy=AuditPolicy(mode="best_effort"),
        ),
        payload=payload,
        provider=ProviderId(
            {
                "chat": "openai",
                "responses": "openai",
                "messages": "anthropic",
                "generate_content": "google",
            }[protocol]
        ),
        protocol=protocol,  # type: ignore[arg-type]
        model="m",
        stream=False,
        policy=RequestPolicyContext(rate_limit_key_hash="h", tier="t"),
        pii_config=None,
        band=BandSettings(json_compaction=True),
    )


async def _run(protocol: str, payload: dict[str, Any]) -> PreparedInference:
    before = copy.deepcopy(payload)
    prepared = _prepared(protocol, payload)
    banded = await TransformBandStage().run(prepared)
    assert payload == before, "the band never mutates the payload it got"
    return banded


_PAYLOADS: dict[str, dict[str, Any]] = {
    "chat": {
        "messages": [
            {"role": "system", "content": _INDENTED},
            {"role": "user", "content": _INDENTED},
            {
                "role": "assistant",
                "content": _INDENTED,
                "tool_calls": [
                    {
                        "id": "c1",
                        "type": "function",
                        "function": {"name": "f", "arguments": _INDENTED},
                    }
                ],
            },
            {"role": "tool", "tool_call_id": "c1", "content": _INDENTED},
            {
                "role": "tool",
                "tool_call_id": "c2",
                "content": [{"type": "text", "text": _INDENTED}],
            },
            {"role": "function", "name": "f", "content": _INDENTED},
        ],
        "tools": [
            {"type": "function", "function": {"name": "f", "description": _INDENTED}}
        ],
    },
    "responses": {
        "instructions": _INDENTED,
        "input": [
            {"role": "user", "content": _INDENTED},
            {
                "type": "function_call",
                "call_id": "c1",
                "name": "f",
                "arguments": _INDENTED,
            },
            {"type": "function_call_output", "call_id": "c1", "output": _INDENTED},
            {
                "type": "function_call_output",
                "call_id": "c2",
                "output": [{"type": "input_text", "text": _INDENTED}],
            },
        ],
    },
    "messages": {
        "system": _INDENTED,
        "messages": [
            {"role": "user", "content": _INDENTED},
            {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": _INDENTED},
                    {
                        "type": "tool_use",
                        "id": "t1",
                        "name": "f",
                        "input": {"q": _INDENTED},
                    },
                ],
            },
            {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": "t1", "content": _INDENTED},
                    {
                        "type": "tool_result",
                        "tool_use_id": "t2",
                        "content": [{"type": "text", "text": _INDENTED}],
                    },
                    {"type": "text", "text": _INDENTED},
                ],
            },
        ],
    },
    "generate_content": {
        "systemInstruction": {"parts": [{"text": _INDENTED}]},
        "contents": [
            {"role": "user", "parts": [{"text": _INDENTED}]},
            {
                "role": "model",
                "parts": [{"functionCall": {"name": "f", "args": {"q": _INDENTED}}}],
            },
            {
                "role": "user",
                "parts": [
                    {
                        "functionResponse": {
                            "name": "f",
                            "response": {
                                "output": _INDENTED,
                                "nested": {"deeper": [_INDENTED]},
                                "count": 3,
                            },
                        }
                    }
                ],
            },
        ],
    },
}
# The tool result positions R3 names; every other string keeps its bytes.
_COMPACTED = {
    "chat": [("messages", 3, "content"), ("messages", 4, "content", 0, "text")],
    "responses": [("input", 2, "output"), ("input", 3, "output", 0, "text")],
    "messages": [
        ("messages", 2, "content", 0, "content"),
        ("messages", 2, "content", 1, "content", 0, "text"),
    ],
    "generate_content": [
        ("contents", 2, "parts", 0, "functionResponse", "response", "output"),
        (
            "contents",
            2,
            "parts",
            0,
            "functionResponse",
            "response",
            "nested",
            "deeper",
            0,
        ),
    ],
}


def _at(value: Any, path: tuple) -> Any:
    for key in path:
        value = value[key]
    return value


def _strings(value: Any, path: tuple = ()) -> list[tuple[tuple, str]]:
    if isinstance(value, str):
        return [(path, value)]
    if isinstance(value, dict):
        return [
            item
            for key, child in value.items()
            for item in _strings(child, (*path, key))
        ]
    if isinstance(value, list):
        return [
            item
            for index, child in enumerate(value)
            for item in _strings(child, (*path, index))
        ]
    return []


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", list(_PAYLOADS))
async def test_only_tool_results_are_compacted(protocol) -> None:
    payload = _PAYLOADS[protocol]

    banded = await _run(protocol, payload)

    changed = {
        path for path, text in _strings(payload) if _at(banded.payload, path) != text
    }
    assert changed == set(_COMPACTED[protocol])
    for path in _COMPACTED[protocol]:
        assert _at(banded.payload, path) == _SMALL
    assert banded.transforms_applied == (
        {
            "id": "json_compaction",
            "version": 1,
            "before_chars": 2 * len(_INDENTED),
            "after_chars": 2 * len(_SMALL),
            "items": 2,
        },
    )
    if protocol == "generate_content":
        response = banded.payload["contents"][2]["parts"][0]["functionResponse"]
        assert set(response["response"]) == {"output", "nested", "count"}


@pytest.mark.asyncio
async def test_untouched_turns_are_shared_and_the_rest_copied_on_write() -> None:
    payload = _PAYLOADS["chat"]

    banded = await _run("chat", payload)

    for index in (0, 1, 2, 5):
        assert banded.payload["messages"][index] is payload["messages"][index]
    assert banded.payload["tools"] is payload["tools"]
    assert banded.payload["messages"][3] is not payload["messages"][3]


@pytest.mark.asyncio
async def test_nothing_to_compact_records_an_empty_list() -> None:
    payload = {"messages": [{"role": "tool", "tool_call_id": "c", "content": _SMALL}]}

    banded = await _run("chat", payload)

    assert banded.payload is payload and banded.transforms_applied == ()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fields",
    [
        {"thinking": {"type": "enabled", "budget_tokens": 1024}},
        {"thinking": {"type": "adaptive"}},
        {
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {"type": "thinking", "thinking": "t", "signature": "s"}
                    ],
                },
                *_PAYLOADS["messages"]["messages"],
            ]
        },
    ],
)
async def test_thinking_bound_anthropic_requests_are_skipped(fields) -> None:
    payload = {**_PAYLOADS["messages"], **fields}

    banded = await _run("messages", payload)

    assert banded.payload is payload and banded.transforms_applied == ()
    [verdict] = banded.policy_verdicts
    assert (verdict.rule_id, verdict.stage, verdict.outcome, verdict.reason_code) == (
        "transforms.json_compaction",
        "transforms",
        "skip",
        "TRANSFORM_THINKING_BOUND",
    )


@pytest.mark.asyncio
async def test_large_candidates_are_compacted_off_the_event_loop(monkeypatch) -> None:
    threaded: list[object] = []
    original = transform_band.asyncio.to_thread

    async def to_thread(function, *args):
        threaded.append(function)
        return await original(function, *args)

    monkeypatch.setattr(transform_band.asyncio, "to_thread", to_thread)
    big = json.dumps({"rows": ["x" * 100] * 700}, indent=2)
    small = {"messages": [{"role": "tool", "tool_call_id": "c", "content": _INDENTED}]}
    large = {"messages": [{"role": "tool", "tool_call_id": "c", "content": big}]}

    await _run("chat", small)
    assert threaded == []
    banded = await _run("chat", large)

    assert len(big) >= 65_536 and len(threaded) == 1
    assert banded.payload["messages"][0]["content"] == json.dumps(
        json.loads(big), separators=(",", ":")
    )


@pytest.mark.asyncio
async def test_the_span_carries_items_and_characters_saved() -> None:
    stage = TransformBandStage()

    banded = await stage.run(_prepared("chat", _PAYLOADS["chat"]))

    assert stage.trace_metadata(banded) == {
        "items": 2,
        "chars_saved": 2 * (len(_INDENTED) - len(_SMALL)),
    }


@pytest.mark.parametrize(
    "text",
    [
        "[" + '"\\"", ' * 160_000 + "1]",
        "[" + " " * 999_990 + "1]",
        '["' + "a" * 999_990 + "  ",
        "{" + '"k":' * 249_000,
    ],
    ids=["escaped-quotes", "spaces", "unterminated", "keys-without-values"],
)
def test_a_million_hostile_characters_take_well_under_a_second(text) -> None:
    from time import perf_counter

    started = perf_counter()
    compact_json(text)

    assert perf_counter() - started < 1
