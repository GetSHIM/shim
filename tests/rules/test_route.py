"""Route rules read only a conversation's first turn, so every turn decides alike."""

from __future__ import annotations

import hashlib
import hmac
import re

import pytest
from pydantic import ValidationError

from shim.rules import validate_rule_set
from shim.rules.route import (
    RouteMatch,
    conversation_id,
    owned,
    route_reason,
    start_view,
)

_FIRST = "Faturalarımı özetle"
_TURNS = [
    {"role": "user", "content": _FIRST},
    {"role": "assistant", "content": "Tamam."},
    {"role": "user", "content": "Bir de geçen ayı ekle, uzun bir ikinci soru."},
]


def _when(payload: dict, protocol: str = "chat", **when) -> str | None:
    view = start_view(payload, protocol)
    assert view is not None
    return route_reason(when, payload, view)


def _chat(text: str, **extra) -> dict:
    return {"messages": [{"role": "user", "content": text}], **extra}


def test_the_match_is_checked_and_a_foreign_on_value_is_kept_as_sent() -> None:
    match = RouteMatch.model_validate(
        {"from": ["strong"], "to": "cheap", "when": {"max_start_chars": 400}}
    ).model_dump()
    assert match == {
        "from": ["strong"],
        "to": "cheap",
        "when": {"max_start_chars": 400},
    }
    assert owned(match)
    for refused in (
        {"from": ["strong"], "to": "strong"},
        {"from": [], "to": "cheap"},
        {"from": ["strong"] * 21, "to": "cheap"},
        {"from": ["strong"], "to": "cheap", "when": {}},
        {"from": ["strong"], "to": "cheap", "when": {"max_start_chars": 0}},
        {"from": ["strong"], "to": "cheap", "when": {"colour": "red"}},
        {"from": ["strong"], "to": "cheap", "when": {"keywords_any": ["x" * 65]}},
        {"from": ["strong"], "to": "cheap", "when": {"keywords_any": ["x"] * 51}},
        {"from": ["strong"], "to": "cheap", "extra": 1},
        {"on": 5},
    ):
        with pytest.raises(ValidationError):
            RouteMatch.model_validate(refused)
    foreign = {"on": "shadow", "to": "candidate", "sample": 0.1}
    assert RouteMatch.model_validate(foreign).model_dump() == foreign
    assert not owned(foreign)


def test_a_route_rule_is_available_with_its_one_action() -> None:
    rule = {
        "id": "cheap_start",
        "name": "Short starts",
        "kind": "route",
        "action": "route",
        "state": "monitor",
        "match": {"from": ["strong"], "to": "cheap"},
    }
    [stored] = validate_rule_set({"revision": 1, "rules": [rule]}).rules
    assert stored.match == {"from": ["strong"], "to": "cheap"}


@pytest.mark.parametrize(
    ("when", "reason"),
    [
        ({"max_start_chars": 19}, None),
        ({"max_start_chars": 20}, "max_start_chars"),
        ({"max_start_chars": 21}, "max_start_chars"),
        ({"min_start_chars": 19}, "min_start_chars"),
        ({"min_start_chars": 20}, "min_start_chars"),
        ({"min_start_chars": 21}, None),
        ({"tools": False}, "tools"),
        ({"tools": True}, None),
        ({"media": False}, "media"),
        ({"structured_output": False}, "structured_output"),
        ({"keywords_any": ["fatura"]}, "keywords_any"),
        ({"keywords_any": ["ozet"]}, "keywords_any"),
        ({"keywords_any": ["afatura", "rapor"]}, None),
        ({"keywords_none": ["fatura"]}, None),
        ({"keywords_none": ["rapor"]}, "keywords_none"),
        # All must hold; the reason is the first one named.
        ({"max_start_chars": 400, "keywords_any": ["fatura"]}, "max_start_chars"),
        ({"max_start_chars": 400, "tools": True}, None),
    ],
)
def test_each_condition_at_and_around_its_bound(when, reason) -> None:
    # "x " plus the 19 characters of the first message: 20 in all.
    payload = _chat(f"x {_FIRST[:-1]}")
    assert len(f"x {_FIRST[:-1]}") == 20

    assert _when(payload, **when) == reason
    assert route_reason(None, payload, ("", [])) == "always"


def test_keywords_fold_turkish_casing_and_match_at_a_word_start() -> None:
    def found(text: str, keyword: str) -> bool:
        return _when(_chat(text), keywords_any=[keyword]) is not None

    assert found("İstanbul şubesi", "istanbul")
    assert found("ISTANBUL", "İstanbul")
    assert found("FATURA  geldi", "fatura")
    assert found("Faturalarımı\n\tözetle", "faturalarımı özetle")
    assert found("ｆａｔｕｒａ", "fatura")  # full-width: NFKC first
    assert not found("afatura", "fatura")
    # Keywords are looked for in the first 20,000 characters only.
    assert not found("x " * 10_000 + "fatura", "fatura")


def test_tools_media_and_structured_output_per_protocol() -> None:
    assert _when(_chat("hi", tools=[{"type": "function"}]), tools=True) == "tools"
    image = {"type": "image_url", "image_url": {"url": "data:image/png;base64,AA"}}
    assert (
        _when({"messages": [{"role": "user", "content": [image]}]}, media=True)
        == "media"
    )
    gemini = {"contents": [{"parts": [{"inlineData": {"data": "AA"}}]}]}
    assert _when(gemini, "generate_content", media=True) == "media"
    for payload, protocol in (
        (_chat("x", response_format={"type": "json_schema"}), "chat"),
        (_chat("x", response_format={"type": "json_object"}), "chat"),
        (_chat("x", output_config={"format": {"type": "json_schema"}}), "messages"),
        (
            {"input": "x", "store": False, "text": {"format": {"type": "json_schema"}}},
            "responses",
        ),
        (
            {"contents": [], "generationConfig": {"responseSchema": {}}},
            "generate_content",
        ),
        (
            {"contents": [], "generationConfig": {"responseJsonSchema": {}}},
            "generate_content",
        ),
    ):
        assert _when(payload, protocol, structured_output=True) == "structured_output"
    assert (
        _when(_chat("x", response_format={"type": "text"}), structured_output=True)
        is None
    )


@pytest.mark.parametrize(
    ("protocol", "turn_one", "turn_five"),
    [
        (
            "chat",
            {"messages": [{"role": "system", "content": "Be brief."}, _TURNS[0]]},
            {
                "messages": [
                    {"role": "system", "content": "Be brief."},
                    *_TURNS,
                    {"role": "assistant", "content": "Eklendi."},
                    {"role": "user", "content": "Teşekkürler"},
                ]
            },
        ),
        (
            "messages",
            {"system": "Be brief.", "messages": [_TURNS[0]]},
            {"system": "Be brief.", "messages": _TURNS},
        ),
        (
            "generate_content",
            {
                "systemInstruction": {"parts": [{"text": "Be brief."}]},
                "contents": [{"role": "user", "parts": [{"text": _FIRST}]}],
            },
            {
                "systemInstruction": {"parts": [{"text": "Be brief."}]},
                "contents": [
                    {"role": "user", "parts": [{"text": _FIRST}]},
                    {"role": "model", "parts": [{"text": "Tamam."}]},
                    {"role": "user", "parts": [{"text": "Devam"}]},
                ],
            },
        ),
        (
            "responses",
            {
                "instructions": "Be brief.",
                "store": False,
                "input": [
                    {
                        "role": "user",
                        "content": [{"type": "input_text", "text": _FIRST}],
                    }
                ],
            },
            {
                "instructions": "Be brief.",
                "store": False,
                "input": [
                    {
                        "role": "user",
                        "content": [{"type": "input_text", "text": _FIRST}],
                    },
                    {"role": "assistant", "content": "Tamam."},
                    {"role": "user", "content": "Devam"},
                ],
            },
        ),
    ],
)
def test_the_start_view_is_the_same_for_turn_one_and_turn_five(
    protocol, turn_one, turn_five
) -> None:
    first = start_view(turn_one, protocol)

    assert first == start_view(turn_five, protocol)
    assert first is not None and first[0] == f"Be brief.\n{_FIRST}"


def test_provider_kept_conversations_and_other_endpoints_get_no_view() -> None:
    for payload in (
        {"input": "x"},
        {"input": "x", "store": True},
        {"input": "x", "store": False, "previous_response_id": "resp_1"},
        {"input": "x", "store": False, "conversation": "conv_1"},
    ):
        assert start_view(payload, "responses") is None
    for protocol in ("count_tokens", "embeddings", "embed_content"):
        assert start_view(_chat("x"), protocol) is None


def test_the_conversation_id_is_the_header_or_a_keyed_digest() -> None:
    key = b"k" * 32
    digest = hmac.new(key, b"Be brief.", hashlib.sha256).hexdigest()[:16]

    assert conversation_id("app-7:conv.42_x", key, "Be brief.") == "app-7:conv.42_x"
    assert conversation_id(None, key, "Be brief.") == digest
    for ignored in ("has space", "x" * 129, "", "ünicode"):
        assert conversation_id(ignored, key, "Be brief.") == digest
    assert conversation_id(None, b"o" * 32, "Be brief.") != digest
    assert re.fullmatch(r"[0-9a-f]{16}", conversation_id(None, key, "a\ud800b"))
