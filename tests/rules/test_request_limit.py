from __future__ import annotations

import pytest

from shim.rules import RuleSetError, validate_rule_set
from shim.rules.request_limit import request_measures


def _rule(match: dict) -> dict:
    return {
        "id": "tool_cap",
        "name": "Tool cap",
        "kind": "request_limit",
        "action": "block",
        "state": "monitor",
        "match": match,
    }


@pytest.mark.parametrize(
    "match",
    [
        {"max_tools": 0},
        {"max_tools": 10_000},
        {"max_documents": 1_000},
        {"max_history": 1},
        {"max_input_bytes": 1_024},
        {"max_input_bytes": 32_000_000},
        {"below_price_tier": True},
        {"max_tools": 5, "below_price_tier": True},
    ],
)
def test_a_limit_inside_its_bounds_is_stored(match) -> None:
    [rule] = validate_rule_set({"revision": 1, "rules": [_rule(match)]}).rules

    assert {
        key: value for key, value in rule.match.items() if value is not None
    } == match


@pytest.mark.parametrize(
    "match",
    [
        {},
        {"max_tools": None},
        {"max_tools": -1},
        {"max_tools": 10_001},
        {"max_documents": 1_001},
        {"max_history": 0},
        {"max_history": 100_001},
        {"max_input_bytes": 1_023},
        {"max_input_bytes": 32_000_001},
        {"below_price_tier": False},
        {"max_tools": 5, "max_images": 1},
    ],
)
def test_a_limit_out_of_bounds_or_absent_is_refused(match) -> None:
    with pytest.raises(RuleSetError) as refused:
        validate_rule_set({"revision": 1, "rules": [_rule(match)]})

    assert refused.value.code == "RULE_MATCH_INVALID"


def _tools(n: int) -> list[dict]:
    return [{"type": "function", "function": {"name": f"f{i}"}} for i in range(n)]


@pytest.mark.parametrize(
    ("protocol", "payload", "measures"),
    [
        (
            "chat",
            {
                "tools": _tools(3),
                "messages": [
                    {"role": "system", "content": "s"},
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": "read"},
                            {"type": "file", "file": {"file_id": "f1"}},
                            {"type": "image_url", "image_url": {"url": "x"}},
                            {"type": "file", "file": {"file_id": "f2"}},
                        ],
                    },
                ],
            },
            (3, 2, 2),
        ),
        (
            "responses",
            {
                "tools": _tools(1),
                "input": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "input_text", "text": "x"},
                            {"type": "input_file", "file_id": "f1"},
                            {"type": "input_image", "image_url": "x"},
                        ],
                    },
                    {"type": "function_call_output", "call_id": "c", "output": "o"},
                ],
            },
            (1, 1, 2),
        ),
        ("responses", {"input": "a plain question"}, (0, 0, 1)),
        (
            "messages",
            {
                "tools": _tools(2),
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "document",
                                "source": {"type": "text", "data": "d"},
                            },
                            {
                                "type": "image",
                                "source": {"type": "base64", "data": "x"},
                            },
                            {
                                "type": "tool_result",
                                "tool_use_id": "t",
                                "content": [
                                    {
                                        "type": "document",
                                        "source": {"type": "text", "data": "d"},
                                    },
                                    {"type": "text", "text": "t"},
                                ],
                            },
                        ],
                    },
                    {"role": "assistant", "content": "ok"},
                    {"role": "user", "content": "plain text"},
                ],
            },
            (2, 2, 3),
        ),
        (
            "count_tokens",
            {"messages": [{"role": "user", "content": [{"type": "document"}]}]},
            (0, 1, 1),
        ),
        (
            "generate_content",
            {
                "tools": [
                    {"functionDeclarations": [{"name": "a"}, {"name": "b"}]},
                    {"googleSearch": {}},
                    {"functionDeclarations": "not a list"},
                ],
                "contents": [
                    {
                        "role": "user",
                        "parts": [
                            {
                                "inlineData": {
                                    "mimeType": "application/pdf",
                                    "data": "x",
                                }
                            },
                            {"fileData": {"mimeType": "text/plain", "fileUri": "u"}},
                            {"inlineData": {"mimeType": "image/png", "data": "x"}},
                            {"inlineData": {"mimeType": "audio/wav", "data": "x"}},
                            {"fileData": {"mimeType": "video/mp4", "fileUri": "u"}},
                            {"text": "read"},
                        ],
                    },
                    {"role": "model", "parts": [{"text": "ok"}]},
                ],
            },
            (3, 2, 2),
        ),
    ],
)
def test_each_protocol_counts_tools_documents_and_history(
    protocol, payload, measures
) -> None:
    assert request_measures(payload, protocol) == measures


@pytest.mark.parametrize(
    "protocol", ["chat", "responses", "messages", "generate_content"]
)
@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"tools": "x", "messages": "x", "input": 3, "contents": {"a": 1}},
        {"tools": None, "messages": [None, 3, "x"], "contents": [None, {"parts": "x"}]},
    ],
)
def test_values_that_are_not_lists_count_nothing(protocol, payload) -> None:
    tools, documents, history = request_measures(payload, protocol)

    assert (tools, documents) == (0, 0)
    assert history in {0, 3, 2}
