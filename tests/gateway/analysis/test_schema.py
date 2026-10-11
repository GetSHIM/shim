from __future__ import annotations

import json

import pytest

from shim.gateway.analyzers import ANALYZERS
from shim.gateway.analyzers.language import LanguageAnalyzer
from shim.gateway.analyzers.schema import SchemaAnalyzer, requested_output
from shim.gateway.pipeline.analysis import AnalysisContext, AnalysisToolCall
from shim.gateway.streaming import StreamMeter

SCHEMA = {
    "type": "object",
    "properties": {
        "status": {"type": "string"},
        "count": {"type": "integer"},
        "items": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["status", "count", "items"],
    "additionalProperties": False,
}
GEMINI_SCHEMA = {
    "type": "OBJECT",
    "properties": {"status": {"type": "STRING"}, "count": {"type": "INTEGER"}},
    "required": ["status", "count"],
}
OK = '{"status":"ok","count":3,"items":["a"]}'
WRONG = '{"status":"ok","count":"three","items":["a"]}'


def _context(
    payload: dict,
    protocol: str = "chat",
    answer: str = OK,
    *,
    calls: tuple[AnalysisToolCall, ...] = (),
    outcome: str | None = "complete",
    truncated: bool = False,
    restore=lambda text: text,
) -> AnalysisContext:
    return AnalysisContext(
        request_id="req",
        protocol=protocol,
        model="m",
        payload=payload,
        answer_text=answer,
        answer_truncated=truncated,
        tool_calls=calls,
        completion_outcome=outcome,
        restore=restore,
    )


def _chat_schema(strict: bool = True) -> dict:
    return {
        "response_format": {
            "type": "json_schema",
            "json_schema": {"name": "r", "schema": SCHEMA, "strict": strict},
        }
    }


@pytest.mark.parametrize(
    ("protocol", "payload", "kind", "dialect", "strict"),
    [
        ("chat", _chat_schema(), "json_schema", "json_schema", True),
        (
            "chat",
            {"response_format": {"type": "json_object"}},
            "json_object",
            "json_schema",
            False,
        ),
        (
            "responses",
            {"text": {"format": {"type": "json_schema", "schema": SCHEMA}}},
            "json_schema",
            "json_schema",
            False,
        ),
        (
            "responses",
            {"text": {"format": {"type": "json_object"}}},
            "json_object",
            "json_schema",
            False,
        ),
        (
            "messages",
            {"output_config": {"format": {"type": "json_schema", "schema": SCHEMA}}},
            "json_schema",
            "json_schema",
            True,
        ),
        (
            "messages",
            {"output_format": {"type": "json_schema", "schema": SCHEMA}},
            "json_schema",
            "json_schema",
            True,
        ),
        (
            "generate_content",
            {"generationConfig": {"responseJsonSchema": SCHEMA}},
            "json_schema",
            "json_schema",
            True,
        ),
        (
            "generate_content",
            {"generationConfig": {"responseSchema": GEMINI_SCHEMA}},
            "json_schema",
            "openapi",
            True,
        ),
        (
            "generate_content",
            {"generationConfig": {"responseMimeType": "application/json"}},
            "json_object",
            "json_schema",
            False,
        ),
    ],
)
def test_the_requested_output_per_protocol(
    protocol, payload, kind, dialect, strict
) -> None:
    found = requested_output(payload, protocol)

    assert found is not None
    assert (found.kind, found.dialect, found.strict) == (kind, dialect, strict)


@pytest.mark.parametrize(
    ("protocol", "payload"),
    [
        ("chat", {"response_format": {"type": "text"}}),
        ("responses", {}),
        ("messages", {"output_config": {"effort": "low"}}),
        ("generate_content", {"generationConfig": {"temperature": 0}}),
    ],
)
def test_no_structured_output_is_none(protocol, payload) -> None:
    assert requested_output(payload, protocol) is None
    assert SchemaAnalyzer().analyze(_context(payload, protocol))["expected"] == "none"


def test_a_schema_answer_is_valid_or_names_where_it_fails() -> None:
    valid = SchemaAnalyzer().analyze(_context(_chat_schema()))
    wrong = SchemaAnalyzer().analyze(_context(_chat_schema(), answer=WRONG))
    unparsable = SchemaAnalyzer().analyze(_context(_chat_schema(), answer='{"status":'))

    assert valid == {
        "expected": "json_schema",
        "valid": True,
        "error_path": None,
        "error_keyword": None,
        "error_tool": None,
        "unsupported": False,
        "unsupported_keywords": [],
        "strict": True,
        "reason": None,
    }
    assert (wrong["valid"], wrong["error_path"], wrong["error_keyword"]) == (
        False,
        "/count",
        "type",
    )
    assert (unparsable["valid"], unparsable["error_keyword"]) == (False, "parse")


def test_gemini_upper_case_schema_and_unsupported_keywords() -> None:
    gemini = {"generationConfig": {"responseSchema": GEMINI_SCHEMA}}
    patterned = {
        "text": {
            "format": {
                "type": "json_schema",
                "schema": {
                    "type": "object",
                    "properties": {"status": {"type": "string", "pattern": "^o"}},
                },
            }
        }
    }

    wrong = SchemaAnalyzer().analyze(_context(gemini, "generate_content", WRONG))
    unknown = SchemaAnalyzer().analyze(_context(patterned, "responses"))

    assert (wrong["valid"], wrong["error_path"]) == (False, "/count")
    assert (
        unknown["valid"],
        unknown["unsupported"],
        unknown["unsupported_keywords"],
    ) == (None, True, ["pattern"])


@pytest.mark.parametrize(
    ("answer", "valid", "keyword"),
    [
        ("{}", True, None),
        ("[1]", False, "type"),
        ("nope", False, "parse"),
        ('  {"a": 1}\n', True, None),
    ],
)
def test_json_object_needs_an_object(answer, valid, keyword) -> None:
    result = SchemaAnalyzer().analyze(
        _context({"response_format": {"type": "json_object"}}, answer=answer)
    )

    assert (result["expected"], result["valid"], result["error_keyword"]) == (
        "json_object",
        valid,
        keyword,
    )


@pytest.mark.parametrize(
    ("outcome", "truncated", "reason"),
    [
        ("truncated", False, "truncated"),
        ("refused", False, "refused"),
        ("filtered", False, "filtered"),
        ("empty", False, "empty"),
        ("complete", True, "too_large"),
    ],
)
def test_an_unfinished_answer_is_not_checked(outcome, truncated, reason) -> None:
    result = SchemaAnalyzer().analyze(
        _context(_chat_schema(), answer=WRONG, outcome=outcome, truncated=truncated)
    )

    assert (result["valid"], result["reason"]) == (None, reason)


def test_a_huge_schema_and_a_bound_give_their_reason() -> None:
    huge = {"type": "object", "description": "x" * 100_001}
    deep: dict = {}
    cursor = deep
    for _ in range(40):
        cursor["a"] = {}
        cursor = cursor["a"]

    big = SchemaAnalyzer().analyze(
        _context(
            {"text": {"format": {"type": "json_schema", "schema": huge}}},
            "responses",
            "{}",
        )
    )
    bounded = SchemaAnalyzer().analyze(
        _context(
            {
                "text": {
                    "format": {
                        "type": "json_schema",
                        "schema": {
                            "$ref": "#/$defs/n",
                            "$defs": {
                                "n": {"properties": {"a": {"$ref": "#/$defs/n"}}}
                            },
                        },
                    }
                }
            },
            "responses",
            json.dumps(deep),
        )
    )

    assert (big["valid"], big["reason"]) == (None, "too_large")
    assert (bounded["valid"], bounded["reason"]) == (None, "depth")


def test_a_masked_enum_is_restored_before_the_check() -> None:
    placeholder = "<EMAIL_ADDRESS_0123abcd>"
    payload = {
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "schema": {
                    "type": "object",
                    "properties": {"contact": {"enum": [placeholder]}},
                }
            },
        }
    }
    answer = '{"contact":"ops@example.com"}'

    restored = SchemaAnalyzer().analyze(
        _context(
            payload,
            answer=answer,
            restore=lambda text: text.replace(placeholder, "ops@example.com"),
        )
    )
    unrestored = SchemaAnalyzer().analyze(_context(payload, answer=answer))

    assert restored["valid"] is True
    assert (unrestored["valid"], unrestored["error_keyword"]) == (False, "enum")
    assert payload["response_format"]["json_schema"]["schema"]["properties"]["contact"][
        "enum"
    ] == [placeholder]


_TOOLS = {
    "tools": [
        {
            "type": "function",
            "function": {"name": "lookup", "parameters": SCHEMA, "strict": True},
        }
    ]
}


def test_tool_calls_are_checked_against_their_tool() -> None:
    def run(*calls: AnalysisToolCall) -> dict:
        return SchemaAnalyzer().analyze(_context(_TOOLS, answer="", calls=calls))

    valid = run(AnalysisToolCall("lookup", OK))
    wrong = run(AnalysisToolCall("lookup", OK), AnalysisToolCall("lookup", WRONG))
    unknown = run(AnalysisToolCall("missing", OK))
    unparsable = run(AnalysisToolCall("lookup", '{"status"'))

    assert (valid["expected"], valid["valid"], valid["strict"]) == (
        "tool_args",
        True,
        True,
    )
    assert (
        wrong["valid"],
        wrong["error_path"],
        wrong["error_tool"],
        wrong["error_keyword"],
    ) == (
        False,
        "/tool_calls/1/count",
        "lookup",
        "type",
    )
    assert (unknown["error_keyword"], unknown["error_tool"], unknown["error_path"]) == (
        "unknown_tool",
        "missing",
        "/tool_calls/0",
    )
    assert unparsable["error_keyword"] == "parse"


@pytest.mark.parametrize(
    ("protocol", "payload"),
    [
        (
            "responses",
            {
                "tools": [
                    {"type": "function", "name": "lookup", "parameters": SCHEMA},
                    {"type": "web_search"},
                ]
            },
        ),
        (
            "messages",
            {
                "tools": [
                    {"name": "lookup", "input_schema": SCHEMA},
                    {"type": "web_search_20250305", "name": "web_search"},
                ]
            },
        ),
        (
            "generate_content",
            {
                "tools": [
                    {
                        "functionDeclarations": [
                            {"name": "lookup", "parametersJsonSchema": SCHEMA}
                        ]
                    },
                    {"googleSearch": {}},
                ]
            },
        ),
    ],
)
def test_tool_schemas_per_protocol_and_built_ins_are_skipped(protocol, payload) -> None:
    calls = (AnalysisToolCall("web_search", "{}"), AnalysisToolCall("lookup", WRONG))

    result = SchemaAnalyzer().analyze(_context(payload, protocol, "", calls=calls))

    if protocol == "generate_content":
        # A Gemini built-in is not a function, so its call is unknown.
        assert result["error_keyword"] == "unknown_tool"
    else:
        assert (result["valid"], result["error_path"]) == (False, "/tool_calls/1/count")


def test_gemini_openapi_parameters() -> None:
    payload = {
        "tools": [
            {"functionDeclarations": [{"name": "lookup", "parameters": GEMINI_SCHEMA}]}
        ]
    }

    result = SchemaAnalyzer().analyze(
        _context(
            payload, "generate_content", "", calls=(AnalysisToolCall("lookup", WRONG),)
        )
    )

    assert (result["valid"], result["error_path"]) == (False, "/tool_calls/0/count")


def test_tool_arguments_split_over_many_stream_fragments() -> None:
    def fragment(arguments: str, name: str | None = None) -> bytes:
        function = {"arguments": arguments, **({"name": name} if name else {})}
        event = {
            "choices": [{"delta": {"tool_calls": [{"index": 0, "function": function}]}}]
        }
        return f"data: {json.dumps(event)}\n\n".encode()

    meter = StreamMeter(
        provider="openai",
        requested_model="gpt-5-nano",
        prompt_tokens_estimated=5,
        keep_answer=True,
    )
    pieces = [WRONG[index : index + 3] for index in range(0, len(WRONG), 3)]
    meter.observe_sse(
        fragment("", "lookup") + b"".join(fragment(piece) for piece in pieces)
    )

    result = SchemaAnalyzer().analyze(
        _context(_TOOLS, answer="", calls=meter.kept_tool_calls())
    )

    assert len(pieces) > 10
    assert (result["valid"], result["error_path"]) == (False, "/tool_calls/0/count")


def test_language_still_labels_json_answers_unknown() -> None:
    result = LanguageAnalyzer().analyze(
        _context(_chat_schema(), answer="This is an English answer here.")
    )

    assert result["answer"] == "unknown"


def test_the_analyzer_is_registered_after_language() -> None:
    names = [analyzer.name for analyzer in ANALYZERS]

    assert names.index("schema") == names.index("language") + 1
