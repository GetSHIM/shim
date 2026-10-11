from __future__ import annotations

from importlib.resources import files
import json

import pytest

from shim.gateway.analyzers import ANALYZER_NAMES, ANALYZERS
from shim.gateway.analyzers.language import (
    LanguageAnalyzer,
    _asks_for_json,
    _fold,
    _turkish_lower,
    label,
    request_text,
)
from shim.gateway.pipeline.analysis import AnalysisContext

TURKISH = "Bu raporu yarın sabaha kadar hazırlayabilir misin, müşteri bekliyor."
ENGLISH = "Could you explain why the interest rate went up this month?"


def _context(
    payload: dict, protocol: str = "chat", answer: str = ENGLISH
) -> AnalysisContext:
    return AnalysisContext(
        request_id="req",
        protocol=protocol,
        model="m",
        payload=payload,
        answer_text=answer,
        answer_truncated=False,
        tool_calls=(),
        completion_outcome="complete",
        restore=lambda text: text,
    )


@pytest.mark.parametrize(
    ("protocol", "payload"),
    [
        (
            "chat",
            {
                "messages": [
                    {"role": "user", "content": TURKISH},
                    {"role": "assistant", "content": "ok"},
                    {"role": "tool", "content": "tool output in English only"},
                ]
            },
        ),
        (
            "chat",
            {
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": TURKISH},
                            {"type": "image_url"},
                        ],
                    }
                ]
            },
        ),
        ("responses", {"input": TURKISH}),
        (
            "responses",
            {
                "input": [
                    {
                        "role": "user",
                        "content": [{"type": "input_text", "text": TURKISH}],
                    },
                    {
                        "type": "function_call_output",
                        "output": "an English tool result here",
                    },
                ]
            },
        ),
        (
            "messages",
            {
                "messages": [
                    {"role": "user", "content": [{"type": "text", "text": TURKISH}]},
                    {
                        "role": "assistant",
                        "content": [{"type": "tool_use", "name": "f", "input": {}}],
                    },
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "content": "English tool output text",
                            }
                        ],
                    },
                ]
            },
        ),
        (
            "generate_content",
            {
                "contents": [
                    {"role": "user", "parts": [{"text": TURKISH}]},
                    {
                        "role": "user",
                        "parts": [
                            {"functionResponse": {"name": "f", "response": {"r": "x"}}}
                        ],
                    },
                ]
            },
        ),
    ],
)
def test_the_request_text_is_the_last_user_turn_with_text(protocol, payload) -> None:
    assert request_text(payload, protocol) == TURKISH


@pytest.mark.parametrize(
    ("protocol", "payload"),
    [
        ("chat", {"response_format": {"type": "json_object"}}),
        ("chat", {"response_format": {"type": "json_schema", "json_schema": {}}}),
        ("responses", {"text": {"format": {"type": "json_schema"}}}),
        ("messages", {"output_config": {"format": {"type": "json_schema"}}}),
        ("messages", {"output_format": {"type": "json_schema"}}),
        (
            "generate_content",
            {"generationConfig": {"responseMimeType": "application/json"}},
        ),
        ("generate_content", {"generationConfig": {"responseSchema": {}}}),
        ("generate_content", {"generationConfig": {"responseJsonSchema": {}}}),
    ],
)
def test_a_json_answer_is_unknown(protocol, payload) -> None:
    assert _asks_for_json(payload, protocol) is True
    result = LanguageAnalyzer().analyze(_context(payload, protocol))
    assert (result["answer"], result["answer_words"]) == ("unknown", 0)


def test_text_output_and_empty_answers() -> None:
    assert _asks_for_json({"response_format": {"type": "text"}}, "chat") is False
    assert LanguageAnalyzer().analyze(_context({}, answer=""))["answer"] == "unknown"


def test_the_result_holds_labels_and_counts_only() -> None:
    result = LanguageAnalyzer().analyze(
        _context({"messages": [{"role": "user", "content": TURKISH}]})
    )

    assert result == {
        "request": "tr",
        "answer": "en",
        "answer_mixed": False,
        "request_words": 9,
        "answer_words": 11,
    }


def test_code_urls_mail_and_placeholders_are_removed_first() -> None:
    noise = (
        "```python\nprint('the and of to is in that for with')\n```\n"
        "`the and of to` https://example.com/the/and/of the@example.com "
        "<EMAIL_ADDRESS_0123abcd> "
    )

    assert label(noise + TURKISH)[0] == "tr"
    assert label(noise)[0] == "unknown"


def test_turkish_lowercase_and_the_ascii_fold() -> None:
    assert _turkish_lower("IŞIK İzmir") == "ışık izmir"
    assert _fold("Çok Güzel ŞİMDİ") == "cok guzel simdi"
    assert (
        label("cok guzel olmus, bu konuda bana biraz daha yardim eder misin")[0] == "tr"
    )


def test_the_english_i_counts_only_written_uppercase() -> None:
    assert label("I qwer asdf zxcv I")[0] == "en"
    assert label("i qwer asdf zxcv i")[0] == "other"


def test_only_the_first_4000_characters_are_read() -> None:
    assert label("x" * 4_000 + " " + TURKISH)[0] == "unknown"


@pytest.mark.parametrize("text", ["iki kelime", "bir iki üç", "Tamam", "aaaa bbbb ccc"])
def test_too_few_words_or_letters_is_unknown(text) -> None:
    assert label(text)[0] == "unknown"


def test_the_word_lists_are_valid() -> None:
    data = json.loads(
        files("shim.gateway.analyzers").joinpath("language-v1.json").read_text("utf-8")
    )
    turkish, english = data["tr_function_words"], data["en_function_words"]

    assert len(turkish) == len(set(turkish)) and len(english) == len(set(english))
    folded = {_fold(word) for word in turkish}
    assert len(folded) == len(turkish)
    assert not folded & {word.lower() for word in english}
    assert not {"de", "da", "ne", "mi", "o", "en", "ya", "her"} & (
        folded | set(english)
    )


def test_the_analyzer_is_registered_after_shape() -> None:
    names = [analyzer.name for analyzer in ANALYZERS]

    assert "language" in ANALYZER_NAMES
    assert names.index("language") == names.index("shape") + 1
