from __future__ import annotations

from importlib.resources import files
import json

import pytest

from shim.gateway.analyzers import ANALYZERS
from shim.gateway.analyzers.refusal import RefusalAnalyzer, normalise, soft_refusal
from shim.gateway.pipeline.analysis import AnalysisContext


def _context(answer: str, outcome: str | None = "complete") -> AnalysisContext:
    return AnalysisContext(
        request_id="req",
        protocol="chat",
        model="m",
        payload={},
        answer_text=answer,
        answer_truncated=False,
        tool_calls=(),
        completion_outcome=outcome,
        restore=lambda text: text,
    )


@pytest.mark.parametrize("outcome", ["refused", "filtered", "truncated", "empty", None])
def test_only_a_complete_answer_with_text_is_read(outcome) -> None:
    assert (
        RefusalAnalyzer().analyze(_context("I can't help with that.", outcome)) is None
    )


@pytest.mark.parametrize("answer", ["", "   \n"])
def test_an_answer_without_text_is_skipped(answer) -> None:
    assert RefusalAnalyzer().analyze(_context(answer)) is None


def test_the_result_holds_the_marker_id_only() -> None:
    assert RefusalAnalyzer().analyze(
        _context("Üzgünüm, bu konuda yardımcı olamam.")
    ) == {
        "soft_refusal": True,
        "marker": "tr.yardimci_olamam",
    }
    assert RefusalAnalyzer().analyze(_context("Elbette, işte rapor.")) == {
        "soft_refusal": False,
        "marker": None,
    }


def test_normalising_the_start() -> None:
    assert normalise("  \n> ## **“Üzgünüm”**, BU KONUDA __YARDIMCI__ OLAMAM") == (
        '"uzgunum", bu konuda yardimci olamam'
    )
    assert normalise("“Bu konuda yardımcı olamam.”") == "bu konuda yardimci olamam."
    assert normalise("Ｉ ｃａｎ’ｔ\n  ｈｅｌｐ") == "i can't\nhelp"
    assert normalise("I’M SORRY, BUT I CAN’T") == "i'm sorry, but i can't"
    assert normalise("İZMİR IŞIK") == "izmir isik"
    assert len(normalise("x" * 1_000)) == 400


def _at(offset: int, phrase: str = "I can't help with that.") -> str:
    return "x" * (offset - 1) + " " + phrase if offset else phrase


def test_the_phrase_must_start_within_200_characters() -> None:
    assert soft_refusal(_at(199)) == "en.cant_help"
    assert soft_refusal(_at(200)) is None


def test_the_answer_is_at_most_1500_characters() -> None:
    refusal = "I can't help with that."

    assert (
        soft_refusal(refusal + " " + "y" * (1_500 - len(refusal) - 1)) == "en.cant_help"
    )
    assert soft_refusal(refusal + " " + "y" * (1_501 - len(refusal) - 1)) is None


def test_an_exception_phrase_counts_within_60_characters_after_the_match() -> None:
    def after(gap: int) -> str:
        return "I can't help with " + "z" * gap + " instead"

    # "instead" starts gap + 2 characters after the match: a space, the gap, a space.
    assert soft_refusal(after(58)) is None
    assert soft_refusal(after(59)) == "en.cant_help"


def test_a_phrase_after_an_open_quote_on_its_line_is_not_a_refusal() -> None:
    assert soft_refusal("He wrote: 'I can't help with that' and left.") is None
    assert soft_refusal('He wrote: "Sorry, I can\'t help with that"') is None
    assert soft_refusal("He wrote: I can't help with that.") == "en.cant_help"
    assert soft_refusal("That's it: I can't help with that.") == "en.cant_help"
    assert soft_refusal('He wrote "no".\nI can\'t help with that.') == "en.cant_help"


def test_a_phrase_is_a_whole_word_run() -> None:
    assert soft_refusal("Bunu yapamamanız durumunda yazın.") is None
    assert soft_refusal("Yardımcı olamam. Diyet planı için...") == "tr.yardimci_olamam"


def test_the_first_marker_in_table_order_wins() -> None:
    assert (
        soft_refusal("I'm sorry, but I can't help with that request.") == "en.cant_help"
    )
    assert soft_refusal("I'm sorry, but I can't share it.") == "en.sorry_but"


def test_every_phrase_alone_loads_as_its_own_marker() -> None:
    data = json.loads(
        files("shim.gateway.analyzers")
        .joinpath(f"refusal-v{RefusalAnalyzer.version}.json")
        .read_text("utf-8")
    )
    ids = [marker["id"] for marker in data["markers"]]
    phrases = [phrase for marker in data["markers"] for phrase in marker["phrases"]]

    assert len(ids) == len(set(ids)) and all(
        marker_id.startswith(("tr.", "en.")) for marker_id in ids
    )
    assert len({normalise(phrase) for phrase in phrases}) == len(phrases)
    for marker in data["markers"]:
        for phrase in marker["phrases"]:
            assert soft_refusal(phrase) == marker["id"], phrase


def test_the_analyzer_is_registered_after_schema() -> None:
    names = [analyzer.name for analyzer in ANALYZERS]

    assert names.index("refusal") == names.index("schema") + 1
