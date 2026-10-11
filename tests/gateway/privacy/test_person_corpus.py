"""The Turkish person-name corpora, measured with only PERSON_NAME_TR on.

`person-tr-v1.json` is written with the recognizer and holds every case to its
label. `person-tr-heldout-v1.json` is written by an author who never saw the name
lists or the recognizer; it is scored as written, and the bar must hold on it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from shim.privacy.pii_scrubber import PIIScrubberService
from shim.privacy.policies import effective_entity_actions


def _load(name: str) -> dict[str, Any]:
    return json.loads(
        (Path(__file__).parent / "corpus" / name).read_text(encoding="utf-8")
    )


CORPUS = _load("person-tr-v1.json")
HELD_OUT = _load("person-tr-heldout-v1.json")
CASES: list[dict[str, Any]] = CORPUS["cases"]
ACTIONS = {entity: "off" for entity in effective_entity_actions()} | {
    "PERSON_NAME_TR": "mask"
}


def _label(case: dict[str, Any], item: dict[str, Any]) -> str:
    """The labelled text; the held-out corpus labels by offsets."""
    return (
        item["value"] if "value" in item else case["text"][item["start"] : item["end"]]
    )


def _expected(case: dict[str, Any], key: str = "expect") -> set[str]:
    return {_label(case, item) for item in case[key]}


def _actual(case: dict[str, Any]) -> set[str]:
    text = case["text"]
    return {
        text[finding["start"] : finding["end"]]
        for finding in PIIScrubberService().analyze(text, ACTIONS)
    }


def test_corpus_is_well_formed() -> None:
    measured = [case for case in CASES if "known_gap" not in case]

    assert (CORPUS["format"], CORPUS["version"], CORPUS["entities"]) == (
        "shim.detection.corpus",
        1,
        ["PERSON_NAME_TR"],
    )
    assert len({case["id"] for case in CASES}) == len(CASES) >= 200
    assert sum(1 for case in measured if case["expect"]) >= 100
    assert sum(1 for case in measured if not case["expect"]) >= 100
    for case in CASES:
        assert ("known_gap" in case) == ("known_actual" in case), case["id"]
        for item in case["expect"] + case.get("known_actual", []):
            assert item["entity"] == "PERSON_NAME_TR", case["id"]
            assert item["value"] in case["text"], case["id"]


def test_held_out_corpus_is_well_formed() -> None:
    cases = HELD_OUT["cases"]

    assert (HELD_OUT["format"], HELD_OUT["version"], HELD_OUT["entities"]) == (
        "shim.detection.corpus",
        1,
        ["PERSON_NAME_TR"],
    )
    assert len({case["id"] for case in cases}) == len(cases) == 180
    assert not any("known_gap" in case for case in cases)
    for case in cases:
        for item in case["expect"]:
            assert item["entity_type"] == "PERSON_NAME_TR", case["id"]
            # Each label occurs once, so comparing texts is comparing offsets.
            assert case["text"].count(_label(case, item)) == 1, case["id"]


@pytest.mark.parametrize("case", CASES, ids=[case["id"] for case in CASES])
def test_corpus_case(case: dict[str, Any]) -> None:
    expected, actual = _expected(case), _actual(case)

    if "known_gap" in case:
        assert actual != expected, (
            f"{case['id']} now passes: remove its known_gap ({case['known_gap']})"
        )
        assert actual == _expected(case, "known_actual"), (
            f"{case['id']}: known gap output changed to {sorted(actual)}"
        )
    else:
        assert actual == expected, (
            f"{case['id']}: expected {sorted(expected)}, actual {sorted(actual)}"
        )


@pytest.mark.parametrize("corpus", [CORPUS, HELD_OUT], ids=["v1", "held-out"])
def test_precision_and_recall_meet_the_bar(corpus: dict[str, Any]) -> None:
    true_positive = false_positive = false_negative = 0
    for case in corpus["cases"]:
        if "known_gap" in case:
            continue
        expected, actual = _expected(case), _actual(case)
        true_positive += len(expected & actual)
        false_positive += len(actual - expected)
        false_negative += len(expected - actual)
        if actual != expected:
            print(f"{case['id']}: expected {sorted(expected)}, actual {sorted(actual)}")
    precision = true_positive / (true_positive + false_positive)
    recall = true_positive / (true_positive + false_negative)

    print(f"PERSON_NAME_TR: precision {precision:.3f}, recall {recall:.3f}")
    assert precision >= 0.95
    assert recall >= 0.85
