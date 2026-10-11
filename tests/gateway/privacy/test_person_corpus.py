"""The Turkish person-name corpus, measured with only PERSON_NAME_TR on."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from shim.privacy.pii_scrubber import PIIScrubberService
from shim.privacy.policies import effective_entity_actions


CORPUS: dict[str, Any] = json.loads(
    (Path(__file__).parent / "corpus" / "person-tr-v1.json").read_text(encoding="utf-8")
)
CASES: list[dict[str, Any]] = CORPUS["cases"]
ACTIONS = {entity: "off" for entity in effective_entity_actions()} | {
    "PERSON_NAME_TR": "mask"
}


def _expected(case: dict[str, Any], key: str = "expect") -> set[str]:
    return {item["value"] for item in case[key]}


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


def test_precision_and_recall_meet_the_bar() -> None:
    true_positive = false_positive = false_negative = 0
    for case in CASES:
        if "known_gap" in case:
            continue
        expected, actual = _expected(case), _actual(case)
        true_positive += len(expected & actual)
        false_positive += len(actual - expected)
        false_negative += len(expected - actual)
    precision = true_positive / (true_positive + false_positive)
    recall = true_positive / (true_positive + false_negative)

    print(f"PERSON_NAME_TR: precision {precision:.3f}, recall {recall:.3f}")
    assert precision >= 0.95
    assert recall >= 0.85
