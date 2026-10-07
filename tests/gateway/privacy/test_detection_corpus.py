"""The detection corpus: what the detector must find, leave alone, and still misses."""

from __future__ import annotations

from collections import Counter
from importlib.metadata import version
import json
from pathlib import Path
import tomllib
from typing import Any

import pytest

from shim.privacy.pii_scrubber import PIIScrubberService


CORPUS = json.loads(
    (Path(__file__).parent / "corpus" / "detection-v1.json").read_text(encoding="utf-8")
)
CASES: list[dict[str, Any]] = CORPUS["cases"]


def _expected(case: dict[str, Any], key: str = "expect") -> set[tuple[str, str]]:
    return {(item["entity"], item["value"]) for item in case[key]}


def _actual(case: dict[str, Any]) -> set[tuple[str, str]]:
    text = case["text"]
    return {
        (finding["type"], text[finding["start"] : finding["end"]])
        for finding in PIIScrubberService().analyze(text)
    }


def test_corpus_is_well_formed() -> None:
    ids = [case["id"] for case in CASES]
    entities = set(CORPUS["entities"])

    assert CORPUS["format"] == "shim.detection.corpus"
    assert CORPUS["version"] == 1
    assert len(ids) == len(set(ids))
    for case in CASES:
        assert ("known_gap" in case) == ("known_actual" in case), case["id"]
        for item in case["expect"] + case.get("known_actual", []):
            assert item["entity"] in entities, case["id"]
            assert item["value"] in case["text"], case["id"]


@pytest.mark.parametrize("case", CASES, ids=[case["id"] for case in CASES])
def test_corpus_case(case: dict[str, Any]) -> None:
    expected, actual = _expected(case), _actual(case)

    if "known_gap" in case:
        assert actual != expected, (
            f"{case['id']} now passes: remove its known_gap ({case['known_gap']})"
        )
        # A gap that turns into a different wrong result is a change to review.
        assert actual == _expected(case, "known_actual"), (
            f"{case['id']}: known gap output changed to {sorted(actual)}"
        )
    else:
        assert actual == expected, (
            f"{case['id']}: expected {sorted(expected)}, actual {sorted(actual)}"
        )


def test_corpus_precision_and_recall_per_entity() -> None:
    measured = [case for case in CASES if "known_gap" not in case]
    true_positive: Counter[str] = Counter()
    false_positive: Counter[str] = Counter()
    false_negative: Counter[str] = Counter()
    for case in measured:
        expected, actual = _expected(case), _actual(case)
        for entity, _ in expected & actual:
            true_positive[entity] += 1
        for entity, _ in actual - expected:
            false_positive[entity] += 1
        for entity, _ in expected - actual:
            false_negative[entity] += 1

    print(
        f"corpus: {len(CASES)} cases, {len(CASES) - len(measured)} known gaps, "
        f"{sum(true_positive.values())} findings, "
        f"{sum(1 for case in measured if not case['expect'])} negatives"
    )
    for entity in sorted(
        set(true_positive) | set(false_positive) | set(false_negative)
    ):
        found = true_positive[entity] + false_positive[entity]
        wanted = true_positive[entity] + false_negative[entity]
        assert true_positive[entity] / found == 1.0, f"{entity} precision"
        assert true_positive[entity] / wanted == 1.0, f"{entity} recall"


def test_detector_inputs_are_the_reviewed_pins() -> None:
    # The corpus was measured against these releases; a bump is reviewed against it.
    project = tomllib.loads(
        (Path(__file__).parents[3] / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]
    pins = dict(
        requirement.split("==")
        for requirement in project["dependencies"]
        if requirement.startswith(("presidio-analyzer==", "phonenumbers=="))
    )

    assert pins.keys() == {"presidio-analyzer", "phonenumbers"}
    for name, pinned in pins.items():
        assert version(name) == pinned, name
