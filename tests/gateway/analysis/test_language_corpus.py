"""The language corpus: what the heuristic must label, and the cases it still gets wrong."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
from typing import Any

import pytest

from shim.gateway.analyzers.language import label

CORPUS = json.loads(
    (Path(__file__).parent / "corpus" / "language-v1.json").read_text(encoding="utf-8")
)
CASES: list[dict[str, Any]] = CORPUS["cases"]


def test_the_corpus_is_well_formed() -> None:
    ids = [case["id"] for case in CASES]

    assert (CORPUS["format"], CORPUS["version"]) == ("shim.language.corpus", 1)
    assert all(case["id"].rsplit("-", 1)[1].isdigit() for case in CASES)
    assert len(ids) == len(set(ids))
    assert all(case["expect"] in {"tr", "en", "other", "unknown"} for case in CASES)


@pytest.mark.parametrize("case", CASES, ids=[case["id"] for case in CASES])
def test_corpus_case(case: dict[str, Any]) -> None:
    actual = label(case["text"])[:2]
    expected = (case["expect"], case["mixed"])

    if "known_gap" in case:
        assert actual != expected, (
            f"{case['id']} now passes: remove its known_gap ({case['known_gap']})"
        )
    else:
        assert actual == expected, f"{case['id']}: expected {expected}, actual {actual}"


def test_every_group_meets_its_minimum() -> None:
    counts = Counter(
        case["id"].rsplit("-", 1)[0].removesuffix("-held")
        for case in CASES
        if "known_gap" not in case
    )
    gaps = sum("known_gap" in case for case in CASES)

    print(f"language corpus: {len(CASES)} cases, {gaps} known gaps, {dict(counts)}")
    minimums = {
        "tr": 40,
        "en": 40,
        "mixed": 10,
        "other-latin": 10,
        "non-latin": 8,
        "short": 8,
    }
    assert {group: counts[group] for group in minimums} == {
        group: max(counts[group], minimum) for group, minimum in minimums.items()
    }
