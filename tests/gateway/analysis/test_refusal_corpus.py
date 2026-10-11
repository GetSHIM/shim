"""The refusal corpus: refusals in words, and helpful answers that only look like one."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
from typing import Any

import pytest

from shim.gateway.analyzers.refusal import soft_refusal

CORPUS = json.loads(
    (Path(__file__).parent / "corpus" / "refusal-v1.json").read_text(encoding="utf-8")
)
CASES: list[dict[str, Any]] = CORPUS["cases"]


def test_the_corpus_is_well_formed() -> None:
    ids = [case["id"] for case in CASES]

    assert (CORPUS["format"], CORPUS["version"]) == ("shim.refusal.corpus", 1)
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("case", CASES, ids=[case["id"] for case in CASES])
def test_corpus_case(case: dict[str, Any]) -> None:
    actual = soft_refusal(case["text"])

    if "known_gap" in case:
        assert actual != case["expect"], (
            f"{case['id']} now passes: remove its known_gap ({case['known_gap']})"
        )
    else:
        assert actual == case["expect"], f"{case['id']}: {actual}"


def test_hits_per_marker() -> None:
    hits = Counter(case["expect"] for case in CASES if "known_gap" not in case)
    print(
        f"refusal corpus: {len(CASES)} cases, "
        f"{sum('known_gap' in case for case in CASES)} known gaps, {dict(hits)}"
    )

    assert hits[None] >= 30 and sum(hits.values()) - hits[None] >= 45
