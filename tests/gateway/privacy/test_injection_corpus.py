"""The injection corpus: the markers each text must carry, exactly."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from shim.privacy.injection import MARKERS, scan


CORPUS: dict[str, Any] = json.loads(
    (Path(__file__).parent / "corpus" / "injection-v1.json").read_text(encoding="utf-8")
)
CASES: list[dict[str, Any]] = CORPUS["cases"]


def test_corpus_is_well_formed() -> None:
    measured = [case for case in CASES if "known_gap" not in case]
    english = [case for case in measured if case["id"].startswith("en-")]

    assert (CORPUS["format"], CORPUS["version"]) == ("shim.injection.corpus", 1)
    assert len({case["id"] for case in CASES}) == len(CASES)
    assert sum(1 for case in english if case["expect"]) >= 20
    assert sum(1 for case in english if not case["expect"]) >= 20
    for case in CASES:
        assert set(case["expect"]) <= set(MARKERS), case["id"]
        assert ("known_gap" in case) == ("known_actual" in case), case["id"]


@pytest.mark.parametrize("case", CASES, ids=[case["id"] for case in CASES])
def test_corpus_case(case: dict[str, Any]) -> None:
    actual = list(scan(case["text"]))

    if "known_gap" in case:
        assert actual != case["expect"], (
            f"{case['id']} now passes: remove its known_gap ({case['known_gap']})"
        )
        assert actual == case["known_actual"], case["id"]
    else:
        assert actual == case["expect"], case["id"]
