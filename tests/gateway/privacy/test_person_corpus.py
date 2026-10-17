"""The person-name corpora, each measured with only its own type on.

`person-tr-v1.json` and `person-en-v1.json` are written with the recognizers and
hold every case to its label or to its recorded gap. The held-out corpora are written by an author who
never saw the name lists or the recognizer; they are scored as written, and the
bar must hold on them. `person-en-heldout-v1.json` was measured before the rules
changed, so it is reported without a bar; `person-en-heldout-v2.json` carries it.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import random
from typing import Any

import pytest

from scripts.bench import pii_corpus
from shim.privacy.pii_scrubber import PIIScrubberService
from shim.privacy.policies import effective_entity_actions


def _load(name: str) -> dict[str, Any]:
    return json.loads(
        (Path(__file__).parent / "corpus" / name).read_text(encoding="utf-8")
    )


CORPUS = _load("person-tr-v1.json")
HELD_OUT = _load("person-tr-heldout-v1.json")
CASES: list[dict[str, Any]] = CORPUS["cases"]
EN_CORPUS = _load("person-en-v1.json")
EN_HELD_OUT = _load("person-en-heldout-v1.json")
# (entity, corpus file, precision and recall bars, or None for a report only)
MEASURED: dict[str, tuple[str, str, tuple[float, float] | None]] = {
    "tr-v1": ("PERSON_NAME_TR", "person-tr-v1.json", (0.95, 0.85)),
    "tr-held-out": ("PERSON_NAME_TR", "person-tr-heldout-v1.json", (0.95, 0.85)),
    "en-v1": ("PERSON_NAME_EN", "person-en-v1.json", (0.95, 0.90)),
    "en-held-out-v1": ("PERSON_NAME_EN", "person-en-heldout-v1.json", None),
    "en-held-out": ("PERSON_NAME_EN", "person-en-heldout-v2.json", (0.95, 0.90)),
}


def _only(entity: str) -> dict[str, str]:
    return {name: "off" for name in effective_entity_actions()} | {entity: "mask"}


Span = tuple[int, int]


def _span(case: dict[str, Any], item: dict[str, Any]) -> Span:
    """The labelled span; the tuning corpora label a value, the held-out ones offsets."""
    if "value" not in item:
        return item["start"], item["end"]
    start = case["text"].index(item["value"])
    return start, start + len(item["value"])


def _expected(case: dict[str, Any], key: str = "expect") -> set[Span]:
    return {_span(case, item) for item in case[key]}


def _actual(case: dict[str, Any], entity: str = "PERSON_NAME_TR") -> set[Span]:
    return {
        (finding["start"], finding["end"])
        for finding in PIIScrubberService().analyze(case["text"], _only(entity))
    }


def _texts(case: dict[str, Any], spans: set[Span]) -> list[str]:
    return [case["text"][start:end] for start, end in sorted(spans)]


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


@pytest.mark.parametrize(
    ("corpus", "entity", "size"),
    [(HELD_OUT, "PERSON_NAME_TR", 180), (EN_HELD_OUT, "PERSON_NAME_EN", 330)],
    ids=["tr", "en"],
)
def test_held_out_corpus_is_well_formed(
    corpus: dict[str, Any], entity: str, size: int
) -> None:
    cases = corpus["cases"]

    assert (corpus["format"], corpus["version"], corpus["entities"]) == (
        "shim.detection.corpus",
        1,
        [entity],
    )
    assert len({case["id"] for case in cases}) == len(cases) == size
    assert not any("known_gap" in case for case in cases)
    for case in cases:
        for item in case["expect"]:
            assert item["entity_type"] == entity, case["id"]
            assert 0 <= item["start"] < item["end"] <= len(case["text"]), case["id"]


def test_english_corpus_holds_the_required_mix() -> None:
    cases = EN_CORPUS["cases"]
    groups = {case["id"].rsplit("-", 1)[0] for case in cases}

    assert (EN_CORPUS["format"], EN_CORPUS["version"], EN_CORPUS["entities"]) == (
        "shim.detection.corpus",
        1,
        ["PERSON_NAME_EN"],
    )
    assert len({case["id"] for case in cases}) == len(cases)
    assert sum(len(case["expect"]) for case in cases if "known_gap" not in case) >= 120
    assert sum(1 for case in cases if not case["expect"]) >= 120
    assert sum(len(c["expect"]) for c in cases if c["id"].startswith("mixed")) >= 40
    assert sum(1 for c in cases if c["id"].startswith("not-turkish")) >= 30
    assert {
        "cue",
        "pair",
        "middle",
        "initial",
        "apostrophe",
        "hyphen",
        "mc",
        "capitals",
        "international",
        "mixed",
        "not-institution",
        "not-brand",
        "not-ambiguous",
        "not-heading",
        "not-date",
        "not-turkish",
    } <= groups
    for case in cases:
        assert ("known_gap" in case) == ("known_actual" in case), case["id"]
        for item in case["expect"]:
            assert item["entity"] == "PERSON_NAME_EN", case["id"]
            assert case["text"].count(item["value"]) == 1, case["id"]


TUNING = [("PERSON_NAME_TR", case) for case in CASES] + [
    ("PERSON_NAME_EN", case) for case in EN_CORPUS["cases"]
]


@pytest.mark.parametrize(
    ("entity", "case"),
    TUNING,
    ids=[f"{entity}-{case['id']}" for entity, case in TUNING],
)
def test_corpus_case(entity: str, case: dict[str, Any]) -> None:
    expected, actual = _expected(case), _actual(case, entity)

    if "known_gap" in case:
        assert actual != expected, (
            f"{case['id']} now passes: remove its known_gap ({case['known_gap']})"
        )
        assert actual == _expected(case, "known_actual"), (
            f"{case['id']}: known gap output changed to {_texts(case, actual)}"
        )
    else:
        assert actual == expected, (
            f"{case['id']}: expected {_texts(case, expected)}, "
            f"actual {_texts(case, actual)}"
        )


@pytest.mark.parametrize("measured", MEASURED.values(), ids=MEASURED.keys())
def test_precision_and_recall_meet_the_bar(
    measured: tuple[str, str, tuple[float, float] | None],
) -> None:
    entity, name, bars = measured
    corpus = _load(name)
    assert corpus["entities"] == [entity]
    true_positive = false_positive = false_negative = 0
    for case in corpus["cases"]:
        if "known_gap" in case:
            continue
        expected, actual = _expected(case), _actual(case, entity)
        true_positive += len(expected & actual)
        false_positive += len(actual - expected)
        false_negative += len(expected - actual)
        if actual != expected:
            print(
                f"{case['id']}: expected {_texts(case, expected)}, "
                f"actual {_texts(case, actual)}"
            )
    precision = true_positive / (true_positive + false_positive)
    recall = true_positive / (true_positive + false_negative)

    print(f"{entity} {name}: precision {precision:.3f}, recall {recall:.3f}")
    if bars is not None:
        assert precision >= bars[0]
        assert recall >= bars[1]


@pytest.mark.parametrize("corpus", [CORPUS, HELD_OUT], ids=["v1", "held-out"])
def test_english_names_find_nothing_but_turkish_names_in_turkish_text(
    corpus: dict[str, Any],
) -> None:
    for case in corpus["cases"]:
        labels = _expected(case)
        for start, end in _actual(case, "PERSON_NAME_EN"):
            assert any(start < last and first < end for first, last in labels), (
                case["id"],
                case["text"][start:end],
            )


def test_turkish_names_are_unchanged_since_s41() -> None:
    """R8: the Turkish spans recorded on cf8c454, before the engine took English data."""
    recorded = _load("person-tr-r8-cf8c454.json")
    rng = random.Random(pii_corpus.SEED)
    texts = [case["text"] for case in CASES + HELD_OUT["cases"]] + [
        pii_corpus.render(template, rng)["text"]
        for template in pii_corpus.TEMPLATES
        for _ in range(30)
    ]
    scrubber = PIIScrubberService()
    actions = _only("PERSON_NAME_TR")

    assert len(texts) == 914
    assert (
        hashlib.sha256("\n".join(texts).encode()).hexdigest()
        == recorded["texts_sha256"]
    )
    assert [
        [
            [finding["start"], finding["end"]]
            for finding in scrubber.analyze(text, actions)
        ]
        for text in texts
    ] == recorded["spans"]
