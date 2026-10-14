"""The schema-subset corpus, and a seeded fuzz: check never raises."""

from __future__ import annotations

import json
from pathlib import Path
import random
import sys
from typing import Any

import pytest

from shim.jsonschema_subset import SchemaCheck, check

CORPUS = json.loads(
    (
        Path(__file__).parent / "gateway" / "analysis" / "corpus" / "schema-v1.json"
    ).read_text(encoding="utf-8")
)
CASES: list[dict[str, Any]] = CORPUS["cases"]


def test_the_corpus_is_well_formed() -> None:
    ids = [case["id"] for case in CASES]

    assert (CORPUS["format"], CORPUS["version"]) == ("shim.schema.corpus", 1)
    assert len(ids) == len(set(ids)) and len(ids) >= 120 - 2


@pytest.mark.parametrize("case", CASES, ids=[case["id"] for case in CASES])
def test_corpus_case(case: dict[str, Any]) -> None:
    found = check(case["instance"], case["schema"], dialect=case["dialect"])

    assert {
        "valid": found.valid,
        "error_path": found.error_path,
        "error_keyword": found.error_keyword,
        "unsupported": list(found.unsupported),
    } == case["expect"]


@pytest.mark.parametrize(
    ("case_id", "reason"),
    [
        ("bound-depth-33", "depth"),
        ("ref-unresolved", "bad_schema"),
        ("bad-schema-type", "bad_schema"),
        ("bad-schema-minimum-string", "bad_schema"),
    ],
)
def test_a_bound_or_a_bad_schema_gives_its_reason(case_id: str, reason: str) -> None:
    [case] = [case for case in CASES if case["id"] == case_id]

    assert (
        check(case["instance"], case["schema"], dialect=case["dialect"]).reason
        == reason
    )


@pytest.mark.parametrize(
    ("count", "valid", "reason"), [(9_999, True, None), (10_000, None, "nodes")]
)
def test_an_array_is_charged_its_length_against_the_node_bound(
    count: int, valid: bool | None, reason: str | None
) -> None:
    found = check(list(range(count)), {"type": "array", "items": {"type": "integer"}})

    assert (found.valid, found.reason) == (valid, reason)


def _work(instance: Any, schema: Any) -> tuple[SchemaCheck, int]:
    """The check and its work: every call and return it made, counted, not timed."""

    events = 0

    def count(*_: object) -> None:
        nonlocal events
        events += 1

    sys.setprofile(count)
    try:
        found = check(instance, schema)
    finally:
        sys.setprofile(None)
    return found, events


def test_hostile_schemas_end_fast_with_a_decision_or_the_node_bound() -> None:
    branches, branches_work = _work(
        list(range(50_000)),
        {"anyOf": [{"items": {"type": "string"}}] * 2_000},
    )
    nested, nested_work = _work(
        [[0] * 2_999 + [index] for index in range(100)],
        {"uniqueItems": True},
    )
    wide, wide_work = _work(
        [
            {f"k{key}": key for key in range(1_499)} | {"last": index}
            for index in range(140)
        ],
        {"uniqueItems": True},
    )
    short, short_work = _work(
        [[0] * 50 + [index] for index in range(100)], {"uniqueItems": True}
    )

    assert (branches.valid, branches.reason) == (None, "nodes")
    assert (nested.valid, nested.reason) == (None, "nodes")
    assert (wide.valid, wide.reason) == (None, "nodes")
    assert (short.valid, short.reason) == (True, None)
    # About 14 events per node of the default 10,000-node budget; the uncharged pairwise
    # uniqueness check this replaced made millions on `nested`.
    assert max(branches_work, nested_work, wide_work, short_work) < 30 * 10_000


def test_unique_items_keeps_json_equality() -> None:
    assert check([1, 1.0], {"uniqueItems": True}).valid is False
    assert check([True, 1], {"uniqueItems": True}).valid is True
    assert check([{"a": [1]}, {"a": [1.0]}], {"uniqueItems": True}).valid is False
    assert check([{"a": 1}, {"b": 1}], {"uniqueItems": True}).valid is True


@pytest.mark.parametrize(
    ("instance", "schema", "expected"),
    [
        ({"a": 1}, {"required": [1]}, (None, "bad_schema")),
        (
            {"x": "s"},
            {
                "properties": {"x": {"$ref": "#a"}},
                "$defs": {"a": {"$anchor": "a", "type": "integer"}},
            },
            (None, None),
        ),
        ([1, 2], {"minItems": "2"}, (True, None)),
        ([1], {"maxItems": "0"}, (False, None)),
        ("ab", {"type": "STRING", "maxLength": "1"}, (False, None)),
        ([1], {"minItems": "-1"}, (None, "bad_schema")),
    ],
    ids=[
        "required-not-a-string",
        "anchor-ref",
        "int64-min",
        "int64-max",
        "int64-openapi",
        "int64-not-a-count",
    ],
)
def test_odd_schemas_never_raise_and_never_guess(instance, schema, expected) -> None:
    found = check(instance, schema, dialect="openapi")

    assert (found.valid, found.reason) == expected


def test_unsupported_keywords_come_from_a_fixed_vocabulary() -> None:
    found = check(
        {}, {"pattern": "x", "not": {}, "x-customer-name-Ahmet": 1, "$ref": "https://x"}
    )

    assert found.unsupported == ("$ref", "not", "pattern", "unknown")


def test_paths_and_the_unsupported_list_are_bounded() -> None:
    name = "k" * 100
    schema: dict[str, Any] = {"type": "integer"}
    instance: Any = "x"
    for _ in range(12):
        schema = {"properties": {name: schema}}
        instance = {name: instance}

    deep = check(instance, schema)

    assert deep.valid is False and len(deep.error_path) == 512
    assert deep.error_path.startswith("/" + "k" * 64 + "/")


def _value(rng: random.Random, depth: int = 0) -> Any:
    kind = rng.randrange(8 if depth < 4 else 6)
    if kind == 0:
        return None
    if kind == 1:
        return rng.choice([True, False])
    if kind == 2:
        return rng.choice(
            [0, 1, -3, 2**70, 1.0, 0.1, 1e308, float("nan"), float("inf")]
        )
    if kind == 3:
        return rng.choice(["", "a", "ışık", "😀", "x" * 50])
    if kind == 4:
        return rng.choice([[], {}, "#", "#/$defs/a", "https://x"])
    if kind == 5:
        return rng.choice(["string", "INTEGER", "nope", ["null", "number"], 3])
    if kind == 6:
        return [_value(rng, depth + 1) for _ in range(rng.randrange(4))]
    return {
        rng.choice(_KEYWORDS + ["a", "b"]): _value(rng, depth + 1)
        for _ in range(rng.randrange(5))
    }


_KEYWORDS = [
    "type", "enum", "const", "properties", "required", "additionalProperties",
    "minProperties", "maxProperties", "items", "prefixItems", "minItems", "maxItems",
    "uniqueItems", "minLength", "maxLength", "minimum", "maximum", "exclusiveMinimum",
    "exclusiveMaximum", "multipleOf", "allOf", "anyOf", "oneOf", "$ref", "$defs",
    "pattern", "not", "if", "nullable", "format",
]  # fmt: skip


def test_two_thousand_random_pairs_never_raise() -> None:
    rng = random.Random(39)

    for _ in range(2_000):
        schema, instance = _value(rng), _value(rng)
        for dialect in ("json_schema", "openapi"):
            assert isinstance(check(instance, schema, dialect=dialect), SchemaCheck)
