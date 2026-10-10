"""The schema-subset corpus, and a seeded fuzz: check never raises."""

from __future__ import annotations

import json
from pathlib import Path
import random
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
    assert len(ids) == len(set(ids)) and len(ids) >= 120


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
        ("bound-nodes-10001", "nodes"),
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


def test_paths_and_the_unsupported_list_are_bounded() -> None:
    name = "k" * 100
    schema: dict[str, Any] = {"type": "integer"}
    instance: Any = "x"
    for _ in range(12):
        schema = {"properties": {name: schema}}
        instance = {name: instance}
    many = {f"x-{index:02d}": 1 for index in range(20)}

    deep = check(instance, schema)
    listed = check({}, many)

    assert deep.valid is False and len(deep.error_path) == 512
    assert deep.error_path.startswith("/" + "k" * 64 + "/")
    assert len(listed.unsupported) == 16 and list(listed.unsupported) == sorted(
        listed.unsupported
    )


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
