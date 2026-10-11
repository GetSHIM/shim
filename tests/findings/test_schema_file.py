from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import re

from pydantic import ValidationError
import pytest

from scripts.export_finding_schema import OUTPUT, SCHEMA_ID, render_schema
from shim.findings import Finding
from shim.jsonschema_subset import check

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads(render_schema())
# jsonschema is not a dependency, so the repository's own validator checks every
# keyword but the two it never runs; the patterns are checked with re below.
UNCHECKED = ("pattern", "patternProperties")


def _example() -> dict:
    document = (ROOT / "docs" / "FINDINGS_SCHEMA.md").read_text(encoding="utf-8")
    [block] = re.findall(r"```json\n(.*?)```", document, flags=re.DOTALL)
    return json.loads(block)


def test_the_committed_file_equals_the_regenerated_schema() -> None:
    assert OUTPUT.relative_to(ROOT).as_posix() == "docs/schemas/finding-v1.json"
    assert OUTPUT.read_text(encoding="utf-8") == render_schema()


def test_the_schema_names_its_draft_and_id() -> None:
    assert SCHEMA["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert SCHEMA["$id"] == SCHEMA_ID
    assert SCHEMA_ID.endswith("/docs/schemas/finding-v1.json")


def test_objects_are_open_for_additions_and_measurements_hold_names_only() -> None:
    objects = {"Finding": SCHEMA, **SCHEMA["$defs"]}

    assert set(SCHEMA["$defs"]) == {
        "FindingEvidence",
        "FindingImpact",
        "FindingRemediation",
        "FindingSubject",
        "FindingText",
        "FindingWindow",
    }
    assert not any("additionalProperties" in item for item in objects.values())
    measurements = SCHEMA["properties"]["measurements"]
    assert measurements["additionalProperties"] is False
    [name] = measurements["patternProperties"]
    assert re.search(name, "repeated_requests")
    for free_text in ("Ahmet Yilmaz TCKN 12345678901", "share\n", "Share"):
        assert not re.search(name, free_text)


def test_the_documented_example_is_a_finding() -> None:
    example = _example()

    Finding.model_validate(example)
    assert check(example, SCHEMA) == check(example, SCHEMA).__class__(
        None, None, None, UNCHECKED, None
    )
    assert check({**example, "added_in_a_later_v1": True}, SCHEMA).valid is None


def _mutated(path: str, value: object) -> dict:
    data = deepcopy(_example())
    *parents, last = path.split(".")
    target = data
    for name in parents:
        target = target[name]
    if value is _DROP:
        del target[last]
    else:
        target[last] = value
    return data


_DROP = object()


@pytest.mark.parametrize(
    ("path", "value"),
    [
        ("schema_version", "2"),
        ("source", "proxy"),
        ("rule_version", 0),
        ("title", "t" * 201),
        ("summary.tr", ""),
        ("severity", "severe"),
        ("occurrences", 0),
        ("evidence", [{"kind": "request", "id": "req_1"}] * 51),
        ("measurements", {f"m{index}": index for index in range(33)}),
        ("impact.requests", -1),
        ("remediation.mode", "auto"),
        (
            "remediation",
            {**_example()["remediation"], "mode": "suggest", "max_mode": "observe"},
        ),
        ("impact", _DROP),
    ],
)
def test_a_mutation_the_model_refuses_the_schema_refuses_too(path, value) -> None:
    data = _mutated(path, value)

    with pytest.raises(ValidationError):
        Finding.model_validate(data)
    assert check(data, SCHEMA).valid is False


def _at(*keys: str | int) -> dict:
    node = SCHEMA
    for key in keys:
        node = node[key]
    return node


@pytest.mark.parametrize(
    ("node", "accepted", "refused"),
    [
        (_at("properties", "id"), "gateway:finding.1-2_3", "gateway:finding.1\n"),
        (_at("properties", "rule_id"), "gateway.retry_storm", "gateway.retry_storm\n"),
        (
            _at("$defs", "FindingWindow", "properties", "start"),
            "2026-10-08T12:00:00Z",
            "2026-10-08T15:00:00+03:00",
        ),
        (
            _at("$defs", "FindingImpact", "properties", "usd", "anyOf", 0),
            "0.20",
            "1e-7",
        ),
        (_at("properties", "resolved_by", "anyOf", 0), "system", "a user's name"),
    ],
)
def test_patterns_refuse_what_the_model_refuses_under_python_re(
    node, accepted, refused
) -> None:
    assert re.search(node["pattern"], accepted)
    assert not re.search(node["pattern"], refused)
