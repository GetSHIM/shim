from __future__ import annotations

from importlib.resources import files
import json
from pathlib import Path

from scripts.export_finding_schema import OUTPUTS, SCHEMA_ID, render_schema

ROOT = Path(__file__).resolve().parents[2]


def test_both_committed_copies_equal_the_regenerated_schema() -> None:
    rendered = render_schema()

    assert [output.read_text(encoding="utf-8") for output in OUTPUTS] == [rendered] * 2
    assert {output.relative_to(ROOT).as_posix() for output in OUTPUTS} == {
        "src/shim/findings/finding-v1.schema.json",
        "docs/schemas/finding-v1.json",
    }
    assert (
        files("shim.findings")
        .joinpath("finding-v1.schema.json")
        .read_text(encoding="utf-8")
        == rendered
    )


def test_the_schema_names_its_draft_and_id() -> None:
    schema = json.loads(render_schema())

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == SCHEMA_ID
    assert SCHEMA_ID.endswith("/docs/schemas/finding-v1.json")


def test_objects_are_closed_except_measurements_and_action_params() -> None:
    schema = json.loads(render_schema())
    objects = {"Finding": schema, **schema["$defs"]}

    assert all(
        definition.get("additionalProperties") is False
        for definition in objects.values()
        if definition.get("type") == "object"
    )
    assert "additionalProperties" not in schema["properties"]["measurements"]
    assert schema["$defs"]["Action"]["properties"]["params"]["additionalProperties"]
