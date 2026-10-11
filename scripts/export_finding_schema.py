"""Write the Finding v1 JSON Schema to docs/schemas; tests/findings fails while it is stale."""

from __future__ import annotations

import json
from pathlib import Path

from shim.findings import Finding

OUTPUT = Path(__file__).resolve().parents[1] / "docs" / "schemas" / "finding-v1.json"
SCHEMA_ID = (
    "https://raw.githubusercontent.com/GetSHIM/shim/main/docs/schemas/finding-v1.json"
)


def render_schema() -> str:
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": SCHEMA_ID,
        **Finding.model_json_schema(mode="serialization"),
    }
    return json.dumps(schema, indent=2, sort_keys=True) + "\n"


if __name__ == "__main__":
    OUTPUT.write_text(render_schema(), encoding="utf-8")
