"""Export the Finding v1 JSON Schema to the package and to docs/schemas, byte-identical."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from shim.findings import Finding

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
OUTPUTS = (
    REPOSITORY_ROOT / "src" / "shim" / "findings" / "finding-v1.schema.json",
    REPOSITORY_ROOT / "docs" / "schemas" / "finding-v1.json",
)
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail instead of writing when a committed copy is stale",
    )
    args = parser.parse_args()
    rendered = render_schema()
    for output in OUTPUTS:
        if args.check:
            if not output.exists() or output.read_text(encoding="utf-8") != rendered:
                parser.error(f"{output} is stale; rerun this command without --check")
            continue
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
