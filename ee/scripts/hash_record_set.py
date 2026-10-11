"""Hash a customer list or confidential documents on your own machine for a shim record set.

The CSV and the documents never leave this machine: the tool writes, or uploads, only keyed
hashes, and prints only counts.

  hash_record_set.py --key-file key.txt --csv customers.csv \\
      --field "Müşteri No=token:primary" --field "Ad Soyad=name" --out chunks/
  SHIM_ADMIN_TOKEN=... hash_record_set.py --key-file key.txt --documents contracts/ \\
      --upload https://shim.example.com --set <record set id>

Give the fields in the order the set declares them; an upload checks them against the set
first. A digits field takes its length range: "Hesap No=digits:primary:8-12". The admin
token comes from SHIM_ADMIN_TOKEN, else the first line of standard input, never the
command line, where other users of the machine could read it.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import csv
import json
import os
from pathlib import Path
import sys
from urllib.request import Request, urlopen

from shim.privacy.record_match import (
    FIELD_KINDS,
    KEY_BYTES,
    RecordField,
    fingerprints,
    normalize,
    record_hash,
)

RECORDS_PER_CHUNK = 10_000
DOCUMENTS_PER_CHUNK = 50


def read_key(path: Path) -> bytes:
    try:
        key = base64.urlsafe_b64decode(path.read_text().strip())
    except (binascii.Error, ValueError):
        key = b""
    if len(key) != KEY_BYTES:
        raise SystemExit("the key file must hold the set's 32-byte base64url key")
    return key


def parse_field(spec: str) -> tuple[str, RecordField]:
    column, _, rest = spec.rpartition("=")
    kind, *options = rest.split(":")
    if not column or kind not in FIELD_KINDS:
        raise SystemExit(f'--field {spec!r}: use "Column=kind[:primary][:min-max]"')
    length = next(
        (
            tuple(int(part) for part in option.split("-"))
            for option in options
            if "-" in option
        ),
        None,
    )
    return column, RecordField(kind, "primary" in options, length)


def hash_records(
    key: bytes, rows: list[dict[str, str]], fields: list[tuple[str, RecordField]]
) -> list[list[int]]:
    hashed = []
    for row in rows:
        values = []
        for column, field in fields:
            normalized = normalize(field.kind, row.get(column) or "", field.length)
            values.append(record_hash(key, field.kind, normalized) if normalized else 0)
        # A record no primary value can find is no use to the gateway.
        if any(value for value, (_, field) in zip(values, fields) if field.primary):
            hashed.append(values)
    return hashed


def chunks(items: list, size: int, name: str) -> list[dict[str, list[list[str]]]]:
    return [
        {
            name: [
                [f"{value:016x}" for value in item]
                for item in items[start : start + size]
            ]
        }
        for start in range(0, len(items), size)
    ]


def _call(method: str, url: str, token: str, body: object | None = None) -> dict:
    request = Request(
        url,
        method=method,
        data=None if body is None else json.dumps(body).encode(),
        headers={
            "authorization": f"Bearer {token}",
            "content-type": "application/json",
        },
    )
    with urlopen(request, timeout=60) as response:  # noqa: S310 - the operator's own URL
        return json.loads(response.read() or b"{}")


def upload(
    base: str,
    token: str,
    set_id: str,
    parts: list[dict],
    fields: list[RecordField] | None,
) -> int:
    """Uploads `parts` as a new revision once the set's kind and fields are the ones
    hashed; `fields` is None for documents."""
    root = f"{base.rstrip('/')}/api/v1/management/record-sets/{set_id}"
    declared = _call("GET", root, token)
    expected = (
        [
            RecordField(
                item["kind"],
                bool(item.get("primary")),
                tuple(item["length"]) if item.get("length") else None,
            )
            for item in declared["fields"]
        ]
        if declared["kind"] == "records"
        else None
    )
    if expected != fields:
        raise SystemExit(
            "the set declares other fields, or another kind, than the ones hashed; "
            "give --field in the order, kinds and options of the set"
        )
    revision = _call("POST", f"{root}/revisions", token)["revision"]
    for index, part in enumerate(parts):
        _call("PUT", f"{root}/revisions/{revision}/chunks/{index}", token, part)
    _call("POST", f"{root}/revisions/{revision}/activate", token)
    return revision


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--key-file", type=Path, required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--csv", type=Path)
    source.add_argument("--documents", type=Path)
    parser.add_argument("--field", action="append", default=[])
    parser.add_argument("--label-from-filename", action="store_true")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--out", type=Path)
    target.add_argument("--upload", metavar="BASE_URL")
    parser.add_argument("--set", dest="set_id")
    args = parser.parse_args(argv)
    if args.upload and not args.set_id:
        parser.error("--upload needs --set")
    key = read_key(args.key_file)
    labels: list[str] = []
    record_fields: list[RecordField] | None = None
    if args.csv:
        fields = [parse_field(spec) for spec in args.field]
        if not 2 <= len(fields) <= 6 or not any(field.primary for _, field in fields):
            parser.error("give 2 to 6 --field options, at least one primary")
        with args.csv.open(encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.DictReader(handle))
        missing = sorted(
            {column for column, _ in fields} - set(rows[0] if rows else ())
        )
        if missing:
            parser.error(f"the CSV has no column {', '.join(missing)}")
        hashed = hash_records(key, rows, fields)
        record_fields = [field for _, field in fields]
        parts = chunks(hashed, RECORDS_PER_CHUNK, "records")
        summary = f"{len(rows)} rows read, {len(hashed)} records hashed"
    else:
        files = sorted(
            path
            for path in args.documents.iterdir()
            if path.suffix in {".txt", ".md"} and path.is_file()
        )
        documents = [
            sorted(fingerprints(key, path.read_text(encoding="utf-8")))
            for path in files
        ]
        # File names can be confidential, so they are labels only when asked for.
        labels = [
            path.name if args.label_from_filename else f"doc-{number:04d}"
            for number, path in enumerate(files, 1)
        ]
        parts = chunks(documents, DOCUMENTS_PER_CHUNK, "documents")
        summary = f"{len(files)} documents, {sum(len(prints) for prints in documents)} fingerprints"
    if args.upload:
        token = os.environ.get("SHIM_ADMIN_TOKEN") or sys.stdin.readline().strip()
        if not token:
            parser.error("give the admin token in SHIM_ADMIN_TOKEN or on stdin")
        revision = upload(args.upload, token, args.set_id, parts, record_fields)
        print(f"{summary}; revision {revision} active")
    else:
        args.out.mkdir(parents=True, exist_ok=True)
        for index, part in enumerate(parts):
            (args.out / f"chunk-{index:04d}.json").write_text(json.dumps(part))
        if labels:
            # Kept here: which file each document number came from.
            (args.out / "labels.json").write_text(
                json.dumps(labels, ensure_ascii=False)
            )
        print(f"{summary}; {len(parts)} chunk files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
