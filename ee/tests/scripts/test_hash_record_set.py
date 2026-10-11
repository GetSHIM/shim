from __future__ import annotations

import base64
import csv
import json
from pathlib import Path
import runpy
from types import SimpleNamespace
from uuid import uuid4

import pytest

from shim_enterprise.api.v1 import management
from shim_enterprise.tenants.models import User
from shim_enterprise.tenants.record_sets import load_index

_TOOL = runpy.run_path(
    str(Path(__file__).parents[2] / "scripts" / "hash_record_set.py")
)
_NAMES = ["Ayşe Yılmaz", "İsmail Işık", "Çağrı Öztürk", "Şule Ünal", "Gökhan Demir"]


def _csv(path: Path, rows: int) -> Path:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Müşteri No", "Ad Soyad", "Not"])
        for number in range(rows):
            writer.writerow([f"MUS{number:06d}", _NAMES[number % 5], "gizli not"])
        # No primary value: dropped.
        writer.writerow(["", "Kimsesiz Satır", ""])
    return path


def _key(path: Path, size: int = 32) -> Path:
    path.write_text(base64.urlsafe_b64encode(bytes(range(size))).decode())
    return path


def test_the_tool_hashes_rows_in_chunks_and_prints_counts_only(
    tmp_path, capsys
) -> None:
    source = _csv(tmp_path / "customers.csv", 25_003)

    _TOOL["main"](
        [
            "--key-file", str(_key(tmp_path / "key.txt")),
            "--csv", str(source),
            "--field", "Müşteri No=token:primary",
            "--field", "Ad Soyad=name",
            "--out", str(tmp_path / "out"),
        ]
    )  # fmt: skip

    parts = sorted((tmp_path / "out").glob("chunk-*.json"))
    records = [json.loads(part.read_text())["records"] for part in parts]
    written = "".join(part.read_text() for part in parts) + capsys.readouterr().out
    assert [len(chunk) for chunk in records] == [10_000, 10_000, 5_003]
    assert all(len(row) == 2 and len(row[0]) == 16 for row in records[0])
    assert "25004 rows read, 25003 records hashed; 3 chunk files" in written
    for secret in ("MUS000001", "Ayşe", "gizli", "Kimsesiz"):
        assert secret not in written


def test_the_tool_refuses_a_key_of_the_wrong_size(tmp_path) -> None:
    with pytest.raises(SystemExit, match="32-byte"):
        _TOOL["main"](
            [
                "--key-file", str(_key(tmp_path / "key.txt", 16)),
                "--csv", str(_csv(tmp_path / "c.csv", 1)),
                "--field", "Müşteri No=token:primary",
                "--field", "Ad Soyad=name",
                "--out", str(tmp_path / "out"),
            ]
        )  # fmt: skip


def test_documents_get_numbered_labels_unless_file_names_are_asked_for(
    tmp_path,
) -> None:
    folder = tmp_path / "docs"
    folder.mkdir()
    (folder / "gizli-sozlesme.txt").write_text(
        "sözleşme maddesi " * 30, encoding="utf-8"
    )
    (folder / "notes.pdf").write_bytes(b"%PDF")
    arguments = [
        "--key-file",
        str(_key(tmp_path / "key.txt")),
        "--documents",
        str(folder),
    ]

    _TOOL["main"]([*arguments, "--out", str(tmp_path / "numbered")])
    _TOOL["main"](
        [*arguments, "--label-from-filename", "--out", str(tmp_path / "named")]
    )

    assert json.loads((tmp_path / "numbered" / "labels.json").read_text()) == [
        "doc-0001"
    ]
    assert json.loads((tmp_path / "named" / "labels.json").read_text()) == [
        "gizli-sozlesme.txt"
    ]
    [chunk] = (tmp_path / "numbered").glob("chunk-*.json")
    assert len(json.loads(chunk.read_text())["documents"]) == 1


@pytest.mark.asyncio
async def test_tool_output_reaches_the_api_and_matches_in_the_index(
    db, test_org, tmp_path
) -> None:
    admin = User(
        id=uuid4(),
        email=f"tool-{uuid4().hex}@example.com",
        is_active=True,
        is_verified=True,
        organization_id=test_org.id,
        role="admin",
    )
    db.add(admin)
    await db.flush()
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(cache=None)))
    created = await management.create_record_set(
        management.RecordSetCreate(
            name="customers",
            kind="records",
            fields=[
                management.RecordSetFieldSpec(
                    name="Müşteri No", kind="token", primary=True
                ),
                management.RecordSetFieldSpec(name="Ad Soyad", kind="name"),
            ],
        ),
        request,
        admin,
        db,
    )
    (tmp_path / "key.txt").write_text(created["hash_key"])
    _TOOL["main"](
        [
            "--key-file", str(tmp_path / "key.txt"),
            "--csv", str(_csv(tmp_path / "customers.csv", 50)),
            "--field", "Müşteri No=token:primary",
            "--field", "Ad Soyad=name",
            "--out", str(tmp_path / "out"),
        ]
    )  # fmt: skip
    set_id = created["id"]
    revision = (await management.open_record_set_revision(set_id, admin, db))[
        "revision"
    ]
    for index, part in enumerate(sorted((tmp_path / "out").glob("chunk-*.json"))):
        await management.put_record_set_chunk(
            set_id,
            revision,
            index,
            management.RecordSetChunkPut.model_validate_json(part.read_text()),
            admin,
            db,
        )
    await management.activate_record_set_revision(set_id, revision, request, admin, db)

    index = await load_index(db, test_org.id, set_id, revision)

    assert index is not None
    assert index.match_records("MUS000012 numaralı Çağrı Öztürk aradı", 2)[0] == {12}
    assert index.match_records("MUS000012 numaralı Ayşe Yılmaz aradı", 2)[0] == set()
