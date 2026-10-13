from __future__ import annotations

from datetime import date

import pytest

from shim_enterprise.config_file.loader import (
    MAX_FILE_BYTES,
    ConfigFileError,
    load_config,
)

HEADER = """format: shim.config
version: 1
organization_id: 6f1c2a3e-1111-4222-8333-444455556666
serial: 8
"""


def _file(body: str) -> bytes:
    return (HEADER + body).encode()


def _refused(data: bytes) -> ConfigFileError:
    with pytest.raises(ConfigFileError) as refused:
        load_config(data)
    return refused.value


def test_a_valid_file_reads_its_header_and_sections() -> None:
    document = load_config(
        _file(
            "exported_from: {policy_version: 41}\n"
            "resources:\n"
            "  privacy: {block_email: true}\n"
            "  rules:\n"
            "    - {id: atlas, kind: term, match: {terms: [Atlas]}}\n"
        )
    )

    assert (str(document.organization_id), document.serial) == (
        "6f1c2a3e-1111-4222-8333-444455556666",
        8,
    )
    assert document.resources == {
        "privacy": {"block_email": True},
        "rules": [{"id": "atlas", "kind": "term", "match": {"terms": ["Atlas"]}}],
    }


def test_only_true_and_false_are_booleans() -> None:
    document = load_config(
        _file(
            "resources:\n  gateway_settings:\n"
            "    a: off\n    b: on\n    c: yes\n    d: no\n"
            "    e: True\n    f: false\n    g: FALSE\n    h: 'true'\n"
        )
    )

    assert document.resources["gateway_settings"] == {
        "a": "off",
        "b": "on",
        "c": "yes",
        "d": "no",
        "e": True,
        "f": False,
        "g": False,
        "h": "true",
    }


@pytest.mark.parametrize(
    ("body", "path", "message"),
    [
        ("resources: &shared {privacy: {}}\n", "line 5, column 12", "anchors"),
        ("x: &a 1\nresources: {privacy: *a}\n", "line 5, column 4", "anchors"),
        ("resources: {}\nserial: 9\n", "line 6, column 1", "duplicate key 'serial'"),
        ("resources: {}\n---\nformat: shim.config\n", "line 6, column 1", "single"),
        ("resources: {privacy: {a: 1, a: 2}}\n", "line 5, column 29", "duplicate key"),
        ("resources: {}\nextra: 1\n", "extra", "Extra inputs"),
        ("resources: [privacy]\n", "resources", "valid dictionary"),
    ],
)
def test_yaml_surprises_are_refused_with_a_path(body, path, message) -> None:
    refused = _refused(_file(body))

    assert refused.path == path
    assert message in str(refused)


def test_deep_nesting_and_oversized_files_are_refused() -> None:
    nested = _refused(_file("resources: " + "[" * 5000 + "]" * 5000 + "\n"))
    oversized = _refused(b"#" * (MAX_FILE_BYTES + 1))
    fits = _refused(b"#" * MAX_FILE_BYTES)

    assert (nested.path, str(nested)) == ("file", "the file nests too deeply")
    assert oversized.path == "file" and "at most 1000000 bytes" in str(oversized)
    # A full-size file is read, then refused for what it holds, not its size.
    assert "at most" not in str(fits)


def test_the_header_is_checked() -> None:
    assert (
        _refused(_file("resources: {}\n").replace(b"version: 1", b"version: 2")).path
        == "version"
    )
    assert (
        _refused(_file("resources: {}\n").replace(b"serial: 8", b"serial: 0")).path
        == "serial"
    )
    assert _refused(b"\xff\xfe").path == "file"
    assert _refused(b"- a list\n").path == "file"
    # A date stays a date, for the resource to refuse where it expects a string.
    assert load_config(_file("resources: {rules: [2026-10-13]}\n")).resources == {
        "rules": [date(2026, 10, 13)]
    }
