"""The quickstart in the README must be a command that actually runs.

The release workflow smokes the published image, but it does so with its own
invocation. That is how the documented `docker run` came to be missing the key
the container requires: the pipeline proved the image starts, and never proved
the documented command starts it. These assertions close that gap by reading
the README itself.
"""

from __future__ import annotations

from pathlib import Path
import re

import pytest


ROOT = Path(__file__).resolve().parents[2]
README = ROOT / "README.md"
IMAGE = "ghcr.io/getshim/shim"


def _console_blocks() -> list[str]:
    return re.findall(r"```console\n(.*?)```", README.read_text(), re.DOTALL)


def _quickstart() -> str:
    body = README.read_text().split("## Quickstart", 1)[1]
    return body.split("\n## ", 1)[0]


def test_the_documented_run_command_carries_a_key() -> None:
    # The image binds 0.0.0.0, and the gateway refuses a non-loopback host
    # without SHIM_API_KEY. A documented command without one exits immediately.
    runs = [
        block for block in _console_blocks() if "docker run" in block and IMAGE in block
    ]

    assert runs, "the quickstart must show how to run the published image"
    for command in runs:
        assert "SHIM_API_KEY" in command, (
            f"this documented command exits without a key:\n{command}"
        )


@pytest.mark.parametrize(
    "route", ["/v1/scan", "/v1/chat/completions", "/v1/messages", "/v1/responses"]
)
def test_documented_requests_to_a_keyed_gateway_authenticate(route: str) -> None:
    # The documented container has a key, so every documented call to a guarded
    # route needs to send one, or a reader's first request answers 401.
    for command in _console_blocks():
        if "curl" not in command or route not in command:
            continue
        assert "Authorization:" in command or "x-api-key:" in command, (
            f"this documented request would be rejected:\n{command}"
        )


def test_the_quickstart_shows_a_real_response() -> None:
    quickstart = _quickstart()

    assert '"verdict"' in quickstart, "show what the gateway actually answers"
    assert "EMAIL_ADDRESS" in quickstart, "placeholders carry the entity name"
    # <EMAIL_1> style placeholders were never what this gateway produces.
    assert not re.search(r"<[A-Z_]+_\d>", quickstart), "invented placeholder shape"
