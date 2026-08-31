from __future__ import annotations

from pathlib import Path
import re

import pytest


ROOT = Path(__file__).resolve().parents[2]
README = (ROOT / "README.md").read_text()
CONSOLE_BLOCKS = re.findall(r"```console\n(.*?)```", README, re.DOTALL)
QUICKSTART = README.split("## Quickstart", 1)[1].split("\n## ", 1)[0]


def test_the_documented_run_command_carries_a_key() -> None:
    runs = [
        block
        for block in CONSOLE_BLOCKS
        if "docker run" in block and "ghcr.io/getshim/shim" in block
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
    for command in CONSOLE_BLOCKS:
        if "curl" not in command or route not in command:
            continue
        assert "Authorization:" in command or "x-api-key:" in command, (
            f"this documented request would be rejected:\n{command}"
        )


def test_the_quickstart_shows_a_real_response() -> None:
    assert '"verdict"' in QUICKSTART, "show what the gateway actually answers"
    assert "EMAIL_ADDRESS" in QUICKSTART, "placeholders carry the entity name"
    assert not re.search(r"<[A-Z_]+_\d>", QUICKSTART), "invented placeholder shape"
