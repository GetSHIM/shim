from __future__ import annotations

from pathlib import Path
import re

import pytest


ROOT = Path(__file__).resolve().parents[2]
README = (ROOT / "README.md").read_text()
# The community cookbook copies the quickstart; the enterprise one uses its own keys.
DOCUMENTS = (README, (ROOT / "docs" / "COOKBOOK.md").read_text())
CONSOLE_BLOCKS = [
    block
    for text in DOCUMENTS
    for block in re.findall(r"```console\n(.*?)```", text, re.DOTALL)
]
CODE_BLOCKS = [
    block
    for text in DOCUMENTS
    for block in re.findall(r"```[a-z]*\n(.*?)```", text, re.DOTALL)
]
SHIM_KEY_LITERALS = re.compile(
    r"SHIM_API_KEY=([^\s\\]+)|Bearer ([^\s']+)|api_key=\"([^\"]+)\"|"
    r"x-shim-key: ([^\s']+)|x-api-key: ([^\s']+)"
)
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


def test_every_documented_example_uses_the_quickstart_key() -> None:
    keys = {
        value
        for block in CODE_BLOCKS
        for match in SHIM_KEY_LITERALS.finditer(block)
        for value in match.groups()
        if value
    }

    assert len(keys) == 1, f"the README's examples use different shim keys: {keys}"


def test_every_llms_txt_link_resolves_to_a_file() -> None:
    text = (ROOT / "llms.txt").read_text()
    links = re.findall(r"\]\(([^)]+)\)", text)

    assert text.startswith("# shim\n") and links
    assert [link for link in links if not (ROOT / link).is_file()] == []
