from __future__ import annotations

from pathlib import Path
import re

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
RELEASE = WORKFLOWS / "release.yml"
IMAGE = "ghcr.io/getshim/shim"
DEPLOYMENT_COMMANDS = ("gcloud run", "gcloud builds", "update-traffic", "kubectl")
RELEASE_TEXT = RELEASE.read_text()
RELEASE_WORKFLOW = yaml.safe_load(RELEASE_TEXT)


def test_release_is_driven_by_a_version_tag() -> None:
    triggers = RELEASE_WORKFLOW[True]
    assert set(triggers) == {"push"}
    assert triggers["push"] == {"tags": ["v*"]}


def test_release_publishes_the_community_image_with_an_sbom() -> None:
    assert f"{IMAGE}:latest" in RELEASE_TEXT
    assert "spdx-json" in RELEASE_TEXT
    assert "attest-build-provenance" in RELEASE_TEXT
    assert "linux/amd64,linux/arm64" in RELEASE_TEXT
    assert "ee/Dockerfile" not in RELEASE_TEXT


def test_release_never_deploys() -> None:
    for command in DEPLOYMENT_COMMANDS:
        assert command not in RELEASE_TEXT, (
            f"the release workflow must not run {command!r}"
        )


@pytest.mark.parametrize(
    "workflow", sorted(WORKFLOWS.glob("*.yml")), ids=lambda path: path.name
)
def test_every_action_is_pinned_to_a_commit(workflow: Path) -> None:
    unpinned = [
        line.strip()
        for line in workflow.read_text().splitlines()
        if (match := re.search(r"uses:\s*(\S+)", line))
        and not re.fullmatch(r"[^@]+@[0-9a-f]{40}", match.group(1))
    ]
    assert not unpinned, f"pin these to a commit: {unpinned}"
