"""The release pipeline publishes artifacts and never deploys."""

from __future__ import annotations

from pathlib import Path
import re

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
RELEASE = WORKFLOWS / "release.yml"
IMAGE = "ghcr.io/getshim/shim"
# Anything that moves traffic, revisions or Cloud Build work belongs to the
# deployment trigger, not to a workflow a merged pull request can influence.
DEPLOYMENT_COMMANDS = ("gcloud run", "gcloud builds", "update-traffic", "kubectl")


def _workflow(path: Path) -> dict:
    # "on" is the YAML boolean True, so the trigger block arrives under that key.
    return yaml.safe_load(path.read_text())


def test_release_is_driven_by_a_version_tag() -> None:
    triggers = _workflow(RELEASE)[True]
    assert set(triggers) == {"push"}
    assert triggers["push"] == {"tags": ["v*"]}


def test_release_publishes_the_community_image_with_an_sbom() -> None:
    text = RELEASE.read_text()
    assert f"{IMAGE}:latest" in text
    assert "spdx-json" in text
    assert "attest-build-provenance" in text
    assert "linux/amd64,linux/arm64" in text
    # The enterprise image is source-available and never leaves our registry.
    assert "ee/Dockerfile" not in text


def test_release_never_deploys() -> None:
    text = RELEASE.read_text()
    for command in DEPLOYMENT_COMMANDS:
        assert command not in text, f"the release workflow must not run {command!r}"


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
