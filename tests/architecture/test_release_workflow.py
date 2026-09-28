from __future__ import annotations

from pathlib import Path
import os
import re
import subprocess

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
RELEASE = WORKFLOWS / "release.yml"
ENTERPRISE_RELEASE = WORKFLOWS / "enterprise-release.yml"
IMAGE = "ghcr.io/getshim/shim"
DEPLOYMENT_COMMANDS = ("gcloud run", "gcloud builds", "update-traffic", "kubectl")
RELEASE_TEXT = RELEASE.read_text()
RELEASE_WORKFLOW = yaml.safe_load(RELEASE_TEXT)


@pytest.mark.parametrize("step_id", ["deploy-gateway", "deploy-outbox-worker"])
def test_cloud_deployment_requires_polar_only_when_enabled(
    tmp_path: Path, step_id: str
) -> None:
    deployment = yaml.safe_load((ROOT / "cloudbuild.yaml").read_text())
    step = next(step for step in deployment["steps"] if step["id"] == step_id)
    assert step["entrypoint"] == "bash"
    fake = tmp_path / "gcloud"
    fake.write_text('#!/bin/bash\nprintf "%s\\n" "$@"\n')
    fake.chmod(0o755)
    args = [arg.replace("$$", "$") for arg in step["args"]]
    environment = os.environ | {
        "PATH": f"{tmp_path}:{os.environ['PATH']}",
        "CLOUD_BILLING_ENABLED": "false",
        "SECRET_PREFIX": "shim",
        "POLAR_ORGANIZATION_ID": "",
        "CLOUD_DASHBOARD_URL": "",
    }
    disabled = subprocess.run(
        ["bash", *args], env=environment, capture_output=True, text=True
    )
    assert disabled.returncode == 0, disabled.stderr
    assert "POLAR_" not in disabled.stdout
    assert "CLOUD_DASHBOARD_URL" not in disabled.stdout
    assert "CLOUD_BILLING_ENABLED=${_CLOUD_BILLING_ENABLED}" in disabled.stdout
    environment["CLOUD_BILLING_ENABLED"] = "true"
    missing = subprocess.run(
        ["bash", *args], env=environment, capture_output=True, text=True
    )
    assert missing.returncode != 0
    environment["POLAR_ORGANIZATION_ID"] = "11111111-1111-4111-8111-111111111111"
    missing_url = subprocess.run(
        ["bash", *args], env=environment, capture_output=True, text=True
    )
    assert missing_url.returncode != 0
    environment["CLOUD_DASHBOARD_URL"] = "https://getshim.tech"
    enabled = subprocess.run(
        ["bash", *args], env=environment, capture_output=True, text=True
    )
    assert enabled.returncode == 0, enabled.stderr
    for binding in (
        "POLAR_ACCESS_TOKEN=shim-polar-access-token:1",
        "POLAR_WEBHOOK_SECRET=shim-polar-webhook-secret:1",
        "POLAR_PRODUCTS=shim-polar-products:1",
        "POLAR_SERVER=production",
        "POLAR_ORGANIZATION_ID=11111111-1111-4111-8111-111111111111",
        "CLOUD_DASHBOARD_URL=https://getshim.tech",
    ):
        assert binding in enabled.stdout
    assert (
        "--no-traffic" if step_id == "deploy-gateway" else "--no-promote"
    ) in enabled.stdout


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
    assert "ee/cloud" not in RELEASE_TEXT
    assert "shim-cloud" not in RELEASE_TEXT


def test_enterprise_release_excludes_the_cloud_composition() -> None:
    release_text = ENTERPRISE_RELEASE.read_text()

    assert "file: ee/Dockerfile" in release_text
    assert "ee/cloud" not in release_text
    assert "shim-cloud" not in release_text
    assert "uv build" not in release_text


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
