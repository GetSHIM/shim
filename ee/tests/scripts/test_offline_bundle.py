"""Real local signatures; Docker is replaced only for small archive fixtures."""

import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys

import pytest


@pytest.mark.skipif(shutil.which("cosign") is None, reason="Install cosign 3.1.3")
def test_offline_bundle_rejects_tampering_before_import(tmp_path, monkeypatch):
    monkeypatch.setenv("COSIGN_PASSWORD", "")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("NO_PROXY", "")
    for name in ("trusted", "wrong"):
        subprocess.run(
            [
                "cosign",
                "generate-key-pair",
                "--output-key-prefix",
                str(tmp_path / name),
            ],
            check=True,
            capture_output=True,
        )
    script = Path(__file__).parents[2] / "scripts" / "offline_bundle.py"
    scope = runpy.run_path(str(script))
    original_run = scope["run"]
    docker_calls = []
    image_id = "sha256:" + "b" * 64

    def run(*args):
        if args[0] != "docker":
            return original_run(*args)
        docker_calls.append(args)
        if args[1] == "save":
            Path(args[5]).write_bytes(b"test-image-archive")
        return image_id

    monkeypatch.setitem(scope["create"].__globals__, "run", run)
    (tmp_path / "chart.tgz").write_bytes(b"test-chart")
    spec = tmp_path / "spec.json"
    spec.write_text(
        json.dumps(
            {
                "bundle_id": "pilot-1",
                "platform": "linux/amd64",
                "images": [
                    {
                        "name": "backend",
                        "version": "0.1.3",
                        "source": "example.test/backend@sha256:" + "a" * 64,
                    }
                ],
                "files": ["chart.tgz"],
            }
        )
    )
    directory = tmp_path / "bundle"
    scope["create"](spec, directory, str(tmp_path / "trusted.key"))
    verify = scope["verify"]
    key = str(tmp_path / "trusted.pub")
    assert verify(directory, key, "pilot-1")["images"][0]["image_id"] == image_id
    with pytest.raises(subprocess.CalledProcessError):
        verify(directory, str(tmp_path / "wrong.pub"), "pilot-1")
    with pytest.raises(ValueError, match="release ID"):
        verify(directory, key, "old-release")
    manifest_path = directory / "manifest.json"
    manifest = manifest_path.read_bytes()
    manifest_path.write_bytes(manifest + b" ")
    with pytest.raises(subprocess.CalledProcessError):
        verify(directory, key, "pilot-1")
    manifest_path.write_bytes(manifest)
    archive = directory / "backend.tar"
    archive.write_bytes(b"tampered")
    docker_calls.clear()
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(script),
            "import",
            "--directory",
            str(directory),
            "--key",
            key,
            "--expected-id",
            "pilot-1",
        ],
    )
    with pytest.raises(SystemExit) as error:
        scope["main"]()
    assert error.value.code == 1
    assert docker_calls == []
    archive.write_bytes(b"test-image-archive")
    extra = directory / "extra"
    extra.write_text("unlisted")
    with pytest.raises(ValueError, match="inventory"):
        verify(directory, key, "pilot-1")
    # Replace the extra file with a symlink, preserving the fixture for cleanup.
    extra.rename(tmp_path / "extra")
    extra.symlink_to(archive)
    with pytest.raises(ValueError, match="symlinks"):
        verify(directory, key, "pilot-1")
    extra.rename(tmp_path / "extra-link")
    scope["main"]()
    assert any(args[1] == "load" for args in docker_calls)
    assert os.environ["HTTPS_PROXY"] == "http://127.0.0.1:9"
