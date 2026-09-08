"""Real local signatures; Docker is replaced only for small archive fixtures."""

import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tarfile

import pytest


def image_archive(path, oci, layer_digest="b" * 64):
    layers = ["sha256:" + layer_digest]
    config = json.dumps(
        {
            "os": "linux",
            "architecture": "amd64",
            "rootfs": {"type": "layers", "diff_ids": layers},
        }
    ).encode()
    digest = "sha256:" + hashlib.sha256(config).hexdigest()
    config_path = (
        ("blobs/sha256/" + digest.removeprefix("sha256:"))
        if oci
        else digest.removeprefix("sha256:") + ".json"
    )
    files = {
        config_path: config,
        "manifest.json": json.dumps(
            [{"Config": config_path, "RepoTags": None}]
        ).encode(),
    }
    # containerd can synthesize an ID absent from a classic Docker archive.
    loaded_id = "sha256:" + "d" * 64
    if oci:
        manifest = json.dumps({"config": {"digest": digest}}).encode()
        loaded_id = "sha256:" + hashlib.sha256(manifest).hexdigest()
        files["blobs/sha256/" + loaded_id.removeprefix("sha256:")] = manifest
        files["index.json"] = json.dumps(
            {"manifests": [{"digest": loaded_id}]}
        ).encode()
    with tarfile.open(path, "w") as archive:
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return digest, loaded_id


@pytest.mark.skipif(shutil.which("cosign") is None, reason="Install cosign 3.1.3")
@pytest.mark.parametrize("oci", [False, True])
def test_offline_bundle_rejects_tampering_before_import(tmp_path, monkeypatch, oci):
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
    fixture = tmp_path / "fixture.tar"
    config_digest, loaded_id = image_archive(fixture, oci)
    archive_bytes = fixture.read_bytes()
    exported_bytes = archive_bytes
    source_index_id = "sha256:" + "a" * 64
    assert loaded_id != source_index_id

    def run(*args):
        if args[0] != "docker":
            return original_run(*args)
        docker_calls.append(args)
        if args[1] == "save":
            Path(args[5]).write_bytes(
                exported_bytes if args[-1] == loaded_id else archive_bytes
            )
        elif args[1] == "load":
            return f"Loaded image ID: {loaded_id}"
        else:
            assert args[1] == "pull", "Do not inspect non-portable daemon IDs"
        return ""

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
    assert (
        verify(directory, key, "pilot-1")["images"][0]["config_digest"] == config_digest
    )
    with pytest.raises(ValueError, match="platform"):
        scope["archive_config_digest"](fixture, "linux/arm64")
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
    archive.write_bytes(archive_bytes)
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
    image_archive(fixture, oci, layer_digest="c" * 64)
    exported_bytes = fixture.read_bytes()
    with pytest.raises(SystemExit):
        scope["main"]()
    assert os.environ["HTTPS_PROXY"] == "http://127.0.0.1:9"
