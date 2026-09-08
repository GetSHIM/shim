"""Create and verify a directory of signed offline installation artifacts."""

import argparse
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

RESERVED = {"manifest.json", "manifest.sigstore.json"}
NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]*")
DIGEST = re.compile(r"[a-zA-Z0-9][^\s@]*@sha256:[0-9a-f]{64}")


def run(*args: str) -> str:
    return subprocess.check_output(args, text=True).strip()


def checksum(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def filename(value: str) -> str:
    if not NAME.fullmatch(value) or value in RESERVED:
        raise ValueError(f"Invalid artifact name: {value!r}")
    return value


def create(spec_path: Path, directory: Path, key: str) -> None:
    spec = json.loads(spec_path.read_text())
    filename(spec["bundle_id"])
    if spec["platform"] not in {"linux/amd64", "linux/arm64"}:
        raise ValueError("Supported platforms: linux/amd64, linux/arm64")
    images = spec["images"]
    if not images or len({image["name"] for image in images}) != len(images):
        raise ValueError("Images must have unique names")
    for image in images:
        filename(image["name"])
        filename(image["version"])
        if not DIGEST.fullmatch(image["source"]):
            raise ValueError("Every source image must use an immutable sha256 digest")
    # A failed creation stays visibly incomplete; never overwrite an existing bundle.
    directory.mkdir(parents=True, exist_ok=False)
    for source in spec["files"]:
        path = (spec_path.parent / source).resolve()
        target = directory / filename(path.name)
        if not path.is_file() or target.exists():
            raise ValueError(f"Missing or duplicate input: {source}")
        shutil.copyfile(path, target)
    for image in images:
        archive = directory / filename(image["name"] + ".tar")
        if archive.exists():
            raise ValueError(f"Duplicate artifact: {archive.name}")
        run("docker", "pull", "--platform", spec["platform"], image["source"])
        image["image_id"] = run(
            "docker", "image", "inspect", "--format", "{{.Id}}", image["source"]
        )
        run(
            "docker",
            "save",
            "--platform",
            spec["platform"],
            "--output",
            str(archive),
            image["source"],
        )
        image["archive"] = archive.name
    manifest = {
        "schema": 1,
        "bundle_id": spec["bundle_id"],
        "platform": spec["platform"],
        "images": images,
        "files": {path.name: checksum(path) for path in sorted(directory.iterdir())},
    }
    payload = directory / "manifest.json"
    payload.write_text(json.dumps(manifest, indent=2) + "\n")
    run(
        "cosign",
        "sign-blob",
        "--yes",
        "--key",
        key,
        "--use-signing-config=false",
        "--tlog-upload=false",
        "--bundle",
        str(directory / "manifest.sigstore.json"),
        str(payload),
    )


def verify(directory: Path, key: str, expected_id: str) -> dict:
    # The key is provisioned separately by the operator, never trusted from the bundle.
    if not Path(key).is_file():
        raise ValueError(
            "Verification requires a local, independently trusted public key"
        )
    paths = list(directory.iterdir())
    if any(path.is_symlink() or not path.is_file() for path in paths):
        raise ValueError("Bundle must contain only regular files, without symlinks")
    payload = directory / "manifest.json"
    run(
        "cosign",
        "verify-blob",
        "--key",
        key,
        "--insecure-ignore-tlog",
        "--bundle",
        str(directory / "manifest.sigstore.json"),
        str(payload),
    )
    manifest = json.loads(payload.read_text())
    if manifest["schema"] != 1 or manifest["bundle_id"] != expected_id:
        raise ValueError("Unexpected bundle schema or release ID")
    if manifest["platform"] not in {"linux/amd64", "linux/arm64"}:
        raise ValueError("Unsupported platform")
    files = manifest["files"]
    if set(files) | RESERVED != {path.name for path in paths}:
        raise ValueError("Bundle file inventory does not match manifest")
    for name, digest in files.items():
        path = directory / filename(name)
        if checksum(path) != digest:
            raise ValueError(f"Checksum mismatch: {name}")
    for image in manifest["images"]:
        if image["archive"] not in files or not DIGEST.fullmatch(image["source"]):
            raise ValueError("Invalid image metadata")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image["image_id"]):
            raise ValueError("Invalid image configuration digest")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("create")
    build.add_argument("--spec", type=Path, required=True)
    for command in (
        build,
        commands.add_parser("verify"),
        commands.add_parser("import"),
    ):
        command.add_argument("--directory", type=Path, required=True)
        command.add_argument("--key", required=True)
        if command is not build:
            command.add_argument("--expected-id", required=True)
    args = parser.parse_args()
    try:
        if args.command == "create":
            create(args.spec, args.directory, args.key)
        else:
            manifest = verify(args.directory, args.key, args.expected_id)
            if args.command == "import":
                for image in manifest["images"]:
                    run(
                        "docker",
                        "load",
                        "--input",
                        str(args.directory / image["archive"]),
                    )
                    run("docker", "image", "inspect", image["image_id"])
            print(f"Verified {manifest['bundle_id']} ({manifest['platform']})")
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        subprocess.CalledProcessError,
    ) as error:
        parser.exit(1, f"Bundle operation failed: {error}\n")


if __name__ == "__main__":
    main()
