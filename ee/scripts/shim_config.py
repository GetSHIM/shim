"""Keep a tenant's shim policy in a signed YAML file: make a key, sign, plan, push, export.

The management token is read from SHIM_MANAGEMENT_TOKEN only, never from an
argument, and neither it nor a key path is printed. Exit codes: 0 applied,
unchanged or planned; 3 waiting for a second administrator; 1 refused; 2 usage.
"""

import argparse
import json
import os
from pathlib import Path
import sys

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

from shim_enterprise.config_file.loader import ConfigFileError, load_config
from shim_enterprise.config_file.signing import key_id, sign

TIMEOUT_SECONDS = 30.0
PRIVATE_KEY = "shim-config-signing.key"
PUBLIC_KEY = "shim-config-signing.pub"


class Usage(Exception):
    pass


def keygen(out_dir: Path) -> int:
    private_path, public_path = out_dir / PRIVATE_KEY, out_dir / PUBLIC_KEY
    if private_path.exists() or public_path.exists():
        raise Usage(f"{PRIVATE_KEY} or {PUBLIC_KEY} already exists there")
    private_key = Ed25519PrivateKey.generate()
    out_dir.mkdir(parents=True, exist_ok=True)
    # Created 0600 in one step, so the private key is never readable by others.
    descriptor = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(
            private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        )
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        )
    )
    print(key_id(private_key.public_key()))
    return 0


def _private_key(path: Path) -> Ed25519PrivateKey:
    try:
        key = load_pem_private_key(path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError):
        raise Usage("the private key cannot be read") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise Usage("the private key is not an Ed25519 key")
    return key


def _signature(private_key: Path, file: Path) -> str:
    data = file.read_bytes()
    try:
        organization_id = load_config(data).organization_id
    except ConfigFileError as error:
        raise Usage(f"the file is not valid at {error.path}: {error}") from None
    return sign(_private_key(private_key), organization_id, data)


def _client(url: str) -> httpx.Client:
    token = os.environ.get("SHIM_MANAGEMENT_TOKEN")
    if not token:
        raise Usage("set SHIM_MANAGEMENT_TOKEN")
    return httpx.Client(
        base_url=f"{url.rstrip('/')}/api/v1/management/config",
        headers={"authorization": f"Bearer {token}"},
        follow_redirects=False,
        timeout=TIMEOUT_SECONDS,
    )


def push(arguments: argparse.Namespace) -> int:
    if arguments.signature is not None:
        signature = arguments.signature
    elif arguments.signature_file is not None:
        signature = arguments.signature_file.read_text().strip()
    else:
        signature = _signature(arguments.private_key, arguments.file)
    with _client(arguments.url) as client:
        response = client.post(
            "/plan" if arguments.plan_only else "/apply",
            # Bytes, not read_text: newline translation would change what was signed.
            json={
                "file": arguments.file.read_bytes().decode("utf-8"),
                "signature": signature,
            },
        )
    try:
        print(json.dumps(response.json(), indent=2))
    except ValueError:
        print(f"HTTP {response.status_code}")
    if response.status_code == 202:
        return 3
    return 0 if response.status_code == 200 else 1


def export(arguments: argparse.Namespace) -> int:
    params = {} if arguments.version is None else {"version": arguments.version}
    with _client(arguments.url) as client:
        response = client.get("/export", params=params)
    if response.status_code != 200:
        print(f"HTTP {response.status_code}: {response.text[:500]}")
        return 1
    arguments.out.write_bytes(response.content)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    make = commands.add_parser("keygen", help="Make a signing key pair.")
    make.add_argument("--out-dir", type=Path, required=True)
    signing = commands.add_parser("sign", help="Sign a configuration file.")
    signing.add_argument("--private-key", type=Path, required=True)
    signing.add_argument("--file", type=Path, required=True)
    signing.add_argument("--out", type=Path)
    pushing = commands.add_parser("push", help="Plan or apply a signed file.")
    pushing.add_argument("--url", required=True)
    pushing.add_argument("--file", type=Path, required=True)
    given = pushing.add_mutually_exclusive_group(required=True)
    given.add_argument("--signature")
    given.add_argument("--signature-file", type=Path)
    given.add_argument("--private-key", type=Path)
    pushing.add_argument("--plan-only", action="store_true")
    exporting = commands.add_parser("export", help="Download the current file.")
    exporting.add_argument("--url", required=True)
    exporting.add_argument("--version", type=int)
    exporting.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "keygen":
            return keygen(arguments.out_dir)
        if arguments.command == "sign":
            signature = _signature(arguments.private_key, arguments.file)
            if arguments.out is None:
                print(signature)
            else:
                arguments.out.write_text(signature + "\n")
            return 0
        if arguments.command == "push":
            return push(arguments)
        return export(arguments)
    except Usage as error:
        print(f"shim_config: {error}", file=sys.stderr)
        return 2
    except httpx.HTTPError as error:
        print(f"shim_config: request failed ({type(error).__name__})", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
