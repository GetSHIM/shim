"""Issue the licence signing key pair and customer licence keys."""

import argparse
import base64
from datetime import date
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)


def keygen() -> None:
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    )
    public_pem = private_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    print("# Store this in Secret Manager. It never enters the repository.")
    print(private_pem.decode(), end="")
    print("# Write this to ee/src/shim_enterprise/core/license_public_key.pem.")
    print(public_pem.decode(), end="")


def sign(private_key_path: Path, customer: str, expires: date) -> None:
    private_key = load_pem_private_key(private_key_path.read_bytes(), password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise SystemExit(f"{private_key_path} is not an Ed25519 private key")
    payload = _encode(
        json.dumps(
            {"customer": customer, "expires": expires.isoformat()},
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    )
    print(f"{payload}.{_encode(private_key.sign(payload.encode('ascii')))}")


def _encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("keygen", help="Generate a new signing key pair.")
    issue = commands.add_parser("sign", help="Issue a licence key for one customer.")
    issue.add_argument("--private-key", type=Path, required=True)
    issue.add_argument("--customer", required=True)
    issue.add_argument("--expires", type=date.fromisoformat, required=True)
    arguments = parser.parse_args()
    if arguments.command == "keygen":
        keygen()
    else:
        sign(arguments.private_key, arguments.customer, arguments.expires)


if __name__ == "__main__":
    main()
