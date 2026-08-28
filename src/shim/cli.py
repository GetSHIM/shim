"""Command-line entry point for the community gateway."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from ipaddress import ip_address

from pydantic import ValidationError
import uvicorn

from shim.core.community_config import CommunitySettings


def main(argv: Sequence[str] | None = None) -> None:
    parser = _parser()
    arguments = parser.parse_args(argv)
    try:
        settings = CommunitySettings()
    except ValidationError:
        parser.error("invalid SHIM configuration")
    if settings.SHIM_API_KEY is None and not _is_loopback(arguments.host):
        parser.error("SHIM_API_KEY is required for a non-loopback host")
    uvicorn.run(
        "shim.application:create_community_app",
        factory=True,
        host=arguments.host,
        port=arguments.port,
        workers=1,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="shim")
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="run the community gateway")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", default=8000, type=_port)
    return parser


def _port(value: str) -> int:
    port = int(value)
    if not 1 <= port <= 65_535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def _is_loopback(host: str) -> bool:
    if host.casefold() == "localhost":
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False
