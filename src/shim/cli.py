"""Command-line entry point for the community gateway."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from ipaddress import ip_address

from pydantic import ValidationError
import uvicorn

from shim.core import egress_guard, startup_guard
from shim.core.community_config import CommunitySettings
from shim.observability.logging import configure_logging


def main(argv: Sequence[str] | None = None) -> None:
    parser = _parser()
    arguments = parser.parse_args(argv)
    try:
        settings = CommunitySettings()
    except ValidationError as exc:
        parser.error(
            "\n".join(
                f"{'.'.join(map(str, error['loc'])) or 'configuration'}: {error['msg']}"
                for error in exc.errors(include_input=False)
            )
        )
    if settings.SHIM_API_KEY is None and not _is_loopback(arguments.host):
        parser.error("SHIM_API_KEY is required for a non-loopback host")
    configure_logging(settings.LOG_LEVEL)
    start_guards(settings)
    uvicorn.run(
        "shim.application:create_community_app",
        factory=True,
        host=arguments.host,
        port=arguments.port,
        workers=1,
    )


def start_guards(settings: CommunitySettings) -> None:
    """Egress first, so a thread a startup hook started is covered while the scan runs.

    Exits with EX_CONFIG (78) when `enforce` finds a hook the image does not ship.
    """

    egress_guard.install(settings)
    if startup_guard.check(settings.SHIM_STARTUP_GUARD) and (
        settings.SHIM_STARTUP_GUARD == "enforce"
    ):
        raise SystemExit(startup_guard.EX_CONFIG)


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
