"""A process audit hook that reports or refuses lookups of unlisted hosts and metadata.

`shim serve` installs it before the app starts; `create_community_app` never does,
because an audit hook cannot be removed. It sees only the audited Python socket calls:
native code and work done before it was installed stay outside it.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import sys
import threading
from collections.abc import Set
from typing import Final, Literal
from urllib.parse import urlsplit

from shim.core.community_config import CommunitySettings
from shim.observability.metrics import EGRESS_DENIED_TOTAL

Mode = Literal["off", "report", "enforce"]
Kind = Literal["host", "metadata", "link_local"]

LOOKUPS: Final = frozenset(
    {
        "socket.getaddrinfo",
        "socket.gethostbyname",
        "socket.gethostbyname_ex",
        "socket.gethostbyaddr",
    }
)
CONNECTS: Final = frozenset({"socket.connect", "socket.connect_ex"})
METADATA: Final = frozenset(
    ipaddress.ip_address(address)
    for address in (
        "169.254.169.254",
        "fd00:ec2::254",
        "169.254.170.2",
        "169.254.170.23",
        "fd00:ec2::23",
    )
)
LINK_LOCAL: Final = (
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
)
MAX_LOGGED: Final = 256
_INET: Final = (socket.AF_INET, socket.AF_INET6)

_logger = logging.getLogger(__name__)
# Recording logs and counts; the flag keeps an event raised meanwhile out of the hook.
_recording = threading.local()
_logged: set[tuple[str, str]] = set()
# The mode of this process's hook, which isolation passes to its spawned workers.
installed_mode: Mode = "off"
# Rebound, never mutated, so the hook never iterates a set another thread changes.
_hosts: frozenset[str] = frozenset()


def allowed_hosts(settings: CommunitySettings) -> frozenset[str]:
    """The names this gateway resolves: its providers, exporters and the operator's list."""

    urls = (
        settings.OPENAI_BASE_URL or "https://api.openai.com/v1",
        settings.ANTHROPIC_BASE_URL or "https://api.anthropic.com",
        settings.GOOGLE_BASE_URL,
        settings.SHIM_AZURE_OPENAI_ENDPOINT,
        settings.SHIM_AZURE_AUTHORITY_HOST
        if settings.SHIM_AZURE_CLIENT_SECRET
        else None,
        settings.OTEL_EXPORTER_OTLP_ENDPOINT,
        settings.SENTRY_DSN,
    )
    hosts = {urlsplit(url).hostname for url in urls if url}
    return frozenset(
        {"localhost", *settings.SHIM_EGRESS_ALLOW_HOSTS}
        | {host.rstrip(".") for host in hosts if host}
    )


def decide(
    event: str, args: tuple[object, ...], hosts: Set[str]
) -> tuple[Kind, str] | None:
    """The kind and destination an audit event is denied for, or None."""

    if event in LOOKUPS:
        return _destination(args[0], hosts)
    if event in CONNECTS:
        sock, address = args
        if getattr(sock, "family", None) not in _INET or not isinstance(address, tuple):
            return None
        return _destination(address[0], hosts)
    return None


def _destination(host: object, hosts: Set[str]) -> tuple[Kind, str] | None:
    if host is None:
        return None
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    name = str(host).lower().rstrip(".")
    try:
        address = ipaddress.ip_address(name.split("%", 1)[0])
    except ValueError:
        if name in hosts or any(
            name.endswith(host[1:]) for host in hosts if host.startswith("*.")
        ):
            return None
        return "host", name[:255]
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if address in METADATA:
        return "metadata", str(address)
    if any(address in network for network in LINK_LOCAL):
        return "link_local", str(address)
    return None


def install(
    settings: CommunitySettings,
    extra_hosts: Set[str] = frozenset(),
    *,
    allow_kinds: Set[Kind] = frozenset(),
) -> None:
    """Add the hook once per process, in the configured mode; `off` adds none.

    `allow_kinds` names what this process may reach anyway: `host` for one that
    delivers to tenants' own hosts, `metadata` for one whose credentials come from it.
    """

    global installed_mode, _hosts
    mode = settings.SHIM_EGRESS_GUARD
    if mode == "off" or installed_mode != "off":
        return
    _hosts = allowed_hosts(settings) | extra_hosts

    def hook(event: str, args: tuple[object, ...]) -> None:
        if not event.startswith("socket.") or getattr(_recording, "on", False):
            return
        try:
            denied = decide(event, args, _hosts)
        except Exception:
            _record("guard_error", "", mode)
            return
        if denied is None or denied[0] in allow_kinds:
            return
        _record(*denied, mode)
        if mode == "enforce":
            raise PermissionError(f"shim egress guard denied {denied[1]}")

    installed_mode = mode
    sys.addaudithook(hook)


def allow(*hosts: str | None) -> None:
    """Add hosts learned at run time, such as an identity provider's discovered endpoints."""

    global _hosts
    _hosts = _hosts | {host.lower().rstrip(".") for host in hosts if host}


def _record(kind: str, destination: str, mode: Mode) -> None:
    _recording.on = True
    try:
        EGRESS_DENIED_TOTAL.labels(kind=kind, mode=mode).inc()
        if (
            kind != "guard_error"
            and (kind, destination) not in _logged
            and len(_logged) < MAX_LOGGED
        ):
            _logged.add((kind, destination))
            _logger.warning(
                "egress_denied",
                extra={"kind": kind, "destination": destination, "mode": mode},
            )
    except Exception:
        # A fault in the guard must never take the gateway down.
        pass
    finally:
        _recording.on = False


def install_worker(mode: Mode) -> None:
    """In a spawned isolation worker, which needs no network, refuse all of it.

    Only under `enforce`: a worker logs nothing, so `report` would record nothing.
    """

    global installed_mode
    if mode == "enforce" and installed_mode == "off":
        installed_mode = mode
        sys.addaudithook(_refuse_network)


def _refuse_network(event: str, args: tuple[object, ...]) -> None:
    if event in LOOKUPS or (
        event in CONNECTS and getattr(args[0], "family", None) != socket.AF_UNIX
    ):
        raise PermissionError("shim egress guard denied network in an isolation worker")
