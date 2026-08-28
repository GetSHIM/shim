"""Resolve-and-validate guard for tenant-configured HTTPS destinations."""

from __future__ import annotations

import asyncio
from ipaddress import IPv4Address, IPv6Address, ip_address
import socket
from typing import cast
from urllib.parse import urlsplit


class UnsafeForwardURL(ValueError):
    """Raised when an outbound target can reach a non-public address."""


def _parse_address(value: str) -> IPv4Address | IPv6Address | None:
    try:
        return ip_address(value)
    except ValueError:
        return None


def _is_public(address: IPv4Address | IPv6Address) -> bool:
    return address.is_global


async def assert_safe_forward_url(url: str) -> IPv4Address | IPv6Address:
    """Require a public HTTPS target and return its first resolved address."""

    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise UnsafeForwardURL("outbound destination must be an absolute HTTPS URL")
    if parts.username is not None or parts.password is not None:
        raise UnsafeForwardURL("outbound destination must not contain user info")
    try:
        port = parts.port or 443
    except ValueError as exc:
        raise UnsafeForwardURL("outbound destination has an invalid port") from exc

    literal = _parse_address(parts.hostname)
    if literal is not None:
        if not _is_public(literal):
            raise UnsafeForwardURL("outbound destination must use a public address")
        return literal

    try:
        addresses = await asyncio.get_running_loop().getaddrinfo(
            parts.hostname,
            port,
            type=socket.SOCK_STREAM,
        )
    except OSError as exc:
        raise UnsafeForwardURL("outbound destination could not be resolved") from exc
    resolved = [_parse_address(cast(str, result[4][0])) for result in addresses]
    if not resolved or any(
        address is None or not _is_public(address) for address in resolved
    ):
        raise UnsafeForwardURL("outbound destination resolved to a non-public address")
    return cast(IPv4Address | IPv6Address, resolved[0])
