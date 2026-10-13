"""JSON-RPC over MCP's Streamable HTTP, JSON only and stateless, in both protocol eras.

Modern (`2026-07-28`) requests carry their version in `params._meta` and mirror the
method and name into headers; legacy ones (`2025-11-25` and earlier) start with
`initialize`. Nothing is kept between requests.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

MODERN = "2026-07-28"
LEGACY = ("2025-11-25", "2025-06-18", "2025-03-26")
SUPPORTED = (MODERN, *LEGACY)
# What a request without MCP-Protocol-Version is (the transport's MAY).
UNVERSIONED = "2025-03-26"
# What initialize answers when the client asks for a version shim does not serve.
LEGACY_DEFAULT = "2025-11-25"
VERSION_META = "io.modelcontextprotocol/protocolVersion"
NAMED = {"tools/call": "name", "resources/read": "uri", "prompts/get": "name"}
_SHARED = {
    "ping",
    "tools/list",
    "tools/call",
    "prompts/list",
    "prompts/get",
    "resources/list",
    "resources/read",
}
MODERN_METHODS = frozenset({"server/discover", *_SHARED})
LEGACY_METHODS = frozenset({"initialize", *_SHARED})
NOTIFICATIONS = frozenset({"notifications/initialized", "notifications/cancelled"})
# List and read results a modern client may cache; shim asks it not to.
CACHEABLE = frozenset(
    {"tools/list", "prompts/list", "resources/list", "resources/read"}
)

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
HEADER_MISMATCH = -32020
UNSUPPORTED_VERSION = -32022


@dataclass(eq=False)
class Rejected(Exception):
    """A JSON-RPC error answered with `status`."""

    status: int
    code: int
    message: str
    id: Any = None
    data: Mapping[str, Any] | None = None

    def body(self) -> dict[str, Any]:
        return error(self.id, self.code, self.message, self.data)


@dataclass(frozen=True)
class Call:
    id: Any
    method: str
    params: dict[str, Any]
    modern: bool
    version: str

    @property
    def notification(self) -> bool:
        return self.id is None


def error(
    request_id: Any, code: int, message: str, data: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    failure: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        failure["data"] = dict(data)
    return {"jsonrpc": "2.0", "id": request_id, "error": failure}


def result(call: Call, payload: dict[str, Any]) -> dict[str, Any]:
    if call.modern:
        payload = {**payload, "resultType": "complete"}
        if call.method in CACHEABLE:
            payload |= {"ttlMs": 0, "cacheScope": "private"}
    return {"jsonrpc": "2.0", "id": call.id, "result": payload}


def _header_name(value: str) -> str:
    if value.startswith("=?base64?") and value.endswith("?="):
        try:
            return base64.b64decode(value[9:-2], validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            return ""
    return value


def parse(body: bytes, headers: Mapping[str, str]) -> Call:
    """One JSON-RPC request or notification, its era, and the modern header checks."""
    try:
        message = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        raise Rejected(400, PARSE_ERROR, "Parse error") from None
    if (
        not isinstance(message, dict)
        or message.get("jsonrpc") != "2.0"
        or not isinstance(message.get("method"), str)
        or not isinstance(message.get("params", {}), dict)
        or not isinstance(message.get("id"), (str, int, type(None)))
        or isinstance(message.get("id"), bool)
    ):
        raise Rejected(400, INVALID_REQUEST, "Invalid Request")
    request_id, method = message.get("id"), message["method"]
    params: dict[str, Any] = message.get("params") or {}
    header = headers.get("mcp-protocol-version")
    # Notifications carry no mirrored headers in either era.
    if method in NOTIFICATIONS:
        return Call(request_id, method, params, header == MODERN, header or UNVERSIONED)
    if method == "initialize" or header in LEGACY:
        return Call(request_id, method, params, False, header or UNVERSIONED)
    if header is None:
        return Call(request_id, method, params, False, UNVERSIONED)
    if header != MODERN:
        raise Rejected(
            400,
            UNSUPPORTED_VERSION,
            "Unsupported protocol version",
            request_id,
            {"supported": list(SUPPORTED), "requested": header},
        )
    meta = params.get("_meta")
    named = NAMED.get(method)
    if (
        not isinstance(meta, dict)
        or meta.get(VERSION_META) != MODERN
        or headers.get("mcp-method") != method
        or (
            named is not None
            and _header_name(headers.get("mcp-name", "")) != params.get(named)
        )
    ):
        raise Rejected(400, HEADER_MISMATCH, "Header mismatch", request_id)
    return Call(request_id, method, params, True, MODERN)
