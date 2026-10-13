from __future__ import annotations

import base64
import json

import pytest

from shim_enterprise.mcp import protocol
from shim_enterprise.mcp.protocol import Call, Rejected, parse, result

META = {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}


def _body(method: str, params: dict | None = None, request_id=1) -> bytes:
    message: dict = {"jsonrpc": "2.0", "method": method, "params": params or {}}
    if request_id is not None:
        message["id"] = request_id
    return json.dumps(message).encode()


def _modern(method: str, **headers: str) -> dict[str, str]:
    return {"mcp-protocol-version": "2026-07-28", "mcp-method": method, **headers}


def _rejected(body: bytes, headers: dict[str, str]) -> Rejected:
    with pytest.raises(Rejected) as rejected:
        parse(body, headers)
    return rejected.value


@pytest.mark.parametrize(
    ("method", "header", "modern", "version"),
    [
        ("initialize", "2026-07-28", False, "2026-07-28"),
        ("initialize", None, False, "2025-03-26"),
        ("tools/list", "2025-11-25", False, "2025-11-25"),
        ("tools/list", "2025-06-18", False, "2025-06-18"),
        ("tools/list", None, False, "2025-03-26"),
    ],
)
def test_the_era_comes_from_initialize_or_the_version_header(
    method, header, modern, version
) -> None:
    headers = {"mcp-protocol-version": header} if header else {}

    call = parse(_body(method), headers)

    assert (call.modern, call.version) == (modern, version)


def test_a_modern_request_is_checked_against_its_headers() -> None:
    good = parse(
        _body("tools/call", {"name": "get_rules", "_meta": META}),
        _modern("tools/call", **{"mcp-name": "get_rules"}),
    )
    encoded = parse(
        _body("resources/read", {"uri": "shim://guide/agent", "_meta": META}),
        _modern(
            "resources/read",
            **{
                "mcp-name": "=?base64?"
                + base64.b64encode(b"shim://guide/agent").decode()
                + "?="
            },
        ),
    )
    cases = [
        (
            _body(
                "tools/list",
                {
                    "_meta": {
                        **META,
                        "io.modelcontextprotocol/protocolVersion": "2025-11-25",
                    }
                },
            ),
            _modern("tools/list"),
        ),
        (_body("tools/list", {}), _modern("tools/list")),
        (_body("tools/list", {"_meta": META}), _modern("tools/call")),
        (_body("tools/list", {"_meta": META}), {"mcp-protocol-version": "2026-07-28"}),
        (
            _body("tools/call", {"name": "get_rules", "_meta": META}),
            _modern("tools/call", **{"mcp-name": "list_plans"}),
        ),
        (
            _body("tools/call", {"name": "get_rules", "_meta": META}),
            _modern("tools/call"),
        ),
        (
            _body("tools/call", {"name": "get_rules", "_meta": META}),
            _modern("tools/call", **{"mcp-name": "=?base64?***?="}),
        ),
    ]

    assert (good.modern, good.params["name"]) == (True, "get_rules")
    assert encoded.params["uri"] == "shim://guide/agent"
    for body, headers in cases:
        rejected = _rejected(body, headers)
        assert (rejected.status, rejected.code) == (400, -32020), headers


def test_an_unsupported_version_lists_the_supported_ones() -> None:
    rejected = _rejected(
        _body("tools/list", {"_meta": META}), {"mcp-protocol-version": "1900-01-01"}
    )

    assert (rejected.status, rejected.code) == (400, -32022)
    assert rejected.body()["error"]["data"] == {
        "supported": ["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"],
        "requested": "1900-01-01",
    }


@pytest.mark.parametrize(
    ("body", "code"),
    [
        (b"{not json", -32700),
        (b"\xff", -32700),
        (b'[{"jsonrpc": "2.0", "id": 1, "method": "ping"}]', -32600),
        (b'{"id": 1, "method": "ping"}', -32600),
        (b'{"jsonrpc": "2.0", "id": 1}', -32600),
        (b'{"jsonrpc": "2.0", "id": true, "method": "ping"}', -32600),
        (b'{"jsonrpc": "2.0", "id": 1, "method": "ping", "params": []}', -32600),
    ],
)
def test_a_malformed_message_is_refused(body, code) -> None:
    rejected = _rejected(body, {})

    assert (rejected.status, rejected.code) == (400, code)
    assert set(rejected.body()["error"]) == {"code", "message"}


def test_notifications_need_no_mirrored_headers() -> None:
    call = parse(
        _body("notifications/initialized", request_id=None), _modern("tools/list")
    )

    assert call.notification and call.method == "notifications/initialized"


def test_only_modern_results_carry_result_type_and_cache_fields() -> None:
    legacy = Call(1, "ping", {}, False, "2025-11-25")
    listed = Call(2, "tools/list", {}, True, "2026-07-28")
    called = Call(3, "tools/call", {}, True, "2026-07-28")

    assert result(legacy, {}) == {"jsonrpc": "2.0", "id": 1, "result": {}}
    assert result(listed, {"tools": []})["result"] == {
        "tools": [],
        "resultType": "complete",
        "ttlMs": 0,
        "cacheScope": "private",
    }
    assert result(called, {"isError": False})["result"] == {
        "isError": False,
        "resultType": "complete",
    }
    assert protocol.SUPPORTED[0] == protocol.MODERN


@pytest.mark.parametrize(
    ("method", "params"),
    [
        ("tools/call", {"name": ["get_rules"]}),
        ("tools/call", {"name": {"a": 1}}),
        ("resources/read", {"uri": 7}),
    ],
)
def test_a_name_or_uri_that_is_not_a_string_is_invalid_params(method, params) -> None:
    rejected = _rejected(_body(method, params), {})

    assert (rejected.code, rejected.id) == (protocol.INVALID_PARAMS, 1)
