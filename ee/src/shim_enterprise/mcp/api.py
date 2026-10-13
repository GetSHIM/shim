"""POST /api/v1/mcp: the MCP endpoint for agents holding a service account key.

A tool call is dispatched in-process to its management route with the caller's
own Authorization header, so the route's guard, validation, plans, four eyes,
audit and apply limit decide; this module authorizes nothing itself.
"""

from __future__ import annotations

import asyncio
from importlib.metadata import version
import json
import logging
from string import Formatter
from time import perf_counter
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from shim.gateway.auth import authentication_error
from shim_enterprise.api.v1.management._common import bounded_body
from shim_enterprise.core.database import AsyncSessionLocal
from shim_enterprise.mcp import protocol
from shim_enterprise.mcp.catalog import INSTRUCTIONS, PROMPTS, RESOURCES
from shim_enterprise.mcp.protocol import Call, Rejected
from shim_enterprise.mcp.tools import BY_NAME, TOOLS, Tool
from shim_enterprise.observability.enterprise_metrics import (
    MCP_REQUESTS_TOTAL,
    MCP_TOOL_CALLS_TOTAL,
)
from shim_enterprise.tenants.permissions import user_permissions
from shim_enterprise.tenants.service import (
    SERVICE_ACCOUNT_KEY_PREFIX,
    authenticate_service_account,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["mcp"])

MAX_BODY_BYTES = 1_000_000
MAX_RESULT_BYTES = 256 * 1024
TOOL_TIMEOUT_SECONDS = 30.0
_CAPABILITIES = {"tools": {}, "prompts": {}, "resources": {}}


def _server_info() -> dict[str, str]:
    return {"name": "shim", "version": version("shim-enterprise")}


async def _caller(request: Request) -> frozenset[str]:
    """The service account's permissions, read in a session closed before any tool runs."""
    scheme, _, key = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not key:
        raise authentication_error("Invalid API Key", code="INVALID_API_KEY")
    if not key.startswith(SERVICE_ACCOUNT_KEY_PREFIX):
        # A JWT or a gateway key is never looked up here.
        raise HTTPException(
            status_code=403,
            detail={
                "code": "MCP_SERVICE_ACCOUNT_REQUIRED",
                "message": "The MCP endpoint takes a service account key.",
                "hint": "Connect with a service account key (sk-shim-svc-).",
            },
        )
    async with AsyncSessionLocal() as session:
        account = await authenticate_service_account(session, key)
        if account is None:
            raise authentication_error("Invalid API Key", code="INVALID_API_KEY")
        return await user_permissions(session, account)


def _tool_result(structured: dict[str, Any], *, error: bool) -> dict[str, Any]:
    return {
        "content": [
            {"type": "text", "text": json.dumps(structured, separators=(",", ":"))}
        ],
        "structuredContent": structured,
        "isError": error,
    }


async def _dispatch(request: Request, tool: Tool, arguments: Any) -> dict[str, Any]:
    try:
        values = tool.arguments.model_validate(arguments or {}).model_dump(
            mode="json", exclude_none=True
        )
    except ValidationError as exc:
        return _tool_result(
            {
                "status": 422,
                "code": "INVALID_TOOL_ARGUMENTS",
                "errors": [
                    {"loc": list(item["loc"]), "msg": item["msg"]}
                    for item in exc.errors(include_url=False)
                ],
            },
            error=True,
        )
    names = [name for _, name, _, _ in Formatter().parse(tool.path) if name]
    path = tool.path.format(**{name: values.pop(name) for name in names})
    body = values.pop("body", None)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=request.app), base_url="http://shim.internal"
    ) as client:
        try:
            response = await asyncio.wait_for(
                client.request(
                    tool.method,
                    path,
                    params=values,
                    json=body,
                    headers={
                        "authorization": request.headers["authorization"],
                        "x-shim-channel": "mcp",
                    },
                ),
                TOOL_TIMEOUT_SECONDS,
            )
        except TimeoutError:
            return _tool_result(
                {
                    "status": 504,
                    "code": "TOOL_TIMEOUT",
                    "message": "The tool timed out.",
                },
                error=True,
            )
    if len(response.content) > MAX_RESULT_BYTES:
        return _tool_result(
            {
                "status": response.status_code,
                "code": "RESULT_TOO_LARGE",
                "message": "The result is larger than 256 KB; ask again with narrower "
                "filters or a smaller limit.",
            },
            error=True,
        )
    try:
        data = response.json()
    except ValueError:
        data = {"message": response.text[:500]}
    if response.status_code >= 400:
        detail = data.get("detail", data) if isinstance(data, dict) else data
        if isinstance(detail, dict):
            structured = {"status": response.status_code, **detail}
        elif isinstance(detail, str):
            structured = {"status": response.status_code, "message": detail}
        else:
            structured = {"status": response.status_code, "errors": detail}
        return _tool_result(structured, error=True)
    return _tool_result(
        data if isinstance(data, dict) else {"items": data}, error=False
    )


async def _answer(
    request: Request, call: Call, granted: frozenset[str]
) -> dict[str, Any]:
    method, params = call.method, call.params
    if method == "initialize":
        asked = params.get("protocolVersion")
        return protocol.result(
            call,
            {
                "protocolVersion": asked
                if asked in protocol.LEGACY
                else protocol.LEGACY_DEFAULT,
                "capabilities": _CAPABILITIES,
                "serverInfo": _server_info(),
                "instructions": INSTRUCTIONS,
            },
        )
    if method == "server/discover":
        return protocol.result(
            call,
            {
                "supportedVersions": list(protocol.SUPPORTED),
                "capabilities": _CAPABILITIES,
                "instructions": INSTRUCTIONS,
                "_meta": {"io.modelcontextprotocol/serverInfo": _server_info()},
                "ttlMs": 0,
                "cacheScope": "private",
            },
        )
    if method == "ping":
        return protocol.result(call, {})
    if method == "tools/list":
        listed = [
            tool.listing() for tool in TOOLS if granted & set(tool.permissions_any)
        ]
        return protocol.result(call, {"tools": listed})
    if method == "tools/call":
        tool = BY_NAME.get(params.get("name"))  # type: ignore[arg-type]
        if tool is None:
            MCP_TOOL_CALLS_TOTAL.labels(tool="unknown", outcome="error").inc()
            raise Rejected(200, protocol.INVALID_PARAMS, "Unknown tool", call.id)
        outcome = await _dispatch(request, tool, params.get("arguments"))
        MCP_TOOL_CALLS_TOTAL.labels(
            tool=tool.name, outcome="error" if outcome["isError"] else "ok"
        ).inc()
        return protocol.result(call, outcome)
    if method == "prompts/list":
        return protocol.result(call, {"prompts": list(PROMPTS)})
    if method == "prompts/get":
        raise Rejected(200, protocol.INVALID_PARAMS, "Unknown prompt", call.id)
    if method == "resources/list":
        return protocol.result(
            call,
            {
                "resources": [
                    {
                        "uri": item.uri,
                        "name": item.name,
                        "description": item.description,
                        "mimeType": item.mime_type,
                    }
                    for item in RESOURCES
                ]
            },
        )
    if method == "resources/read":
        found = next(
            (item for item in RESOURCES if item.uri == params.get("uri")), None
        )
        if found is None:
            raise Rejected(200, protocol.INVALID_PARAMS, "Unknown resource", call.id)
        return protocol.result(
            call,
            {
                "contents": [
                    {
                        "uri": found.uri,
                        "mimeType": found.mime_type,
                        "text": found.text(),
                    }
                ]
            },
        )
    raise AssertionError(method)


async def mcp_endpoint(request: Request) -> Response:
    started, method, outcome = perf_counter(), "other", "protocol_error"
    status = 200
    try:
        if "origin" in request.headers:
            # The transport's DNS-rebinding rule: agents send no Origin, browsers do.
            status = 403
            return JSONResponse(
                protocol.error(None, protocol.INVALID_REQUEST, "Origin not allowed"),
                403,
            )
        granted = await _caller(request)
        content_type = request.headers.get("content-type", "").split(";")[0].strip()
        if content_type != "application/json":
            status = 415
            return JSONResponse(
                protocol.error(None, protocol.INVALID_REQUEST, "Send application/json"),
                415,
            )
        try:
            call = protocol.parse(await request.body(), request.headers)
            if call.method in protocol.NOTIFICATIONS:
                method, outcome, status = call.method, "ok", 202
                return Response(status_code=202)
            known = protocol.MODERN_METHODS if call.modern else protocol.LEGACY_METHODS
            if call.method not in known:
                raise Rejected(
                    404 if call.modern else 200,
                    protocol.METHOD_NOT_FOUND,
                    "Method not found",
                    call.id,
                )
            method = call.method
            answer = await _answer(request, call, granted)
        except Rejected as rejected:
            status = rejected.status
            return JSONResponse(rejected.body(), rejected.status)
        outcome = "tool_error" if answer["result"].get("isError") is True else "ok"
        return JSONResponse(answer)
    except HTTPException as exc:
        status = exc.status_code
        raise
    finally:
        MCP_REQUESTS_TOTAL.labels(method=method, outcome=outcome).inc()
        logger.info(
            "MCP request method=%s status=%s duration_ms=%d",
            method,
            status,
            (perf_counter() - started) * 1000,
        )


router.add_api_route(
    "/mcp",
    mcp_endpoint,
    methods=["POST"],
    operation_id="mcp_endpoint",
    response_class=JSONResponse,
    summary="MCP endpoint for agents with a service account key",
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": {"type": "object"}}},
        }
    },
    route_class_override=bounded_body(
        MAX_BODY_BYTES, "An MCP message is at most 1,000,000 bytes."
    ),
)
