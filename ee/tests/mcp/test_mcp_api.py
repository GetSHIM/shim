from __future__ import annotations

import asyncio
from datetime import timedelta
import json

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ee.tests.findings.test_findings import _deployment, _evaluate
from shim_enterprise.api.v1 import management
from shim_enterprise.api.v1.router import management_router
from shim_enterprise.core.config import settings
from shim_enterprise.core.database import get_db
from shim_enterprise.findings.models import Finding
from shim_enterprise.mcp import api as mcp_api
from shim_enterprise.mcp.tools import TOOLS
from shim_enterprise.tenants.models import (
    ModelDeployment,
    OrganizationGatewaySettings,
    User,
)
from shim_enterprise.tenants.plans import activate_organization_plan

MCP = "/api/v1/mcp"
WRITE_TOOLS = {
    "plan_from_finding",
    "create_plan",
    "apply_plan",
    "restore_version",
    "propose_rules",
}


@pytest_asyncio.fixture
async def mcp_app(db, monkeypatch) -> FastAPI:
    connection = await db.connection()

    def session() -> AsyncSession:
        # Each session its own savepoint of the test's transaction, as requests are.
        return AsyncSession(
            bind=connection,
            join_transaction_mode="create_savepoint",
            expire_on_commit=False,
        )

    async def request_session():
        async with session() as opened:
            yield opened

    monkeypatch.setattr(mcp_api, "AsyncSessionLocal", session)
    # The test deployments live at https://a.internal (ee/tests/findings helpers).
    monkeypatch.setattr(
        settings, "MODEL_DEPLOYMENT_ALLOWED_ORIGINS", ["https://a.internal"]
    )
    app = FastAPI()
    app.include_router(management_router, prefix="/api/v1")
    app.dependency_overrides[get_db] = request_session
    return app


@pytest_asyncio.fixture
async def accounts(db, test_user_with_org, test_api_key) -> dict[str, str]:
    owner = test_user_with_org
    owner.role = "owner"
    await activate_organization_plan(db, owner.organization_id, "enterprise")
    keys = {}
    for role in ("recommender", "auditor", "admin"):
        created = await management.members.create_service_account(
            management.members.ServiceAccountInput(
                name=f"mcp-{role}", role=role, expires_in_days=1
            ),
            owner,
            db,
        )
        keys[role] = created.plaintext
    keys["owner_id"] = str(owner.id)
    return keys


async def _post(
    app, key: str | None, message, headers: dict | None = None
) -> httpx.Response:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        return await client.post(
            MCP,
            content=message if isinstance(message, bytes) else json.dumps(message),
            headers={
                "content-type": "application/json",
                **({"authorization": f"Bearer {key}"} if key else {}),
                **(headers or {}),
            },
        )


async def _rpc(
    app, key: str, method: str, params: dict | None = None, *, modern: bool = False
):
    params = dict(params or {})
    headers = {}
    if modern:
        params["_meta"] = {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}
        headers = {"mcp-protocol-version": "2026-07-28", "mcp-method": method}
        if "name" in params or "uri" in params:
            headers["mcp-name"] = params.get("name") or params["uri"]
    response = await _post(
        app,
        key,
        {"jsonrpc": "2.0", "id": 7, "method": method, "params": params},
        headers,
    )
    return response


async def _tool(
    app, key: str, name: str, arguments: dict | None = None, *, modern=False
):
    response = await _rpc(
        app,
        key,
        "tools/call",
        {"name": name, "arguments": arguments or {}},
        modern=modern,
    )
    assert response.status_code == 200, response.text
    return response.json()["result"]


async def _direct(app, key: str, method: str, path: str, **kwargs) -> httpx.Response:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        return await client.request(
            method, path, headers={"authorization": f"Bearer {key}"}, **kwargs
        )


@pytest.mark.asyncio
async def test_only_a_valid_service_account_key_connects(mcp_app, accounts, db) -> None:
    revoked = await management.members.create_service_account(
        management.members.ServiceAccountInput(
            name="gone", role="auditor", expires_in_days=1
        ),
        await db.get(User, accounts["owner_id"]),
        db,
    )
    await management.members.delete_service_account(
        revoked.id, await db.get(User, accounts["owner_id"]), db
    )
    ping = {"jsonrpc": "2.0", "id": 1, "method": "ping"}

    missing = await _post(mcp_app, None, ping)
    gone = await _post(mcp_app, revoked.plaintext, ping)
    jwt = await _post(mcp_app, "eyJhbGciOiJIUzI1NiJ9.e30.x", ping)
    gateway = await _post(mcp_app, "sk-shim-" + "0" * 64, ping)
    browser = await _post(
        mcp_app, accounts["auditor"], ping, {"origin": "https://example.test"}
    )
    large = await _post(mcp_app, accounts["auditor"], b" " * 1_000_001)
    form = await _post(
        mcp_app, accounts["auditor"], ping, {"content-type": "text/plain"}
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=mcp_app), base_url="http://test"
    ) as client:
        get = await client.get(MCP)
        delete = await client.delete(MCP)
    ok = await _post(mcp_app, accounts["auditor"], ping)

    assert (missing.status_code, gone.status_code) == (401, 401)
    assert missing.headers["www-authenticate"] == "Bearer"
    for refused in (jwt, gateway):
        assert refused.status_code == 403
        assert refused.json()["detail"]["code"] == "MCP_SERVICE_ACCOUNT_REQUIRED"
    assert (browser.status_code, large.status_code, form.status_code) == (403, 413, 415)
    assert (get.status_code, delete.status_code) == (405, 405)
    assert ok.json() == {"jsonrpc": "2.0", "id": 1, "result": {}}
    assert "mcp-session-id" not in ok.headers


@pytest.mark.asyncio
async def test_both_eras_handshake_and_discover(mcp_app, accounts) -> None:
    key = accounts["recommender"]

    initialized = await _rpc(
        mcp_app, key, "initialize", {"protocolVersion": "2025-06-18"}
    )
    fallback = await _rpc(mcp_app, key, "initialize", {"protocolVersion": "2024-01-01"})
    notified = await _post(
        mcp_app,
        key,
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"mcp-session-id": "abc"},
    )
    discovered = await _rpc(mcp_app, key, "server/discover", modern=True)
    unknown_modern = await _rpc(mcp_app, key, "sampling/createMessage", modern=True)
    unknown_legacy = await _rpc(mcp_app, key, "sampling/createMessage")
    discover_legacy = await _rpc(mcp_app, key, "server/discover")

    result = initialized.json()["result"]
    assert result["protocolVersion"] == "2025-06-18"
    assert set(result) == {
        "protocolVersion",
        "capabilities",
        "serverInfo",
        "instructions",
    }
    assert result["serverInfo"]["name"] == "shim"
    assert len(result["instructions"]) <= 1500
    assert fallback.json()["result"]["protocolVersion"] == "2025-11-25"
    assert (notified.status_code, notified.content) == (202, b"")
    assert "mcp-session-id" not in initialized.headers
    found = discovered.json()["result"]
    assert (found["resultType"], found["ttlMs"], found["cacheScope"]) == (
        "complete",
        0,
        "private",
    )
    assert found["supportedVersions"] == [
        "2026-07-28",
        "2025-11-25",
        "2025-06-18",
        "2025-03-26",
    ]
    assert (unknown_modern.status_code, unknown_modern.json()["error"]["code"]) == (
        404,
        -32601,
    )
    assert (unknown_legacy.status_code, unknown_legacy.json()["error"]["code"]) == (
        200,
        -32601,
    )
    assert discover_legacy.json()["error"]["code"] == -32601


@pytest.mark.asyncio
async def test_tools_are_listed_by_the_callers_permissions(mcp_app, accounts) -> None:
    listed = {}
    for role in ("recommender", "auditor", "admin"):
        response = await _rpc(mcp_app, accounts[role], "tools/list")
        listed[role] = {tool["name"] for tool in response.json()["result"]["tools"]}
    modern = await _rpc(mcp_app, accounts["recommender"], "tools/list", modern=True)

    every = {tool.name for tool in TOOLS}
    assert listed["recommender"] == listed["admin"] == every
    assert listed["auditor"] == every - WRITE_TOOLS
    assert len(listed["auditor"]) == 12
    assert modern.json()["result"]["cacheScope"] == "private"
    tool = next(
        t for t in modern.json()["result"]["tools"] if t["name"] == "apply_plan"
    )
    assert tool["annotations"] == {"readOnlyHint": False, "destructiveHint": True}
    assert tool["inputSchema"]["required"] == ["plan_id"]


async def _suggested_finding(db, key) -> Finding:
    """An unused-deployment finding that suggests disabling it."""
    # The finding suggests its action only in suggest mode (E42).
    db.add(
        OrganizationGatewaySettings(
            organization_id=key.organization_id,
            settings={"finding_modes": {"gateway.unused_deployment": "suggest"}},
        )
    )
    await _deployment(db, key, age=timedelta(days=40))
    await _evaluate(db, key)
    finding = await db.scalar(
        select(Finding).where(
            Finding.organization_id == key.organization_id,
            Finding.rule_id == "gateway.unused_deployment",
        )
    )
    assert finding is not None
    return finding


@pytest.mark.asyncio
async def test_a_recommender_plans_from_a_finding_without_deployments_manage(
    mcp_app, accounts, db, test_api_key
) -> None:
    finding = await _suggested_finding(db, test_api_key)

    planned = await _tool(
        mcp_app,
        accounts["recommender"],
        "plan_from_finding",
        {"finding_id": str(finding.id)},
    )

    assert planned["isError"] is False, planned
    assert planned["structuredContent"]["source"] == "mcp"
    assert planned["structuredContent"]["changes"][0]["after"]["enabled"] is False


@pytest.mark.asyncio
async def test_every_tool_answers_what_its_route_answers(
    mcp_app, accounts, db, test_api_key
) -> None:
    finding = await _suggested_finding(db, test_api_key)
    key = accounts["admin"]
    calls = {
        "list_findings": (
            {},
            "GET",
            "/findings",
            {"params": {"limit": 20, "offset": 0}},
        ),
        "get_finding": (
            {"finding_id": str(finding.id)},
            "GET",
            f"/findings/{finding.id}",
            {},
        ),
        "explain_finding": (
            {"finding_id": str(finding.id)},
            "GET",
            f"/findings/{finding.id}/explain",
            {},
        ),
        "list_finding_rules": ({}, "GET", "/findings/rules", {}),
        "list_requests": (
            {},
            "GET",
            "/requests",
            {"params": {"limit": 20, "offset": 0}},
        ),
        "get_rules": ({}, "GET", "/rules", {}),
        "get_privacy_settings": ({}, "GET", "/settings/pii", {}),
        "get_gateway_settings": ({}, "GET", "/gateway-settings", {}),
        "list_deployments": ({}, "GET", "/model-deployments", {}),
        "list_versions": ({}, "GET", "/policy/versions", {"params": {"limit": 20}}),
    }
    for name, (arguments, method, path, kwargs) in calls.items():
        tool = await _tool(mcp_app, key, name, arguments)
        direct = await _direct(
            mcp_app, key, method, f"/api/v1/management{path}", **kwargs
        )
        expected = (
            direct.json()
            if isinstance(direct.json(), dict)
            else {"items": direct.json()}
        )
        assert tool["isError"] is False, (name, tool)
        assert json.loads(tool["content"][0]["text"]) == tool["structuredContent"]
        # Only the moment of reading differs between the two calls.
        for body in (tool["structuredContent"], expected):
            body.pop("generated_at", None)
        assert tool["structuredContent"] == expected, name

    planned = await _tool(
        mcp_app, key, "plan_from_finding", {"finding_id": str(finding.id)}
    )
    assert "id" in planned["structuredContent"], planned
    plan_id = planned["structuredContent"]["id"]
    shown = await _tool(mcp_app, key, "get_plan", {"plan_id": plan_id})
    plans = await _tool(mcp_app, key, "list_plans", {"status": "draft"})
    applied = await _tool(mcp_app, key, "apply_plan", {"plan_id": plan_id})
    restored = await _tool(mcp_app, key, "restore_version", {"version": 0, "body": {}})

    assert planned["structuredContent"]["source"] == "mcp"
    assert shown["structuredContent"]["changes"][0]["impact"]["basis"] == "metadata"
    assert [item["id"] for item in plans["structuredContent"]["items"]] == [plan_id]
    assert applied["structuredContent"]["status"] == "applied"
    assert restored["isError"] is False, restored
    assert restored["structuredContent"]["plan"]["source"] == "restore"


@pytest.mark.asyncio
async def test_route_refusals_reach_the_agent_with_their_codes(
    mcp_app, accounts, db, test_api_key
) -> None:
    agent = accounts["recommender"]
    alias = await _deployment(db, test_api_key, age=timedelta(days=1))
    deployment_id = str(
        await db.scalar(
            select(ModelDeployment.id).where(ModelDeployment.alias == alias)
        )
    )
    created = await _tool(
        mcp_app,
        agent,
        "create_plan",
        {
            "body": {
                "changes": [
                    {
                        "resource": "deployments",
                        "item": deployment_id,
                        "set": {"enabled": False},
                    }
                ]
            }
        },
        modern=True,
    )
    assert "id" in created["structuredContent"], created
    plan_id = created["structuredContent"]["id"]
    refused = await _tool(
        mcp_app, agent, "apply_plan", {"plan_id": plan_id}, modern=True
    )
    forbidden = await _tool(
        mcp_app,
        accounts["auditor"],
        "create_plan",
        {"body": {"changes": [{"resource": "privacy", "item": "_", "set": {}}]}},
    )
    invalid = await _tool(mcp_app, agent, "get_plan", {"plan_id": "nope", "extra": 1})
    missing = await _rpc(mcp_app, agent, "tools/call", {"name": "delete_everything"})
    by_human = await _direct(mcp_app, agent, "GET", "/api/v1/management/policy/plans")

    assert created["structuredContent"]["source"] == "mcp"
    assert created["resultType"] == "complete"
    assert refused["isError"] is True
    assert refused["structuredContent"]["status"] == 403
    assert refused["structuredContent"]["code"] == "PLAN_NOT_ALLOWLISTED"
    assert refused["structuredContent"]["changes"][-1]["reason"] == "not_allowlisted"
    assert "hint" in refused["structuredContent"]
    assert (forbidden["isError"], forbidden["structuredContent"]["status"]) == (
        True,
        403,
    )
    assert invalid["structuredContent"]["code"] == "INVALID_TOOL_ARGUMENTS"
    assert {error["loc"][0] for error in invalid["structuredContent"]["errors"]} == {
        "plan_id",
        "extra",
    }
    assert missing.json()["error"]["code"] == -32602
    assert by_human.status_code == 200


@pytest.mark.asyncio
async def test_a_person_sending_the_channel_header_still_gets_api(
    db, test_user_with_org
) -> None:
    from ee.tests.config_file.test_config_api import call

    test_user_with_org.role = "owner"
    response = await call(
        db,
        test_user_with_org,
        "POST",
        "/api/v1/management/policy/plans",
        json={
            "changes": [
                {"resource": "privacy", "item": "_", "set": {"block_email": False}}
            ]
        },
        headers={"x-shim-channel": "mcp"},
    )

    assert response.status_code == 201, response.text
    assert response.json()["source"] == "api"


@pytest.mark.asyncio
async def test_timeouts_and_large_results_become_tool_errors(
    mcp_app, accounts, monkeypatch
) -> None:
    monkeypatch.setattr(mcp_api, "MAX_RESULT_BYTES", 10)
    large = await _tool(mcp_app, accounts["auditor"], "get_rules")
    monkeypatch.setattr(mcp_api, "TOOL_TIMEOUT_SECONDS", 0.001)
    original = httpx.AsyncClient.request

    async def slow(self, *args, **kwargs):
        await asyncio.sleep(0.05)
        return await original(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "request", slow)
    late = await _tool(mcp_app, accounts["auditor"], "get_rules")

    assert (large["isError"], large["structuredContent"]["code"]) == (
        True,
        "RESULT_TOO_LARGE",
    )
    assert (late["isError"], late["structuredContent"]["code"]) == (
        True,
        "TOOL_TIMEOUT",
    )


@pytest.mark.asyncio
async def test_the_guides_are_resources_and_write_rules_a_prompt(
    mcp_app, accounts
) -> None:
    key = accounts["auditor"]

    listed = await _rpc(mcp_app, key, "resources/list")
    read = await _rpc(
        mcp_app, key, "resources/read", {"uri": "shim://guide/agent"}, modern=True
    )
    rules_en = await _rpc(
        mcp_app, key, "resources/read", {"uri": "shim://guide/rules/en"}
    )
    unknown = await _rpc(mcp_app, key, "resources/read", {"uri": "shim://nothing"})
    prompts = await _rpc(mcp_app, key, "prompts/list", modern=True)
    turkish = await _rpc(
        mcp_app,
        key,
        "prompts/get",
        {"name": "write_rules", "arguments": {"language": "tr"}},
    )
    english = await _rpc(
        mcp_app,
        key,
        "prompts/get",
        {"name": "write_rules", "arguments": {"language": "en"}},
        modern=True,
    )
    default = await _rpc(mcp_app, key, "prompts/get", {"name": "write_rules"})
    wrong = await _rpc(
        mcp_app,
        key,
        "prompts/get",
        {"name": "write_rules", "arguments": {"language": "de"}},
    )
    missing = await _rpc(mcp_app, key, "prompts/get", {"name": "nothing"})

    assert [item["uri"] for item in listed.json()["result"]["resources"]] == [
        "shim://guide/agent",
        "shim://guide/rules/tr",
        "shim://guide/rules/en",
    ]
    content = read.json()["result"]["contents"][0]
    assert content["mimeType"] == "text/markdown"
    assert content["text"].startswith("# Working with shim as an agent")
    assert len(content["text"].encode()) <= 8 * 1024
    assert read.json()["result"]["ttlMs"] == 0
    guide = rules_en.json()["result"]["contents"][0]["text"]
    assert guide.startswith("# Writing shim rules") and len(guide.encode()) <= 8 * 1024
    assert unknown.json()["error"]["code"] == -32602
    assert [item["name"] for item in prompts.json()["result"]["prompts"]] == [
        "write_rules"
    ]

    def text(response) -> str:
        [message] = response.json()["result"]["messages"]
        assert message["role"] == "user"
        return message["content"]["text"]

    assert text(turkish).startswith("# Kullanıcının cümlesinden")
    assert text(english) == guide
    assert english.json()["result"]["resultType"] == "complete"
    assert text(default) == text(turkish)
    assert wrong.json()["error"]["code"] == missing.json()["error"]["code"] == -32602
