"""A warning set after privacy reaches JSON and stream responses; the upstream call is unchanged."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from ee.tests.gateway.test_fallback import _row
from ee.tests.semantic.test_live import _Redis

from ee.tests.tenants.test_deployments import (  # noqa: F401
    _deployments,
    _gateway,
    _success,
    db,
    origins,
    test_org,
)
from shim.gateway.contracts.ids import CURRENT_REQUEST_ID
from shim.gateway.request_policy import RequestPolicyContext
from shim.rules import validate_rule_set
from shim_enterprise.billing.models import RequestLifecycle
from shim_enterprise.core.config import settings
from shim_enterprise.gateway.attempts import TenantAttemptPolicy
from shim_enterprise.semantic.call import CHECK_TAG, run_semantic_call
from shim_enterprise.semantic.live import SemanticPreCheck
from shim_enterprise.semantic.models import OrganizationSemanticQuestions
from shim_enterprise.tenants.gateway_settings import GatewaySettings
from shim_enterprise.tenants.models import ApiKey

pytestmark = pytest.mark.usefixtures("origins")


class _Warns:
    """Stands in for the semantic check: it warns and never chooses a target."""

    name = "semantic_check"

    def __init__(self, events: list[str]) -> None:
        self.events = events

    async def after_privacy(self, prepared):
        self.events.append("check")
        prepared.warn("SEMANTIC_WARN")

    async def after_outcome(self, outcome):
        return None


async def _send(db, key, stream: bool, checked: bool):  # noqa: F811
    events: list[str] = []
    sent: list[dict] = []

    def upstream(request):
        events.append("upstream")
        sent.append(json.loads(request.content))
        return _success(request, stream, "chat")

    async with _gateway(db, key, upstream) as (client, app, _):
        if checked:
            app.state.gateway_service.kernel.attempt_policy = TenantAttemptPolicy(
                async_sessionmaker(db.bind), (_Warns(events),)
            )
        response = await client.post(
            "/v1/chat/completions",
            json={
                "model": "internal-a",
                "stream": stream,
                "messages": [{"role": "user", "content": "hello"}],
            },
        )
    return response, events, sent


@pytest.mark.asyncio
@pytest.mark.parametrize("stream", [False, True])
async def test_the_warning_reaches_the_response_and_the_payload_is_unchanged(
    db,  # noqa: F811
    test_api_key,
    stream,
) -> None:
    await _deployments(db, test_api_key)

    plain, _, plain_sent = await _send(db, test_api_key, stream, checked=False)
    checked, events, checked_sent = await _send(db, test_api_key, stream, checked=True)

    assert (plain.status_code, checked.status_code) == (200, 200)
    assert "SEMANTIC_WARN" not in plain.headers.get("x-shim-warnings", "")
    assert "SEMANTIC_WARN" in checked.headers["x-shim-warnings"].split(",")
    assert events == ["check", "upstream"]
    assert checked_sent == plain_sent
    assert checked.text.count("data:") == plain.text.count("data:")


# The real check through the real kernel: what reaches the check model's host.
CHECK_TEXT = "Project Atlas closes next quarter"
TEAM = "00000000-0000-4000-8000-0000000000aa"
QUESTIONS = [{"id": "atlas", "text": "The request discusses Project Atlas."}]


def _atlas(scope: dict) -> dict:
    return {
        "id": "atlas_term",
        "name": "Atlas",
        "kind": "term",
        "action": "mask",
        "state": "enforced",
        "match": {"terms": ["Atlas"]},
        "scope": scope,
    }


async def _marked(
    db,  # noqa: F811
    key,
    monkeypatch,
    rules,
    tag: str,
    *,
    check_host: str = "b",
    text=CHECK_TEXT,
):
    monkeypatch.setattr(
        settings, "MODEL_DEPLOYMENT_INTERNAL_ORIGINS", ["https://a.internal"]
    )
    await _row(db, key, "a")
    await _row(
        db,
        key,
        check_host,
        alias="kontrol",
        deployment_kind="external" if check_host == "b" else "internal",
        upstream_model="model-k",
    )
    check_key = ApiKey(
        id=uuid4(),
        user_id=key.user_id,
        organization_id=key.organization_id,
        key_hash=uuid4().hex,
        prefix="sk-shim-chk",
        name="Check key",
        tier=key.tier,
        is_active=True,
    )
    db.add(check_key)
    db.add(
        OrganizationSemanticQuestions(
            organization_id=key.organization_id, revision=1, questions=QUESTIONS
        )
    )
    await db.flush()
    gateway = GatewaySettings.model_validate(
        {
            "semantic_check": {
                "enabled": True,
                "scope": {"tags": ["hukuk"]},
                "model": "kontrol",
                "api_key_id": str(check_key.id),
                "warn_header": True,
            }
        }
    )
    sent: list[tuple[str, str]] = []

    def upstream(request):
        host = request.url.host[0]
        sent.append((host, request.content.decode()))
        if json.loads(request.content)["model"] == "model-k":
            verdict = json.dumps({"matches": [{"question_id": "atlas", "match": True}]})
            return httpx.Response(
                200,
                json={
                    "id": "chatcmpl-check",
                    "object": "chat.completion",
                    "created": 1,
                    "model": "model-k",
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": verdict},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 9,
                        "completion_tokens": 9,
                        "total_tokens": 18,
                    },
                },
            )
        return _success(request, False, "chat")

    rule_set = validate_rule_set({"revision": 1, "rules": rules}) if rules else None
    async with _gateway(db, key, upstream, rule_set) as (client, app, _):
        kernel = app.state.gateway_service.kernel
        resolve = kernel.policy_resolver.resolve
        base = resolve.return_value

        async def policy(principal):
            # The caller is in team TEAM; the check key is in no team.
            team = TEAM if principal.api_key_id == key.id else None
            return base.model_copy(
                update={
                    "tenant_gateway_settings": gateway,
                    "request_policy": RequestPolicyContext(
                        rate_limit_key_hash=base.request_policy.rate_limit_key_hash,
                        tier="free",
                        team_id=team,
                    ),
                }
            )

        kernel.policy_resolver.resolve = AsyncMock(side_effect=policy)
        check = SemanticPreCheck(
            async_sessionmaker(db.bind, expire_on_commit=False),
            SimpleNamespace(redis=_Redis()),
        )
        check.kernel = kernel
        kernel.attempt_policy = TenantAttemptPolicy(
            async_sessionmaker(db.bind), (check,)
        )
        response = await client.post(
            "/v1/chat/completions",
            headers={"x-shim-tag": tag},
            json={
                "model": "internal-a",
                "messages": [{"role": "user", "content": text}],
            },
        )
    row = await db.scalar(
        select(RequestLifecycle)
        .where(
            RequestLifecycle.organization_id == key.organization_id,
            RequestLifecycle.api_key_id == key.id,
        )
        .execution_options(populate_existing=True)
    )
    return response, sent, row


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scope",
    [
        # Out of scope at the internal target and on the check call (the check key).
        {"team_ids": [TEAM], "deployment_kinds": ["external"]},
        # Out of scope at the internal target and on the check call (the check tag).
        {"tags": ["hukuk"], "models": ["model-k"]},
    ],
)
async def test_text_a_caller_rule_masks_at_the_check_model_never_reaches_it(
    db,  # noqa: F811
    test_api_key,
    monkeypatch,
    scope,
) -> None:
    response, sent, row = await _marked(
        db, test_api_key, monkeypatch, [_atlas(scope)], "hukuk"
    )

    assert response.status_code == 200, response.text
    assert [host for host, _ in sent] == ["a"]
    assert row.lifecycle_metadata["semantic_check"]["outcome"] == "skipped_guard"


@pytest.mark.asyncio
async def test_without_such_a_rule_the_check_model_reads_the_text(
    db,  # noqa: F811
    test_api_key,
    monkeypatch,
) -> None:
    response, sent, row = await _marked(db, test_api_key, monkeypatch, [], "hukuk")

    assert response.status_code == 200, response.text
    assert [host for host, _ in sent] == ["b", "a"]
    assert "Atlas" in sent[0][1]
    assert row.lifecycle_metadata["semantic_check"]["outcome"] == "matched"
    assert "SEMANTIC_WARN" in response.headers["x-shim-warnings"]


@pytest.mark.asyncio
@pytest.mark.parametrize("reserved", ["shim:semantic_check", "shim:semantic_review"])
async def test_a_client_sent_reserved_tag_never_opts_out_of_the_check(
    db,  # noqa: F811
    test_api_key,
    monkeypatch,
    reserved,
) -> None:
    response, sent, row = await _marked(
        db, test_api_key, monkeypatch, [], f"hukuk,{reserved}"
    )

    assert response.status_code == 200, response.text
    assert [host for host, _ in sent] == ["b", "a"]
    assert row.lifecycle_metadata["semantic_check"]["outcome"] == "matched"


@pytest.mark.asyncio
async def test_of_a_request_with_personal_data_only_the_outcome_is_kept(
    db,  # noqa: F811
    test_api_key,
    monkeypatch,
) -> None:
    response, sent, row = await _marked(
        db,
        test_api_key,
        monkeypatch,
        [],
        "hukuk",
        check_host="a",
        text=f"{CHECK_TEXT}, ask alice@example.com",
    )

    assert response.status_code == 200, response.text
    assert [host for host, _ in sent] == ["a", "a"], row.lifecycle_metadata.get("semantic_check")
    assert "alice@example.com" not in sent[0][1]
    record = row.lifecycle_metadata["semantic_check"]
    assert record["outcome"] == "matched"
    assert "matched" not in record
    assert "SEMANTIC_WARN" in response.headers["x-shim-warnings"]


@pytest.mark.asyncio
async def test_the_check_call_never_takes_over_the_callers_request_id(
    db,  # noqa: F811
    test_api_key,
) -> None:
    await _deployments(db, test_api_key)

    async with _gateway(
        db, test_api_key, lambda request: _success(request, False, "chat")
    ) as (_, app, _):
        token = CURRENT_REQUEST_ID.set("req_marked")
        try:
            result = await run_semantic_call(
                app.state.gateway_service.kernel,
                api_key_id=test_api_key.id,
                alias="internal-a",
                provider="openai",
                text="hello",
                questions=QUESTIONS,
                tag=CHECK_TAG,
            )
            assert result.request_id is not None
            assert CURRENT_REQUEST_ID.get() == "req_marked"
        finally:
            CURRENT_REQUEST_ID.reset(token)
