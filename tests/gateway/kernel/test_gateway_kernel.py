import io
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from starlette.responses import Response

from shim.application import create_community_app
from shim.core.community_config import CommunitySettings
import shim.gateway.kernel.gateway_kernel as kernel_module
from shim.gateway.contracts.ids import CURRENT_REQUEST_ID
from shim.gateway.kernel.gateway_kernel import GatewayKernel
from shim.gateway.pipeline.authenticate import GatewayRequestMetadata
from shim.gateway.pipeline.provider_execution import ERROR_HINTS, ProviderCallError
from shim.privacy.policies import (
    PrivacyAction,
    PrivacyOutcome,
    effective_entity_actions,
)
from shim.services.gateway.service import GatewayService

_NO_PII = PrivacyOutcome(action=PrivacyAction.DETECTED, pii_detected=False)


def _kernel(usage) -> GatewayKernel:
    execution = SimpleNamespace(pii_scrubber=object())
    return GatewayKernel(
        {
            "openai": execution,
            "anthropic": execution,
            "google": execution,
        },
        chain_store=object(),
        policy_resolver=object(),
        rate_limiter=object(),
        loop_detector=object(),
        loop_repeat_limit=3,
        loop_window_seconds=60,
        cost_tag_max_length=64,
        usage=usage,
    )


@pytest.mark.asyncio
async def test_kernel_runs_the_authoritative_stage_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    order: list[str] = []
    prepared = SimpleNamespace(
        stream=False, protocol="chat", privacy=_NO_PII, payload={}, rules=None
    )
    provider_output = object()
    response = Response("ok")

    def stage(name: str):
        return lambda *_args, **_kwargs: SimpleNamespace(name=name, reserved=False)

    for class_name, stage_name in (
        ("AuthenticateStage", "resolve_principal"),
        ("AdmissionStage", "admission"),
        ("PrivacyStage", "privacy"),
        ("ProviderSpendStage", "provider_spend"),
        ("ProviderExecutionStage", "provider_execution"),
        ("PostprocessStage", "postprocess"),
    ):
        monkeypatch.setattr(kernel_module, class_name, stage(stage_name))

    async def run_stage(stage, _value):
        order.append(stage.name)
        if stage.name == "provider_execution":
            return provider_output
        if stage.name == "postprocess":
            return response
        return prepared

    async def record_privacy(*_args):
        order.append("record_privacy")

    monkeypatch.setattr(kernel_module, "run_stage", run_stage)
    provider_execution = SimpleNamespace(pii_scrubber=object())
    kernel = GatewayKernel(
        {
            "openai": provider_execution,
            "anthropic": provider_execution,
            "google": provider_execution,
        },
        chain_store=object(),
        policy_resolver=object(),
        rate_limiter=object(),
        loop_detector=object(),
        loop_repeat_limit=3,
        loop_window_seconds=60,
        cost_tag_max_length=64,
        usage=SimpleNamespace(
            record_privacy=record_privacy,
            fail=AsyncMock(),
        ),
    )

    result = await kernel._execute(SimpleNamespace(provider="google"))

    assert result is response
    assert order == [
        "resolve_principal",
        "admission",
        "privacy",
        "record_privacy",
        "provider_spend",
        "provider_execution",
        "postprocess",
    ]


def test_kernel_accepts_a_supported_provider_subset() -> None:
    kernel = GatewayKernel(
        {"openai": SimpleNamespace(pii_scrubber=object())},
        chain_store=object(),
        policy_resolver=object(),
        rate_limiter=object(),
        loop_detector=object(),
        loop_repeat_limit=3,
        loop_window_seconds=60,
        cost_tag_max_length=64,
        usage=object(),
    )

    assert set(kernel.executions) == {"openai"}


@pytest.mark.parametrize("executions", [{}, {"unsupported": object()}])
def test_kernel_rejects_empty_or_unsupported_execution_sets(
    executions: dict[str, object],
) -> None:
    with pytest.raises(ValueError, match="supported native providers"):
        GatewayKernel(
            executions,
            chain_store=object(),
            policy_resolver=object(),
            rate_limiter=object(),
            loop_detector=object(),
            loop_repeat_limit=3,
            loop_window_seconds=60,
            cost_tag_max_length=64,
            usage=object(),
        )


@pytest.mark.asyncio
async def test_kernel_sanitizes_an_unconfigured_provider() -> None:
    usage = SimpleNamespace(fail=AsyncMock())
    kernel = GatewayKernel(
        {"openai": SimpleNamespace(pii_scrubber=object())},
        chain_store=object(),
        policy_resolver=object(),
        rate_limiter=object(),
        loop_detector=object(),
        loop_repeat_limit=3,
        loop_window_seconds=60,
        cost_tag_max_length=64,
        usage=usage,
    )

    response = await GatewayService(kernel).dispatch_inference(
        payload={},
        provider="google",
        protocol="generate_content",
        model="gemini-test",
        stream=False,
        headers={},
        provider_credential=None,
        principal=SimpleNamespace(),  # type: ignore[arg-type]
        request_metadata=GatewayRequestMetadata(
            endpoint="/v1beta/models/gemini-test:generateContent"
        ),
    )

    assert response.status_code == 503
    payload = json.loads(response.body)
    assert payload == {
        "error": {
            "code": 503,
            "message": "The Google request failed.",
            "status": "UNAVAILABLE",
            "details": [
                {
                    "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                    "reason": "PROVIDER_UNAVAILABLE",
                    "domain": "getshim.tech",
                    "metadata": {"hint": ERROR_HINTS["PROVIDER_UNAVAILABLE"]},
                }
            ],
        }
    }
    usage.fail.assert_not_awaited()


@pytest.mark.parametrize(
    ("status_code", "error_code", "expected_reason"),
    [
        (400, "PROVIDER_REJECTED_REQUEST", "provider_rejected_without_usage"),
        (401, "INVALID_PROVIDER_CREDENTIAL", "provider_rejected_without_usage"),
        (400, "INVALID_REQUEST", "provider_rejected_without_usage"),
        (409, "PROVIDER_UNAVAILABLE", "provider_rejected_without_usage"),
        (429, "PROVIDER_RATE_LIMITED", "provider_rejected_without_usage"),
        (408, "PROVIDER_TIMEOUT", "request_aborted"),
        (503, "PROVIDER_UNAVAILABLE", "request_aborted"),
    ],
)
@pytest.mark.asyncio
async def test_kernel_maps_provider_failures_to_usage_reason(
    monkeypatch: pytest.MonkeyPatch,
    status_code: int,
    error_code: str,
    expected_reason: str,
) -> None:
    prepared = SimpleNamespace(
        stream=False, protocol="chat", privacy=_NO_PII, payload={}, rules=None
    )
    failure = ProviderCallError(
        status_code=status_code,
        error_code=error_code,
        retryable=status_code >= 500,
        provider="openai",
    )

    async def run_stage(stage, _value):
        if stage.name == "provider_execution":
            raise failure
        return prepared

    monkeypatch.setattr(kernel_module, "run_stage", run_stage)
    usage = SimpleNamespace(record_privacy=AsyncMock(), fail=AsyncMock())

    with pytest.raises(ProviderCallError) as error:
        await _kernel(usage)._execute(SimpleNamespace(provider="openai"))

    assert error.value is failure
    usage.fail.assert_awaited_once_with(prepared, reason=expected_reason)


@pytest.mark.asyncio
async def test_kernel_publishes_the_request_id_once_a_request_is_prepared() -> None:
    kernel = _kernel(SimpleNamespace())

    async def fail_after_preparing(_invocation, *, prepared_observer):
        prepared_observer(
            SimpleNamespace(policy=SimpleNamespace(tier="team"), request_id="req_seen")
        )
        raise RuntimeError("refused after admission")

    kernel._execute = fail_after_preparing  # type: ignore[method-assign]
    invocation = SimpleNamespace(
        metadata=GatewayRequestMetadata(endpoint="/v1/chat/completions"),
        protocol="chat",
    )

    with pytest.raises(RuntimeError):
        await kernel.execute(invocation)  # type: ignore[arg-type]

    assert CURRENT_REQUEST_ID.get() == "req_seen"


@pytest.mark.asyncio
async def test_kernel_maps_post_reservation_admission_abort(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = SimpleNamespace(
        stream=False, protocol="chat", privacy=_NO_PII, payload={}, rules=None
    )
    failure = RuntimeError("admission interrupted")

    async def run_stage(stage, _value):
        if stage.name == "admission":
            stage.reserved = True
            raise failure
        return prepared

    monkeypatch.setattr(kernel_module, "run_stage", run_stage)
    usage = SimpleNamespace(fail=AsyncMock())

    with pytest.raises(RuntimeError) as error:
        await _kernel(usage)._execute(SimpleNamespace(provider="openai"))

    assert error.value is failure
    usage.fail.assert_awaited_once_with(prepared, reason="admission_aborted")


@pytest.mark.asyncio
async def test_recovery_session_failure_does_not_mask_original_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = SimpleNamespace(
        stream=False, protocol="chat", privacy=_NO_PII, payload={}, rules=None
    )
    failure = RuntimeError("admission interrupted")

    async def run_stage(stage, _value):
        if stage.name == "admission":
            stage.reserved = True
            raise failure
        return prepared

    monkeypatch.setattr(kernel_module, "run_stage", run_stage)
    usage = SimpleNamespace(fail=AsyncMock(side_effect=RuntimeError("I/O failed")))

    with pytest.raises(RuntimeError) as error:
        await _kernel(usage)._execute(SimpleNamespace(provider="openai"))

    assert error.value is failure


_GATEWAY_KEY = "gateway-secret-12345"
_PASTED_KEY = "sk-proj-" + "0" * 32
_CHAT_REPLY = {
    "id": "chatcmpl-1",
    "object": "chat.completion",
    "created": 0,
    "model": "gpt-5-nano",
    "choices": [
        {
            "index": 0,
            "message": {"role": "assistant", "content": "ok"},
            "finish_reason": "stop",
        }
    ],
    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
}
_ROUTES = {
    "chat": (
        "/v1/chat/completions",
        {"authorization": f"Bearer {_GATEWAY_KEY}"},
        lambda text: {
            "model": "gpt-5-nano",
            "messages": [{"role": "user", "content": text}],
        },
    ),
    "messages": (
        "/v1/messages",
        {"x-api-key": _GATEWAY_KEY},
        lambda text: {
            "model": "claude-sonnet-4-6",
            "max_tokens": 16,
            "messages": [{"role": "user", "content": text}],
        },
    ),
    "count_tokens": (
        "/v1/messages/count_tokens",
        {"x-api-key": _GATEWAY_KEY},
        lambda text: {
            "model": "claude-sonnet-4-6",
            "messages": [{"role": "user", "content": text}],
        },
    ),
    "gemini": (
        "/v1beta/models/gemini-3.5-flash:generateContent",
        {"x-goog-api-key": _GATEWAY_KEY},
        lambda text: {"contents": [{"role": "user", "parts": [{"text": text}]}]},
    ),
    "responses": (
        "/v1/responses",
        {"authorization": f"Bearer {_GATEWAY_KEY}"},
        lambda text: {"model": "gpt-5-nano", "input": text},
    ),
    "chat_stream": (
        "/v1/chat/completions",
        {"authorization": f"Bearer {_GATEWAY_KEY}"},
        lambda text: {
            "model": "gpt-5-nano",
            "stream": True,
            "messages": [{"role": "user", "content": text}],
        },
    ),
}


async def _send(
    actions: dict[str, str],
    route: str,
    payload: dict,
    *,
    usage=None,
    settings: dict[str, str] | None = None,
) -> tuple[httpx.Response, list[httpx.Request], list[dict]]:
    calls: list[httpx.Request] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json=_CHAT_REPLY)

    events = io.StringIO()
    path, headers = _ROUTES[route][:2]
    async with httpx.AsyncClient(transport=httpx.MockTransport(upstream)) as outbound:
        app = create_community_app(
            CommunitySettings(
                _env_file=None,
                SHIM_API_KEY=_GATEWAY_KEY,
                PII_ENTITY_ACTIONS=json.dumps(actions),
                **(settings or {}),
            ),
            http_client=outbound,
            event_stream=events,
        )
        async with app.router.lifespan_context(app):
            if usage is not None:
                app.state.gateway_service.kernel.usage = usage
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app), base_url="http://shim.test"
            ) as inbound:
                response = await inbound.post(
                    path,
                    headers={**headers, "x-provider-key": "provider-secret"},
                    json=payload,
                )
    return (
        response,
        calls,
        [json.loads(line) for line in events.getvalue().splitlines()],
    )


def _privacy_verdict(event: dict) -> tuple[str, str, str]:
    verdict = next(
        item for item in event["policy_verdicts"] if item["rule_id"] == "privacy.input"
    )
    return verdict["outcome"], verdict["reason_code"], verdict["policy_version"]


@pytest.mark.asyncio
@pytest.mark.parametrize("route", list(_ROUTES))
async def test_a_blocked_secret_stops_every_protocol_before_the_provider(route):
    build = _ROUTES[route][2]

    response, calls, events = await _send(
        {"SECRET": "block", "EMAIL_ADDRESS": "monitor"},
        route,
        build(f"Deploy with {_PASTED_KEY} for alice@example.com"),
    )

    body = response.json()
    assert response.status_code == 400
    assert calls == []
    assert response.headers["x-shim-error-code"] == "SECRET_BLOCKED"
    assert _PASTED_KEY not in response.text
    assert "alice@example.com" not in response.text
    message = "Request blocked by privacy policy: SECRET."
    if route in {"chat", "chat_stream", "responses"}:
        assert body["error"]["code"] == "SECRET_BLOCKED"
        assert body["error"]["message"] == message
    elif route == "gemini":
        assert body["error"]["code"] == 400
        assert body["error"]["message"] == message
        assert body["error"]["details"][0]["reason"] == "SECRET_BLOCKED"
    else:
        assert body["type"] == "error"
        assert body["error"]["code"] == "SECRET_BLOCKED"
        assert body["error"]["message"] == message
    [event] = events
    assert event["outcome"] == "rejected"
    assert (event["estimated_cost_usd"], event["estimated"]) == ("0", False)
    assert event["blocked_entities"] == {"SECRET": 1}
    assert event["monitored_entities"] == {"EMAIL_ADDRESS": 1}
    assert _privacy_verdict(event)[:2] == ("deny", "SECRET_BLOCKED")


_IDENTIFIER_ROUTES = {
    "chat": lambda name: {
        "model": "gpt-5-nano",
        "messages": [{"role": "user", "name": name, "content": "hi"}],
    },
    "chat_stream": lambda name: {
        "model": "gpt-5-nano",
        "stream": True,
        "messages": [{"role": "user", "name": name, "content": "hi"}],
    },
    "responses": lambda name: {
        "model": "gpt-5-nano",
        "input": [{"role": "user", "name": name, "content": "hi"}],
    },
}


@pytest.mark.asyncio
@pytest.mark.parametrize("route", list(_IDENTIFIER_ROUTES))
@pytest.mark.parametrize(
    ("actions", "name", "code", "entity_type"),
    [
        ({"SECRET": "block"}, _PASTED_KEY, "SECRET_BLOCKED", "SECRET"),
        (
            {"EMAIL_ADDRESS": "block"},
            "alice@example.com",
            "PII_BLOCKED",
            "EMAIL_ADDRESS",
        ),
    ],
)
async def test_a_blocked_type_in_a_protocol_identifier_uses_the_block_code(
    route, actions, name, code, entity_type
):
    response, calls, [event] = await _send(
        actions, route, _IDENTIFIER_ROUTES[route](name)
    )

    assert (response.status_code, calls) == (400, [])
    assert response.headers["x-shim-error-code"] == code
    assert response.json()["error"]["message"] == (
        f"Request blocked by privacy policy: {entity_type}."
    )
    assert name not in response.text
    assert event["outcome"] == "rejected"
    assert _privacy_verdict(event)[:2] == ("deny", code)


@pytest.mark.asyncio
async def test_a_block_records_privacy_counts_before_refusing():
    usage = AsyncMock()

    response, calls, _ = await _send(
        {"TR_NATIONAL_ID": "block", "EMAIL_ADDRESS": "monitor"},
        "chat",
        _ROUTES["chat"][2](
            "TCKN 10000000146, alice@example.com, IBAN TR33 0006 1005 1978 6457 8413 26"
        ),
        usage=usage,
    )

    assert response.status_code == 400
    assert response.headers["x-shim-error-code"] == "PII_BLOCKED"
    assert response.json()["error"]["message"] == (
        "Request blocked by privacy policy: TR_NATIONAL_ID."
    )
    assert calls == []
    privacy = usage.record_privacy.await_args.args[0].privacy
    assert dict(privacy.blocked_entities) == {"TR_NATIONAL_ID": 1}
    assert dict(privacy.monitored_entities) == {"EMAIL_ADDRESS": 1}
    assert dict(privacy.pii_entities) == {"IBAN_CODE": 1}
    assert privacy.monitored_values == {"alice@example.com"}
    assert "alice@example.com" not in repr(privacy)
    usage.reserve_provider_spend.assert_not_awaited()
    usage.mark_provider_started.assert_not_awaited()
    assert usage.fail.await_args.args[0].policy_verdicts[-1].outcome == "deny"


@pytest.mark.asyncio
async def test_a_blocked_count_tokens_is_rejected_without_a_count():
    usage = AsyncMock()

    response, calls, _ = await _send(
        {"SECRET": "block"},
        "count_tokens",
        _ROUTES["count_tokens"][2](f"key {_PASTED_KEY}"),
        usage=usage,
    )

    assert (response.status_code, calls) == (400, [])
    usage.record_token_count.assert_not_awaited()
    usage.record_privacy.assert_not_awaited()
    usage.reject.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("actions", "text", "verdict", "forwarded"),
    [
        ({}, "Email alice@example.com", ("mask", "PII_MASKED"), False),
        (
            {"EMAIL_ADDRESS": "monitor"},
            "Email alice@example.com",
            ("allow", "PII_MONITORED"),
            True,
        ),
        ({}, "Nothing private here", ("allow", "PII_NOT_DETECTED"), None),
        (
            {name: "off" for name in effective_entity_actions()},
            "Email alice@example.com",
            ("skip", "PII_DISABLED"),
            True,
        ),
    ],
)
async def test_the_privacy_verdict_says_what_happened(
    actions, text, verdict, forwarded
):
    response, calls, [event] = await _send(actions, "chat", _ROUTES["chat"][2](text))

    assert response.status_code == 200
    assert _privacy_verdict(event)[:2] == verdict
    if forwarded is not None:
        assert ("alice@example.com" in calls[0].content.decode()) is forwarded
    if verdict[1] == "PII_MONITORED":
        assert event["monitored_entities"] == {"EMAIL_ADDRESS": 1}
        assert event["privacy_counts"] == {}
        assert response.json()["choices"][0]["message"]["content"] == "ok"


@pytest.mark.asyncio
async def test_changing_an_action_changes_the_privacy_policy_version():
    payload = _ROUTES["chat"][2]("Nothing private here")

    *_, [masked] = await _send({}, "chat", payload)
    *_, [monitored] = await _send({"IBAN_CODE": "monitor"}, "chat", payload)

    assert _privacy_verdict(masked)[2] != _privacy_verdict(monitored)[2]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "message",
    [
        {"role": "user", "name": "alice@example.com", "content": "hi"},
        {
            "role": "user",
            "content": [
                {
                    "type": "image_url",
                    "image_url": {"url": "https://example.test/a.png"},
                }
            ],
        },
    ],
)
async def test_an_all_monitor_tenant_is_not_refused_for_media_or_identifiers(
    message,
):
    payload = {"model": "gpt-5-nano", "messages": [message]}
    monitor_all = {name: "monitor" for name in effective_entity_actions()}

    refused, refused_calls, _ = await _send({}, "chat", payload)
    sent, sent_calls, _ = await _send(monitor_all, "chat", payload)

    assert (refused.status_code, refused_calls) == (400, [])
    assert refused.headers["x-shim-error-code"] == "PRIVACY_POLICY_BLOCKED"
    assert sent.status_code == 200
    assert json.loads(sent_calls[0].content)["messages"] == [message]


@pytest.mark.asyncio
async def test_mask_last4_shows_the_tail_to_the_provider_and_counts_only_elsewhere():
    response, calls, events = await _send(
        {"CREDIT_CARD": "mask_last4"},
        "chat",
        _ROUTES["chat"][2]("Refund card 4111 1111 1111 1111 please"),
    )

    sent = json.loads(calls[0].content)["messages"][0]["content"]
    assert response.status_code == 200
    assert "4111 1111 1111 1111" not in sent
    assert sent.startswith("Refund card <CREDIT_CARD_") and "~1111> please" in sent
    [event] = events
    assert event["privacy_counts"] == {"CREDIT_CARD": 1}
    assert "~1111" not in json.dumps(event)


@pytest.mark.asyncio
async def test_stable_placeholders_repeat_across_requests_and_never_leave_the_scrubber(
    caplog: pytest.LogCaptureFixture,
):
    caplog.set_level("DEBUG")
    stable = {"PII_PLACEHOLDER_MODE": "stable", "PII_PLACEHOLDER_KEY": "k" * 32}
    payload = _ROUTES["chat"][2]("Write to alice@example.com")
    sent = []
    for settings in (stable, stable, {}):
        response, calls, events = await _send({}, "chat", payload, settings=settings)
        assert response.status_code == 200
        sent.append(json.loads(calls[0].content)["messages"][0]["content"])
        assert "k" * 32 not in json.dumps(events)

    assert sent[0] == sent[1] != sent[2]
    assert "alice@example.com" not in "".join(sent)
    assert "k" * 32 not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("threshold", "actions", "bulk", "status"),
    [
        ("3", {}, {"distinct_values": 3, "threshold": 3}, 200),
        ("4", {}, None, 200),
        ("0", {}, None, 200),
        ("3", {"EMAIL_ADDRESS": "block"}, {"distinct_values": 3, "threshold": 3}, 400),
    ],
)
async def test_a_bulk_disclosure_is_recorded_in_the_event_and_the_request_decides_alone(
    threshold, actions, bulk, status
):
    emails = "a@example.com, b@example.com, c@example.com, a@example.com"
    response, calls, events = await _send(
        actions,
        "chat",
        _ROUTES["chat"][2](f"Mail {emails}"),
        settings={"PII_BULK_THRESHOLD": threshold},
    )

    [event] = events
    assert response.status_code == status
    assert len(calls) == (1 if status == 200 else 0)
    assert event["bulk_disclosure"] == bulk
    assert ("privacy.bulk" in {v["rule_id"] for v in event["policy_verdicts"]}) is (
        bulk is not None
    )
    assert "a@example.com" not in json.dumps(event)


@pytest.mark.asyncio
async def test_community_hashes_the_system_prompt_only_with_a_key(
    caplog: pytest.LogCaptureFixture,
):
    caplog.set_level("DEBUG")
    key = {"SYSTEM_PROMPT_HASH_KEY": "h" * 32}

    def chat(system: str | None) -> dict:
        messages = [{"role": "user", "content": "Summarise"}]
        if system is not None:
            messages.insert(0, {"role": "system", "content": system})
        return {"model": "gpt-5-nano", "messages": messages}

    hashes = []
    for settings, system in (
        (key, "Be brief."),
        (key, "Be brief."),
        (key, "Be brief!"),
        (key, None),
        ({}, "Be brief."),
    ):
        response, _, events = await _send({}, "chat", chat(system), settings=settings)
        assert response.status_code == 200
        hashes.append(events[0]["system_prompt_hash"])

    assert hashes[0] is not None and hashes[0].startswith("hmac-sha256:v1:")
    assert hashes[0] == hashes[1] != hashes[2]
    assert hashes[3:] == [None, None]
    assert "h" * 32 not in caplog.text


# Tenant rules (S35): a resolver hands the app a rule set and a privacy-point stub
# records a match for every rule, as a kind's matcher will.

_RULE_REPLIES = {
    "/v1/chat/completions": _CHAT_REPLY,
    "/v1/responses": {
        "id": "resp_rules",
        "object": "response",
        "created_at": 1.0,
        "status": "completed",
        "model": "gpt-5-nano",
        "output": [],
        "parallel_tool_calls": True,
        "tool_choice": "auto",
        "tools": [],
        "usage": {
            "input_tokens": 1,
            "input_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
            "output_tokens": 1,
            "output_tokens_details": {"reasoning_tokens": 0},
            "total_tokens": 2,
        },
    },
    "/v1/messages": {
        "id": "msg_rules",
        "type": "message",
        "role": "assistant",
        "model": "claude-sonnet-4-6",
        "content": [{"type": "text", "text": "ok"}],
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 1, "output_tokens": 1},
    },
    "/v1/messages/count_tokens": {"input_tokens": 3},
    "/v1beta/models/gemini-3.5-flash:generateContent": {
        "candidates": [
            {
                "content": {"role": "model", "parts": [{"text": "ok"}]},
                "finishReason": "STOP",
            }
        ],
        "usageMetadata": {
            "promptTokenCount": 1,
            "candidatesTokenCount": 1,
            "totalTokenCount": 2,
        },
    },
}


class _RulesResolver:
    def __init__(self, inner, rules) -> None:
        self.inner = inner
        self.rules = rules

    async def resolve(self, principal):
        policy = await self.inner.resolve(principal)
        return policy.model_copy(update={"rules": self.rules})


def _rule_set(*rules: tuple[str, str, str]):
    from shim.rules import Rule, RuleSet

    # A kind with no matcher yet, so only the stub below records its matches.
    return RuleSet(
        revision=4,
        rules=tuple(
            Rule(id=rule_id, name="n", kind="record_set", action=action, state=state)
            for rule_id, action, state in rules
        ),
    )


def _matching_privacy(monkeypatch) -> None:
    import shim.gateway.pipeline.privacy as privacy

    original = privacy.PrivacyStage.run

    async def run(self, value):
        prepared = await original(self, value)
        for rule in prepared.rules.rules if prepared.rules else ():
            if rule.kind == "record_set":
                prepared.record_rule_match(rule, 2)
        return prepared

    monkeypatch.setattr(privacy.PrivacyStage, "run", run)


async def _call_with_rules(
    monkeypatch,
    rules,
    route: str,
    *,
    text="hello",
    gate=None,
    headers=None,
    settings=None,
):
    _matching_privacy(monkeypatch)
    calls: list[httpx.Request] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if json.loads(request.content).get("stream"):
            chunk = {
                **_CHAT_REPLY,
                "object": "chat.completion.chunk",
                "choices": [
                    {"index": 0, "delta": {"content": "ok"}, "finish_reason": "stop"}
                ],
            }
            return httpx.Response(
                200,
                text=f"data: {json.dumps(chunk)}\n\ndata: [DONE]\n\n",
                headers={"content-type": "text/event-stream"},
            )
        return httpx.Response(200, json=_RULE_REPLIES[request.url.path])

    events = io.StringIO()
    path, auth, build = _ROUTES[route]
    async with httpx.AsyncClient(transport=httpx.MockTransport(upstream)) as outbound:
        app = create_community_app(
            CommunitySettings(
                _env_file=None, SHIM_API_KEY=_GATEWAY_KEY, **(settings or {})
            ),
            http_client=outbound,
            event_stream=events,
        )
        async with app.router.lifespan_context(app):
            kernel = app.state.gateway_service.kernel
            kernel.policy_resolver = _RulesResolver(kernel.policy_resolver, rules)
            kernel.approval_gate = gate
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app), base_url="http://shim.test"
            ) as inbound:
                response = await inbound.post(
                    path,
                    headers={
                        **auth,
                        "x-provider-key": "provider-secret",
                        **(headers or {}),
                    },
                    json=build(text),
                )
    return (
        response,
        calls,
        [json.loads(line) for line in events.getvalue().splitlines()],
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("route", list(_ROUTES))
async def test_an_enforced_block_refuses_before_any_provider_call(
    monkeypatch, route
) -> None:
    rules = _rule_set(("zeta", "block", "enforced"), ("alpha", "block", "enforced"))

    response, calls, lines = await _call_with_rules(monkeypatch, rules, route)

    assert response.status_code == 400
    assert response.headers["x-shim-error-code"] == "RULE_BLOCKED"
    assert response.headers["x-shim-rule-id"] == "alpha"
    assert calls == []
    if route in {"chat", "responses"}:
        assert response.json()["error"]["param"] == "alpha"
        assert (
            response.json()["error"]["message"]
            == "Request blocked by tenant rule alpha."
        )
    [line] = lines
    verdicts = {
        v["rule_id"]: (v["outcome"], v["reason_code"]) for v in line["policy_verdicts"]
    }
    assert verdicts["rule.alpha"] == ("deny", "RULE_BLOCKED")
    assert verdicts["rules.evaluated"] == ("allow", "RULES_EVALUATED")
    assert [match["rule_id"] for match in line["rule_matches"]] == ["alpha", "zeta"]
    assert line["rule_matches"][0] == {
        "rule_id": "alpha",
        "kind": "record_set",
        "action": "block",
        "state": "enforced",
        "count": 2,
    }
    assert line["rule_matches_truncated"] is False


@pytest.mark.asyncio
async def test_the_base_privacy_block_wins_over_a_rule_block(monkeypatch) -> None:
    response, calls, _ = await _call_with_rules(
        monkeypatch,
        _rule_set(("alpha", "block", "enforced")),
        "chat",
        text=f"Deploy with {_PASTED_KEY}",
        settings={"PII_ENTITY_ACTIONS": json.dumps({"SECRET": "block"})},
    )

    assert response.headers["x-shim-error-code"] == "SECRET_BLOCKED"
    assert "x-shim-rule-id" not in response.headers and calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("route", ["chat", "chat_stream"])
async def test_an_enforced_warn_adds_rule_warn_and_changes_nothing_else(
    monkeypatch, route
) -> None:
    rules = _rule_set(("careful", "warn", "enforced"), ("watch", "block", "monitor"))

    response, calls, lines = await _call_with_rules(monkeypatch, rules, route)

    assert response.status_code == 200 and len(calls) == 1
    assert response.headers["x-shim-warnings"] == "RULE_WARN"
    [line] = lines
    verdicts = {v["rule_id"]: v["reason_code"] for v in line["policy_verdicts"]}
    assert verdicts["rule.careful"] == "RULE_WARN"
    assert verdicts["rule.watch"] == "RULE_WOULD_BLOCK"
    assert line["warnings"] == ["RULE_WARN"]


class _Gate:
    def __init__(
        self, outcome=None, approval_id="apr_0123456789abcdef", fails=False
    ) -> None:
        self.outcome = outcome
        self.approval_id = approval_id
        self.fails = fails
        self.requests = []

    async def check(self, prepared, request):
        from shim.rules.approval import ApprovalDecision

        self.requests.append(request)
        if self.fails:
            raise ConnectionError("approval store at private-host down")
        return ApprovalDecision(
            self.outcome, None if self.outcome == "queue_full" else self.approval_id
        )


@pytest.mark.asyncio
async def test_without_rules_no_rule_key_or_verdict_is_written(monkeypatch) -> None:
    response, calls, lines = await _call_with_rules(monkeypatch, None, "chat")

    assert response.status_code == 200 and len(calls) == 1
    [line] = lines
    assert "rule_matches" not in line
    assert not any(v["stage"] == "rules" for v in line["policy_verdicts"])


@pytest.mark.asyncio
@pytest.mark.parametrize("rules", [None, _rule_set(("careful", "warn", "enforced"))])
async def test_without_an_approval_rule_the_gate_and_its_header_are_not_used(
    monkeypatch, rules
) -> None:
    gate = _Gate("rejected")

    response, calls, _ = await _call_with_rules(
        monkeypatch, rules, "chat", gate=gate, headers={"x-shim-approval-id": "apr_x"}
    )

    assert response.status_code == 200 and len(calls) == 1 and gate.requests == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("outcome", "status", "code"),
    [
        ("approved", 200, None),
        ("required", 403, "APPROVAL_REQUIRED"),
        ("rejected", 403, "APPROVAL_REJECTED"),
        ("queue_full", 403, "APPROVAL_QUEUE_FULL"),
    ],
)
@pytest.mark.parametrize("route", ["chat", "responses", "messages", "gemini"])
async def test_the_approval_gate_decides_a_held_request(
    monkeypatch, outcome, status, code, route
) -> None:
    gate = _Gate(outcome)
    rules = _rule_set(("needs_review", "require_approval", "enforced"))

    response, calls, lines = await _call_with_rules(
        monkeypatch, rules, route, gate=gate, headers={"x-shim-approval-id": " apr_x "}
    )

    assert response.status_code == status
    [request] = gate.requests
    assert request.rule_ids == ("needs_review",) and request.presented_id == "apr_x"
    assert "hello" in json.dumps(request.admitted_payload)
    verdicts = {
        v["rule_id"]: (v["outcome"], v["reason_code"])
        for v in lines[0]["policy_verdicts"]
    }
    if outcome == "approved":
        assert len(calls) == 1
        assert verdicts["rule.needs_review"] == ("allow", "RULE_APPROVED")
        return
    assert calls == []
    assert response.headers["x-shim-error-code"] == code
    assert response.headers["x-shim-rule-id"] == "needs_review"
    assert response.headers["x-should-retry"] == "false"
    assert verdicts["rule.needs_review"] == ("deny", code)
    if outcome == "queue_full":
        assert "x-shim-approval-id" not in response.headers
    else:
        assert response.headers["x-shim-approval-id"] == "apr_0123456789abcdef"
        if route in {"chat", "responses"}:
            assert response.json()["error"]["param"] == "apr_0123456789abcdef"


@pytest.mark.asyncio
async def test_a_held_stream_is_refused_before_its_first_byte(monkeypatch) -> None:
    response, calls, _ = await _call_with_rules(
        monkeypatch,
        _rule_set(("needs_review", "require_approval", "enforced")),
        "chat_stream",
        gate=_Gate("required"),
    )

    assert response.status_code == 403 and calls == []
    assert response.headers["content-type"] == "application/json"


@pytest.mark.asyncio
async def test_token_counting_never_calls_the_gate(monkeypatch) -> None:
    gate = _Gate("approved")

    response, calls, _ = await _call_with_rules(
        monkeypatch,
        _rule_set(("needs_review", "require_approval", "enforced")),
        "count_tokens",
        gate=gate,
    )

    assert response.status_code == 403 and calls == [] and gate.requests == []
    assert response.headers["x-shim-error-code"] == "APPROVAL_REQUIRED"
    assert "x-shim-approval-id" not in response.headers


@pytest.mark.asyncio
async def test_a_block_wins_over_approval_and_a_failing_gate_fails_closed(
    monkeypatch, caplog
) -> None:
    blocked, block_calls, _ = await _call_with_rules(
        monkeypatch,
        _rule_set(
            ("held", "require_approval", "enforced"), ("stop", "block", "enforced")
        ),
        "chat",
        gate=(gate := _Gate("approved")),
    )
    failing, fail_calls, lines = await _call_with_rules(
        monkeypatch,
        _rule_set(("held", "require_approval", "enforced")),
        "chat",
        gate=_Gate(fails=True),
    )
    no_gate, no_gate_calls, _ = await _call_with_rules(
        monkeypatch, _rule_set(("held", "require_approval", "enforced")), "chat"
    )

    assert (
        blocked.headers["x-shim-error-code"],
        blocked.headers["x-shim-rule-id"],
    ) == (
        "RULE_BLOCKED",
        "stop",
    )
    assert gate.requests == [] and block_calls == []
    assert failing.status_code == 503 and fail_calls == []
    assert failing.headers["x-shim-error-code"] == "APPROVAL_UNAVAILABLE"
    assert failing.headers["retry-after"] == "5"
    assert "private-host" not in caplog.text
    verdicts = {
        v["rule_id"]: (v["outcome"], v["reason_code"])
        for v in lines[0]["policy_verdicts"]
    }
    assert verdicts["rule.held"] == ("error", "APPROVAL_UNAVAILABLE")
    assert (no_gate.status_code, no_gate.headers["x-shim-error-code"]) == (
        400,
        "RULE_BLOCKED",
    )
    assert no_gate_calls == []


@pytest.mark.asyncio
async def test_the_gate_sees_the_admitted_payload_and_the_provider_the_masked_one(
    monkeypatch,
) -> None:
    gate = _Gate("approved")

    response, calls, _ = await _call_with_rules(
        monkeypatch,
        _rule_set(("needs_review", "require_approval", "enforced")),
        "chat",
        text="Email alice@example.com",
        gate=gate,
    )

    assert response.status_code == 200
    [request] = gate.requests
    assert "alice@example.com" in json.dumps(request.admitted_payload)
    [sent] = calls
    assert "alice@example.com" not in sent.content.decode()


def _term_rules(action: str = "mask", **values):
    from shim.rules import validate_rule_set

    rule = {
        "id": "projects",
        "name": "Projects",
        "kind": "term",
        "action": action,
        "state": "enforced",
        "match": {"terms": ["Atlas"]},
        **values,
    }
    return validate_rule_set({"revision": 1, "rules": [rule]})


_EVERY_SWITCH_OFF = {
    "PII_ENTITY_ACTIONS": json.dumps(
        dict.fromkeys(
            [
                "CREDIT_CARD",
                "DB_URI",
                "EMAIL_ADDRESS",
                "FILE_PATH",
                "IBAN_CODE",
                "IP_ADDRESS",
                "MAC_ADDRESS",
                "PHONE_NUMBER",
                "SECRET",
                "TR_LICENSE_PLATE",
                "TR_NATIONAL_ID",
                "TR_VKN",
                "US_SSN",
            ],
            "off",
        )
    )
}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "route", ["chat", "responses", "messages", "gemini", "count_tokens"]
)
async def test_an_enforced_term_is_masked_with_every_switch_off(
    monkeypatch, route
) -> None:
    response, calls, lines = await _call_with_rules(
        monkeypatch,
        _term_rules(),
        route,
        text="Atlas'ın raporu",
        settings=_EVERY_SWITCH_OFF,
    )

    assert response.status_code == 200
    [sent] = calls
    body = json.dumps(json.loads(sent.content), ensure_ascii=False)
    assert "Atlas" not in body and "<TERM_" in body and "'ın raporu" in body
    if route != "count_tokens":
        [line] = lines
        assert line["rule_matches"] == [
            {
                "rule_id": "projects",
                "kind": "term",
                "action": "mask",
                "state": "enforced",
                "count": 1,
            }
        ]


@pytest.mark.asyncio
@pytest.mark.parametrize("route", ["chat", "count_tokens", "gemini"])
async def test_an_enforced_term_block_refuses_before_the_provider(
    monkeypatch, route
) -> None:
    response, calls, _ = await _call_with_rules(
        monkeypatch, _term_rules("block"), route, text="Atlas'ın raporu"
    )

    assert (response.status_code, response.headers["x-shim-rule-id"]) == (
        400,
        "projects",
    )
    assert response.headers["x-shim-error-code"] == "RULE_BLOCKED" and calls == []


@pytest.mark.asyncio
async def test_a_term_rule_scoped_to_another_model_changes_nothing(monkeypatch) -> None:
    response, calls, lines = await _call_with_rules(
        monkeypatch,
        _term_rules("block", scope={"models": ["some-other-model"]}),
        "chat",
        text="Atlas'ın raporu",
    )

    assert response.status_code == 200
    [sent] = calls
    assert "Atlas'ın raporu" in sent.content.decode()
    [line] = lines
    assert line["rule_matches"] == []
