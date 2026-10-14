"""The semantic call through the real kernel, resolver and ledger."""

from __future__ import annotations

import json
import logging

import httpx
import pytest
from sqlalchemy import select

from ee.tests.tenants.test_deployments import (  # noqa: F401
    _deployments,
    _gateway,
    db,
    origins,
    test_org,
)
from shim_enterprise.billing.models import RequestLifecycle
from shim_enterprise.semantic.call import (
    MAX_TEXT_CHARACTERS,
    REVIEW_TAG,
    request_text,
    run_semantic_call,
    semantic_payload,
)

pytestmark = pytest.mark.usefixtures("origins")
QUESTIONS = [
    {"id": "atlas", "text": "The request discusses Project Atlas.", "examples": []},
    {"id": "payroll", "text": "The request discusses salaries.", "examples": ["maaş"]},
]
SECRET_ANSWER = "the model's own words that must never be stored"


@pytest.mark.parametrize(
    ("payload", "protocol", "text"),
    [
        (
            {
                "messages": [
                    {"role": "system", "content": "be brief"},
                    {"role": "user", "content": [{"type": "text", "text": "hello"}]},
                ],
                "tools": [{"type": "function", "function": {"name": "secret_tool"}}],
            },
            "chat",
            "be brief\nhello",
        ),
        (
            {
                "instructions": "be brief",
                "input": [
                    {"role": "user", "content": [{"type": "input_text", "text": "hi"}]}
                ],
            },
            "responses",
            "be brief\nhi",
        ),
        (
            {
                "system": "be brief",
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": "a"},
                            {"type": "image", "source": {"data": "AAAA"}},
                            {"type": "tool_result", "content": "b"},
                        ],
                    }
                ],
            },
            "messages",
            "be brief\na\nb",
        ),
        (
            {
                "systemInstruction": {"parts": [{"text": "be brief"}]},
                "contents": [{"role": "user", "parts": [{"text": "merhaba"}]}],
            },
            "generate_content",
            "be brief\nmerhaba",
        ),
    ],
)
def test_request_text_takes_the_text_in_document_order(payload, protocol, text) -> None:
    assert request_text(payload, protocol) == text


def test_request_text_is_cut_at_the_bound() -> None:
    payload = {"messages": [{"role": "user", "content": "x" * 30_000}]}

    assert len(request_text(payload, "chat")) == MAX_TEXT_CHARACTERS


def test_each_provider_gets_its_own_bounded_payload() -> None:
    openai = semantic_payload("openai", "denetci", "text", QUESTIONS)
    anthropic = semantic_payload("anthropic", "denetci", "text", QUESTIONS)
    google = semantic_payload("google", "denetci", "text", QUESTIONS)

    assert "max_tokens" not in openai and "max_completion_tokens" not in openai
    assert openai["response_format"]["json_schema"]["strict"] is True
    enum = openai["response_format"]["json_schema"]["schema"]["properties"]["matches"][
        "items"
    ]["properties"]["question_id"]["enum"]
    assert enum == ["atlas", "payroll"]
    assert (anthropic["max_tokens"], anthropic["temperature"]) == (1024, 0)
    assert google["generationConfig"]["maxOutputTokens"] == 1024
    assert "<<<REQUEST\ntext\nREQUEST>>>" in openai["messages"][1]["content"]
    assert "examples: maaş" in openai["messages"][1]["content"]


def _upstream(content: str | None, status: int = 200):
    def handler(request):
        if status != 200:
            return httpx.Response(status, json={"error": {"message": "down"}})
        body = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "id": "chat-1",
                "object": "chat.completion",
                "created": 1,
                "model": body["model"],
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": content},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 40,
                    "completion_tokens": 10,
                    "total_tokens": 50,
                },
            },
        )

    return handler


def _answer(*pairs: tuple[str, bool]) -> str:
    return json.dumps(
        {"matches": [{"question_id": qid, "match": match} for qid, match in pairs]}
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("content", "status", "outcome", "matched", "code"),
    [
        (
            _answer(("atlas", True), ("payroll", False)),
            200,
            "matched",
            ("atlas",),
            None,
        ),
        (_answer(("atlas", False), ("payroll", False)), 200, "clear", (), None),
        (_answer(("atlas", True)), 200, "invalid_answer", (), None),
        (_answer(("atlas", True), ("atlas", True)), 200, "invalid_answer", (), None),
        (_answer(("atlas", True), ("unknown", True)), 200, "invalid_answer", (), None),
        (SECRET_ANSWER, 200, "invalid_answer", (), None),
        (None, 503, "failed", (), "PROVIDER_UNAVAILABLE"),
    ],
)
async def test_the_answer_is_checked_and_the_call_is_its_own_request(
    db,  # noqa: F811
    test_api_key,
    caplog,
    content,
    status,
    outcome,
    matched,
    code,
) -> None:
    await _deployments(db, test_api_key)
    caplog.set_level(logging.DEBUG)

    async with _gateway(db, test_api_key, _upstream(content, status)) as (_, app, _):
        result = await run_semantic_call(
            app.state.gateway_service.kernel,
            api_key_id=test_api_key.id,
            alias="internal-a",
            provider="openai",
            text="the deal we are running",
            questions=QUESTIONS,
            tag=REVIEW_TAG,
        )

    assert (result.outcome, result.matched_ids, result.error_code) == (
        outcome,
        matched,
        code,
    )
    assert result.request_id is not None
    row = await db.scalar(
        select(RequestLifecycle).where(RequestLifecycle.request_id == result.request_id)
    )
    assert row is not None
    assert REVIEW_TAG in row.lifecycle_metadata["tags"]
    assert SECRET_ANSWER not in caplog.text


@pytest.mark.asyncio
async def test_an_inactive_key_fails_with_its_code(db, test_api_key) -> None:  # noqa: F811
    await _deployments(db, test_api_key)
    test_api_key.is_active = False

    async with _gateway(db, test_api_key, _upstream("{}")) as (_, app, _):
        result = await run_semantic_call(
            app.state.gateway_service.kernel,
            api_key_id=test_api_key.id,
            alias="internal-a",
            provider="openai",
            text="anything",
            questions=QUESTIONS,
            tag=REVIEW_TAG,
        )

    assert (result.outcome, result.error_code) == ("failed", "INVALID_API_KEY")
