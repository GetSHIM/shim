from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

from fastapi import HTTPException, Response
import pytest
from pydantic import ValidationError
from sqlalchemy.dialects import postgresql

from shim_enterprise.shared_results.api import (
    SHARE_MAX_VIEWS,
    SharedResultCreate,
    create_shared_result,
    view_shared_result,
)


@pytest.mark.asyncio
async def test_create_always_scrubs_public_fields_and_persists_only_token_hash() -> (
    None
):
    tenant_opt_out = SimpleNamespace(
        block_email=False,
        block_phone=False,
        block_credit_card=False,
        block_secrets=False,
        block_pii_tr=False,
    )
    session = SimpleNamespace(
        execute=AsyncMock(
            return_value=SimpleNamespace(scalar_one_or_none=lambda: tenant_opt_out)
        ),
        add=Mock(),
        commit=AsyncMock(),
    )
    api_key = SimpleNamespace(organization_id=uuid4())
    response = Response()

    created = await create_shared_result(
        SharedResultCreate(
            prompt=(
                "Email alice@example.com, phone +90 532 123 45 67, "
                "card 4111 1111 1111 1111"
            ),
            response='TCKN 10000000146 and {"password": "SuperSecret123!"}',
        ),
        response,
        api_key,
        session,
    )

    stored = session.add.call_args.args[0]
    session.execute.assert_not_awaited()
    public_text = f"{stored.prompt} {stored.response}"
    for sensitive_value in (
        "alice@example.com",
        "+90 532 123 45 67",
        "4111 1111 1111 1111",
        "10000000146",
        "SuperSecret123!",
    ):
        assert sensitive_value not in public_text
    assert stored.token_hash == hashlib.sha256(created.token.encode()).hexdigest()
    assert created.token not in stored.token_hash
    assert created.max_views == stored.max_views == SHARE_MAX_VIEWS
    assert response.headers["Cache-Control"] == "no-store"
    session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_create_retokenizes_the_same_pii_for_each_share() -> None:
    session = SimpleNamespace(add=Mock(), commit=AsyncMock())
    api_key = SimpleNamespace(organization_id=uuid4())
    payload = SharedResultCreate(
        prompt="Email alice@example.com",
        response="Contact alice@example.com",
    )

    await create_shared_result(payload, Response(), api_key, session)
    first = session.add.call_args.args[0]
    session.add.reset_mock()
    await create_shared_result(payload, Response(), api_key, session)
    second = session.add.call_args.args[0]

    assert first.prompt != second.prompt
    assert first.response != second.response
    assert first.prompt.removeprefix("Email ") == first.response.removeprefix(
        "Contact "
    )
    assert second.prompt.removeprefix("Email ") == second.response.removeprefix(
        "Contact "
    )
    assert "alice@example.com" not in first.prompt + first.response
    assert "alice@example.com" not in second.prompt + second.response


@pytest.mark.asyncio
async def test_public_read_atomically_increments_and_returns_safe_fields() -> None:
    token = "A" * 43
    now = datetime.now(timezone.utc)
    row = SimpleNamespace(
        prompt="safe prompt",
        response="safe response",
        created_at=now,
        expires_at=now + timedelta(hours=1),
        view_count=1,
        max_views=25,
    )
    result = SimpleNamespace(scalar_one_or_none=lambda: row)
    session = SimpleNamespace(
        execute=AsyncMock(return_value=result),
        commit=AsyncMock(),
    )
    response = Response()

    viewed = await view_shared_result(token, response, session)

    statement = session.execute.await_args.args[0]
    compiled = statement.compile(dialect=postgresql.dialect())
    sql = str(compiled)
    assert "UPDATE shared_results" in sql
    assert "shared_results.token_hash =" in sql
    assert "shared_results.expires_at >" in sql
    assert "shared_results.view_count < shared_results.max_views" in sql
    assert "view_count=(shared_results.view_count +" in sql
    assert "RETURNING shared_results.id" in sql
    assert token not in compiled.params.values()
    assert hashlib.sha256(token.encode()).hexdigest() in compiled.params.values()
    assert viewed.model_dump() == {
        "prompt": "safe prompt",
        "response": "safe response",
        "created_at": now,
        "expires_at": row.expires_at,
        "view_count": 1,
        "max_views": 25,
    }
    assert response.headers["Cache-Control"] == "no-store"
    session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_public_read_uses_the_same_404_for_invalid_and_missing_tokens() -> None:
    session = SimpleNamespace(
        execute=AsyncMock(
            return_value=SimpleNamespace(scalar_one_or_none=lambda: None)
        ),
        commit=AsyncMock(),
    )

    with pytest.raises(HTTPException) as invalid:
        await view_shared_result("invalid!", Response(), session)
    with pytest.raises(HTTPException) as missing:
        await view_shared_result("A" * 43, Response(), session)

    assert (invalid.value.status_code, invalid.value.detail) == (404, "Not found.")
    assert (missing.value.status_code, missing.value.detail) == (404, "Not found.")
    assert (
        invalid.value.headers == missing.value.headers == {"Cache-Control": "no-store"}
    )
    session.commit.assert_not_awaited()


@pytest.mark.parametrize(
    "payload",
    [
        {"prompt": " ", "response": "ok"},
        {"prompt": "ok", "response": "\n"},
        {"prompt": "p" * 4_001, "response": "ok"},
        {"prompt": "ok", "response": "r" * 12_001},
        {"prompt": "ok", "response": "ok", "raw_secret": "no"},
    ],
)
def test_create_rejects_unbounded_blank_or_extra_input(payload: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        SharedResultCreate.model_validate(payload)
