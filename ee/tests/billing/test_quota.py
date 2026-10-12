from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from sqlalchemy import select

from shim_enterprise.billing.ledger import (
    AccountingConflictError,
    DurableAccountingRepository,
    QuotaLimitExceeded,
    QuotaPolicySnapshot,
    QuotaReservationCommand,
)
from shim_enterprise.billing.models import QuotaPeriodUsage, RequestLifecycle
from shim_enterprise.billing.quota import BurstRateLimiter


@pytest.mark.asyncio
async def test_burst_window_passes_the_limit_to_the_atomic_script() -> None:
    redis = SimpleNamespace(eval=AsyncMock(return_value=1))
    limiter = BurstRateLimiter(SimpleNamespace(redis=redis))

    allowed = await limiter.allow("tenant:key", limit=3, window_seconds=60, amount=2)

    assert allowed is True
    arguments = redis.eval.await_args.args
    assert arguments[1:] == (1, "burst:tenant:key", 2, 60, 3)


@pytest.mark.asyncio
async def test_burst_window_reads_a_refusal_from_the_script() -> None:
    redis = SimpleNamespace(eval=AsyncMock(return_value=0))
    limiter = BurstRateLimiter(SimpleNamespace(redis=redis))

    assert await limiter.allow("key", limit=10, window_seconds=60) is False


@pytest.mark.asyncio
async def test_burst_window_fails_open_when_the_script_fails() -> None:
    redis = SimpleNamespace(eval=AsyncMock(side_effect=ConnectionError("down")))
    limiter = BurstRateLimiter(SimpleNamespace(redis=redis))

    assert await limiter.allow("key", limit=10, window_seconds=60) is True


@pytest.mark.asyncio
async def test_burst_window_fails_open_when_redis_is_unavailable() -> None:
    limiter = BurstRateLimiter(SimpleNamespace(redis=None))

    assert await limiter.allow("key", limit=10, window_seconds=60) is True


@pytest.mark.asyncio
async def test_invalid_counter_amount_is_rejected() -> None:
    limiter = BurstRateLimiter(SimpleNamespace(redis=None))

    with pytest.raises(ValueError, match="must be positive"):
        await limiter.allow("key", limit=10, window_seconds=60, amount=0)


# One start for every command, so a replay names the same request.
_NOW = datetime.now(timezone.utc)


def _command(test_api_key, request_id: str, policy, **values):

    return QuotaReservationCommand(
        tenant_id=test_api_key.organization_id,
        api_key_id=test_api_key.id,
        request_id=request_id,
        requested_model="gpt-5-nano",
        source_endpoint="chat.completions",
        started_at=_NOW,
        reconciliation_due_at=_NOW + timedelta(minutes=2),
        estimated_input_tokens=3,
        maximum_output_tokens=7,
        policy=policy,
        **values,
    )


async def _counters(db, organization_id) -> dict[str, tuple[int, int]]:

    rows = await db.scalars(
        select(QuotaPeriodUsage)
        .where(QuotaPeriodUsage.organization_id == organization_id)
        .execution_options(populate_existing=True)
    )
    return {
        row.period_type: (row.reserved_requests, row.reserved_tokens) for row in rows
    }


@pytest.mark.asyncio
async def test_an_extra_attempt_reserves_tokens_and_no_request_unit(
    db, test_api_key
) -> None:

    repository = DurableAccountingRepository()
    policy = QuotaPolicySnapshot("limits", 5, 50, 1_000)
    first = f"req_{uuid4().hex}"
    second = f"req_{uuid4().hex}"

    await repository.reserve_quota(db, _command(test_api_key, first, policy))
    after_first = await _counters(db, test_api_key.organization_id)
    await repository.reserve_quota(
        db,
        _command(
            test_api_key,
            second,
            policy,
            request_delta=0,
            attempt_group_id=first,
            attempt_number=2,
            attempt_reason="fallback",
            attempt_rule_id="fallback_rule",
        ),
    )

    assert after_first == {"daily": (1, 0), "monthly": (1, 10)}
    assert await _counters(db, test_api_key.organization_id) == {
        "daily": (1, 0),
        "monthly": (1, 20),
    }
    metadata = await db.scalar(
        select(RequestLifecycle.lifecycle_metadata).where(
            RequestLifecycle.request_id == second
        )
    )
    first_metadata = await db.scalar(
        select(RequestLifecycle.lifecycle_metadata).where(
            RequestLifecycle.request_id == first
        )
    )
    assert {key: metadata[key] for key in metadata if key.startswith("attempt_")} == {
        "attempt_group_id": first,
        "attempt_number": 2,
        "attempt_reason": "fallback",
        "attempt_rule_id": "fallback_rule",
    }
    assert not any(key.startswith("attempt_") for key in first_metadata)


@pytest.mark.asyncio
async def test_a_request_limit_of_zero_still_admits_an_extra_attempt(
    db, test_api_key
) -> None:

    repository = DurableAccountingRepository()
    closed = QuotaPolicySnapshot("closed", 0, 0, None)

    with pytest.raises(QuotaLimitExceeded):
        await repository.reserve_quota(
            db, _command(test_api_key, f"req_{uuid4().hex}", closed)
        )
    await repository.reserve_quota(
        db,
        _command(
            test_api_key,
            f"req_{uuid4().hex}",
            closed,
            request_delta=0,
            attempt_group_id="req_first",
            attempt_number=2,
            attempt_reason="fallback",
            attempt_rule_id="r",
        ),
    )

    assert await _counters(db, test_api_key.organization_id) == {
        "daily": (0, 0),
        "monthly": (0, 10),
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(("stored", "replayed"), [(0, 1), (1, 0)])
async def test_a_replay_must_name_the_same_request_count(
    db, test_api_key, stored, replayed
) -> None:

    repository = DurableAccountingRepository()
    policy = QuotaPolicySnapshot("open", None, None, None)
    request_id = f"req_{uuid4().hex}"
    await repository.reserve_quota(
        db, _command(test_api_key, request_id, policy, request_delta=stored)
    )

    same = await repository.reserve_quota(
        db, _command(test_api_key, request_id, policy, request_delta=stored)
    )
    with pytest.raises(AccountingConflictError):
        await repository.reserve_quota(
            db, _command(test_api_key, request_id, policy, request_delta=replayed)
        )

    assert same.replayed
