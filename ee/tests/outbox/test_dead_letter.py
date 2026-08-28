from datetime import datetime, timezone

from shim_enterprise.outbox.dead_letter import (
    failure_status,
    next_retry_at,
    sanitize_failure,
)


def test_failure_policy_moves_the_last_attempt_to_dead_letter() -> None:
    assert failure_status(4, 5) == "failed"
    assert failure_status(5, 5) == "dead_letter"


def test_retry_policy_uses_bounded_exponential_delay() -> None:
    now = datetime(2026, 7, 12, tzinfo=timezone.utc)

    assert (next_retry_at(now, 4) - now).total_seconds() == 8
    assert (next_retry_at(now, 20, maximum_seconds=60) - now).total_seconds() == 60


def test_failure_text_redacts_credentials() -> None:
    error = RuntimeError("authorization=secret-value bearer abc.def api_key=visible")

    sanitized = sanitize_failure(error)

    assert "secret-value" not in sanitized
    assert "abc.def" not in sanitized
    assert "visible" not in sanitized
