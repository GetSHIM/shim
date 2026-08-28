"""Pure retry and failure-recording policy for outbox delivery."""

from __future__ import annotations

from datetime import datetime, timedelta
import re
from typing import Literal


FailureStatus = Literal["failed", "dead_letter"]
_ERROR_LIMIT = 1_000
_SECRET_PATTERNS = (
    re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]+"),
    re.compile(
        r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization)\b"
        r"\s*[\"']?\s*[:=]\s*[\"']?([^\s,;}\"']+)"
    ),
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"),
)


def failure_status(attempt_count: int, max_attempts: int) -> FailureStatus:
    if attempt_count < 1 or max_attempts < 1:
        raise ValueError("outbox attempt counts must be positive")
    return "dead_letter" if attempt_count >= max_attempts else "failed"


def next_retry_at(
    now: datetime,
    attempt_count: int,
    *,
    base_seconds: int = 1,
    maximum_seconds: int = 3_600,
) -> datetime:
    if attempt_count < 1 or base_seconds < 1 or maximum_seconds < 1:
        raise ValueError("retry bounds must be positive")
    delay = min(maximum_seconds, base_seconds * (2 ** (attempt_count - 1)))
    return now + timedelta(seconds=delay)


def sanitize_failure(error: BaseException) -> str:
    value = " ".join(f"{type(error).__name__}: {error}".split())
    for pattern in _SECRET_PATTERNS:
        value = pattern.sub(_redaction, value)
    return value[:_ERROR_LIMIT]


def _redaction(match: re.Match[str]) -> str:
    if match.lastindex and match.lastindex > 1:
        return f"{match.group(1)}=[REDACTED]"
    return "[REDACTED]"
