"""Pure retention-window and poller-health evaluation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal


DEFAULT_UNHEALTHY_MULTIPLE = 3
RETENTION_RISK = "retention_risk"
POLLER_UNHEALTHY = "poller_unhealthy"
RETENTION_GAP = "retention_gap"
SECONDS_PER_DAY = 86_400
AUTH_ERROR = "auth_error"
HealthKind = Literal[
    "retention_risk",
    "poller_unhealthy",
    "retention_gap",
    "auth_error",
]


@dataclass(frozen=True, slots=True)
class HealthAlert:
    stream: str
    kind: HealthKind
    message: str
    lag_seconds: float | None = None


def retention_budget_days(retention_days: int, lag_seconds: float) -> float:
    if retention_days <= 0 or lag_seconds < 0:
        raise ValueError("retention and lag values must be non-negative")
    return retention_days - lag_seconds / SECONDS_PER_DAY


def stream_lag_seconds(
    last_end_time: datetime | None,
    now: datetime,
) -> float | None:
    if last_end_time is None:
        return None
    return max(0.0, (now - last_end_time).total_seconds())


def evaluate_stream_health(
    streams: list[Mapping[str, Any]],
    *,
    retention_days: int,
    risk_threshold_days: int,
    poll_interval_seconds: int,
    now: datetime,
    unhealthy_multiple: int = DEFAULT_UNHEALTHY_MULTIPLE,
) -> list[HealthAlert]:
    if min(retention_days, poll_interval_seconds, unhealthy_multiple) <= 0:
        raise ValueError("health intervals must be positive")
    alerts: list[HealthAlert] = []
    for state in streams:
        stream = str(state.get("event_type") or "unknown")
        lag = stream_lag_seconds(state.get("last_end_time"), now)
        if lag is not None:
            budget = retention_budget_days(retention_days, lag)
            if budget <= 0:
                alerts.append(
                    HealthAlert(
                        stream,
                        RETENTION_GAP,
                        "Provider retention window has already been exceeded",
                        lag,
                    )
                )
            elif budget <= risk_threshold_days:
                alerts.append(
                    HealthAlert(
                        stream,
                        RETENTION_RISK,
                        "Provider retention headroom is below the configured threshold",
                        lag,
                    )
                )
        last_success = state.get("last_success_at")
        if isinstance(last_success, datetime):
            inactivity = max(0.0, (now - last_success).total_seconds())
            if inactivity > poll_interval_seconds * unhealthy_multiple:
                alerts.append(
                    HealthAlert(
                        stream,
                        POLLER_UNHEALTHY,
                        "Compliance poller has exceeded its success deadline",
                        inactivity,
                    )
                )
    return alerts


def detect_retention_gap(
    cursor_last_end: datetime | None,
    retention_floor: datetime,
    stream: str,
) -> HealthAlert | None:
    if cursor_last_end is None or cursor_last_end >= retention_floor:
        return None
    lag = (retention_floor - cursor_last_end).total_seconds()
    return HealthAlert(
        stream,
        RETENTION_GAP,
        "Stored cursor predates the provider retention floor",
        lag,
    )
