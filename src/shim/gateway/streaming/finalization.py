"""Typed terminal state delivered exactly once by a streaming session."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from shim.gateway.streaming.meter import StreamUsageSnapshot

StreamTerminalStatus = Literal[
    "completed",
    "provider_error",
    "client_disconnected",
    "timeout",
    "cancelled",
    "internal_error",
]


@dataclass(frozen=True, slots=True)
class StreamFinalization:
    terminal_status: StreamTerminalStatus
    usage: StreamUsageSnapshot
    completed_at: datetime
    error_code: str | None
    error_message: str | None
