"""Incremental Server-Sent Events framing helpers."""

from __future__ import annotations

import json
from typing import Any


def data_payload(line: str) -> str | None:
    stripped = line.strip()
    if not stripped.startswith("data:"):
        return None
    return stripped[5:].strip()


def pop_event(buffer: bytes) -> tuple[bytes | None, bytes]:
    normalized = buffer.replace(b"\r\n", b"\n")
    boundary = normalized.find(b"\n\n")
    if boundary < 0:
        return None, buffer
    event = normalized[:boundary]
    remainder = normalized[boundary + 2 :]
    return event, remainder


def encode_responses_event(payload: dict[str, Any]) -> bytes:
    event_type = str(payload.get("type", "error"))
    data = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return f"event: {event_type}\ndata: {data}\n\n".encode()


def encode_data(payload: dict[str, Any]) -> bytes:
    data = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return f"data: {data}\n\n".encode()
