"""Provider-neutral, in-memory compliance ingestion contracts."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class ContentRef:
    provider: str
    content_type: str
    content_id: str
    actor_email: str | None = None
    actor_user_id: str | None = None
    model: str | None = None
    occurred_at: datetime | None = None
    extras: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ContentUnit:
    """Ephemeral raw content; callers must discard it after scanning."""

    unit_id: str
    text: str
    role: str | None = None
    occurred_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class NormalizedContent:
    provider: str
    content_type: str
    content_id: str
    units: list[ContentUnit] = field(default_factory=list)
    model: str | None = None
    actor_email: str | None = None
    actor_user_id: str | None = None
    occurred_at: datetime | None = None
    extras: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class NormalizedActivity:
    provider: str
    provider_event_id: str
    event_type: str
    occurred_at: datetime
    actor_email: str | None = None
    actor_user_id: str | None = None
    actor_ip: str | None = None
    content_refs: list[ContentRef] = field(default_factory=list)
    inline_content: NormalizedContent | None = None
    extras: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.content_refs and self.inline_content is not None:
            raise ValueError(
                "activity cannot contain both references and inline content"
            )
