"""Anthropic compliance activity and ephemeral-content adapter."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Mapping
from datetime import datetime, timedelta, timezone
import json
from typing import Any

import httpx

from shim_enterprise.compliance.adapters.base import ComplianceAdapter
from shim_enterprise.compliance.normalized import (
    ContentRef,
    ContentUnit,
    NormalizedActivity,
    NormalizedContent,
)


BASE_URL = "https://api.anthropic.com/v1/compliance"
PAGE_SIZE = 100
MAX_PAGES = 2_000
MAX_ATTEMPTS = 5
MAX_RETRY_DELAY_SECONDS = 30.0
CURSOR_OVERLAP = timedelta(minutes=15)
DEFAULT_CONTENT_ACTIVITY_TYPES = frozenset({"claude_chat_created"})
SAFE_EXTRA_KEYS = frozenset(
    {
        "organization_id",
        "organization_uuid",
        "claude_chat_id",
        "claude_project_id",
        "api_key_id",
        "admin_api_key_id",
        "service_account_id",
        "directory_id",
        "idp_connection_type",
        "workos_event_id",
        "scopes",
    }
)
CORE_ACTIVITY_KEYS = frozenset({"id", "type", "created_at", "actor"})


class MalformedAnthropicActivity(ValueError):
    """An activity lacked fields required for durable cursor progression."""


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def _bounded_scalar(value: Any) -> str | int | float | bool | None:
    if isinstance(value, str):
        return value[:256]
    return value if isinstance(value, (int, float, bool)) else None


def _safe_extras(
    activity: Mapping[str, Any], actor: Mapping[str, Any]
) -> dict[str, Any]:
    extras: dict[str, Any] = {
        key: bounded
        for key in SAFE_EXTRA_KEYS
        if (bounded := _bounded_scalar(activity.get(key))) is not None
    }
    if (actor_type := _bounded_scalar(actor.get("type"))) is not None:
        extras["actor_type"] = actor_type
    extras["dropped_fields"] = sorted(
        set(activity).difference(CORE_ACTIVITY_KEYS, extras)
    )
    return extras


class AnthropicComplianceAdapter(ComplianceAdapter):
    provider = "anthropic"

    def __init__(
        self,
        api_key: str,
        content_activity_types: set[str] | None = None,
        config: Mapping[str, Any] | None = None,
        *,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        super().__init__(api_key, config)
        self.content_activity_types = frozenset(
            content_activity_types or DEFAULT_CONTENT_ACTIVITY_TYPES
        )
        self.rate_limiter: Any | None = None
        self._owns_client = client is None
        self.client = client or httpx.AsyncClient(timeout=60, follow_redirects=False)

    async def close(self) -> None:
        if self._owns_client:
            await self.client.aclose()

    def _headers(self) -> dict[str, str]:
        return {"x-api-key": self.api_key}

    async def _get_json(
        self,
        path: str,
        params: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        response: httpx.Response | None = None
        for attempt in range(1, MAX_ATTEMPTS + 1):
            if self.rate_limiter is not None:
                await self.rate_limiter.acquire()
            response = await self.client.get(
                f"{BASE_URL}/{path.lstrip('/')}",
                params=params,
                headers=self._headers(),
            )
            if response.status_code == 200:
                payload = response.json()
                if not isinstance(payload, dict):
                    raise ValueError("Anthropic compliance response must be an object")
                return payload
            if response.status_code not in {429, 500, 502, 503, 504}:
                break
            if attempt == MAX_ATTEMPTS:
                break
            await asyncio.sleep(_retry_delay(response, attempt))
        assert response is not None
        raise httpx.HTTPStatusError(
            f"Anthropic compliance request failed with status {response.status_code}",
            request=response.request,
            response=response,
        )

    async def verify_key(self) -> bool:
        try:
            await self._get_json("activities", {"limit": 1})
        except (httpx.HTTPError, ValueError):
            return False
        return True

    @staticmethod
    def cursor_for(activity: NormalizedActivity) -> str:
        return json.dumps(
            {
                "hwm_id": activity.provider_event_id,
                "hwm_at": activity.occurred_at.isoformat(),
            },
            separators=(",", ":"),
            sort_keys=True,
        )

    @staticmethod
    def initial_cursor(since: datetime) -> str:
        return json.dumps(
            {"hwm_id": None, "hwm_at": since.isoformat()},
            separators=(",", ":"),
            sort_keys=True,
        )

    @staticmethod
    def _decode_cursor(cursor: str | None) -> tuple[str | None, datetime | None]:
        if cursor is None:
            return None, None
        try:
            payload = json.loads(cursor)
        except json.JSONDecodeError:
            return None, None
        if not isinstance(payload, dict):
            return None, None
        identifier = payload.get("hwm_id")
        return (
            str(identifier) if identifier is not None else None,
            _timestamp(payload.get("hwm_at")),
        )

    def _normalize_activity(self, raw: Mapping[str, Any]) -> NormalizedActivity:
        identifier = raw.get("id")
        occurred_at = _timestamp(raw.get("created_at"))
        if not isinstance(identifier, str) or not identifier or occurred_at is None:
            raise MalformedAnthropicActivity(
                "Anthropic activity requires id and created_at"
            )
        actor_value = raw.get("actor")
        actor = actor_value if isinstance(actor_value, dict) else {}
        actor_email = actor.get("email_address") or actor.get(
            "unauthenticated_email_address"
        )
        event_type = str(raw.get("type") or "unknown")
        references: list[ContentRef] = []
        chat_id = raw.get("claude_chat_id")
        if isinstance(chat_id, str) and event_type in self.content_activity_types:
            references.append(
                ContentRef(
                    provider=self.provider,
                    content_type="chat",
                    content_id=chat_id,
                    actor_email=str(actor_email) if actor_email else None,
                    actor_user_id=(
                        str(actor["user_id"]) if actor.get("user_id") else None
                    ),
                    occurred_at=occurred_at,
                )
            )
        return NormalizedActivity(
            provider=self.provider,
            provider_event_id=identifier,
            event_type=event_type,
            occurred_at=occurred_at,
            actor_email=str(actor_email) if actor_email else None,
            actor_user_id=str(actor["user_id"]) if actor.get("user_id") else None,
            actor_ip=str(actor["ip_address"]) if actor.get("ip_address") else None,
            content_refs=references,
            extras=_safe_extras(raw, actor),
        )

    async def iter_activities(
        self, cursor: str | None
    ) -> AsyncIterator[NormalizedActivity]:
        high_water_id, high_water_at = self._decode_cursor(cursor)
        backstop = high_water_at - CURSOR_OVERLAP if high_water_at else None
        collected: list[NormalizedActivity] = []
        after_id: str | None = None

        for _page in range(MAX_PAGES):
            params: dict[str, Any] = {"limit": PAGE_SIZE}
            if after_id is not None:
                params["after_id"] = after_id
            page = await self._get_json("activities", params)
            raw_items = page.get("data")
            items = raw_items if isinstance(raw_items, list) else []
            reached_cursor = False
            for raw in items:
                if not isinstance(raw, dict):
                    raise MalformedAnthropicActivity(
                        "Anthropic activity must be an object"
                    )
                occurred_at = _timestamp(raw.get("created_at"))
                if backstop is not None and occurred_at is not None:
                    if occurred_at < backstop:
                        reached_cursor = True
                        break
                elif high_water_id is not None and raw.get("id") == high_water_id:
                    reached_cursor = True
                    break
                collected.append(self._normalize_activity(raw))
            if reached_cursor or not page.get("has_more"):
                break
            next_after = page.get("last_id")
            if not isinstance(next_after, str) or next_after == after_id:
                raise RuntimeError("Anthropic compliance cursor did not advance")
            after_id = next_after
        else:
            raise RuntimeError("Anthropic compliance activity page limit exceeded")

        for activity in reversed(collected):
            yield activity

    async def fetch_content(self, ref: ContentRef) -> NormalizedContent:
        if ref.provider != self.provider or ref.content_type != "chat":
            raise ValueError("Anthropic adapter only fetches Anthropic chat content")
        units: list[ContentUnit] = []
        model: str | None = None
        after_id: str | None = None
        path = f"apps/chats/{ref.content_id}/messages"

        for _page in range(MAX_PAGES):
            params = {"after_id": after_id} if after_id else None
            body = await self._get_json(path, params)
            if model is None and body.get("model") is not None:
                model = str(body["model"])
            messages = body.get("chat_messages")
            for index, message in enumerate(
                messages if isinstance(messages, list) else []
            ):
                if not isinstance(message, dict):
                    continue
                text = _content_text(message.get("content"))
                if text:
                    units.append(
                        ContentUnit(
                            unit_id=str(message.get("id") or f"message-{index}"),
                            text=text,
                            role=str(message["role"]) if message.get("role") else None,
                            occurred_at=_timestamp(message.get("created_at")),
                        )
                    )
            if not body.get("has_more"):
                break
            next_after = body.get("last_id")
            if not isinstance(next_after, str) or next_after == after_id:
                raise RuntimeError("Anthropic chat cursor did not advance")
            after_id = next_after
        else:
            raise RuntimeError("Anthropic chat page limit exceeded")

        return NormalizedContent(
            provider=self.provider,
            content_type=ref.content_type,
            content_id=ref.content_id,
            units=units,
            model=model,
            actor_email=ref.actor_email,
            actor_user_id=ref.actor_user_id,
            occurred_at=ref.occurred_at,
        )


def _content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    return "\n".join(
        str(block["text"])
        for block in content
        if isinstance(block, dict)
        and block.get("type") == "text"
        and isinstance(block.get("text"), str)
        and block["text"]
    )


def _retry_delay(response: httpx.Response, attempt: int) -> float:
    value = response.headers.get("retry-after")
    try:
        requested = float(value) if value is not None else float(2**attempt)
    except ValueError:
        requested = float(2**attempt)
    return min(max(0.0, requested), MAX_RETRY_DELAY_SECONDS)
