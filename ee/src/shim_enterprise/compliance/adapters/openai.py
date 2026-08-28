"""OpenAI compliance-log adapter with bounded streaming and no secret redirects."""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from typing import Any, cast
from urllib.parse import quote

import httpx

from shim_enterprise.compliance.adapters.base import (
    ComplianceAdapter,
    ProviderConfigError,
)
from shim_enterprise.compliance.normalized import (
    ContentRef,
    ContentUnit,
    NormalizedActivity,
    NormalizedContent,
)
from shim_enterprise.compliance.url_guard import assert_safe_forward_url


BASE_URL = "https://api.chatgpt.com/v1/compliance"
DEFAULT_EVENT_TYPES = ("AUTH_LOG",)
DEFAULT_RETENTION_DAYS = 30
MAX_PAGE_SIZE = 100
MAX_REDIRECTS = 3
DOWNLOAD_CHUNK_BYTES = 64 * 1_024
MAX_LINE_BYTES = 8 * 1_024 * 1_024
SAFE_EXTRA_KEYS = frozenset(
    {
        "object",
        "action",
        "method",
        "status",
        "result",
        "outcome",
        "role",
        "ip_country",
        "ip_region",
    }
)
CONTENT_FIELDS = (
    ("content", None),
    ("input", "user"),
    ("prompt", "user"),
    ("output", "assistant"),
    ("completion", "assistant"),
    ("body", None),
    ("text", None),
    ("message", None),
)


class MalformedLogLine(ValueError):
    """A bounded JSONL record could not be decoded safely."""


class UnknownEventTypeError(ValueError):
    """The configured compliance event stream does not exist."""


@dataclass(frozen=True, slots=True)
class LogFileDescriptor:
    file_id: str
    window_start: datetime | None = None
    window_end: datetime | None = None
    raw: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class LogPage:
    descriptors: list[LogFileDescriptor]
    has_more: bool
    last_end_time: str | None


def _parse_timestamp(value: Any) -> datetime | None:
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def _first(record: Mapping[str, Any], keys: Sequence[str]) -> Any | None:
    return next((record[key] for key in keys if record.get(key) is not None), None)


def validate_openai_event_types(config: Mapping[str, Any]) -> None:
    event_types = config.get("event_types")
    if "event_types" in config and (
        not isinstance(event_types, list)
        or not event_types
        or any(not isinstance(value, str) or not value for value in event_types)
    ):
        raise ProviderConfigError(
            "event_types must be a non-empty list of non-empty strings"
        )
    content_event_types = config.get("content_event_types")
    if "content_event_types" in config and (
        not isinstance(content_event_types, list)
        or any(not isinstance(value, str) or not value for value in content_event_types)
    ):
        raise ProviderConfigError(
            "content_event_types must be a list of non-empty strings"
        )


class OpenAIComplianceAdapter(ComplianceAdapter):
    provider = "openai"

    def __init__(
        self,
        api_key: str,
        config: Mapping[str, Any] | None = None,
        *,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        super().__init__(api_key, config)
        self._validate_config()
        self.base_url = BASE_URL
        self.event_types = [
            str(value) for value in self.config.get("event_types", DEFAULT_EVENT_TYPES)
        ]
        self.content_event_types = {
            str(value) for value in self.config.get("content_event_types", [])
        }
        self.client = client or httpx.AsyncClient(timeout=60, follow_redirects=False)
        self._owns_client = client is None

    def _validate_config(self) -> None:
        scope_id = self.config.get("scope_id")
        scope_type = self.config.get("scope_type")
        if not isinstance(scope_id, str) or not scope_id:
            raise ProviderConfigError("OpenAI compliance scope_id is required")
        if scope_type not in {None, "workspace", "organization"}:
            raise ProviderConfigError("scope_type must be workspace or organization")
        validate_openai_event_types(self.config)

    async def close(self) -> None:
        if self._owns_client:
            await self.client.aclose()

    def _scope_segment(self) -> str:
        scope_id = str(self.config["scope_id"])
        scope_type = self.config.get("scope_type")
        collection = (
            "organizations"
            if scope_type == "organization"
            or (scope_type is None and scope_id.startswith("org-"))
            else "workspaces"
        )
        return f"{collection}/{quote(scope_id, safe='')}"

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.api_key}"}

    def retention_days(self) -> int:
        try:
            value = int(self.config.get("retention_days", DEFAULT_RETENTION_DAYS))
        except (TypeError, ValueError):
            value = DEFAULT_RETENTION_DAYS
        return max(1, value)

    def backfill_window_days(self) -> int:
        try:
            value = int(self.config.get("backfill_window_days", self.retention_days()))
        except (TypeError, ValueError):
            value = self.retention_days()
        return max(0, min(value, self.retention_days()))

    def backfill_start(self, now: datetime | None = None) -> datetime:
        current = now or datetime.now(timezone.utc)
        return current - timedelta(days=self.backfill_window_days())

    def retention_floor(self, now: datetime | None = None) -> datetime:
        current = now or datetime.now(timezone.utc)
        return current - timedelta(days=self.retention_days())

    async def verify_key(self) -> bool:
        try:
            await self._get_json(
                f"{self.base_url}/{self._scope_segment()}/logs",
                {"event_type": self.event_types[0], "limit": 1},
            )
        except (httpx.HTTPError, ValueError):
            return False
        return True

    async def _get_json(
        self,
        url: str,
        params: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        response = await self.client.get(url, params=params, headers=self._headers())
        if response.status_code != 200:
            raise httpx.HTTPStatusError(
                f"OpenAI compliance request failed with status {response.status_code}",
                request=response.request,
                response=response,
            )
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("OpenAI compliance response must be an object")
        return payload

    @staticmethod
    def _descriptor(raw: Mapping[str, Any]) -> LogFileDescriptor | None:
        file_id = _first(raw, ("id", "file_id", "log_file_id", "object_id"))
        if not isinstance(file_id, str) or not file_id:
            return None
        return LogFileDescriptor(
            file_id=file_id,
            window_start=_parse_timestamp(
                _first(raw, ("start_time", "window_start", "from"))
            ),
            window_end=_parse_timestamp(
                _first(raw, ("end_time", "window_end", "last_end_time", "to"))
            ),
            raw=dict(raw),
        )

    async def list_logs(
        self,
        event_type: str,
        after: str | None,
        limit: int = MAX_PAGE_SIZE,
    ) -> LogPage:
        params: dict[str, Any] = {
            "event_type": event_type,
            "limit": min(max(1, limit), MAX_PAGE_SIZE),
        }
        if after is not None:
            params["after"] = after
        try:
            payload = await self._get_json(
                f"{self.base_url}/{self._scope_segment()}/logs", params
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                raise UnknownEventTypeError(event_type) from exc
            raise
        raw_items = payload.get("data")
        if not isinstance(raw_items, list):
            raise ValueError("OpenAI compliance response data must be a list")
        descriptors: list[LogFileDescriptor] = []
        for item in raw_items:
            descriptor = self._descriptor(item) if isinstance(item, dict) else None
            if descriptor is None:
                raise ValueError(
                    "OpenAI compliance response contained an invalid log descriptor"
                )
            descriptors.append(descriptor)
        has_more = payload.get("has_more")
        if not isinstance(has_more, bool):
            raise ValueError("OpenAI compliance response has_more must be a boolean")
        cursor = payload.get("last_end_time")
        if cursor is not None and (
            not isinstance(cursor, str) or _parse_timestamp(cursor) is None
        ):
            raise ValueError(
                "OpenAI compliance response last_end_time must be an ISO timestamp"
            )
        return LogPage(
            descriptors=descriptors,
            has_more=has_more,
            last_end_time=cursor,
        )

    async def _download_lines(self, file_id: str) -> AsyncIterator[str]:
        url = httpx.URL(
            f"{self.base_url}/{self._scope_segment()}/logs/{quote(file_id, safe='')}"
        )
        headers = self._headers()
        for _hop in range(MAX_REDIRECTS + 1):
            request_url = url
            request_headers = headers
            extensions = None
            if not headers:
                address = await assert_safe_forward_url(str(url))
                request_url = url.copy_with(host=str(address))
                request_headers = {"host": url.netloc.decode("ascii")}
                extensions = {"sni_hostname": url.raw_host.decode("ascii")}
            async with self.client.stream(
                "GET",
                request_url,
                headers=request_headers,
                follow_redirects=False,
                extensions=extensions,
            ) as response:
                if response.is_redirect:
                    location = response.headers.get("location")
                    if location is None:
                        raise httpx.HTTPStatusError(
                            "OpenAI compliance redirect had no location",
                            request=response.request,
                            response=response,
                        )
                    next_url = url.join(location)
                    if (
                        next_url.scheme != "https"
                        or next_url.username
                        or next_url.password
                    ):
                        raise httpx.UnsupportedProtocol(
                            "OpenAI compliance redirects must use credential-free HTTPS"
                        )
                    if (
                        next_url.scheme,
                        next_url.host,
                        next_url.port,
                    ) != (
                        url.scheme,
                        url.host,
                        url.port,
                    ):
                        headers = {}
                    url = next_url
                    continue
                if response.status_code != 200:
                    raise httpx.HTTPStatusError(
                        f"OpenAI compliance download failed with status {response.status_code}",
                        request=response.request,
                        response=response,
                    )
                async for line in self._iter_jsonl_lines(response):
                    yield line
                return
        raise httpx.TooManyRedirects(
            "OpenAI compliance download exceeded redirect limit"
        )

    @staticmethod
    async def _iter_jsonl_lines(response: httpx.Response) -> AsyncIterator[str]:
        buffer = bytearray()
        async for chunk in response.aiter_bytes(DOWNLOAD_CHUNK_BYTES):
            buffer.extend(chunk)
            while (newline := buffer.find(b"\n")) >= 0:
                if newline > MAX_LINE_BYTES:
                    raise MalformedLogLine(
                        "compliance JSONL line exceeded the size limit"
                    )
                line = bytes(buffer[:newline])
                del buffer[: newline + 1]
                yield line.decode("utf-8")
            if len(buffer) > MAX_LINE_BYTES:
                raise MalformedLogLine("compliance JSONL line exceeded the size limit")
        if buffer:
            yield bytes(buffer).decode("utf-8")

    async def download_records(
        self,
        event_type: str,
        descriptor: LogFileDescriptor,
    ) -> AsyncIterator[NormalizedActivity]:
        line_number = 0
        async for line in self._download_lines(descriptor.file_id):
            if not line.strip():
                continue
            line_number += 1
            try:
                record = json.loads(line)
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise MalformedLogLine(
                    "compliance JSONL contained invalid JSON"
                ) from exc
            if not isinstance(record, dict):
                raise MalformedLogLine("compliance JSONL record must be an object")
            yield self._normalize_record(event_type, descriptor, line_number, record)

    @staticmethod
    def _actor(record: Mapping[str, Any]) -> tuple[str | None, str | None, str | None]:
        sources = [record]
        sources.extend(
            nested
            for key in ("actor", "user", "principal", "subject")
            if isinstance((nested := record.get(key)), dict)
        )
        email = user_id = ip = None
        for source in sources:
            email = email or _first(
                source, ("actor_email", "user_email", "email", "email_address")
            )
            user_id = user_id or _first(
                source, ("actor_id", "user_id", "actor_user_id", "subject_id")
            )
            ip = ip or _first(source, ("ip_address", "ip", "client_ip", "source_ip"))
        return (
            str(email) if email is not None else None,
            str(user_id) if user_id is not None else None,
            str(ip) if ip is not None else None,
        )

    @staticmethod
    def _text(value: Any) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, list):
            return "\n".join(
                filter(None, (OpenAIComplianceAdapter._text(item) for item in value))
            )
        if isinstance(value, dict):
            return next(
                (
                    text
                    for key in ("content", "text", "body", "value")
                    if (text := OpenAIComplianceAdapter._text(value.get(key)))
                ),
                "",
            )
        return ""

    @classmethod
    def _content_units(cls, record: Mapping[str, Any]) -> list[ContentUnit]:
        messages: Any = record.get("messages")
        conversation = record.get("conversation")
        if messages is None and isinstance(conversation, dict):
            messages = conversation.get("messages")
        if messages is None:
            messages = record.get("turns") or record.get("parts")
        units: list[ContentUnit] = []
        if isinstance(messages, list):
            for index, message in enumerate(messages):
                text = cls._text(message)
                if not text:
                    continue
                mapping: Mapping[str, Any] = cast(
                    Mapping[str, Any], message if isinstance(message, dict) else {}
                )
                units.append(
                    ContentUnit(
                        unit_id=str(mapping.get("id") or f"m{index}"),
                        text=text,
                        role=str(mapping["role"]) if mapping.get("role") else None,
                        occurred_at=_parse_timestamp(mapping.get("created_at")),
                    )
                )
        if not units:
            units = [
                ContentUnit(unit_id=key, text=text, role=role)
                for key, role in CONTENT_FIELDS
                if (text := cls._text(record.get(key)))
            ]
        return units

    @staticmethod
    def _safe_extras(record: Mapping[str, Any]) -> dict[str, Any]:
        extras: dict[str, Any] = {}
        for key in SAFE_EXTRA_KEYS:
            value = record.get(key)
            if isinstance(value, (bool, int, float)):
                extras[key] = value
            elif isinstance(value, str):
                extras[key] = value[:256]
        extras["dropped_fields"] = sorted(set(record).difference(extras))
        return extras

    def _normalize_record(
        self,
        stream_event_type: str,
        descriptor: LogFileDescriptor,
        line_number: int,
        record: Mapping[str, Any],
    ) -> NormalizedActivity:
        event_type = str(
            record.get("event_type") or record.get("type") or stream_event_type
        )
        identifier = _first(record, ("id", "event_id", "log_id", "_id", "uuid"))
        event_id = (
            str(identifier)
            if identifier is not None
            else f"{descriptor.file_id}:{line_number}"
        )
        occurred_at = (
            _parse_timestamp(
                _first(
                    record,
                    ("timestamp", "created_at", "event_time", "time", "occurred_at"),
                )
            )
            or descriptor.window_end
            or datetime.now(timezone.utc)
        )
        actor_email, actor_user_id, actor_ip = self._actor(record)
        model_value = _first(record, ("model", "model_name", "engine"))
        model = str(model_value) if model_value is not None else None
        units = self._content_units(record)
        inline_content = None
        if units or event_type in self.content_event_types:
            inline_content = NormalizedContent(
                provider=self.provider,
                content_type="conversation",
                content_id=event_id,
                units=units,
                model=model,
                actor_email=actor_email,
                actor_user_id=actor_user_id,
                occurred_at=occurred_at,
            )
        return NormalizedActivity(
            provider=self.provider,
            provider_event_id=event_id,
            event_type=event_type,
            occurred_at=occurred_at,
            actor_email=actor_email,
            actor_user_id=actor_user_id,
            actor_ip=actor_ip,
            inline_content=inline_content,
            extras=self._safe_extras(record),
        )

    async def fetch_content(self, ref: ContentRef) -> NormalizedContent:
        return NormalizedContent(
            provider=self.provider,
            content_type=ref.content_type,
            content_id=ref.content_id,
        )
