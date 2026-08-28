"""Public schemas for the tenant-scoped compliance management API."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    TypeAdapter,
    field_validator,
    model_validator,
)


class ConnectorCreate(BaseModel):
    provider: Literal["anthropic", "openai"]
    api_key: str = Field(min_length=8, repr=False)
    config: dict[str, Any] = Field(default_factory=dict)


class ConnectorUpdate(BaseModel):
    status: Literal["active", "paused"] | None = None
    config: dict[str, Any] | None = None


class StreamHealth(BaseModel):
    event_type: str
    last_end_time: datetime | None = None
    last_success_at: datetime | None = None
    lag_seconds: int | None = None
    retention_budget_days: float | None = None


class ConnectorRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    provider: str
    status: Literal["active", "paused", "error"]
    masked_key: str
    last_run_at: datetime | None = None
    last_success_at: datetime | None = None
    last_error: str | None = None
    consecutive_errors: int = 0
    config: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime | None = None
    updated_at: datetime | None = None
    scope_type: str | None = None
    scope_id: str | None = None
    retention_days: int | None = None
    backfill_started_at: datetime | None = None
    backfill_completed_at: datetime | None = None
    lag_seconds: float | None = None
    healthy: bool | None = None
    streams: list[StreamHealth] | None = None


class ReportRequest(BaseModel):
    connector_id: UUID | None = None
    start: datetime | None = None
    end: datetime | None = None
    format: Literal["pdf", "csv"] = "pdf"

    @field_validator("start", "end")
    @classmethod
    def normalize_naive_datetime(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            return value.replace(tzinfo=timezone.utc)
        return value

    @model_validator(mode="after")
    def validate_window(self) -> ReportRequest:
        if self.start is None or self.end is None:
            return self
        if self.start > self.end:
            raise ValueError("report start must not be after end")
        if self.end - self.start > timedelta(days=31):
            raise ValueError("synchronous reports are limited to 31 days")
        return self


class RunResult(BaseModel):
    connector_id: UUID
    status: Literal["completed", "skipped_locked", "skipped_paused", "error"]
    activities_ingested: int = 0
    content_scanned: int = 0
    findings_created: int = 0
    detail: str | None = None


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    connector_id: UUID
    activity_id: UUID | None = None
    content_id: str
    entity_type: str
    severity: str
    kvkk_category: str | None = None
    gdpr_category: str | None = None
    match_offset: int
    match_length: int
    actor_email: str | None = None
    model: str | None = None
    occurred_at: datetime | None = None
    created_at: datetime | None = None


class FindingPage(BaseModel):
    items: list[FindingRead]
    total: int
    limit: int
    offset: int


class TopActor(BaseModel):
    actor_email: str
    count: int


class FindingSummary(BaseModel):
    total: int
    by_severity: dict[str, int]
    by_entity_type: dict[str, int]
    by_kvkk_category: dict[str, int]
    top_actors: list[TopActor]


class ForwardTargetCreate(BaseModel):
    kind: Literal["siem_webhook", "slack", "email"] = "siem_webhook"
    endpoint: str = Field(min_length=1)
    secret: str | None = Field(default=None, min_length=16, repr=False)
    min_severity: Literal["low", "medium", "high", "critical"] = "high"
    enabled: bool = True

    @model_validator(mode="after")
    def validate_destination(self) -> ForwardTargetCreate:
        if self.kind == "email":
            self.endpoint = str(TypeAdapter(EmailStr).validate_python(self.endpoint))
        if self.kind != "siem_webhook" and self.secret is not None:
            raise ValueError("only SIEM webhooks support signing secrets")
        return self


class ForwardTargetUpdate(BaseModel):
    endpoint: str | None = Field(default=None, min_length=1)
    secret: str | None = Field(default=None, min_length=16, repr=False)
    min_severity: Literal["low", "medium", "high", "critical"] | None = None
    enabled: bool | None = None


class ForwardTargetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    connector_id: UUID
    kind: Literal["siem_webhook", "slack", "email"]
    endpoint_origin: str
    signed: bool
    min_severity: Literal["low", "medium", "high", "critical"]
    enabled: bool
    created_at: datetime | None = None
    updated_at: datetime | None = None
