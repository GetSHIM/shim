"""Typed HTTP contracts for tenant audit evidence and oversight."""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class OrmReadModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class AuditLogRead(OrmReadModel):
    id: UUID
    seq: int = Field(gt=0)
    created_at: datetime
    event_type: str
    request_id: str | None = None
    model: str | None = None
    provider: str | None = None
    gateway_version: str | None = None
    endpoint: str | None = None
    pii_detected: bool
    pii_entities: dict[str, int] = Field(default_factory=dict)
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    is_cache_hit: bool
    latency_ms: int = Field(ge=0)
    cost_usd: Decimal = Field(ge=0)
    input_hash: str | None = None
    output_hash: str | None = None
    prev_hash: str
    row_hash: str


class AuditLogPage(BaseModel):
    items: list[AuditLogRead]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=500)
    offset: int = Field(ge=0)


class ChainBreak(BaseModel):
    seq: int = Field(gt=0)
    id: str
    reason: str


class AnchorMismatch(BaseModel):
    anchor_date: date
    stored_root: str
    recomputed_root: str | None
    stored_row_count: int = Field(ge=0)
    live_row_count: int = Field(ge=0)


class VerifyResult(BaseModel):
    ok: bool
    rows_checked: int = Field(ge=0)
    first_break: ChainBreak | None = None
    last_verified_seq: int | None = Field(default=None, gt=0)
    anchors_checked: int = Field(ge=0)
    anchor_mismatches: list[AnchorMismatch] = Field(default_factory=list)


class AnchorResult(BaseModel):
    anchor_date: date
    row_count: int = Field(ge=0)
    root_hash: str | None = None
    external_ref: str | None = None


class DetectiveOverview(BaseModel):
    total_findings: int = Field(ge=0)
    by_severity: dict[str, int]
    by_entity_type: dict[str, int]
    by_kvkk_category: dict[str, int]


class PreventiveOverview(BaseModel):
    total_requests: int = Field(ge=0)
    pii_detected_requests: int = Field(ge=0)
    redaction_rate: float = Field(ge=0, le=1)
    cache_hit_rate: float = Field(ge=0, le=1)
    top_entity_types: dict[str, int]


class AuditOverview(BaseModel):
    total_rows: int = Field(ge=0)
    coverage: float = Field(ge=0, le=1)
    retention_days: int = Field(gt=0)
    retention_floor_days: int = Field(gt=0)
    last_anchor_date: date | None = None
    last_anchor_root: str | None = None


class ConnectorOverview(BaseModel):
    total: int = Field(ge=0)
    healthy: int = Field(ge=0)
    errored: int = Field(ge=0)
    max_lag_seconds: float = Field(ge=0)


class OverviewResponse(BaseModel):
    detective: DetectiveOverview
    preventive: PreventiveOverview
    audit_log: AuditOverview
    connectors: ConnectorOverview


class AuditReportRequest(BaseModel):
    frameworks: list[str] = Field(default_factory=lambda: ["ai_act"], min_length=1)
    connector_id: UUID | None = None
    start: datetime | None = None
    end: datetime | None = None
    format: Literal["pdf", "csv"] = "pdf"


class OversightPolicyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    trigger: dict[str, Any] = Field(min_length=1)
    enabled: bool = True
    mode: Literal["flag"] = "flag"
    ttl_seconds: int | None = Field(default=None, gt=0)
    default_on_timeout: Literal["allow", "deny"] = "allow"


class OversightPolicyUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    trigger: dict[str, Any] | None = Field(default=None, min_length=1)
    enabled: bool | None = None
    mode: Literal["flag"] | None = None
    ttl_seconds: int | None = Field(default=None, gt=0)
    default_on_timeout: Literal["allow", "deny"] | None = None


class OversightPolicyRead(OrmReadModel):
    id: UUID
    name: str
    enabled: bool
    mode: Literal["flag"]
    trigger: dict[str, Any]
    ttl_seconds: int = Field(gt=0)
    default_on_timeout: Literal["allow", "deny"]
    created_at: datetime
    updated_at: datetime


class OversightRequestRead(OrmReadModel):
    id: UUID
    request_ref: str
    trigger_detail: dict[str, Any]
    status: Literal["pending", "approved", "rejected", "expired"]
    created_at: datetime
    policy_id: UUID | None = None
    audit_log_id: UUID | None = None
    reason: str | None = None
    approver: str | None = None
    decision_note: str | None = None
    expires_at: datetime | None = None
    decided_at: datetime | None = None


class OversightDecision(BaseModel):
    decision: Literal["approve", "reject"]
    note: str | None = Field(default=None, max_length=2_000)
