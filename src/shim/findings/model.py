"""Finding v1: the one shape of every finding shim produces, published as a JSON Schema."""

from __future__ import annotations

from datetime import timedelta
from typing import Annotated, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    FiniteFloat,
    StringConstraints,
    field_validator,
    model_validator,
)

SubjectKind = Literal["key", "team", "deployment", "model", "tenant", "app"]
Mode = Literal["observe", "suggest", "auto"]
_MODE_ORDER: tuple[Mode, ...] = ("observe", "suggest", "auto")
Number = int | FiniteFloat
MeasurementName = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$")]


class _Closed(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Text(_Closed):
    en: str = Field(min_length=1, max_length=500)
    tr: str = Field(min_length=1, max_length=500)


class Subject(_Closed):
    kind: SubjectKind
    id: str = Field(min_length=1, max_length=200)


class Window(_Closed):
    start: AwareDatetime
    end: AwareDatetime

    @field_validator("start", "end")
    @classmethod
    def utc(cls, value: AwareDatetime) -> AwareDatetime:
        if value.utcoffset() != timedelta(0):
            raise ValueError("must be UTC")
        return value

    @model_validator(mode="after")
    def ordered(self) -> Window:
        if self.start > self.end:
            raise ValueError("start must not be after end")
        return self


class EvidenceRef(_Closed):
    kind: Literal[
        "request", "ledger_row", "audit_row", "finding", "policy_version", "cli_session"
    ]
    id: str = Field(pattern=r"^[A-Za-z0-9_.:/-]{1,200}$")


class Impact(_Closed):
    requests: int | None = Field(ge=0)
    tokens: int | None = Field(ge=0)
    usd: str | None = Field(pattern=r"^\d+(\.\d+)?$")
    risk_class: Literal["privacy", "cost", "reliability", "quality"] | None


class Action(_Closed):
    kind: str = Field(pattern=r"^[a-z][a-z0-9_.]{0,63}$")
    params: dict[str, str | int | FiniteFloat | bool | None | list[str]] = Field(
        max_length=16
    )


class ProofAfter(_Closed):
    metric: str = Field(min_length=1, max_length=200)
    window_hours: int = Field(ge=1, le=720)
    baseline: Number | None
    threshold: Number
    comparison: Literal["lte", "gte"]


class Remediation(_Closed):
    mode: Mode
    max_mode: Mode
    action: Action | None
    reversible: bool
    blast_radius: SubjectKind
    proof_after: ProofAfter | None
    text: Text

    @model_validator(mode="after")
    def mode_within_max(self) -> Remediation:
        if _MODE_ORDER.index(self.mode) > _MODE_ORDER.index(self.max_mode):
            raise ValueError("mode must not be above max_mode")
        return self


class Finding(_Closed):
    """Evidence references, never contains, a value: title, summary and text come from rule templates."""

    schema_version: Literal["1"]
    id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,128}$")
    source: Literal["gateway", "litellm", "shim-cli"]
    rule_id: str = Field(max_length=96, pattern=r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$")
    rule_version: int = Field(ge=1)
    title: str = Field(min_length=1, max_length=200)
    summary: Text
    severity: Literal["informational", "low", "medium", "high", "critical"]
    status: Literal["open", "resolved", "dismissed"]
    status_detail: Literal["new", "in_progress", "suppressed", "resolved"] | None
    subject: Subject
    window: Window
    occurrences: int | None = Field(ge=1)
    evidence: list[EvidenceRef] = Field(max_length=50)
    measurements: dict[MeasurementName, Number] = Field(max_length=32)
    impact: Impact
    remediation: Remediation
    playbook: str = Field(pattern=r"^[A-Za-z0-9_./-]+\.md#[a-z0-9_-]+$")
