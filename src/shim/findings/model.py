"""Finding v1: the one shape of every finding shim produces, published as a JSON Schema."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    FiniteFloat,
    StringConstraints,
    model_validator,
)

SubjectKind = Literal["key", "team", "deployment", "model", "tenant", "app"]
Mode = Literal["observe", "suggest", "auto"]
_MODE_ORDER: tuple[Mode, ...] = ("observe", "suggest", "auto")
Number = int | FiniteFloat
MeasurementName = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$")]


def _utc(value: datetime) -> datetime:
    if value.utcoffset() != timedelta(0):
        raise ValueError("must be UTC")
    return value


UtcDatetime = Annotated[
    AwareDatetime,
    AfterValidator(_utc),
    Field(json_schema_extra={"pattern": r"(?:Z|\+00:00)$"}),
]


def _anchored(node: Any) -> Any:
    """`$` also matches before a final newline in Python's re, which validators use."""

    if isinstance(node, list):
        return [_anchored(item) for item in node]
    if not isinstance(node, dict):
        return node
    return {
        key: value.removesuffix("$") + r"(?![\s\S])"
        if key == "pattern"
        else {
            name.removesuffix("$") + r"(?![\s\S])": _anchored(item)
            for name, item in value.items()
        }
        if key == "patternProperties"
        else _anchored(value)
        for key, value in node.items()
    }


def _published(schema: dict[str, Any]) -> None:
    # Open for additions: a reader ignores keys it does not know (FINDINGS_SCHEMA.md).
    schema.pop("additionalProperties", None)
    schema["properties"] = _anchored(schema["properties"])


def _published_remediation(schema: dict[str, Any]) -> None:
    _published(schema)
    # mode never above max_mode.
    schema["anyOf"] = [
        {"properties": {"max_mode": {"const": "auto"}}},
        {
            "properties": {
                "max_mode": {"const": "suggest"},
                "mode": {"enum": ["observe", "suggest"]},
            }
        },
        {"properties": {"mode": {"const": "observe"}}},
    ]


class _Model(BaseModel):
    """shim's producers refuse keys this version does not define; the published schema does not."""

    model_config = ConfigDict(frozen=True, extra="forbid", json_schema_extra=_published)


class FindingText(_Model):
    en: str = Field(min_length=1, max_length=500)
    tr: str = Field(min_length=1, max_length=500)


class FindingSubject(_Model):
    kind: SubjectKind
    id: str = Field(min_length=1, max_length=200)


class FindingWindow(_Model):
    start: UtcDatetime
    end: UtcDatetime

    @model_validator(mode="after")
    def ordered(self) -> FindingWindow:
        if self.start > self.end:
            raise ValueError("start must not be after end")
        return self


class FindingEvidence(_Model):
    kind: Literal[
        "request", "ledger_row", "audit_row", "finding", "policy_version", "cli_session"
    ]
    id: str = Field(pattern=r"^[A-Za-z0-9_.:/-]{1,200}$")


class FindingImpact(_Model):
    requests: int | None = Field(ge=0)
    tokens: int | None = Field(ge=0)
    usd: str | None = Field(pattern=r"^\d+(\.\d+)?$")
    risk_class: Literal["privacy", "cost", "reliability", "quality"] | None


class FindingRemediation(_Model):
    model_config = ConfigDict(json_schema_extra=_published_remediation)

    mode: Mode
    max_mode: Mode
    # Open objects: the enterprise ladder fills action from suggest, proof_after in auto.
    action: dict[str, Any] | None
    reversible: bool
    blast_radius: SubjectKind
    proof_after: dict[str, Any] | None
    text: FindingText

    @model_validator(mode="after")
    def mode_within_max(self) -> FindingRemediation:
        if _MODE_ORDER.index(self.mode) > _MODE_ORDER.index(self.max_mode):
            raise ValueError("mode must not be above max_mode")
        return self


class Finding(_Model):
    """Evidence references, never contains, a value: title, summary and text come from rule templates."""

    schema_version: Literal["1"]
    id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,128}$")
    source: Literal["gateway", "litellm", "shim-cli"]
    rule_id: str = Field(max_length=96, pattern=r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$")
    rule_version: int = Field(ge=1)
    title: str = Field(min_length=1, max_length=200)
    summary: FindingText
    severity: Literal["informational", "low", "medium", "high", "critical"]
    status: Literal["open", "resolved", "dismissed"]
    status_detail: Literal["new", "in_progress", "suppressed", "resolved"] | None
    subject: FindingSubject
    window: FindingWindow
    occurrences: int | None = Field(ge=1)
    evidence: list[FindingEvidence] = Field(max_length=50)
    # Numbers for templates and charts; an exact amount of money is impact.usd.
    measurements: dict[MeasurementName, Number] = Field(
        max_length=32, json_schema_extra={"additionalProperties": False}
    )
    impact: FindingImpact
    remediation: FindingRemediation
    playbook: str = Field(pattern=r"^[A-Za-z0-9_./-]+\.md#[a-z0-9_-]+$")
    resolved_at: UtcDatetime | None = None
    # A user id, or "system" when the finding resolved itself.
    resolved_by: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.:-]{1,128}$")
