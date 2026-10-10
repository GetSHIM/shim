"""Tenant rules: one rule object for every tenant rule, validated in one place."""

from __future__ import annotations

from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StringConstraints

RuleKind = Literal[
    "term",
    "pattern",
    "record_set",
    "destination",
    "request_limit",
    "parameter_pin",
    "route",
]
RuleAction = Literal[
    "monitor", "warn", "mask", "block", "require_approval", "set", "route"
]
RuleState = Literal["monitor", "enforced"]

LIMITS: dict[str, Any] = {
    "rules_per_set": 100,
    "scope_entries": 100,
    "scope_entry_characters": 200,
    "terms_per_rule": 200,
    "terms_per_set": 2_000,
    "term_characters": [3, 128],
    "patterns_per_rule": 32,
    "patterns_per_set": 64,
    "pattern_characters": 256,
    "templates_per_rule": 32,
    "template_characters": 64,
    "request_bytes": 1_000_000,
}

_ScopeValue = Annotated[str, StringConstraints(min_length=1, max_length=200)]
_UuidText = Annotated[_ScopeValue, AfterValidator(lambda value: str(UUID(value)))]


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class RuleScope(_Frozen):
    api_key_ids: tuple[_UuidText, ...] = Field(default=(), max_length=100)
    team_ids: tuple[_UuidText, ...] = Field(default=(), max_length=100)
    tags: tuple[_ScopeValue, ...] = Field(default=(), max_length=100)
    models: tuple[_ScopeValue, ...] = Field(default=(), max_length=100)
    deployment_kinds: tuple[Literal["internal", "external"], ...] = Field(
        default=(), max_length=100
    )
    endpoints: tuple[
        Literal["chat", "responses", "messages", "count_tokens", "generate_content"],
        ...,
    ] = Field(default=(), max_length=100)


class Rule(_Frozen):
    # No hyphen, so the verdict id rule.<id> fits the verdict pattern.
    id: str = Field(pattern=r"^[a-z][a-z0-9_]{0,47}$")
    name: str = Field(min_length=1, max_length=100)
    kind: RuleKind
    action: RuleAction
    state: RuleState
    scope: RuleScope = RuleScope()
    match: dict[str, Any] = {}


class RuleSet(_Frozen):
    revision: int = Field(ge=1)
    rules: tuple[Rule, ...] = Field(max_length=100)


class RuleMatch(_Frozen):
    rule_id: str
    kind: RuleKind
    action: RuleAction
    state: RuleState
    count: int = Field(ge=0)
    error: bool = False


class RuleSetError(ValueError):
    """A rule set the API refuses with 422: a code and the field path it is about."""

    def __init__(self, code: str, path: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.path = path
