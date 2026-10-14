"""Route rules whose `on` value an enterprise feature owns: one match model and one
registry check per value, run by the rule-set write after the core validation."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterator, Mapping
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import logging
from typing import Annotated, Any, Literal, NamedTuple, TypeVar
from uuid import UUID

from fastapi import HTTPException
from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    model_validator,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shim.rules import Rule, RuleSet
from shim_enterprise.tenants.models import ModelDeployment

logger = logging.getLogger(__name__)

_Alias = Annotated[str, StringConstraints(min_length=1, max_length=200)]
M = TypeVar("M", bound=BaseModel)
MAX_SHADOW_RULES = 10
MAX_SHADOW_WINDOW = timedelta(days=31)
Trigger = Literal["health_flag", "circuit_open", "provider_error", "rate_limited"]


class UnavailableMatch(BaseModel):
    """When `from` cannot serve, `to` in order."""

    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    on: Literal["unavailable"]
    from_: _Alias = Field(alias="from")
    # At most two: a client request makes at most three attempts.
    to: tuple[_Alias, ...] = Field(min_length=1, max_length=2)
    triggers: tuple[Trigger, ...] = Field(min_length=1, max_length=4)

    @model_validator(mode="after")
    def distinct(self) -> UnavailableMatch:
        if self.from_ in self.to:
            raise ValueError("to names the from alias")
        if len(set(self.to)) != len(self.to):
            raise ValueError("to names an alias twice")
        if len(set(self.triggers)) != len(self.triggers):
            raise ValueError("triggers names a trigger twice")
        return self


def _refused(path: str, message: str) -> HTTPException:
    return HTTPException(
        status_code=422,
        detail={"code": "RULE_MATCH_INVALID", "path": path, "message": message},
    )


async def _check_unavailable(
    session: AsyncSession,
    organization_id: UUID,
    rules: list[tuple[int, UnavailableMatch, Mapping[str, Any] | None]],
) -> None:
    """Every alias is registered, `to` speaks the provider of `from`, one rule per `from`."""

    named = {alias for _, match, _ in rules for alias in (match.from_, *match.to)}
    providers = {
        alias: provider
        for alias, provider in await session.execute(
            select(ModelDeployment.alias, ModelDeployment.provider).where(
                ModelDeployment.organization_id == organization_id,
                ModelDeployment.alias.in_(named),
            )
        )
    }
    covered: set[str] = set()
    for index, match, _ in rules:
        path = f"rules[{index}].match"
        provider = providers.get(match.from_)
        if provider is None:
            raise _refused(
                f"{path}.from",
                "from names a model alias this organization has not registered",
            )
        if match.from_ in covered:
            raise _refused(f"{path}.from", "another unavailable rule covers this alias")
        covered.add(match.from_)
        for position, alias in enumerate(match.to):
            if alias not in providers:
                raise _refused(
                    f"{path}.to[{position}]",
                    "to names a model alias this organization has not registered",
                )
            if providers[alias] != provider:
                raise _refused(
                    f"{path}.to[{position}]",
                    "to is an alias of another provider than from",
                )


class SplitMatch(BaseModel):
    """A share of `from`'s conversations goes to `to`."""

    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    on: Literal["split"]
    from_: _Alias = Field(alias="from")
    to: _Alias
    share_percent: float = Field(ge=0, le=100)
    fallback_to_stable: bool = False

    @model_validator(mode="after")
    def one_decimal(self) -> SplitMatch:
        if self.to == self.from_:
            raise ValueError("to is the from alias")
        if abs(self.share_percent * 10 - round(self.share_percent * 10)) > 1e-9:
            raise ValueError("share_percent has at most one decimal")
        return self


async def _check_split(
    session: AsyncSession,
    organization_id: UUID,
    rules: list[tuple[int, SplitMatch, Mapping[str, Any] | None]],
) -> None:
    """Both aliases registered with one provider, never internal to external, one
    split per `from`, and no `from` that is another split's `to`."""

    named = {alias for _, match, _ in rules for alias in (match.from_, match.to)}
    registered = {
        alias: (provider, kind)
        for alias, provider, kind in await session.execute(
            select(
                ModelDeployment.alias,
                ModelDeployment.provider,
                ModelDeployment.deployment_kind,
            ).where(
                ModelDeployment.organization_id == organization_id,
                ModelDeployment.alias.in_(named),
            )
        )
    }
    targets = {match.to for _, match, _ in rules}
    covered: set[str] = set()
    for index, match, _ in rules:
        path = f"rules[{index}].match"
        source, target = registered.get(match.from_), registered.get(match.to)
        if source is None:
            raise _refused(
                f"{path}.from",
                "from names a model alias this organization has not registered",
            )
        if match.from_ in covered:
            raise _refused(f"{path}.from", "another split rule covers this alias")
        if match.from_ in targets:
            raise _refused(f"{path}.from", "from is the to of another split rule")
        covered.add(match.from_)
        if target is None:
            raise _refused(
                f"{path}.to",
                "to names a model alias this organization has not registered",
            )
        if target[0] != source[0]:
            raise _refused(f"{path}.to", "to is an alias of another provider than from")
        # A split sends every kind of request, personal data included.
        if source[1] == "internal" and target[1] != "internal":
            raise _refused(f"{path}.to", "an internal alias splits only to internal")


class SizeMatch(BaseModel):
    """Requests of at least `min_input_tokens` go to the lane replica `to`."""

    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    on: Literal["size"]
    from_: _Alias = Field(alias="from")
    to: _Alias
    min_input_tokens: int = Field(ge=256, le=10_000_000)

    @model_validator(mode="after")
    def another_alias(self) -> SizeMatch:
        if self.to == self.from_:
            raise ValueError("to is the from alias")
        return self


async def _check_size(
    session: AsyncSession,
    organization_id: UUID,
    rules: list[tuple[int, SizeMatch, Mapping[str, Any] | None]],
) -> None:
    """A lane is a replica: the same provider, upstream model and kind as `from`;
    one lane per `from`."""

    named = {alias for _, match, _ in rules for alias in (match.from_, match.to)}
    registered = {
        alias: (provider, upstream_model, kind)
        for alias, provider, upstream_model, kind in await session.execute(
            select(
                ModelDeployment.alias,
                ModelDeployment.provider,
                ModelDeployment.upstream_model,
                ModelDeployment.deployment_kind,
            ).where(
                ModelDeployment.organization_id == organization_id,
                ModelDeployment.alias.in_(named),
            )
        )
    }
    covered: set[str] = set()
    for index, match, _ in rules:
        path = f"rules[{index}].match"
        source, lane = registered.get(match.from_), registered.get(match.to)
        if source is None:
            raise _refused(
                f"{path}.from",
                "from names a model alias this organization has not registered",
            )
        if match.from_ in covered:
            raise _refused(f"{path}.from", "another size rule covers this alias")
        covered.add(match.from_)
        if lane is None:
            raise _refused(
                f"{path}.to",
                "to names a model alias this organization has not registered",
            )
        for position, field in enumerate(("provider", "upstream model", "kind")):
            if lane[position] != source[position]:
                raise _refused(
                    f"{path}.to", f"a lane has the {field} of from: it is a replica"
                )


def _classify_split(
    before: Mapping[str, Any], after: Mapping[str, Any]
) -> Literal["tightening", "relaxing", "neutral"]:
    # A split's share moves conversations between two aliases its checks already
    # allowed (same provider, never internal to external); it changes no protection.
    def rest(match: Mapping[str, Any]) -> dict[str, Any]:
        return {key: value for key, value in match.items() if key != "share_percent"}

    return "neutral" if rest(before) == rest(after) else "relaxing"


class ShadowMatch(BaseModel):
    """A change test: a share of `from`'s requests is also sent to `to`, in a window,
    up to a number of copies and a cost."""

    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    on: Literal["shadow"]
    from_: _Alias = Field(alias="from")
    to: _Alias
    share_percent: float = Field(ge=0.1, le=100)
    starts_at: AwareDatetime
    ends_at: AwareDatetime
    max_requests: int = Field(ge=1, le=100_000)
    max_cost_usd: Decimal = Field(ge=Decimal("0.01"), le=Decimal("100000"))

    @model_validator(mode="after")
    def bounded(self) -> ShadowMatch:
        if self.to == self.from_:
            raise ValueError("to is the from alias")
        if abs(self.share_percent * 10 - round(self.share_percent * 10)) > 1e-9:
            raise ValueError("share_percent has at most one decimal")
        if not self.starts_at < self.ends_at <= self.starts_at + MAX_SHADOW_WINDOW:
            raise ValueError("ends_at is after starts_at and at most 31 days later")
        return self


async def _check_shadow(
    session: AsyncSession,
    organization_id: UUID,
    rules: list[tuple[int, ShadowMatch, Mapping[str, Any] | None]],
) -> None:
    """Both aliases registered with one provider, never internal to external (no copy
    would ever be sent), a future end for a new or changed test, one test per `from`
    and at most ten."""

    if len(rules) > MAX_SHADOW_RULES:
        raise _refused(
            f"rules[{rules[MAX_SHADOW_RULES][0]}].match.on",
            f"a rule set holds at most {MAX_SHADOW_RULES} shadow rules",
        )
    named = {alias for _, match, _ in rules for alias in (match.from_, match.to)}
    registered = {
        alias: (provider, kind)
        for alias, provider, kind in await session.execute(
            select(
                ModelDeployment.alias,
                ModelDeployment.provider,
                ModelDeployment.deployment_kind,
            ).where(
                ModelDeployment.organization_id == organization_id,
                ModelDeployment.alias.in_(named),
            )
        )
    }
    now = datetime.now(timezone.utc)
    covered: set[str] = set()
    for index, match, before in rules:
        path = f"rules[{index}].match"
        source, target = registered.get(match.from_), registered.get(match.to)
        if source is None:
            raise _refused(
                f"{path}.from",
                "from names a model alias this organization has not registered",
            )
        if match.from_ in covered:
            raise _refused(f"{path}.from", "another shadow rule covers this alias")
        covered.add(match.from_)
        if target is None:
            raise _refused(
                f"{path}.to",
                "to names a model alias this organization has not registered",
            )
        if target[0] != source[0]:
            raise _refused(f"{path}.to", "to is an alias of another provider than from")
        if source[1] == "internal" and target[1] != "internal":
            raise _refused(
                f"{path}.to", "an internal alias is never copied to an external one"
            )
        changed = (
            before is None
            # An existing rule id that becomes a test is a new test.
            or before.get("on") != "shadow"
            or ShadowMatch.model_validate(before) != match
        )
        if changed and match.ends_at <= now:
            raise _refused(f"{path}.ends_at", "ends_at is in the past")


def _classify_shadow(
    before: Mapping[str, Any], after: Mapping[str, Any]
) -> Literal["tightening", "relaxing", "neutral"]:
    """Only a lower share, fewer copies, a lower cost cap or an earlier end tightens."""
    old, new = ShadowMatch.model_validate(before), ShadowMatch.model_validate(after)
    if old == new:
        return "neutral"
    narrowed = (
        new.share_percent <= old.share_percent
        and new.max_requests <= old.max_requests
        and new.max_cost_usd <= old.max_cost_usd
        and new.ends_at <= old.ends_at
    )
    same = old.model_dump(
        exclude={"share_percent", "max_requests", "max_cost_usd", "ends_at"}
    ) == new.model_dump(
        exclude={"share_percent", "max_requests", "max_cost_usd", "ends_at"}
    )
    return "tightening" if narrowed and same else "relaxing"


class RouteTrigger(NamedTuple):
    model: type[BaseModel]
    # Reads the registry; gets each rule's index, match and stored match (None if new).
    check: Callable[..., Awaitable[None]]
    # How a match change of an enforced rule classifies; without one, it relaxes.
    classify: Callable[[Mapping[str, Any], Mapping[str, Any]], str] | None = None


# One entry per `on` value. E64 to E70 add theirs.
ROUTE_TRIGGER_TABLE: dict[str, RouteTrigger] = {
    "unavailable": RouteTrigger(UnavailableMatch, _check_unavailable),
    "split": RouteTrigger(SplitMatch, _check_split, _classify_split),
    "size": RouteTrigger(SizeMatch, _check_size),
    "shadow": RouteTrigger(ShadowMatch, _check_shadow, _classify_shadow),
}


async def check_route_triggers(
    session: AsyncSession,
    organization_id: UUID,
    rule_set: RuleSet,
    stored: Mapping[str, Rule],
) -> None:
    """422 with the field path for a route rule whose `on` value is unknown to this
    release or whose match fails its model or its registry check."""

    found: dict[str, list[tuple[int, BaseModel, Mapping[str, Any] | None]]] = {}
    for index, rule in enumerate(rule_set.rules):
        on = rule.match.get("on") if rule.kind == "route" else None
        if on is None:
            continue
        entry = ROUTE_TRIGGER_TABLE.get(on)
        if entry is None:
            raise _refused(
                f"rules[{index}].match.on", f"on {on} is not available in this release"
            )
        try:
            match = entry.model.model_validate(rule.match)
        except ValidationError as error:
            first = error.errors()[0]
            path = "".join(
                f"[{part}]" if isinstance(part, int) else f".{part}"
                for part in first["loc"]
            )
            raise _refused(f"rules[{index}].match{path}", first["msg"]) from None
        before = stored.get(rule.id)
        found.setdefault(on, []).append(
            (index, match, before.match if before is not None else None)
        )
    for on, rules in found.items():
        await ROUTE_TRIGGER_TABLE[on].check(session, organization_id, rules)


def route_classifier(
    before: Rule, after: Rule
) -> Callable[[Mapping[str, Any], Mapping[str, Any]], str] | None:
    """The trigger's own classifier when both are route rules of one `on` value."""
    on = after.match.get("on")
    entry = ROUTE_TRIGGER_TABLE.get(on) if isinstance(on, str) else None
    if entry is None or before.match.get("on") != on:
        return None
    return entry.classify


def trigger_rules(
    rule_set: RuleSet | None, on: str, model: type[M], alias: str
) -> Iterator[tuple[Rule, M]]:
    """The `on` rules whose `from` is `alias`. One stored before its check existed and
    that fails it is skipped: a fallback or a split never protects anything."""

    for rule in rule_set.rules if rule_set is not None else ():
        if (
            rule.kind != "route"
            or rule.match.get("on") != on
            or rule.match.get("from") != alias
        ):
            continue
        try:
            yield rule, model.model_validate(rule.match)
        except ValidationError:
            logger.warning("Route trigger rule skipped on=%s reason=invalid_match", on)
