"""Route rules whose `on` value an enterprise feature owns: one match model and one
registry check per value, run by the rule-set write after the core validation."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterator
import logging
from typing import Annotated, Literal
from uuid import UUID

from fastapi import HTTPException
from pydantic import (
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
    rules: list[tuple[int, UnavailableMatch]],
) -> None:
    """Every alias is registered, `to` speaks the provider of `from`, one rule per `from`."""

    named = {alias for _, match in rules for alias in (match.from_, *match.to)}
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
    for index, match in rules:
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


# One entry per `on` value: its match model and its registry check. E64 to E70 add theirs.
ROUTE_TRIGGER_TABLE: dict[
    str, tuple[type[BaseModel], Callable[..., Awaitable[None]]]
] = {"unavailable": (UnavailableMatch, _check_unavailable)}


async def check_route_triggers(
    session: AsyncSession, organization_id: UUID, rule_set: RuleSet
) -> None:
    """422 with the field path for a route rule whose `on` value is unknown to this
    release or whose match fails its model or its registry check."""

    found: dict[str, list[tuple[int, BaseModel]]] = {}
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
            match = entry[0].model_validate(rule.match)
        except ValidationError as error:
            first = error.errors()[0]
            path = "".join(
                f"[{part}]" if isinstance(part, int) else f".{part}"
                for part in first["loc"]
            )
            raise _refused(f"rules[{index}].match{path}", first["msg"]) from None
        found.setdefault(on, []).append((index, match))
    for on, rules in found.items():
        await ROUTE_TRIGGER_TABLE[on][1](session, organization_id, rules)


def unavailable_rules(
    rule_set: RuleSet | None, alias: str
) -> Iterator[tuple[Rule, UnavailableMatch]]:
    """The `unavailable` rules whose `from` is `alias`. One stored before this check
    existed and that fails it is skipped: a fallback never protects anything."""

    for rule in rule_set.rules if rule_set is not None else ():
        if (
            rule.kind != "route"
            or rule.match.get("on") != "unavailable"
            or rule.match.get("from") != alias
        ):
            continue
        try:
            yield rule, UnavailableMatch.model_validate(rule.match)
        except ValidationError:
            logger.warning("Fallback rule skipped reason=invalid_match")
