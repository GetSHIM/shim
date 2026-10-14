"""Tenant attempt strategies: which second target a tenant rule asks for, and when."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from shim.gateway.kernel.attempts import (
    AttemptOutcome,
    AttemptReason,
    Target,
    skip_attempt,
)
from shim.gateway.kernel.result import PreparedInference
from shim_enterprise.tenants.deployments import alias_target


@dataclass(frozen=True)
class AttemptCandidate:
    # None: the current target again.
    alias: str | None
    reason: AttemptReason
    rule_id: str
    # Set when the strategy already resolved and checked `alias` itself.
    target: Target | None = None


class AttemptStrategy(Protocol):
    name: str

    async def after_privacy(
        self, prepared: PreparedInference
    ) -> AttemptCandidate | None: ...

    async def after_outcome(
        self, outcome: AttemptOutcome
    ) -> AttemptCandidate | None: ...


async def resolve_alias_target(
    session: AsyncSession, prepared: PreparedInference, candidate: AttemptCandidate
) -> Target | None:
    """The registry deployment `candidate` names, checked as the resolver checks one.

    None, with a `gateway.attempt` skip verdict, when the key may not use it or it
    cannot serve: disabled, another provider, marked unhealthy, origin not approved.
    """

    assert candidate.alias is not None
    found = await alias_target(session, prepared, candidate.alias)
    if found == "not_allowed" or found == "unavailable":
        skip_attempt(
            prepared,
            candidate.reason,
            candidate.rule_id,
            "ATTEMPT_TARGET_NOT_ALLOWED"
            if found == "not_allowed"
            else "ATTEMPT_TARGET_UNAVAILABLE",
        )
        return None
    provider_target, kind = found
    return Target(
        provider_target=provider_target,
        deployment_kind=kind,
        reason=candidate.reason,
        rule_id=candidate.rule_id,
    )


class TenantAttemptPolicy:
    """Asks the strategies in order; the first candidate wins. None does no I/O."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        strategies: tuple[AttemptStrategy, ...],
    ) -> None:
        self.session_factory = session_factory
        self.strategies = strategies

    async def choose_target_after_privacy(
        self, prepared: PreparedInference
    ) -> Target | None:
        for strategy in self.strategies:
            candidate = await strategy.after_privacy(prepared)
            if candidate is not None:
                return await self._target(prepared, candidate, after_error=False)
        return None

    async def next_attempt(self, outcome: AttemptOutcome) -> Target | None:
        for strategy in self.strategies:
            candidate = await strategy.after_outcome(outcome)
            if candidate is not None:
                return await self._target(
                    outcome.prepared, candidate, after_error=outcome.error is not None
                )
        return None

    async def _target(
        self,
        prepared: PreparedInference,
        candidate: AttemptCandidate,
        *,
        after_error: bool,
    ) -> Target | None:
        if candidate.target is not None:
            return candidate.target
        if candidate.alias is None:
            # The target that just failed is never asked again: that is a retry.
            if after_error:
                skip_attempt(
                    prepared,
                    candidate.reason,
                    candidate.rule_id,
                    "ATTEMPT_TARGET_UNAVAILABLE",
                )
                return None
            return Target(
                provider_target=prepared.target,
                deployment_kind=prepared.deployment_kind,
                reason=candidate.reason,
                rule_id=candidate.rule_id,
            )
        async with self.session_factory() as session:
            return await resolve_alias_target(session, prepared, candidate)
