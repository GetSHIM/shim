"""The fallback rule: when a registry deployment cannot serve, the one the tenant named."""

from __future__ import annotations

from collections.abc import Callable, Mapping

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from shim.gateway.kernel.attempts import AttemptOutcome, Target, guarded
from shim.gateway.kernel.result import PreparedInference
from shim.rules import Rule, in_scope
from shim.rules.evaluate import record_rule_verdicts
from shim_enterprise.cache.circuit_breaker import RedisCircuitBreaker
from shim_enterprise.gateway.attempts import AttemptCandidate, resolve_alias_target
from shim_enterprise.rules.route_triggers import (
    Trigger,
    UnavailableMatch,
    unavailable_rules,
)
from shim_enterprise.tenants.deployments import (
    unhealthy_refusal,
    unhealthy_seconds_left,
)
from shim_enterprise.tenants.models import ModelDeployment

PROVIDER_ERROR_STATUSES = frozenset({500, 502, 503, 504})
REASONS: dict[Trigger, str] = {
    "health_flag": "FALLBACK_UNHEALTHY",
    "circuit_open": "FALLBACK_CIRCUIT_OPEN",
    "provider_error": "FALLBACK_PROVIDER_ERROR",
    "rate_limited": "FALLBACK_RATE_LIMITED",
}


def _unhealthy_taken_over(prepared: PreparedInference) -> bool:
    """The resolver let an unhealthy primary through for an enforced rule, and no
    request-start route moved the request off it since."""
    return (
        prepared.route_decision is None
        or prepared.route_decision.get("outcome") != "routed"
    ) and any(
        verdict.rule_id == "deployment.registry"
        and verdict.outcome == "skip"
        and verdict.reason_code == "DEPLOYMENT_UNHEALTHY"
        for verdict in prepared.policy_verdicts
    )


class UnavailableFallback:
    """`route` rules with `match.on = "unavailable"`: before the call for a health
    flag or an open circuit, after it for a provider error or a 429."""

    name = "unavailable"

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        circuit_for: Mapping[str, Callable[[PreparedInference], RedisCircuitBreaker]],
    ) -> None:
        self.session_factory = session_factory
        self.circuit_for = circuit_for

    def _rule(
        self, prepared: PreparedInference
    ) -> tuple[Rule, UnavailableMatch] | None:
        # The rule-set write keeps one per alias; scope as the other rule kinds read it.
        tags = prepared.admission.tags if prepared.admission is not None else ()
        return next(
            (
                (rule, match)
                for rule, match in unavailable_rules(prepared.rules, prepared.model)
                if in_scope(rule, prepared, tags)
            ),
            None,
        )

    async def _circuit_open(self, prepared: PreparedInference) -> bool:
        circuit_for = self.circuit_for.get(str(prepared.provider))
        return (
            circuit_for is not None and not await circuit_for(prepared).is_available()
        )

    async def after_privacy(
        self, prepared: PreparedInference
    ) -> AttemptCandidate | None:
        found = self._rule(prepared)
        unhealthy = _unhealthy_taken_over(prepared)
        if (
            found is None
            or found[0].state != "enforced"
            or (unhealthy and "health_flag" not in found[1].triggers)
        ):
            # Never let an unhealthy primary through without the rule that took it over.
            if unhealthy:
                await self._refuse_unhealthy(prepared)
            return None
        rule, match = found
        if unhealthy:
            trigger: Trigger = "health_flag"
        elif "circuit_open" in match.triggers and await self._circuit_open(prepared):
            trigger = "circuit_open"
        else:
            return None
        prepared.record_rule_match(rule, 1)
        async with self.session_factory() as session:
            candidate = await self._candidate(
                session, prepared, rule, match, trigger, 1
            )
        if candidate is None and unhealthy:
            await self._refuse_unhealthy(prepared)
        return candidate

    async def _refuse_unhealthy(self, prepared: PreparedInference) -> None:
        """Today's refusal for an unhealthy alias, with its seconds left."""
        async with self.session_factory() as session:
            primary = await session.scalar(
                select(ModelDeployment).where(
                    ModelDeployment.organization_id == prepared.tenant_id,
                    ModelDeployment.alias == prepared.model,
                )
            )
        raise unhealthy_refusal(
            max(1, unhealthy_seconds_left(primary) if primary else 0)
        )

    async def after_outcome(self, outcome: AttemptOutcome) -> AttemptCandidate | None:
        error = outcome.error
        if error is None:
            return None
        prepared = outcome.prepared
        found = self._rule(prepared)
        if found is None:
            return None
        rule, match = found
        trigger: Trigger | None = None
        if outcome.provider_started:
            if error.status_code in PROVIDER_ERROR_STATUSES:
                trigger = "provider_error"
            elif error.status_code == 429:
                trigger = "rate_limited"
        elif (
            error.error_code == "PROVIDER_UNAVAILABLE"
            and "circuit_open" in match.triggers
            and await self._circuit_open(prepared)
        ):
            trigger = "circuit_open"
        if trigger is None or trigger not in match.triggers:
            return None
        if rule.state != "enforced":
            record_rule_verdicts(prepared, {rule.id: ("allow", "RULE_WOULD_ROUTE")})
            return None
        async with self.session_factory() as session:
            return await self._candidate(
                session, prepared, rule, match, trigger, outcome.attempts
            )

    async def _candidate(
        self,
        session: AsyncSession,
        prepared: PreparedInference,
        rule: Rule,
        match: UnavailableMatch,
        trigger: Trigger,
        attempts: int,
    ) -> AttemptCandidate | None:
        """The first `to` after the current target that the registry, the key and the
        core guards accept; the guards run here so a refused crossing tries the next."""

        ids = {
            alias: str(deployment_id)
            for alias, deployment_id in await session.execute(
                select(ModelDeployment.alias, ModelDeployment.id).where(
                    ModelDeployment.organization_id == prepared.tenant_id,
                    ModelDeployment.alias.in_(match.to),
                )
            )
        }
        current = prepared.target.deployment_id if prepared.target else None
        start = next(
            (
                position + 1
                for position, alias in enumerate(match.to)
                if ids.get(alias) == current
            ),
            0,
        )
        for alias in match.to[start:]:
            candidate = AttemptCandidate(alias, "fallback", rule.id)
            target: Target | None = await resolve_alias_target(
                session, prepared, candidate
            )
            if guarded(prepared, target, attempts=attempts, byok=False) is not None:
                record_rule_verdicts(prepared, {rule.id: ("allow", REASONS[trigger])})
                return AttemptCandidate(alias, "fallback", rule.id, target)
        record_rule_verdicts(prepared, {rule.id: ("skip", "FALLBACK_NO_CANDIDATE")})
        return None
