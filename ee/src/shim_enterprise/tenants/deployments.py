"""Tenant deployment resolution and operator-owned outbound destination policy."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import hmac
import ipaddress
import logging
import math
import re
from typing import TYPE_CHECKING, cast, Literal
from urllib.parse import urlsplit

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from shim.billing.attribution import CostAttribution
from shim.billing.pricing import DEFAULT_PRICE_BOOK
from shim.gateway.kernel.result import (
    PreparedInference,
    ProviderTarget,
    UNSPECIFIED_PROVIDER_MODEL,
)
from shim.gateway.contracts.principal import AuthenticatedPrincipal
from shim.api.v1.chat import model_record
from shim.rules import Rule, in_scope
from shim.rules.route import conversation_id, owned, route_reason, start_view
from shim_enterprise.core.config import settings
from shim_enterprise.gateway.api.enterprise_errors import raise_persistence_error
from shim_enterprise.observability.enterprise_metrics import ROUTE_DECISIONS_TOTAL
from shim_enterprise.secrets.references import format_reference
from shim_enterprise.tenants.gateway_settings import GatewaySettings
from shim_enterprise.tenants.models import (
    ApiKey,
    ModelDeployment,
    ProviderSecret,
    Team,
    User,
)
from shim_enterprise.tenants.permissions import KEY_OWNER_ROLES
from shim_enterprise.tenants.teams import require_team

if TYPE_CHECKING:
    from shim_enterprise.tenants.policy import TenantPolicyService

logger = logging.getLogger(__name__)
# After this, the per-tenant provider circuit breaker guards a failing deployment.
UNHEALTHY_MARK_SECONDS = 300


def unhealthy_seconds_left(deployment: ModelDeployment) -> int:
    checked_at = deployment.health_checked_at
    if deployment.health != "unhealthy" or checked_at is None:
        return 0
    elapsed = (datetime.now(timezone.utc) - checked_at).total_seconds()
    return max(0, math.ceil(UNHEALTHY_MARK_SECONDS - elapsed))


def _origin(url: str) -> tuple[str, str | None, int]:
    parsed = urlsplit(url)
    return (
        parsed.scheme,
        parsed.hostname,
        parsed.port or (443 if parsed.scheme == "https" else 80),
    )


def _operator_origins(items: list[str]) -> set[tuple[str, str | None, int]]:
    return {
        _origin(item)
        for item in items
        if (parsed := urlsplit(item)).path in {"", "/"}
        and not parsed.query
        and not parsed.fragment
        and parsed.username is None
    }


# A Bedrock model or system inference profile id, such as
# eu.anthropic.claude-sonnet-4-5-20250929-v1:0 or openai.gpt-oss-120b-1:0.
BEDROCK_MODEL_ID = re.compile(r"^[a-z0-9-]+\.[A-Za-z0-9._:-]{1,200}$")
BEDROCK_ARN = re.compile(
    r"^arn:aws[a-z-]*:bedrock:[a-z]{2}(-[a-z]+)+-[0-9]:(\d{12})?:"
    r"(?P<kind>foundation-model|inference-profile|application-inference-profile)"
    r"/[A-Za-z0-9._:-]{1,200}$"
)


def bedrock_base_url(provider: str, region: str) -> str:
    """Bedrock's Anthropic-native or OpenAI-compatible route in the region."""
    runtime = settings.AWS_BEDROCK_RUNTIME_URL_TEMPLATE.format(region=region)
    return runtime + ("/anthropic" if provider == "anthropic" else "/openai/v1")


def internal_origin_approved(url: str) -> bool:
    allowed = settings.MODEL_DEPLOYMENT_INTERNAL_ORIGINS
    return not allowed or _origin(url) in _operator_origins(allowed)


def validate_deployment_url(url: str) -> str:
    """Exact origins are approved by the platform operator, never by API callers."""
    parsed = urlsplit(url)
    if (
        parsed.scheme not in {"https", "http"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "\\" in url
        or any(ord(char) < 33 for char in url)
    ):
        raise ValueError(
            "Deployment URL must be an absolute HTTP(S) URL without credentials, query or fragment"
        )
    host = parsed.hostname.casefold().rstrip(".")
    if _origin(url) not in _operator_origins(
        settings.MODEL_DEPLOYMENT_ALLOWED_ORIGINS
    ) and not (
        parsed.scheme == "https"
        and (parsed.port or 443) == 443
        and any(
            host.endswith(suffix) and len(host) > len(suffix)
            for suffix in settings.MODEL_DEPLOYMENT_ALLOWED_ORIGIN_SUFFIXES
        )
    ):
        raise ValueError("Deployment origin is not approved by the platform operator")
    if host in {"metadata.google.internal", "metadata", "instance-data"}:
        raise ValueError("Metadata endpoints are forbidden")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        if address.is_link_local or address.is_multicast or address.is_unspecified:
            raise ValueError("Metadata and non-unicast destinations are forbidden")
    return url.rstrip("/")


async def require_model_aliases(
    session: AsyncSession, tenant_id, aliases: list[str] | None
) -> None:
    if not aliases:
        return
    registered = set(
        (
            await session.scalars(
                select(ModelDeployment.alias).where(
                    ModelDeployment.organization_id == tenant_id,
                    ModelDeployment.alias.in_(aliases),
                    ModelDeployment.enabled.is_(True),
                )
            )
        ).all()
    )
    if not settings.MODEL_DEPLOYMENT_REQUIRED:
        registered.update(
            alias
            for alias in aliases
            if any(
                DEFAULT_PRICE_BOOK.supports(alias, provider)
                for provider in ("openai", "anthropic", "google")
            )
        )
    if set(aliases) - registered:
        raise HTTPException(
            422, detail="Model allowlist contains an unregistered model"
        )


def deployment_target(
    deployment: ModelDeployment, base_url: str, session_tag: str | None = None
) -> ProviderTarget:
    """The invocation destination of an approved deployment row."""
    return ProviderTarget(
        deployment_id=str(deployment.id),
        base_url=base_url,
        upstream_model=deployment.upstream_model,
        credential_reference=format_reference(
            deployment.provider_secret_id, deployment.aws_region, session_tag
        ),
        timeout_seconds=deployment.timeout_seconds,
        declared_version=deployment.declared_version,
        input_per_million=deployment.input_price_per_million,
        output_per_million=deployment.output_price_per_million,
        context_window=deployment.context_window,
        price_model=deployment.price_model,
        cache_read_per_million=deployment.cache_read_price_per_million,
        cache_write_per_million=deployment.cache_write_price_per_million,
    )


async def alias_target(
    session: AsyncSession, prepared: PreparedInference, alias: str
) -> (
    tuple[ProviderTarget, Literal["internal", "external"]]
    | Literal["not_allowed", "unavailable"]
):
    """The registry deployment `alias` names, checked as the resolver checks one:
    the key's allowlist, then disabled, another provider, unhealthy, origin."""

    allowed = await session.scalar(
        select(ApiKey.allowed_models).where(ApiKey.id == prepared.api_key_id)
    )
    if allowed is not None and alias not in allowed:
        return "not_allowed"
    deployment = await session.scalar(
        select(ModelDeployment).where(
            ModelDeployment.organization_id == prepared.tenant_id,
            ModelDeployment.alias == alias,
        )
    )
    base_url = None
    if (
        deployment is not None
        and deployment.enabled
        and deployment.provider == str(prepared.provider)
        and not unhealthy_seconds_left(deployment)
    ):
        try:
            base_url = validate_deployment_url(deployment.base_url)
        except ValueError:
            pass
    if deployment is None or base_url is None:
        return "unavailable"
    kind: Literal["internal", "external"] = (
        "internal"
        if deployment.deployment_kind == "internal"
        and internal_origin_approved(base_url)
        else "external"
    )
    return deployment_target(deployment, base_url), kind


def _conversation_key() -> bytes:
    base = (settings.COMPLIANCE_HASH_SALT or settings.SECRET_KEY).encode("utf-8")
    return hmac.new(base, b"shim-route-conversation-v1", hashlib.sha256).digest()


class DeploymentResolver:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        tiers: TenantPolicyService | None = None,
    ) -> None:
        self.session_factory = session_factory
        # The tier-definition cache the policy resolver fills; without it, a read.
        self.tiers = tiers

    async def resolve(
        self, prepared: PreparedInference, headers: Mapping[str, str]
    ) -> PreparedInference:
        resolved = await self._registered(prepared)
        routes = [
            rule
            for rule in (prepared.rules.rules if prepared.rules is not None else ())
            if rule.kind == "route" and owned(rule.match)
        ]
        # A tenant without route rules runs nothing below.
        return await self._route(resolved, routes, headers) if routes else resolved

    async def _route(
        self,
        prepared: PreparedInference,
        routes: list[Rule],
        headers: Mapping[str, str],
    ) -> PreparedInference:
        """The first route rule that holds decides: enforced ones, then monitor ones."""

        view = start_view(prepared.payload, prepared.protocol)
        if view is None:
            return prepared
        tags = CostAttribution.resolve(
            headers.get("x-shim-tag"),
            api_key_cost_center=prepared.policy.cost_center,
            maximum_length=settings.COST_TAG_MAX_LENGTH,
        ).tags
        for rule in sorted(routes, key=lambda rule: rule.state != "enforced"):
            if prepared.model not in rule.match["from"] or not in_scope(
                rule, prepared, tags
            ):
                continue
            reason = route_reason(rule.match.get("when"), prepared.payload, view)
            if reason is not None:
                break
        else:
            return prepared
        decision = {
            "rule_id": rule.id,
            "state": rule.state,
            "from": prepared.model,
            "to": rule.match["to"],
            "reason": reason,
            "conversation_id": conversation_id(
                headers.get("x-shim-conversation-id"), _conversation_key(), view[0]
            ),
        }
        routed = prepared
        if rule.state == "monitor":
            decision["outcome"] = "would_route"
        else:
            async with self.session_factory() as session:
                found = await alias_target(session, prepared, rule.match["to"])
            if found == "not_allowed":
                decision["outcome"] = "not_allowed_for_key"
            elif found == "unavailable":
                decision["outcome"] = "target_unavailable"
            else:
                target, kind = found
                decision["outcome"] = "routed"
                routed = replace(
                    prepared,
                    payload={**prepared.payload, "model": target.upstream_model},
                    deployment_kind=kind,
                    target=target,
                )
        prepared.record_rule_match(rule, 1)
        ROUTE_DECISIONS_TOTAL.labels(
            state=rule.state, outcome=decision["outcome"]
        ).inc()
        return replace(routed, route_decision=decision)

    async def _registered(self, prepared: PreparedInference) -> PreparedInference:
        async with self.session_factory() as session:
            try:
                key = await self._active_key(session, prepared.api_key_id)
                if key.organization_id != prepared.tenant_id:
                    raise HTTPException(403, detail="Model access is not allowed")
            except HTTPException:
                prepared.record_verdict(
                    "access.api_key",
                    stage="admission",
                    outcome="deny",
                    reason_code="API_KEY_NOT_ACTIVE",
                )
                raise
            allowed = key.allowed_models
            prepared.record_verdict(
                "access.key_models",
                stage="admission",
                outcome="deny"
                if allowed is not None and prepared.model not in allowed
                else "allow",
                reason_code="MODEL_NOT_ALLOWED"
                if allowed is not None and prepared.model not in allowed
                else "KEY_MODEL_ALLOWED",
                policy=allowed,
            )
            if allowed is not None and prepared.model not in allowed:
                raise HTTPException(
                    403,
                    detail={
                        "code": "MODEL_NOT_ALLOWED",
                        "message": "The gateway key does not permit this model.",
                    },
                )
            found = (
                await session.execute(
                    select(ModelDeployment, ProviderSecret.provider)
                    .join(
                        ProviderSecret,
                        (
                            ProviderSecret.organization_id
                            == ModelDeployment.organization_id
                        )
                        & (ProviderSecret.id == ModelDeployment.provider_secret_id),
                    )
                    .where(
                        ModelDeployment.organization_id == prepared.tenant_id,
                        ModelDeployment.alias == prepared.model,
                    )
                )
            ).one_or_none()
        deployment, secret_provider = found if found is not None else (None, None)
        if deployment is None:
            if not settings.MODEL_DEPLOYMENT_REQUIRED and (
                DEFAULT_PRICE_BOOK.supports(prepared.model, str(prepared.provider))
                or (
                    prepared.provider == "openai"
                    and prepared.protocol == "responses"
                    and prepared.model == UNSPECIFIED_PROVIDER_MODEL
                )
            ):
                prepared.record_verdict(
                    "deployment.registry",
                    stage="admission",
                    outcome="skip",
                    reason_code="CATALOG_ROUTING_ENABLED",
                    policy={"required": False},
                )
                return prepared
            prepared.record_verdict(
                "deployment.registry",
                stage="admission",
                outcome="deny",
                reason_code="MODEL_NOT_REGISTERED",
                policy={"required": settings.MODEL_DEPLOYMENT_REQUIRED},
            )
            raise HTTPException(
                403,
                detail={
                    "code": "MODEL_NOT_REGISTERED",
                    "message": "The requested model is not registered for this tenant.",
                },
            )
        registry_policy = {
            "deployment_id": str(deployment.id),
            "updated_at": deployment.updated_at,
            "enabled": deployment.enabled,
            "provider": deployment.provider,
            "version": deployment.declared_version,
        }
        if not deployment.enabled or deployment.provider != str(prepared.provider):
            prepared.record_verdict(
                "deployment.registry",
                stage="admission",
                outcome="deny",
                reason_code="MODEL_NOT_ALLOWED",
                policy=registry_policy,
            )
            raise HTTPException(
                403,
                detail={
                    "code": "MODEL_NOT_ALLOWED",
                    "message": "The model is disabled or does not support this provider protocol.",
                },
            )
        retry_after = unhealthy_seconds_left(deployment)
        if retry_after:
            prepared.record_verdict(
                "deployment.registry",
                stage="admission",
                outcome="deny",
                reason_code="DEPLOYMENT_UNHEALTHY",
                policy={
                    "deployment_id": str(deployment.id),
                    "health_checked_at": deployment.health_checked_at,
                },
            )
            raise HTTPException(
                503,
                detail={
                    "code": "DEPLOYMENT_UNHEALTHY",
                    "message": "The model deployment is marked unhealthy.",
                },
                headers={"Retry-After": str(retry_after), "x-should-retry": "false"},
            )
        bedrock = deployment.upstream == "aws_bedrock"
        if bedrock and prepared.protocol == "count_tokens":
            prepared.record_verdict(
                "deployment.registry",
                stage="admission",
                outcome="deny",
                reason_code="MODEL_CAPABILITY_UNSUPPORTED",
                policy=registry_policy,
            )
            raise HTTPException(
                400,
                detail={
                    "code": "MODEL_CAPABILITY_UNSUPPORTED",
                    "message": "Token counting is not available for Bedrock deployments.",
                },
            )
        try:
            base_url = validate_deployment_url(
                bedrock_base_url(deployment.provider, cast(str, deployment.aws_region))
                if bedrock
                else deployment.base_url
            )
        except ValueError:
            prepared.record_verdict(
                "deployment.destination",
                stage="admission",
                outcome="deny",
                reason_code="DEPLOYMENT_NOT_APPROVED",
                policy=settings.MODEL_DEPLOYMENT_ALLOWED_ORIGINS,
            )
            raise HTTPException(
                503,
                detail={
                    "code": "DEPLOYMENT_NOT_APPROVED",
                    "message": "The deployment destination is not approved.",
                },
            ) from None
        session_tag = (
            await self._bedrock_admission(prepared, deployment, key, secret_provider)
            if bedrock
            else None
        )
        prepared.record_verdict(
            "deployment.registry",
            stage="admission",
            outcome="allow",
            reason_code="MODEL_REGISTERED",
            policy=registry_policy,
        )
        prepared.record_verdict(
            "deployment.destination",
            stage="admission",
            outcome="allow",
            reason_code="DEPLOYMENT_APPROVED",
            policy=settings.MODEL_DEPLOYMENT_ALLOWED_ORIGINS,
        )
        kind = cast(Literal["internal", "external"], deployment.deployment_kind)
        # A row labelled internal before the operator listed internal origins.
        if kind == "internal" and not internal_origin_approved(base_url):
            kind = "external"
            prepared.record_verdict(
                "deployment.classification",
                stage="admission",
                outcome="allow",
                reason_code="INTERNAL_ORIGIN_NOT_APPROVED",
                policy=settings.MODEL_DEPLOYMENT_INTERNAL_ORIGINS,
            )
        return replace(
            prepared,
            payload={**prepared.payload, "model": deployment.upstream_model},
            deployment_kind=kind,
            target=deployment_target(deployment, base_url, session_tag),
        )

    async def _bedrock_admission(
        self,
        prepared: PreparedInference,
        deployment: ModelDeployment,
        key: ApiKey,
        secret_provider: str | None,
    ) -> str | None:
        """The region lock and the operator's ceiling, before any AWS call; then the
        session tag that carries the key's team onto the AWS bill, if any."""
        # Here, not at the top: the AWS helpers import this module.
        from shim_enterprise.aws.regions import (
            ceiling_allows,
            ceiling_of,
            lock_reasons,
            profile_scope,
            tier_ceiling,
        )

        gateway = prepared.tenant_gateway_settings
        current = gateway if isinstance(gateway, GatewaySettings) else GatewaySettings()
        lock, attribution = current.bedrock_region_lock, current.bedrock_attribution
        destinations = deployment.aws_destination_regions
        async with self.session_factory() as session:
            if self.tiers is None:
                ceiling = await tier_ceiling(session, key.tier)
            else:
                tier = await self.tiers.tier_definition(key.tier, session)
                ceiling = ceiling_of(tier["features"] if tier is not None else None)
            reasons = (
                []
                if lock.mode == "off"
                else lock_reasons(
                    lock, profile_scope(deployment.upstream_model), destinations
                )
            )
            within = ceiling_allows(ceiling, destinations)
            if lock.mode != "off" or ceiling:
                policy = {
                    "lock": lock.model_dump(),
                    "ceiling": list(ceiling),
                    "destinations": destinations,
                }
                if within and not reasons:
                    outcome, code = "allow", "BEDROCK_REGION_ALLOWED"
                elif within and lock.mode == "monitor":
                    outcome, code = "allow", "BEDROCK_REGION_OUTSIDE_LOCK"
                else:
                    outcome, code = "deny", "BEDROCK_REGION_NOT_ALLOWED"
                prepared.record_verdict(
                    "aws.region_lock",
                    stage="admission",
                    outcome=outcome,
                    reason_code=code,
                    policy=policy,
                )
                if outcome == "deny":
                    raise HTTPException(
                        403,
                        detail={
                            "code": code,
                            "message": "The Bedrock deployment's inference profile can "
                            "route outside the regions this tenant allows.",
                        },
                    )
            if attribution.mode != "session_tags":
                return None
            # Session tags exist only on assumed roles.
            if secret_provider != "aws_role":
                return None
            team_tag = (
                await session.scalar(
                    select(Team.aws_cost_tag).where(
                        Team.organization_id == deployment.organization_id,
                        Team.id == key.team_id,
                    )
                )
                if key.team_id is not None
                else None
            )
        return f"{attribution.tag_key}={team_tag or attribution.unassigned_value}"

    async def catalog(
        self, principal: AuthenticatedPrincipal, provider: str
    ) -> list[dict[str, object]]:
        try:
            async with self.session_factory() as session:
                key = await self._active_key(session, principal.api_key_id)
                rows = (
                    (
                        await session.execute(
                            select(ModelDeployment)
                            .where(
                                ModelDeployment.organization_id == key.organization_id,
                            )
                            .order_by(ModelDeployment.alias)
                        )
                    )
                    .scalars()
                    .all()
                )
        except (SQLAlchemyError, OSError) as exc:
            logger.error("Model catalog unavailable type=%s", type(exc).__name__)
            raise_persistence_error()
        records = (
            {}
            if settings.MODEL_DEPLOYMENT_REQUIRED
            else {
                alias: model_record(alias, provider)
                for alias in DEFAULT_PRICE_BOOK.models(provider)
            }
        )
        for row in rows:
            records.pop(row.alias, None)
            if (
                not row.enabled
                or unhealthy_seconds_left(row)
                or row.provider != provider
            ):
                continue
            records[row.alias] = (
                {
                    "id": row.alias,
                    "type": "model",
                    "display_name": row.alias,
                    "created_at": row.created_at,
                }
                if provider == "anthropic"
                else {
                    "id": row.alias,
                    "object": "model",
                    "created": int(row.created_at.timestamp()),
                    "owned_by": row.owner,
                }
            )
        return [
            records[alias]
            for alias in sorted(records)
            if key.allowed_models is None or alias in key.allowed_models
        ]

    async def _active_key(self, session: AsyncSession, key_id) -> ApiKey:
        row = (
            await session.execute(
                select(ApiKey, User)
                .join(
                    User,
                    (User.id == ApiKey.user_id)
                    & (User.organization_id == ApiKey.organization_id),
                )
                .where(
                    ApiKey.id == key_id,
                    ApiKey.is_active.is_(True),
                    User.is_active.is_(True),
                )
            )
        ).one_or_none()
        if row is None:
            raise HTTPException(
                401,
                detail={
                    "code": "INVALID_API_KEY",
                    "message": "The gateway key is no longer active.",
                },
            )
        key, owner = row
        if owner.role not in KEY_OWNER_ROLES or (
            key.expires_at is not None and key.expires_at <= datetime.now(timezone.utc)
        ):
            raise HTTPException(
                401,
                detail={
                    "code": "INVALID_API_KEY",
                    "message": "The gateway key is no longer active.",
                },
            )
        if key.team_id is not None:
            await require_team(session, owner, key.team_id)
        return key
