"""Where a Bedrock deployment can route, and whether a tenant's region lock allows it.

The lock compares the destination regions Bedrock lists for an inference profile,
never the profile's prefix alone (AWS: "Don't rely on the geographic prefix").
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import quote

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shim.gateway.contracts.context import TenantPolicy
from shim.gateway.kernel.result import PreparedInference
from shim_enterprise.core.config import settings
from shim_enterprise.secrets.references import parse_reference
from shim_enterprise.tenants.deployments import BEDROCK_ARN, validate_deployment_url
from shim_enterprise.tenants.gateway_settings import BedrockRegionLock
from shim_enterprise.tenants.models import TierDefinition

IN_REGION = "in_region"


def is_profile(model: str) -> bool:
    """A system profile id has two dots before any colon (eu.anthropic.claude-...);
    a model id one (anthropic.claude-...); an ARN says which it is."""
    arn = BEDROCK_ARN.fullmatch(model)
    if arn is not None:
        return arn["kind"] != "foundation-model"
    return model.split(":", 1)[0].count(".") >= 2


def profile_scope(model: str) -> str:
    """`in_region` for a model, else the profile id's prefix (eu, us, apac, global)."""
    if not is_profile(model):
        return IN_REGION
    return model.rsplit("/", 1)[-1].split(".", 1)[0].lower()


def bedrock_model_url(region: str, model: str) -> str:
    """The control-plane read of a model, or of an inference profile."""
    control = validate_deployment_url(
        settings.AWS_BEDROCK_CONTROL_URL_TEMPLATE.format(region=region)
    )
    resource = "inference-profiles" if is_profile(model) else "foundation-models"
    return f"{control}/{resource}/{quote(model, safe='')}"


async def fetch_destinations(
    client: httpx.AsyncClient, token: str, region: str, model: str
) -> list[str] | None:
    """The regions a deployment can route to; None when Bedrock does not say."""
    if not is_profile(model):
        return [region]
    try:
        response = await client.get(
            bedrock_model_url(region, model),
            headers={"Authorization": f"Bearer {token}"},
            timeout=5,
            follow_redirects=False,
        )
        if response.status_code != 200:
            return None
        arns = [entry["modelArn"] for entry in response.json()["models"]]
        found = sorted({arn.split(":")[3] for arn in arns})
    except (httpx.HTTPError, ValueError, KeyError, TypeError, IndexError):
        return None
    return found if found and all(found) else None


def _within(region: str, allowed: Sequence[str]) -> bool:
    return any(region == entry or region.startswith(entry + "-") for entry in allowed)


def lock_reasons(
    lock: BedrockRegionLock, scope: str, destinations: Sequence[str] | None
) -> list[str]:
    """Why a deployment falls outside a lock: scope, region, unknown_destinations."""
    reasons = []
    if lock.scopes and scope not in lock.scopes:
        reasons.append("scope")
    if lock.regions:
        if destinations is None:
            reasons.append("unknown_destinations")
        elif not all(_within(region, lock.regions) for region in destinations):
            reasons.append("region")
    return reasons


def ceiling_allows(ceiling: Sequence[str], destinations: Sequence[str] | None) -> bool:
    """The operator's always-enforced ceiling; unknown destinations are refused."""
    return not ceiling or (
        destinations is not None
        and all(_within(region, ceiling) for region in destinations)
    )


async def tier_ceiling(session: AsyncSession, tier: str | None) -> tuple[str, ...]:
    """The tier's `provider_policy.allowed_regions`: for Bedrock, an always-enforced
    ceiling; no shipped tier sets it."""
    return ceiling_of(
        await session.scalar(
            select(TierDefinition.features).where(TierDefinition.slug == tier)
        )
    )


def ceiling_of(features: Mapping[str, Any] | None) -> tuple[str, ...]:
    policy = (features or {}).get("provider_policy")
    if not isinstance(policy, dict):
        return ()
    return TenantPolicy.model_validate(policy).allowed_regions


_LOCK_STATES = {
    "BEDROCK_REGION_ALLOWED": "pass",
    "BEDROCK_REGION_OUTSIDE_LOCK": "outside",
}


def bedrock_record(prepared: PreparedInference) -> dict[str, str | None] | None:
    """The `aws_bedrock` record key of a Bedrock request; None for any other."""
    target = prepared.target
    # A bare secret id is every other deployment's reference.
    if target is None or "|" not in target.credential_reference:
        return None
    reference = parse_reference(target.credential_reference)
    if reference.aws_region is None:
        return None
    verdict = next(
        (v for v in prepared.policy_verdicts if v.rule_id == "aws.region_lock"), None
    )
    tag = reference.session_tag
    return {
        "region": reference.aws_region,
        "model": target.upstream_model,
        "scope": profile_scope(target.upstream_model),
        "lock": "off"
        if verdict is None
        else _LOCK_STATES.get(verdict.reason_code, "off"),
        "session_tag": None if tag is None else tag.split("=", 1)[1],
    }
