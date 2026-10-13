"""Model deployments, retirements and inventory."""

from __future__ import annotations

from collections.abc import Collection, Mapping
import asyncio
from dataclasses import asdict
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Literal
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    computed_field,
    field_validator,
    model_validator,
)
from sqlalchemy import or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError

from shim_enterprise.api.enterprise_deps import ADMIN_REQUIRED, READER_REQUIRED, require
from shim_enterprise.billing.models import RequestLifecycle
from shim.billing.lifecycle import load_lifecycle
from shim.billing.pricing import DATE_SUFFIX, DEFAULT_PRICE_BOOK
from shim.core.community_config import AZURE_DEPLOYMENT_NAME
from shim.gateway.pipeline.provider_execution import ProviderCallError
from shim_enterprise.core.config import settings
from shim_enterprise.core.database import get_db
from shim.gateway.contracts.ids import TenantId
from shim_enterprise.observability.model_inventory import ModelInventoryReadModel
from shim_enterprise.tenants.audit import (
    change_details,
    record_management_action as _audit,
)
from shim_enterprise.tenants.gateway_settings import (
    Directions,
    classify_fields,
    neutral,
    toward,
)
from shim_enterprise.tenants.gateway_settings import GatewaySettings, stored_settings
from shim_enterprise.tenants.models import (
    ModelDeployment,
    Organization,
    OrganizationGatewaySettings,
    User,
)
from shim_enterprise.aws.regions import (
    bedrock_model_url,
    ceiling_allows,
    fetch_destinations,
    is_profile,
    lock_reasons,
    profile_scope,
    tier_ceiling,
)
from shim_enterprise.secrets.references import AWS_REGION, CredentialReference
from shim_enterprise.tenants.deployments import (
    BEDROCK_ARN,
    BEDROCK_MODEL_ID,
    bedrock_base_url,
    internal_origin_approved,
    validate_deployment_url,
)
from shim_enterprise.policy.plans import (
    Impact,
    Risk,
    State,
    lock_tenant,
    no_impact,
    version_detail,
)
from shim_enterprise.tenants.permissions import Permission
from shim_enterprise.api.v1.management._common import (
    _counted,
    _fresh_resolver,
    _lifecycle_count,
    _managed_write,
    _owned_provider_secret,
    _plain,
    _record_privacy_relaxed,
    _refreshed,
    _sync_window,
    _tenant_id,
    _uuids,
    _validated,
)


router = APIRouter()


_KEPT_WHEN_ABSENT = frozenset(
    {
        "upstream",
        "aws_region",
        "capacity_concurrent_requests",
        "price_model",
        "cache_read_price_per_million",
        "cache_write_price_per_million",
    }
)


class ModelDeploymentInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    alias: str = Field(
        min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$"
    )
    provider: Literal["openai", "anthropic"]
    upstream_model: str = Field(min_length=1, max_length=200)
    base_url: str | None = Field(
        default=None,
        min_length=1,
        max_length=2048,
        description="Required, except for aws_bedrock, where shim derives it from "
        "the region.",
    )
    provider_secret_id: UUID
    timeout_seconds: int = Field(default=60, ge=1, le=300)
    deployment_kind: Literal["internal", "external"]
    declared_version: str = Field(min_length=1, max_length=200)
    owner: str = Field(min_length=1, max_length=200)
    enabled: bool = True
    input_price_per_million: Decimal | None = Field(
        default=None,
        ge=0,
        max_digits=18,
        decimal_places=8,
        description="USD per million input tokens; set both prices or neither.",
    )
    output_price_per_million: Decimal | None = Field(
        default=None,
        ge=0,
        max_digits=18,
        decimal_places=8,
        description="USD per million output tokens; set both prices or neither.",
    )
    context_window: int | None = Field(
        default=None,
        ge=1,
        description="Tokens the served model accepts; a request that certainly exceeds it is refused.",
    )
    upstream: Literal["generic", "azure_openai", "aws_bedrock"] = Field(
        default="generic",
        description="azure_openai: an Azure OpenAI v1 endpoint ending in /openai/v1. "
        "aws_bedrock: Amazon Bedrock in aws_region, Anthropic's or OpenAI's format.",
    )
    capacity_concurrent_requests: int | None = Field(
        default=None,
        ge=1,
        le=100_000,
        description="Concurrent requests the serving hardware holds; the capacity "
        "forecast compares the measured busy hour with it.",
    )
    aws_region: str | None = Field(
        default=None,
        pattern=AWS_REGION.pattern,
        max_length=32,
        description="The AWS region of an aws_bedrock deployment, such as eu-central-1.",
    )
    price_model: str | None = Field(
        default=None,
        max_length=200,
        description="The catalog model whose prices and limits apply when no price is set.",
    )
    cache_read_price_per_million: Decimal | None = Field(
        default=None,
        ge=0,
        max_digits=18,
        decimal_places=8,
        description="USD per million cached input tokens read; needs the input price.",
    )
    cache_write_price_per_million: Decimal | None = Field(
        default=None,
        ge=0,
        max_digits=18,
        decimal_places=8,
        description="USD per million input tokens written to the cache; needs the input price.",
    )

    @model_validator(mode="after")
    def price_pair(self) -> ModelDeploymentInput:
        if (self.input_price_per_million is None) != (
            self.output_price_per_million is None
        ):
            raise ValueError("Set both input and output prices, or neither")
        if self.input_price_per_million is None and (
            self.cache_read_price_per_million is not None
            or self.cache_write_price_per_million is not None
        ):
            raise ValueError("A cache price needs the input and output prices")
        return self

    @model_validator(mode="after")
    def catalog_and_azure_rules(self) -> ModelDeploymentInput:
        if self.price_model is not None and self.price_model not in (
            DEFAULT_PRICE_BOOK.models(self.provider)
        ):
            raise ValueError("price_model is not a catalog model for this provider")
        if self.upstream == "aws_bedrock":
            return self.bedrock_rules()
        if self.aws_region is not None:
            raise ValueError("aws_region is for aws_bedrock deployments only")
        if self.base_url is None:
            raise ValueError("base_url is required")
        if self.upstream != "azure_openai":
            return self
        if self.provider != "openai":
            raise ValueError("An Azure OpenAI deployment uses provider openai")
        if self.deployment_kind != "external":
            raise ValueError("An Azure OpenAI deployment is external")
        if urlsplit(self.base_url).path != "/openai/v1":
            raise ValueError("An Azure OpenAI base_url ends in /openai/v1")
        if not AZURE_DEPLOYMENT_NAME.fullmatch(self.upstream_model):
            raise ValueError("upstream_model is the Azure deployment name")
        return self

    def bedrock_rules(self) -> ModelDeploymentInput:
        if self.aws_region is None:
            raise ValueError("An aws_bedrock deployment names its aws_region")
        if self.deployment_kind != "external":
            raise ValueError("An aws_bedrock deployment is external")
        arn = BEDROCK_ARN.fullmatch(self.upstream_model)
        if arn is None and not BEDROCK_MODEL_ID.fullmatch(self.upstream_model):
            raise ValueError(
                "upstream_model is a Bedrock model or inference profile id, or its ARN"
            )
        if (
            arn is not None
            and arn["kind"] == "application-inference-profile"
            and self.provider == "openai"
        ):
            # Chat Completions rejects application inference profiles with a 400.
            raise ValueError(
                "An application inference profile serves the anthropic format only"
            )
        derived = validate_deployment_url(
            bedrock_base_url(self.provider, self.aws_region)
        )
        if self.base_url is not None and self.base_url.rstrip("/") != derived:
            raise ValueError("An aws_bedrock base_url is derived from aws_region")
        self.base_url = derived
        return self

    @field_validator("upstream_model", "declared_version", "owner")
    @classmethod
    def nonblank(cls, value: str) -> str:
        if not value.strip() or value != value.strip():
            raise ValueError("Value must be nonblank without surrounding whitespace")
        return value

    @field_validator("base_url")
    @classmethod
    def approved_destination(cls, value: str | None) -> str | None:
        return None if value is None else validate_deployment_url(value)


class ModelDeploymentView(ModelDeploymentInput):
    model_config = ConfigDict(from_attributes=True)

    @field_validator("base_url")
    @classmethod
    def approved_destination(cls, value: str | None) -> str | None:
        # Operators must still be able to inspect a now-disallowed deployment.
        return value

    @model_validator(mode="after")
    def catalog_and_azure_rules(self) -> ModelDeploymentView:
        # A catalog update must not hide a row whose price model it dropped.
        return self

    id: UUID
    health: Literal["unknown", "healthy", "unhealthy"]
    health_checked_at: datetime | None
    created_at: datetime
    updated_at: datetime
    aws_destination_regions: list[str] | None = Field(
        default=None,
        description="aws_bedrock: the regions the profile can route to, from "
        "GetInferenceProfile; null when unknown.",
    )
    aws_destinations_checked_at: datetime | None = None

    @computed_field
    @property
    def aws_profile_scope(self) -> str | None:
        """aws_bedrock: in_region for a model, else the profile's prefix (eu, us, global)."""
        return (
            profile_scope(self.upstream_model)
            if self.upstream == "aws_bedrock"
            else None
        )


@router.get("/model-deployments", response_model=list[ModelDeploymentView])
async def list_model_deployments(
    user: User = Depends(require("deployments.read", legacy_detail=READER_REQUIRED)),
    session: AsyncSession = Depends(get_db),
):
    return (
        (
            await session.execute(
                select(ModelDeployment)
                .where(
                    ModelDeployment.organization_id == _tenant_id(user),
                )
                .order_by(ModelDeployment.alias)
            )
        )
        .scalars()
        .all()
    )


class RetiringKeyView(BaseModel):
    id: UUID
    name: str | None
    requests: int
    last_used: datetime


class RetiringTeamView(BaseModel):
    id: UUID
    requests: int


class RetiringTagView(BaseModel):
    tag: str
    requests: int


class RetiringAffectedView(BaseModel):
    api_keys: list[RetiringKeyView]
    teams: list[RetiringTeamView]
    tags: list[RetiringTagView]
    aliases: list[str]


class ModelRetirementView(BaseModel):
    provider: str
    model: str
    retires_on: date
    deprecated_on: date | None
    replacement: str | None
    source: str
    checked_on: date
    affected: RetiringAffectedView


# One pass over the last 30 days: per model, its keys (with names), teams and tags.
_RETIREMENT_USAGE = text(
    """
    SELECT l.provider, l.requested_model, l.api_key_id, k.name AS key_name,
           l.metadata->>'team_id' AS team_id, tag,
           count(DISTINCT l.id) AS requests, max(l.started_at) AS last_used,
           GROUPING(l.api_key_id) AS key_rollup,
           GROUPING(l.metadata->>'team_id') AS team_rollup
    FROM request_lifecycle AS l
    LEFT JOIN api_keys AS k
      ON k.organization_id = l.organization_id AND k.id = l.api_key_id
    LEFT JOIN LATERAL jsonb_array_elements_text(
      CASE WHEN jsonb_typeof(l.metadata->'tags') = 'array'
           THEN l.metadata->'tags' ELSE '[]'::jsonb END
    ) AS tag ON true
    WHERE l.organization_id = :tenant_id AND l.started_at >= :since
      AND (lower(l.requested_model) = ANY(:names)
           OR lower(l.requested_model) LIKE ANY(:prefixes))
    GROUP BY GROUPING SETS (
      (l.provider, l.requested_model, l.api_key_id, k.name),
      (l.provider, l.requested_model, l.metadata->>'team_id'),
      (l.provider, l.requested_model, tag)
    )
    """
)
# Per retiring model, at most this many keys, teams and tags, the busiest first.
_AFFECTED_LIMIT = 100


@router.get("/model-retirements", response_model=list[ModelRetirementView])
async def list_model_retirements(
    days: int = Query(default=90, ge=1, le=730),
    user: User = Depends(require("usage.read", legacy_detail=READER_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> list[ModelRetirementView]:
    """Models retiring within `days` that this organization used in 30 days or registered."""
    tenant_id = _tenant_id(user)
    lifecycle = load_lifecycle(settings.SHIM_MODEL_LIFECYCLE_FILE)
    now = datetime.now(timezone.utc)
    soon = {
        name
        for entries in lifecycle.models.values()
        for name, entry in entries.items()
        if (entry.retires_on - now.date()).days <= days
    }
    if not soon:
        return []
    deployments = {
        alias: (provider, upstream)
        for alias, provider, upstream in await session.execute(
            select(
                ModelDeployment.alias,
                ModelDeployment.provider,
                ModelDeployment.upstream_model,
            ).where(ModelDeployment.organization_id == tenant_id)
        )
    }

    def retiring(provider: str | None, model: str) -> tuple[str, str, Any] | None:
        """The entry a request's model retires under; never the caller's own text."""
        alias = model if model in deployments else None
        if alias is not None:
            provider, model = deployments[alias]
        for candidate in [provider] if provider else ["openai", "anthropic", "google"]:
            if (found := lifecycle.match(model, candidate, alias)) is not None:
                return found
        return None

    items: dict[tuple[str, str], dict[str, Any]] = {}

    def item(found: tuple[str, str, Any]) -> dict[str, Any]:
        return items.setdefault(
            found[:2],
            {
                "retirement": found[2],
                "keys": {},
                "teams": {},
                "tags": {},
                "aliases": set(),
            },
        )

    # Only usage that can match a retiring entry is read: its name, a dated id of
    # it, the undated alias of a snapshot, or a registry alias.
    usage = await session.execute(
        _RETIREMENT_USAGE,
        {
            "tenant_id": tenant_id,
            "since": now - timedelta(days=30),
            "names": sorted(
                soon
                | {DATE_SUFFIX.sub("", name) for name in soon}
                | {alias.casefold() for alias in deployments}
            ),
            "prefixes": sorted(name.replace("_", "\\_") + "-%" for name in soon),
        },
    )
    for row in usage:
        matched = retiring(row.provider, row.requested_model)
        if matched is None:
            continue
        found = item(matched)
        # Several requested names can match one entry, so counts add up.
        if not row.key_rollup:
            if row.api_key_id is not None:
                _, requests, last = found["keys"].get(
                    row.api_key_id, (None, 0, row.last_used)
                )
                found["keys"][row.api_key_id] = (
                    row.key_name,
                    requests + row.requests,
                    max(last, row.last_used),
                )
        elif not row.team_rollup:
            if row.team_id is not None:
                team = UUID(row.team_id)
                found["teams"][team] = found["teams"].get(team, 0) + row.requests
        elif row.tag is not None:
            found["tags"][row.tag] = found["tags"].get(row.tag, 0) + row.requests
    for alias, (provider, _) in deployments.items():
        if (matched := retiring(provider, alias)) is not None:
            item(matched)["aliases"].add(alias)

    views = []
    for (provider, model), found in items.items():
        retirement = found["retirement"]
        if (retirement.retires_on - now.date()).days > days:
            continue
        views.append(
            ModelRetirementView(
                provider=provider,
                model=model,
                **retirement.model_dump(),
                affected=RetiringAffectedView(
                    api_keys=[
                        RetiringKeyView(
                            id=key_id, name=name, requests=requests, last_used=last
                        )
                        for key_id, (name, requests, last) in sorted(
                            found["keys"].items(), key=lambda entry: -entry[1][1]
                        )[:_AFFECTED_LIMIT]
                    ],
                    teams=[
                        RetiringTeamView(id=team_id, requests=requests)
                        for team_id, requests in sorted(
                            found["teams"].items(), key=lambda entry: -entry[1]
                        )[:_AFFECTED_LIMIT]
                    ],
                    tags=[
                        RetiringTagView(tag=tag, requests=requests)
                        for tag, requests in sorted(
                            found["tags"].items(), key=lambda entry: -entry[1]
                        )[:_AFFECTED_LIMIT]
                    ],
                    aliases=sorted(found["aliases"]),
                ),
            )
        )
    return sorted(views, key=lambda view: (view.retires_on, view.provider, view.model))


class ModelInventoryItemView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    route: Literal["registry", "catalog"]
    registered: bool
    deployment_id: UUID | None
    alias: str | None
    provider: str | None
    model: str | None = Field(
        description="The registry's upstream model, or the model a catalog request named."
    )
    deployment_kind: str | None
    declared_version: str | None
    owner: str | None
    enabled: bool | None
    health: str | None
    requests: int = Field(ge=0)
    first_seen: datetime | None
    last_seen: datetime | None
    api_keys: int = Field(ge=0)
    teams: int = Field(ge=0)
    byok_requests: int = Field(
        ge=0, description="Requests that carried their own provider key."
    )


class ModelInventoryView(BaseModel):
    start: datetime
    end: datetime
    items: list[ModelInventoryItemView]
    truncated: bool
    registry_deployments: int = Field(ge=0)
    catalog_models: int = Field(ge=0)
    requests: int = Field(ge=0)
    byok_requests: int = Field(ge=0)


@router.get("/model-inventory", response_model=ModelInventoryView)
async def model_inventory(
    start: datetime | None = Query(
        default=None, description="Inclusive start; defaults to 30 days before end."
    ),
    end: datetime | None = Query(
        default=None, description="Exclusive end; defaults to the current time."
    ),
    user: User = Depends(require("deployments.read", legacy_detail=READER_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> ModelInventoryView:
    start_at, end_at = _sync_window(start, end, days=30)
    inventory = await ModelInventoryReadModel().read(
        session, tenant_id=_tenant_id(user), start_at=start_at, end_at=end_at
    )
    return ModelInventoryView.model_validate(
        {**asdict(inventory), "start": start_at, "end": end_at}
    )


@router.post("/model-deployments", response_model=ModelDeploymentView, status_code=201)
async def create_model_deployment(
    payload: ModelDeploymentInput,
    request: Request,
    user: User = Depends(require("deployments.manage", legacy_detail=ADMIN_REQUIRED)),
    session: AsyncSession = Depends(get_db),
):
    item = str(uuid4())
    after = await DEPLOYMENTS.validate(session, user, None, None, payload.model_dump())
    destinations = await _admit_bedrock(session, user, request, None, after)
    await _managed_write(session, user, DEPLOYMENTS, item, None, after)
    await _store_destinations(session, UUID(item), destinations)
    await session.commit()
    return await _refreshed(session, ModelDeployment, UUID(item))


@router.put("/model-deployments/{deployment_id}", response_model=ModelDeploymentView)
async def update_model_deployment(
    deployment_id: UUID,
    payload: ModelDeploymentInput,
    request: Request,
    user: User = Depends(require("deployments.manage", legacy_detail=ADMIN_REQUIRED)),
    session: AsyncSession = Depends(get_db),
):
    tenant_id, item = _tenant_id(user), str(deployment_id)
    await lock_tenant(session, tenant_id)
    before = (await DEPLOYMENTS.snapshot(session, tenant_id, [item])).get(item)
    if before is None:
        raise HTTPException(404, detail="Model deployment not found")
    # A client that predates these fields never erases them.
    after = await DEPLOYMENTS.validate(
        session,
        user,
        item,
        before,
        payload.model_dump(exclude=set(_KEPT_WHEN_ABSENT - payload.model_fields_set)),
    )
    destinations = await _admit_bedrock(session, user, request, before, after)
    await _managed_write(session, user, DEPLOYMENTS, item, before, after)
    await _store_destinations(session, deployment_id, destinations)
    await session.commit()
    return await _refreshed(session, ModelDeployment, deployment_id)


_UNSET: Any = object()


async def _destinations(
    session: AsyncSession, user: User, client: httpx.AsyncClient, state: State
) -> list[str] | None:
    """Where an aws_bedrock deployment can route; None when Bedrock does not say."""
    region, model = state["aws_region"], state["upstream_model"]
    if not is_profile(model):
        return [region]
    secret = await _owned_provider_secret(
        session, user, UUID(str(state["provider_secret_id"]))
    )
    try:
        async with asyncio.timeout(5):
            token = await _fresh_resolver(state["provider"], client).resolve_row(
                TenantId(_tenant_id(user)),
                secret,
                CredentialReference(secret.id, region),
            )
            return await fetch_destinations(client, token, region, model)
    except (httpx.HTTPError, ValueError, TimeoutError, ProviderCallError):
        return None


async def _admit_bedrock(
    session: AsyncSession,
    user: User,
    request: Request,
    before: State | None,
    after: State,
) -> Any:
    """Fresh destinations when a Bedrock deployment is created or moves (else
    _UNSET), refused with 422 when an enforced lock or the ceiling refuses them."""
    if after["upstream"] != "aws_bedrock" or (
        before is not None
        and before["upstream"] == "aws_bedrock"
        and (before["aws_region"], before["upstream_model"])
        == (after["aws_region"], after["upstream_model"])
    ):
        return _UNSET
    destinations = await _destinations(
        session, user, request.app.state.http_client, after
    )
    tenant_id = _tenant_id(user)
    stored = await session.scalar(
        select(OrganizationGatewaySettings.settings).where(
            OrganizationGatewaySettings.organization_id == tenant_id
        )
    )
    lock = (
        GatewaySettings() if stored is None else stored_settings(stored)
    ).bedrock_region_lock
    organization = await session.get(Organization, tenant_id)
    ceiling = await tier_ceiling(session, organization.tier if organization else None)
    refused = (
        lock.mode == "enforce"
        and lock_reasons(lock, profile_scope(after["upstream_model"]), destinations)
    ) or not ceiling_allows(ceiling, destinations)
    if refused:
        raise HTTPException(
            422,
            detail={
                "code": "BEDROCK_REGION_NOT_ALLOWED",
                "message": "The Bedrock deployment's inference profile can route "
                "outside the regions this tenant allows.",
            },
        )
    return destinations


async def _store_destinations(
    session: AsyncSession, deployment_id: UUID, destinations: Any
) -> None:
    if destinations is _UNSET:
        return
    row = await session.get(ModelDeployment, deployment_id)
    assert row is not None
    row.aws_destination_regions = destinations
    row.aws_destinations_checked_at = datetime.now(timezone.utc)


@router.post(
    "/model-deployments/{deployment_id}/health", response_model=ModelDeploymentView
)
async def check_model_deployment_health(
    deployment_id: UUID,
    request: Request,
    user: User = Depends(require("deployments.manage", legacy_detail=ADMIN_REQUIRED)),
    session: AsyncSession = Depends(get_db),
):
    row = await _owned_model_deployment(session, user, deployment_id)
    secret = await _owned_provider_secret(session, user, row.provider_secret_id)
    try:
        base_url = validate_deployment_url(row.base_url)
    except ValueError:
        raise HTTPException(
            503, detail="Deployment origin is no longer approved"
        ) from None
    checked_version = row.updated_at
    provider, upstream, tenant_id = row.provider, row.upstream, _tenant_id(user)
    region, model = row.aws_region, row.upstream_model
    # Finish the read transaction before secret-store or provider I/O.
    await session.commit()
    client = request.app.state.http_client
    healthy = False
    destinations: list[str] | None = None
    try:
        async with asyncio.timeout(5):
            credential = await _fresh_resolver(provider, client).resolve_row(
                TenantId(tenant_id),
                secret,
                CredentialReference(secret.id, region),
            )
            if upstream == "aws_bedrock":
                assert region is not None
                # Bedrock's control plane answers whether the key reaches the model.
                url = bedrock_model_url(region, model)
                headers = {"Authorization": f"Bearer {credential}"}
            else:
                headers = (
                    {"Authorization": f"Bearer {credential}"}
                    if provider == "openai"
                    else {"x-api-key": credential, "anthropic-version": "2023-06-01"}
                )
                url = base_url + ("/models" if provider == "openai" else "/v1/models")
            # Stream headers only: an unhealthy server cannot force an unbounded body read.
            async with client.stream(
                "GET",
                url,
                headers=headers,
                timeout=5,
                follow_redirects=False,
            ) as response:
                # Azure documents no v1 model listing: a 404 still proves the credential.
                healthy = response.status_code in (
                    {200, 404} if upstream == "azure_openai" else {200}
                )
            if upstream == "aws_bedrock":
                assert region is not None
                destinations = await fetch_destinations(
                    client, credential, region, model
                )
    except (httpx.HTTPError, ValueError, TimeoutError, ProviderCallError):
        healthy = False
    # Locked, so an update committing now cannot be overwritten by a stale result.
    row = await _owned_model_deployment(session, user, deployment_id, for_update=True)
    if row.updated_at != checked_version:
        raise HTTPException(
            409, detail="Deployment changed during health check; check again"
        )
    row.health = "healthy" if healthy else "unhealthy"
    row.health_checked_at = datetime.now(timezone.utc)
    if upstream == "aws_bedrock":
        row.aws_destination_regions = destinations
        row.aws_destinations_checked_at = row.health_checked_at
    await _audit(
        session,
        user,
        "tenant.model_deployment_health_checked",
        str(row.id),
        details={"health": row.health, "declared_version": row.declared_version},
    )
    await session.commit()
    await session.refresh(row)
    return row


async def _owned_model_deployment(
    session: AsyncSession,
    user: User,
    deployment_id: UUID,
    *,
    for_update: bool = False,
) -> ModelDeployment:
    statement = (
        select(ModelDeployment)
        .where(
            ModelDeployment.id == deployment_id,
            ModelDeployment.organization_id == _tenant_id(user),
        )
        .execution_options(populate_existing=True)
    )
    if for_update:
        statement = statement.with_for_update()
    row = (await session.execute(statement)).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, detail="Model deployment not found")
    return row


_DEPLOYMENT_DIRECTIONS: Directions = {
    "enabled": toward(True),
    "deployment_kind": toward("internal"),
    # Labels and the upstream wait: none lets a refused request through.
    "declared_version": neutral,
    "owner": neutral,
    "timeout_seconds": neutral,
    # A planning figure: what the forecast compares with, never a limit.
    "capacity_concurrent_requests": neutral,
}


def _deployment_state(values: Mapping[str, Any]) -> State:
    return {field: _plain(values[field]) for field in ModelDeploymentInput.model_fields}


class _DeploymentResource:
    name = "deployments"
    permission: Permission = "deployments.manage"
    creatable = True
    deletable = False

    async def snapshot(
        self,
        session: AsyncSession,
        organization_id: UUID,
        item_ids: Collection[str] | None,
    ) -> dict[str, State]:
        statement = select(ModelDeployment).where(
            ModelDeployment.organization_id == organization_id
        )
        if item_ids is not None:
            statement = statement.where(ModelDeployment.id.in_(_uuids(item_ids)))
        return {
            str(row.id): _deployment_state(
                {
                    field: getattr(row, field)
                    for field in ModelDeploymentInput.model_fields
                }
            )
            for row in await session.scalars(statement)
        }

    async def validate(
        self,
        session: AsyncSession,
        actor: User,
        item_id: str | None,
        before: State | None,
        proposed: State,
    ) -> State:
        merged = {**(before or {}), **proposed}
        if merged.get("upstream") == "aws_bedrock" and "base_url" not in proposed:
            # Derived from the region: a change that moves the region moves it too.
            merged["base_url"] = None
        payload = _validated(ModelDeploymentInput, merged)
        secret = await _owned_provider_secret(
            session, actor, payload.provider_secret_id
        )
        if (secret.credential_kind != "api_key") != (payload.upstream == "aws_bedrock"):
            raise HTTPException(
                422,
                detail="An AWS credential serves only Amazon Bedrock deployments, "
                "and a Bedrock deployment only an AWS credential",
            )
        if secret.provider == "azure_entra":
            if (payload.provider, payload.upstream) != ("openai", "azure_openai"):
                raise HTTPException(
                    422,
                    detail="An Entra credential can only serve an Azure OpenAI "
                    "deployment",
                )
        elif secret.provider != payload.provider:
            raise HTTPException(
                422, detail="Credential provider does not match deployment"
            )
        # The input model sets base_url for every upstream, derived or given.
        assert payload.base_url is not None
        if payload.deployment_kind == "internal" and not internal_origin_approved(
            payload.base_url
        ):
            raise HTTPException(
                422,
                detail="Deployment origin is not an operator-approved internal origin",
            )
        return _deployment_state(payload.model_dump())

    async def apply(
        self,
        session: AsyncSession,
        actor: User,
        organization_id: UUID,
        item_id: str,
        before: State | None,
        after: State | None,
        *,
        policy_version: int | None,
    ) -> None:
        assert after is not None
        payload = _validated(ModelDeploymentInput, after)
        configuration = payload.model_dump()
        if before is None:
            row = ModelDeployment(
                id=UUID(item_id), organization_id=organization_id, **configuration
            )
            session.add(row)
            action, details = (
                "tenant.model_deployment_created",
                {"configuration": payload.model_dump(mode="json")},
            )
        else:
            # Locked, like the health result, so neither write can overwrite the other.
            row = await _owned_model_deployment(
                session, actor, UUID(item_id), for_update=True
            )
            previous = {field: getattr(row, field) for field in configuration}
            for field, value in configuration.items():
                setattr(row, field, value)
            row.health, row.health_checked_at = "unknown", None
            action, details = (
                "tenant.model_deployment_updated",
                change_details(previous, configuration),
            )
        try:
            await session.flush()
        except IntegrityError:
            await session.rollback()
            raise HTTPException(
                409, detail="Model alias already exists or credential is unavailable"
            ) from None
        await _audit(
            session,
            actor,
            action,
            item_id,
            details={**details, **version_detail(policy_version)},
        )
        # Destination rules let an internal target see what an external one may not,
        # so becoming internal, or an internal target moving, relaxes them.
        relaxed = [
            f"{field}.{item_id}"
            for field in ("deployment_kind", "base_url")
            if before is not None
            and after["deployment_kind"] == "internal"
            and before[field] != after[field]
        ]
        if relaxed:
            await _record_privacy_relaxed(
                session, actor, organization_id, relaxed, policy_version
            )

    def classify(self, before: State | None, after: State | None) -> Risk:
        if before is None:
            return "relaxing"
        assert after is not None
        return classify_fields(before, after, _DEPLOYMENT_DIRECTIONS)[0]

    async def impact(
        self,
        session: AsyncSession,
        organization_id: UUID,
        item_id: str,
        before: State | None,
        after: State | None,
        window_days: int,
    ) -> Impact:
        if before is None or after is None:
            return _counted(0, window_days)
        if not (
            (before["enabled"] and not after["enabled"])
            or before["base_url"] != after["base_url"]
            or before["upstream_model"] != after["upstream_model"]
        ):
            return no_impact(window_days)
        return _counted(
            await _lifecycle_count(
                session,
                organization_id,
                window_days,
                or_(
                    RequestLifecycle.requested_model == before["alias"],
                    RequestLifecycle.lifecycle_metadata["deployment_id"].as_string()
                    == item_id,
                ),
            ),
            window_days,
        )


DEPLOYMENTS = _DeploymentResource()
