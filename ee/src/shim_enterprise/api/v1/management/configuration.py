"""Privacy, rule set, gateway settings, provider-key settings and tier routes."""

from __future__ import annotations

from collections.abc import Collection, Mapping
from datetime import datetime
from typing import Any, Literal, get_args
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator
from sqlalchemy import ColumnDefault, inspect, or_, select
from sqlalchemy.dialects.postgresql import array as sql_array, insert
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.api.enterprise_deps import (
    ADMIN_REQUIRED,
    READER_REQUIRED,
    get_current_user,
    require,
)
from shim_enterprise.archive.service import shorten_retention
from shim.gateway.analyzers import ANALYZERS
from shim.rules import KINDS, LIMITS, Rule, load_rule_set
from shim_enterprise.billing.models import RequestLifecycle
from shim_enterprise.cache.redis_index import CacheManager, CacheService
from shim_enterprise.core.database import get_db
from shim_enterprise.findings.service import apply_modes, finding_ladder
from shim.privacy.policies import (
    PII_CONFIG_DEFAULTS,
    EntityAction,
    effective_entity_actions,
)
from shim_enterprise.tenants.audit import (
    change_details,
    record_management_action as _audit,
)
from shim_enterprise.rules.models import OrganizationRuleSet
from shim_enterprise.rules.preview import checked_set
from shim_enterprise.rules.resource import (
    RULES,
    rule_changes,
    rule_set_row,
    store_rule_set,
)
from shim_enterprise.tenants.gateway_settings import (
    SETTING_AVAILABILITY,
    GatewaySettings,
    GatewaySettingsPatch,
    SemanticCheckSettings,
    SemanticReviewSettings,
    classify_change,
    restore_relaxed,
    patched,
    classify_fields,
    stored_settings,
    toward,
)
from shim_enterprise.semantic.models import OrganizationSemanticQuestions
from shim_enterprise.tenants.models import (
    ApiKey,
    ModelDeployment,
    OrganizationGatewaySettings,
    Organization,
    OrganizationPIIConfig,
    RecordSet,
    TierDefinition,
    Team,
    User,
)
from shim_enterprise.policy.plans import (
    Impact,
    Risk,
    State,
    lock_tenant,
    no_impact,
    record_managed_write,
    require_two_approvers,
    version_detail,
)
from shim_enterprise.tenants.permissions import Permission
from shim_enterprise.tenants.service import ensure_privacy_defaults
from shim_enterprise.api.v1.management._common import (
    _counted,
    _lifecycle_count,
    _lowered,
    _managed_write,
    _only,
    _raised,
    _record_privacy_relaxed,
    _tenant,
    _tenant_id,
    _validated,
    bounded_body,
    logger,
)


router = APIRouter()


class PrivacySettings(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    block_email: bool
    block_phone: bool
    block_credit_card: bool
    block_secrets: bool
    block_pii_tr: bool
    entity_actions: dict[str, EntityAction] = Field(
        description="Stored per-type overrides of the group switches."
    )
    bulk_threshold: int | None = Field(
        description=(
            "Distinct detected values in one request that raise a bulk-disclosure "
            "alert; null turns the alarm off."
        )
    )
    response_scan: Literal["off", "count"] = Field(
        description=(
            "count: after an answer is delivered, count personal data in it that "
            "the request did not carry. The answer is never changed or delayed."
        )
    )
    placeholder_mode: Literal["random", "stable"] = Field(
        description=(
            "random: a new placeholder per request. stable: the same value keeps "
            "its placeholder for up to 30 days, so provider prompt caching works "
            "and the provider can link the value across requests; that linkage "
            "can stay in provider logs after the window ends."
        )
    )
    embeddings_monitor_types: list[str] = Field(
        description=(
            "Entity types an embeddings request only counts and sends unchanged "
            "where their action masks or blocks them; chat keeps the action."
        )
    )

    @computed_field(description="The action every entity type gets.")
    @property
    def effective_actions(self) -> dict[str, EntityAction]:
        return effective_entity_actions(
            {field: getattr(self, field) for field in PII_CONFIG_DEFAULTS},
            self.entity_actions,
        )


class ProviderKeySettings(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    allow_customer_provider_keys: bool = Field(
        description=(
            "When false, a request carrying its own provider key (x-provider-key) "
            "on a catalog route is refused with 403 PROVIDER_KEY_NOT_ALLOWED."
        )
    )


class PrivacyPatch(BaseModel):
    block_email: bool | None = None
    block_phone: bool | None = None
    block_credit_card: bool | None = None
    block_secrets: bool | None = None
    block_pii_tr: bool | None = None
    entity_actions: dict[str, EntityAction] = Field(
        default_factory=dict,
        description="Replaces the stored overrides whole; {} removes them all.",
    )
    placeholder_mode: Literal["random", "stable"] | None = Field(
        default=None, description="Left unchanged when absent; never null."
    )
    response_scan: Literal["off", "count"] | None = Field(
        default=None, description="Left unchanged when absent; never null."
    )
    bulk_threshold: int | None = Field(
        default=None,
        ge=2,
        le=2_147_483_647,
        description="null turns the alarm off; left unchanged when absent.",
    )
    embeddings_monitor_types: list[str] | None = Field(
        default=None,
        description="Replaces the stored list whole; left unchanged when absent.",
    )

    @field_validator("placeholder_mode", "response_scan", "embeddings_monitor_types")
    @classmethod
    def reject_null[Value](cls, value: Value | None) -> Value:
        # None is only the absent default; the columns are NOT NULL.
        if value is None:
            raise ValueError("must not be null")
        return value

    @field_validator("embeddings_monitor_types")
    @classmethod
    def known_monitor_types(cls, value: list[str]) -> list[str]:
        unknown = sorted(set(value) - set(effective_entity_actions()))
        if unknown:
            raise ValueError(f"unknown entity type: {', '.join(unknown)}")
        return sorted(set(value))

    @field_validator("entity_actions")
    @classmethod
    def known_entity_types(
        cls, value: dict[str, EntityAction]
    ) -> dict[str, EntityAction]:
        effective_entity_actions(None, value)
        return value


class TierView(BaseModel):
    tier: str
    name: str
    rate_limit_rpm: int
    rate_limit_tpm: int
    daily_request_limit: int | None
    monthly_request_limit: int
    monthly_token_limit: int


class RuleKindView(BaseModel):
    available: bool
    actions: list[str]
    unavailable_reason: str | None


class RuleSetView(BaseModel):
    revision: int = Field(ge=0)
    rules: list[Rule]
    unavailable_rules: list[dict[str, Any]] = Field(
        description="Stored rules this release cannot run, as stored. A PUT keeps "
        "them; an enforced one refuses the requests in its scope with RULE_BLOCKED."
    )
    updated_by: str | None
    updated_at: datetime | None
    limits: dict[str, Any]
    kinds: dict[str, RuleKindView]


class RuleSetPut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    revision: int = Field(ge=0, description="The revision this set was read at.")
    rules: list[dict[str, Any]]


class GatewaySettingsView(BaseModel):
    settings: GatewaySettings
    revision: int = Field(ge=0)
    updated_at: datetime | None
    updated_by: UUID | None
    available_analyzers: list[str]
    unavailable: dict[str, str] = Field(
        description='Per field, why it is "off, needs X"; empty when everything is available.'
    )
    request_archive_state: Literal["on", "off"] = Field(
        description="on only when this installation allows the archive and the "
        "tenant turned it on."
    )


@router.get("/settings/pii", response_model=PrivacySettings)
async def get_privacy_settings(
    user: User = Depends(require("settings.read")),
    session: AsyncSession = Depends(get_db),
) -> Any:
    row = await ensure_privacy_defaults(session, _tenant_id(user))
    await session.commit()
    await session.refresh(row)
    return row


@router.put("/settings/pii", response_model=PrivacySettings)
async def update_privacy_settings(
    patch: PrivacyPatch,
    request: Request,
    user: User = Depends(require("settings.write", legacy_detail=ADMIN_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> Any:
    tenant_id = _tenant_id(user)
    await lock_tenant(session, tenant_id)
    before = (await PRIVACY.snapshot(session, tenant_id, None))["_"]
    after = {**before, **patch.model_dump(mode="json", exclude_unset=True)}
    await _managed_write(session, user, PRIVACY, "_", before, after)
    await session.commit()
    await PRIVACY.after_commit(request, tenant_id)
    row = await ensure_privacy_defaults(session, tenant_id)
    await session.refresh(row)
    return row


def _rule_set_view(row: OrganizationRuleSet | None) -> RuleSetView:
    stored = (
        load_rule_set(row.revision, row.rules)
        if row is not None and row.rules
        else None
    )
    return RuleSetView(
        revision=row.revision if row is not None else 0,
        rules=list(stored.rules) if stored is not None else [],
        unavailable_rules=[rule.stored for rule in stored.unusable]
        if stored is not None
        else [],
        updated_by=row.updated_by if row is not None else None,
        updated_at=row.updated_at if row is not None else None,
        limits=LIMITS,
        kinds={
            kind: RuleKindView(
                available=spec.match is not None,
                actions=list(spec.actions),
                unavailable_reason=None
                if spec.match is not None
                else "Not available in this release.",
            )
            for kind, spec in KINDS.items()
        },
    )


@router.get("/rules", response_model=RuleSetView)
async def get_rules(
    user: User = Depends(require("rules.read", legacy_detail=READER_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> RuleSetView:
    return _rule_set_view(await session.get(OrganizationRuleSet, _tenant_id(user)))


async def replace_rules(
    payload: RuleSetPut,
    request: Request,
    user: User = Depends(require("rules.write", legacy_detail=ADMIN_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> RuleSetView:
    tenant_id = _tenant_id(user)
    await lock_tenant(session, tenant_id)
    row = await rule_set_row(session, tenant_id)
    if payload.revision != row.revision:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "RULE_SET_REVISION_CONFLICT",
                "message": "The rule set changed since it was read; read it again.",
                "revision": row.revision,
            },
        )
    after = checked_set(row.revision + 1, payload.rules)
    changes = rule_changes(await RULES.snapshot(session, tenant_id, None), after)
    async with record_managed_write(
        session, user, tenant_id, changes, source="api"
    ) as version:
        await store_rule_set(
            session, user, row, after, source="api", policy_version=version
        )
    await session.commit()
    await RULES.after_commit(request, tenant_id)
    await session.refresh(row)
    return _rule_set_view(row)


router.add_api_route(
    "/rules",
    replace_rules,
    methods=["PUT"],
    response_model=RuleSetView,
    route_class_override=bounded_body(
        LIMITS["request_bytes"], "A rule set is at most 1,000,000 bytes."
    ),
)


def _gateway_settings_view(
    row: OrganizationGatewaySettings | None,
) -> GatewaySettingsView:
    if row is None:
        settings, revision, updated_at, updated_by = GatewaySettings(), 0, None, None
    else:
        settings = stored_settings(row.settings)
        revision, updated_at, updated_by = row.revision, row.updated_at, row.updated_by
    return GatewaySettingsView(
        settings=settings,
        revision=revision,
        updated_at=updated_at,
        updated_by=updated_by,
        available_analyzers=[analyzer.name for analyzer in ANALYZERS],
        unavailable={
            field: reason
            for field, available in SETTING_AVAILABILITY.items()
            if (reason := available()) is not None
        },
        request_archive_state="on"
        if settings.request_archive.enabled
        and SETTING_AVAILABILITY["request_archive"]() is None
        else "off",
    )


@router.get("/gateway-settings", response_model=GatewaySettingsView)
async def get_gateway_settings(
    user: User = Depends(require("settings.read")),
    session: AsyncSession = Depends(get_db),
) -> GatewaySettingsView:
    return _gateway_settings_view(
        await session.get(OrganizationGatewaySettings, _tenant_id(user))
    )


@router.patch("/gateway-settings", response_model=GatewaySettingsView)
async def update_gateway_settings(
    patch: GatewaySettingsPatch,
    request: Request,
    user: User = Depends(require("settings.write", legacy_detail=ADMIN_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> GatewaySettingsView:
    tenant_id = _tenant_id(user)
    await lock_tenant(session, tenant_id)
    before = (await GATEWAY_SETTINGS.snapshot(session, tenant_id, None))["_"]
    after = await GATEWAY_SETTINGS.validate(
        session, user, "_", before, patch.model_dump(mode="json", exclude_unset=True)
    )
    async with record_managed_write(
        session, user, tenant_id, [(GATEWAY_SETTINGS, "_", before, after)], source="api"
    ) as version:
        if version is not None:
            await GATEWAY_SETTINGS.apply(
                session, user, tenant_id, "_", before, after, policy_version=version
            )
    await session.commit()
    await GATEWAY_SETTINGS.after_commit(request, tenant_id)
    return _gateway_settings_view(
        await session.get(
            OrganizationGatewaySettings, tenant_id, populate_existing=True
        )
    )


@router.get("/settings/provider-keys", response_model=ProviderKeySettings)
async def get_provider_key_settings(
    user: User = Depends(require("settings.read")),
    session: AsyncSession = Depends(get_db),
) -> Any:
    return await _tenant(session, user)


@router.put("/settings/provider-keys", response_model=ProviderKeySettings)
async def update_provider_key_settings(
    payload: ProviderKeySettings,
    user: User = Depends(require("settings.write", legacy_detail=ADMIN_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> Any:
    tenant_id = _tenant_id(user)
    await lock_tenant(session, tenant_id)
    before = (await PROVIDER_KEYS.snapshot(session, tenant_id, None))["_"]
    await _managed_write(
        session, user, PROVIDER_KEYS, "_", before, payload.model_dump()
    )
    await session.commit()
    return await session.get(Organization, tenant_id)


@router.get("/tier-info", response_model=TierView)
async def tier_info(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> TierView:
    tier = (
        await session.execute(
            select(TierDefinition)
            .join(Organization, Organization.tier == TierDefinition.slug)
            .where(Organization.id == _tenant_id(user))
        )
    ).scalar_one_or_none()
    if tier is None:
        raise HTTPException(
            status_code=503, detail="Organization tier is not configured"
        )
    return TierView(
        tier=tier.slug,
        name=tier.name,
        rate_limit_rpm=tier.rate_limit_rpm,
        rate_limit_tpm=tier.rate_limit_tpm,
        daily_request_limit=tier.daily_request_limit,
        monthly_request_limit=tier.monthly_request_limit,
        monthly_token_limit=tier.monthly_token_limit,
    )


def _privacy_relaxed(before: Mapping[str, Any], after: Mapping[str, Any]) -> list[str]:
    actions = get_args(EntityAction)
    relaxed = [
        field for field in PII_CONFIG_DEFAULTS if before[field] and not after[field]
    ]
    if before["placeholder_mode"] == "random" and after["placeholder_mode"] == "stable":
        relaxed.append("placeholder_mode")
    if _raised(before["bulk_threshold"], after["bulk_threshold"]):
        relaxed.append("bulk_threshold")
    if before["response_scan"] == "count" and after["response_scan"] == "off":
        relaxed.append("response_scan")
    relaxed += [
        f"embeddings_monitor_types.{kind}"
        for kind in sorted(
            set(after["embeddings_monitor_types"])
            - set(before["embeddings_monitor_types"])
        )
    ]
    return relaxed + [
        f"entity_actions.{entity_type}"
        for entity_type, action in after["effective_actions"].items()
        if actions.index(action)
        < actions.index(before["effective_actions"][entity_type])
        and before["entity_actions"].get(entity_type)
        != after["entity_actions"].get(entity_type)
    ]


def _privacy_tightened(before: Mapping[str, Any], after: Mapping[str, Any]) -> bool:
    actions = get_args(EntityAction)
    return (
        any(not before[field] and after[field] for field in PII_CONFIG_DEFAULTS)
        or (before["placeholder_mode"], after["placeholder_mode"])
        == ("stable", "random")
        or _lowered(before["bulk_threshold"], after["bulk_threshold"])
        or (before["response_scan"], after["response_scan"]) == ("off", "count")
        or bool(
            set(before["embeddings_monitor_types"])
            - set(after["embeddings_monitor_types"])
        )
        or any(
            actions.index(action) > actions.index(before["effective_actions"][kind])
            for kind, action in after["effective_actions"].items()
        )
    )


# A field newer than a stored version takes its column default when it is restored.
_PRIVACY_DEFAULTS = {
    field: default.arg(None) if default.is_callable else default.arg
    for field in PrivacySettings.model_fields
    if isinstance(
        default := inspect(OrganizationPIIConfig).columns[field].default, ColumnDefault
    )
}


def _privacy_settings(state: State) -> PrivacySettings:
    return PrivacySettings.model_validate({**_PRIVACY_DEFAULTS, **state})


class _PrivacyResource:
    name = "privacy"
    permission: Permission = "settings.write"
    creatable = False
    deletable = False

    async def snapshot(
        self,
        session: AsyncSession,
        organization_id: UUID,
        item_ids: Collection[str] | None,
    ) -> dict[str, State]:
        row = await ensure_privacy_defaults(session, organization_id)
        return {
            "_": PrivacySettings.model_validate(row).model_dump(
                mode="json", exclude={"effective_actions"}
            )
        }

    async def validate(
        self,
        session: AsyncSession,
        actor: User,
        item_id: str | None,
        before: State | None,
        proposed: State,
    ) -> State:
        patch = _validated(PrivacyPatch, proposed)
        return {**(before or {}), **patch.model_dump(mode="json", exclude_unset=True)}

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
        row = await ensure_privacy_defaults(session, organization_id)
        previous = PrivacySettings.model_validate(row).model_dump()
        values = _privacy_settings(after)
        for field in PrivacySettings.model_fields:
            setattr(row, field, getattr(values, field))
        current = PrivacySettings.model_validate(row).model_dump()
        await _audit(
            session,
            actor,
            "tenant.privacy_policy_updated",
            str(organization_id),
            details={
                **change_details(
                    {field: previous[field] for field in PrivacySettings.model_fields},
                    {field: current[field] for field in PrivacySettings.model_fields},
                ),
                **version_detail(policy_version),
            },
        )
        relaxed = _privacy_relaxed(previous, current)
        if relaxed:
            await _record_privacy_relaxed(
                session, actor, organization_id, relaxed, policy_version
            )

    def classify(self, before: State | None, after: State | None) -> Risk:
        assert before is not None and after is not None
        previous = _privacy_settings(before).model_dump()
        current = _privacy_settings(after).model_dump()
        if _privacy_relaxed(previous, current):
            return "relaxing"
        return "tightening" if _privacy_tightened(previous, current) else "neutral"

    async def impact(
        self,
        session: AsyncSession,
        organization_id: UUID,
        item_id: str,
        before: State | None,
        after: State | None,
        window_days: int,
    ) -> Impact:
        assert before is not None and after is not None
        previous = _privacy_settings(before).effective_actions
        current = _privacy_settings(after).effective_actions
        changed = sorted(kind for kind in current if current[kind] != previous[kind])
        if any(previous[kind] == "off" for kind in changed):
            return no_impact(window_days, "type was off; start with monitor")
        if not changed:
            return _counted(0, window_days)
        metadata = RequestLifecycle.lifecycle_metadata
        return _counted(
            await _lifecycle_count(
                session,
                organization_id,
                window_days,
                or_(
                    *(
                        metadata[key].has_any(sql_array(changed))
                        for key in (
                            "pii_entities",
                            "monitored_entities",
                            "blocked_entities",
                        )
                    )
                ),
            ),
            window_days,
        )

    async def after_commit(self, request: Request, organization_id: UUID) -> None:
        try:
            cache: CacheService = request.app.state.cache
            await CacheManager(cache).invalidate_pii_config(str(organization_id))
        except Exception as exc:
            logger.warning(
                "PII policy cache invalidation failed type=%s", type(exc).__name__
            )


async def _check_semantic_review(
    session: AsyncSession, tenant_id: UUID, review: SemanticReviewSettings
) -> None:
    """The review alias is a registered, enabled deployment and its key an active key
    of this organization that may call it."""
    alias = await session.scalar(
        select(ModelDeployment.alias).where(
            ModelDeployment.organization_id == tenant_id,
            ModelDeployment.alias == review.model,
            ModelDeployment.enabled.is_(True),
        )
    )
    if alias is None:
        raise HTTPException(
            422,
            detail="semantic_review.model is not an enabled deployment of this "
            "organization",
        )
    key = await session.scalar(
        select(ApiKey).where(
            ApiKey.organization_id == tenant_id,
            ApiKey.id == review.api_key_id,
            ApiKey.is_active.is_(True),
        )
    )
    if key is None:
        raise HTTPException(
            422,
            detail="semantic_review.api_key_id is not an active key of this "
            "organization",
        )
    if key.allowed_models is not None and alias not in key.allowed_models:
        raise HTTPException(
            422, detail="semantic_review.api_key_id may not call semantic_review.model"
        )


async def _check_semantic_check(
    session: AsyncSession, tenant_id: UUID, check: SemanticCheckSettings
) -> None:
    """The check model and key as for the review; scoped keys and questions exist."""
    await _check_semantic_review(
        session,
        tenant_id,
        SemanticReviewSettings(
            enabled=True, model=check.model, api_key_id=check.api_key_id
        ),
    )
    if check.scope.api_key_ids:
        known = set(
            await session.scalars(
                select(ApiKey.id).where(
                    ApiKey.organization_id == tenant_id,
                    ApiKey.id.in_(check.scope.api_key_ids),
                )
            )
        )
        if set(check.scope.api_key_ids) - known:
            raise HTTPException(
                422,
                detail="semantic_check.scope names api_key_ids this organization lacks",
            )
    if check.question_ids:
        questions = await session.scalar(
            select(OrganizationSemanticQuestions.questions).where(
                OrganizationSemanticQuestions.organization_id == tenant_id
            )
        )
        current = {question["id"] for question in questions or ()}
        if set(check.question_ids) - current:
            raise HTTPException(
                422,
                detail="semantic_check.question_ids names a question that is not set",
            )


class _GatewaySettingsResource:
    name = "gateway_settings"
    permission: Permission = "settings.write"
    creatable = False
    deletable = False

    async def snapshot(
        self,
        session: AsyncSession,
        organization_id: UUID,
        item_ids: Collection[str] | None,
    ) -> dict[str, State]:
        row = await session.get(OrganizationGatewaySettings, organization_id)
        settings = GatewaySettings() if row is None else stored_settings(row.settings)
        return {"_": settings.model_dump(mode="json")}

    async def validate(
        self,
        session: AsyncSession,
        actor: User,
        item_id: str | None,
        before: State | None,
        proposed: State,
    ) -> State:
        changes = _validated(GatewaySettingsPatch, proposed).model_dump(
            mode="json", exclude_unset=True
        )
        state = before or GatewaySettings().model_dump(mode="json")
        after = _validated(GatewaySettings, patched(state, changes))
        tenant_id = _tenant_id(actor)
        named = {
            kind
            for kind, grant in changes.get("restore_withheld", {}).items()
            if grant is not None
        }
        unknown = named - effective_entity_actions().keys()
        if unknown:
            rules = await session.scalar(
                select(OrganizationRuleSet.rules).where(
                    OrganizationRuleSet.organization_id == tenant_id
                )
            )
            labels = {
                rule["match"].get("label") for rule in rules or () if "match" in rule
            } | set(
                await session.scalars(
                    select(RecordSet.label).where(
                        RecordSet.organization_id == tenant_id
                    )
                )
            )
            if unknown - labels:
                raise HTTPException(
                    422,
                    detail="restore_withheld names no entity type or rule label: "
                    + ", ".join(sorted(unknown - labels)),
                )
        for setting, field, model, ids in (
            (
                "restore_withheld",
                "api_key_ids",
                ApiKey,
                {
                    key
                    for grant in after.restore_withheld.values()
                    for key in grant.api_key_ids
                },
            ),
            (
                "restore_withheld",
                "team_ids",
                Team,
                {
                    team
                    for grant in after.restore_withheld.values()
                    for team in grant.team_ids
                },
            ),
            (
                "inflight_sharing_api_key_ids",
                "api_key_ids",
                ApiKey,
                set(after.inflight_sharing_api_key_ids),
            ),
            ("tool_search", "api_key_ids", ApiKey, set(after.tool_search.api_key_ids)),
        ):
            known = (
                set(
                    await session.scalars(
                        select(model.id).where(
                            model.organization_id == tenant_id, model.id.in_(ids)
                        )
                    )
                )
                if ids and setting in changes
                else ids
            )
            if ids - known:
                raise HTTPException(
                    422, detail=f"{setting} names {field} this organization lacks"
                )
        aliases = set(after.provider_cache.deployments)
        if aliases and "provider_cache" in changes:
            rows = await session.execute(
                select(ModelDeployment.alias, ModelDeployment.upstream).where(
                    ModelDeployment.organization_id == tenant_id,
                    ModelDeployment.alias.in_(aliases),
                )
            )
            upstreams = {alias: upstream for alias, upstream in rows}
            if aliases - upstreams.keys():
                raise HTTPException(
                    422,
                    detail="provider_cache.deployments names a deployment this "
                    "organization lacks",
                )
            if "aws_bedrock" in upstreams.values():
                raise HTTPException(
                    422,
                    detail="Bedrock deployments cannot use automatic cache placement yet",
                )
        review = after.semantic_review
        if review.enabled and "semantic_review" in changes:
            await _check_semantic_review(session, tenant_id, review)
        check = after.semantic_check
        if check.enabled and "semantic_check" in changes:
            await _check_semantic_check(session, tenant_id, check)
        if "inference_metrics" in changes:
            internal = set(
                await session.scalars(
                    select(ModelDeployment.id).where(
                        ModelDeployment.organization_id == tenant_id,
                        ModelDeployment.deployment_kind == "internal",
                    )
                )
            )
            for index, source in enumerate(after.inference_metrics):
                if source.deployment_id not in internal:
                    raise HTTPException(
                        422,
                        detail=f"inference_metrics[{index}].deployment_id is not an "
                        "internal deployment of this organization",
                    )
        return after.model_dump(mode="json")

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
        assert before is not None and after is not None
        previous = GatewaySettings.model_validate(before)
        current = GatewaySettings.model_validate(after)
        # Here, not in validate: approvers are counted under the lock the write holds.
        if current.four_eyes == "relaxing" and previous.four_eyes != "relaxing":
            await require_two_approvers(session, organization_id)
        changed = {
            field
            for field in GatewaySettings.model_fields
            if getattr(previous, field) != getattr(current, field)
        }
        await session.execute(
            insert(OrganizationGatewaySettings)
            .values(organization_id=organization_id)
            .on_conflict_do_nothing()
        )
        row = await session.get(
            OrganizationGatewaySettings,
            organization_id,
            with_for_update=True,
            populate_existing=True,
        )
        assert row is not None
        # Only the changed fields are written; keys another build wrote stay.
        row.settings = {
            key: value for key, value in row.settings.items() if key not in changed
        } | current.model_dump(mode="json", include=changed, exclude_defaults=True)
        row.revision += 1
        row.updated_by = actor.id
        days = current.request_archive.retention_days
        if days < previous.request_archive.retention_days:
            await shorten_retention(session, organization_id, days)
        if "finding_modes" in changed:
            # A lowered mode takes the suggested action away now, not at the next pass.
            await apply_modes(
                session,
                organization_id,
                await finding_ladder(session, organization_id, current),
            )
        await _audit(
            session,
            actor,
            "tenant.gateway_settings_updated",
            str(organization_id),
            details={
                **change_details(
                    previous.model_dump(mode="json"), current.model_dump(mode="json")
                ),
                **version_detail(policy_version),
            },
        )
        _, relaxed = classify_change(previous, current)
        # Restore permission protects personal data, so it is a privacy relaxation.
        relaxed = [field for field in relaxed if field != "restore_withheld"]
        if relaxed:
            await _audit(
                session,
                actor,
                "tenant.gateway_protection_relaxed",
                str(organization_id),
                details={"relaxed": relaxed, **version_detail(policy_version)},
            )
        privacy_relaxed = restore_relaxed(
            previous.restore_withheld, current.restore_withheld
        )
        if privacy_relaxed:
            await _record_privacy_relaxed(
                session, actor, organization_id, privacy_relaxed, policy_version
            )

    def classify(self, before: State | None, after: State | None) -> Risk:
        assert before is not None and after is not None
        return classify_change(
            GatewaySettings.model_validate(before),
            GatewaySettings.model_validate(after),
        )[0]

    async def impact(
        self,
        session: AsyncSession,
        organization_id: UUID,
        item_id: str,
        before: State | None,
        after: State | None,
        window_days: int,
    ) -> Impact:
        return no_impact(window_days)

    async def after_commit(self, request: Request, organization_id: UUID) -> None:
        try:
            cache: CacheService = request.app.state.cache
            await CacheManager(cache).invalidate_gateway_settings(str(organization_id))
        except Exception as exc:
            logger.warning(
                "Gateway settings cache invalidation failed type=%s", type(exc).__name__
            )


class _ProviderKeysResource:
    name = "provider_keys"
    permission: Permission = "settings.write"
    creatable = False
    deletable = False

    async def snapshot(
        self,
        session: AsyncSession,
        organization_id: UUID,
        item_ids: Collection[str] | None,
    ) -> dict[str, State]:
        tenant = await session.get(Organization, organization_id)
        return {"_": ProviderKeySettings.model_validate(tenant).model_dump()}

    async def validate(
        self,
        session: AsyncSession,
        actor: User,
        item_id: str | None,
        before: State | None,
        proposed: State,
    ) -> State:
        _only(proposed, ProviderKeySettings.model_fields)
        return _validated(
            ProviderKeySettings, {**(before or {}), **proposed}
        ).model_dump()

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
        tenant = await session.get(Organization, organization_id)
        assert tenant is not None
        tenant.allow_customer_provider_keys = after["allow_customer_provider_keys"]
        await _audit(
            session,
            actor,
            "tenant.provider_key_policy_updated",
            str(organization_id),
            details={**change_details(before, after), **version_detail(policy_version)},
        )

    def classify(self, before: State | None, after: State | None) -> Risk:
        assert before is not None and after is not None
        return classify_fields(
            before, after, {"allow_customer_provider_keys": toward(True)}
        )[0]

    async def impact(
        self,
        session: AsyncSession,
        organization_id: UUID,
        item_id: str,
        before: State | None,
        after: State | None,
        window_days: int,
    ) -> Impact:
        return no_impact(window_days)


PRIVACY = _PrivacyResource()
GATEWAY_SETTINGS = _GatewaySettingsResource()


PROVIDER_KEYS = _ProviderKeysResource()
