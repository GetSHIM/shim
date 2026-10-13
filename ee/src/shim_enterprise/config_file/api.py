"""The configuration-file routes: mode, signing keys, export, plan and apply."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import hashlib
from typing import Any, Literal
from uuid import UUID

import yaml
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)
from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from shim.gateway.contracts.ids import TenantId
from shim_enterprise.api.enterprise_deps import require
from shim_enterprise.api.v1.management.configuration import PrivacySettings
from shim_enterprise.api.v1.management._common import (
    _managed_write,
    _tenant_id,
    bounded_body,
)
from shim_enterprise.compliance.services.forwarder import ComplianceForwarderService
from shim_enterprise.config_file import FILE_MANAGEABLE
from shim_enterprise.config_file.loader import (
    ConfigFileError,
    ConfigFileV1,
    load_config,
)
from shim_enterprise.config_file.models import (
    CONFIG_MODE,
    ConfigMode,
    ConfigSigningKey,
    OrganizationConfigMode,
    active_signing_keys,
)
from shim_enterprise.config_file.signing import key_id, verify_config_signature
from shim_enterprise.core.database import get_db
from shim_enterprise.policy.api import (
    PlanView,
    _after_commit,
    _apply_plan,
    new_plan,
    planned_change,
)
from shim_enterprise.policy.models import PolicyPlan, Risk
from shim_enterprise.policy.plans import (
    Change,
    State,
    combine_risk,
    current_version,
    lock_tenant,
    state_at,
)
from shim_enterprise.policy.resources import REGISTRY
from shim_enterprise.rules.models import OrganizationRuleSet
from shim_enterprise.rules.preview import checked_set
from shim_enterprise.rules.resource import RULES, rule_state
from shim_enterprise.tenants.audit import record_management_action as _audit
from shim_enterprise.tenants.gateway_settings import GatewaySettings
from shim_enterprise.tenants.models import OrganizationGatewaySettings, User
from shim_enterprise.tenants.permissions import user_permissions

router = APIRouter(prefix="/management/config", tags=["config"])

_MAX_BODY_BYTES = 1_100_000
# A file can rewrite a whole rule set; E32's limit of 100 stays for other sources.
_MAX_FILE_CHANGES = 250
_MAX_ACTIVE_KEYS = 10
_MAX_VERSION = 2_147_483_647


class ModeView(BaseModel):
    mode: Literal["api", "file"]
    resources: list[str]
    last_serial: int = Field(ge=0)
    last_applied_at: datetime | None
    active_signing_keys: int = Field(ge=0)


class SigningKeyInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    public_key_pem: str = Field(max_length=1000)
    user_id: UUID
    name: str = Field(min_length=1, max_length=100)


class SigningKeyView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    key_id: str
    name: str
    user_id: UUID
    created_by: str | None
    created_at: datetime
    revoked_at: datetime | None
    revoked_by: str | None


class FileInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file: str
    signature: str | None = Field(default=None, max_length=200)


class SignatureCheck(BaseModel):
    valid: bool
    key_id: str | None


class FilePlanView(BaseModel):
    stored: bool = False
    serial: int
    risk: Risk
    changes: list[dict[str, Any]]
    signature: SignatureCheck | None


class FileApplyView(BaseModel):
    status: Literal["applied", "pending_approval", "unchanged"]
    serial: int
    plan: PlanView | None = None
    policy_version: int | None = None


def _invalid(path: str, message: str) -> HTTPException:
    return HTTPException(
        status_code=422,
        detail={
            "code": "CONFIG_FILE_INVALID",
            "path": path,
            "message": message,
            "hint": "Fix the file at path and sign it again.",
        },
    )


def _section_error(error: HTTPException, prefix: str) -> HTTPException:
    """A resource's own 422 as a CONFIG_FILE_INVALID at its path in the file."""
    if error.status_code != 422:
        return error
    detail = error.detail
    if isinstance(detail, dict) and "path" in detail:
        return _invalid(f"{prefix}.{detail['path']}", str(detail.get("message", "")))
    if isinstance(detail, list) and detail and isinstance(detail[0], dict):
        loc = [str(part) for part in detail[0].get("loc", ())]
        return _invalid(".".join([prefix, *loc]), str(detail[0].get("msg", "")))
    return _invalid(prefix, str(detail))


async def _mode_row(
    session: AsyncSession, organization_id: UUID
) -> OrganizationConfigMode | None:
    return await session.get(OrganizationConfigMode, organization_id)


def _file_bytes(payload: FileInput) -> bytes:
    try:
        return payload.file.encode("utf-8")
    except UnicodeEncodeError:
        raise _invalid("file", "the file is not valid UTF-8") from None


async def _document(data: bytes, organization_id: UUID) -> ConfigFileV1:
    # Off the event loop: a megabyte of YAML takes the pure-Python parser a while.
    try:
        document = await asyncio.to_thread(load_config, data)
    except ConfigFileError as error:
        raise _invalid(error.path, str(error)) from None
    if document.organization_id != organization_id:
        raise _invalid("organization_id", "the file is for another organization")
    return document


async def _file_changes(
    session: AsyncSession,
    actor: User,
    organization_id: UUID,
    document: ConfigFileV1,
    managed: list[str] | None,
) -> list[Change]:
    """Each section against the current state; `managed` None accepts any subset."""
    sections = document.resources
    for name in sections:
        if name not in (managed if managed is not None else FILE_MANAGEABLE):
            raise _invalid(
                f"resources.{name}", "this resource is not managed by the file"
            )
    for name in managed or ():
        if name not in sections:
            raise _invalid(f"resources.{name}", "the file must hold this resource")
    if not sections:
        raise _invalid("resources", "the file manages no resource")
    changes: list[Change] = []
    for name in FILE_MANAGEABLE:
        if name not in sections:
            continue
        section, prefix = sections[name], f"resources.{name}"
        resource = REGISTRY[name]
        current = await resource.snapshot(session, organization_id, None)
        if name == "rules":
            if not isinstance(section, list):
                raise _invalid(prefix, "rules is a list of rules")
            try:
                proposed = {
                    rule.id: rule_state(rule) for rule in checked_set(1, section).rules
                }
            except HTTPException as error:
                raise _section_error(error, "resources") from None
            # Deletes first, then updates, then creates: set limits hold at every step.
            changes += [
                (RULES, item, current[item], None)
                for item in current
                if item not in proposed
            ]
            changes += [
                (RULES, item, current[item], state)
                for item, state in proposed.items()
                if item in current and current[item] != state
            ]
            changes += [
                (RULES, item, None, state)
                for item, state in proposed.items()
                if item not in current
            ]
            continue
        if not isinstance(section, dict):
            raise _invalid(prefix, f"{name} is a mapping of fields")
        before = current["_"]
        if name == "privacy":
            # Every field: the section is the whole truth, nothing is left as it was.
            for field in sorted(set(PrivacySettings.model_fields) ^ set(section)):
                raise _invalid(
                    f"{prefix}.{field}",
                    "unknown field" if field in section else "field required",
                )
            start: State = before
        else:
            # Fields the file leaves out take their defaults.
            start = GatewaySettings().model_dump(mode="json")
        try:
            after = await resource.validate(session, actor, "_", start, section)
        except HTTPException as error:
            raise _section_error(error, prefix) from None
        if after != before:
            changes.append((resource, "_", before, after))
    if len(changes) > _MAX_FILE_CHANGES:
        raise _invalid("resources", f"a file changes at most {_MAX_FILE_CHANGES} items")
    return changes


async def _planned(
    session: AsyncSession, organization_id: UUID, changes: list[Change]
) -> list[dict[str, Any]]:
    # A rule is previewed within the set the file leaves, not the stored one: at the
    # 100-rule limit a file deletes one rule before it adds another.
    kept = await RULES.snapshot(session, organization_id, None)
    for resource, item, _, after in changes:
        if resource is RULES:
            kept.pop(item, None)
            if after is not None:
                kept[item] = after
    planned = []
    for resource, item, before, after in changes:
        impact = (
            await RULES.impact(
                session,
                organization_id,
                item,
                before,
                after,
                7,
                others=[
                    {"id": other, **state}
                    for other, state in kept.items()
                    if other != item
                ],
            )
            if resource is RULES and after is not None
            else None
        )
        planned.append(
            await planned_change(
                session, organization_id, resource.name, item, before, after, 7, impact
            )
        )
    return planned


async def _mode_view(session: AsyncSession, organization_id: UUID) -> ModeView:
    row = await _mode_row(session, organization_id)
    return ModeView(
        mode="file" if row is not None and row.mode == "file" else "api",
        resources=list(row.resources) if row is not None else [],
        last_serial=row.last_serial if row is not None else 0,
        last_applied_at=row.last_applied_at if row is not None else None,
        active_signing_keys=await active_signing_keys(session, organization_id),
    )


@router.get("/mode", response_model=ModeView)
async def get_config_mode(
    user: User = Depends(require("settings.read")),
    session: AsyncSession = Depends(get_db),
) -> ModeView:
    return await _mode_view(session, _tenant_id(user))


@router.put("/mode", response_model=ModeView)
async def set_config_mode(
    payload: ConfigMode,
    user: User = Depends(require("config.manage")),
    session: AsyncSession = Depends(get_db),
) -> ModeView:
    organization_id = _tenant_id(user)
    await lock_tenant(session, organization_id)
    before = (await CONFIG_MODE.snapshot(session, organization_id, None))["_"]
    after = await CONFIG_MODE.validate(
        session, user, "_", before, payload.model_dump(mode="json")
    )
    await _managed_write(session, user, CONFIG_MODE, "_", before, after)
    await session.commit()
    return await _mode_view(session, organization_id)


@router.get("/signing-keys", response_model=list[SigningKeyView])
async def list_signing_keys(
    user: User = Depends(require("audit.read")),
    session: AsyncSession = Depends(get_db),
) -> list[ConfigSigningKey]:
    return list(
        await session.scalars(
            select(ConfigSigningKey)
            .where(ConfigSigningKey.organization_id == _tenant_id(user))
            .order_by(ConfigSigningKey.created_at, ConfigSigningKey.key_id)
        )
    )


@router.post("/signing-keys", response_model=SigningKeyView, status_code=201)
async def add_signing_key(
    payload: SigningKeyInput,
    user: User = Depends(require("config.manage")),
    session: AsyncSession = Depends(get_db),
) -> ConfigSigningKey:
    organization_id = _tenant_id(user)
    try:
        public_key = load_pem_public_key(payload.public_key_pem.encode("utf-8"))
    except (ValueError, TypeError, UnsupportedAlgorithm, UnicodeEncodeError):
        public_key = None
    if not isinstance(public_key, Ed25519PublicKey):
        raise HTTPException(
            status_code=422, detail="public_key_pem is not an Ed25519 public key"
        )
    await lock_tenant(session, organization_id)
    holder = await session.scalar(
        select(User).where(
            User.organization_id == organization_id, User.id == payload.user_id
        )
    )
    if (
        holder is None
        or not holder.is_active
        or holder.kind != "human"
        or "plans.create" not in await user_permissions(session, holder)
    ):
        raise HTTPException(
            status_code=422,
            detail="The key holder must be an active person of this organization "
            "who may create plans.",
        )
    signer = key_id(public_key)
    if await session.scalar(
        select(ConfigSigningKey.id).where(
            ConfigSigningKey.organization_id == organization_id,
            ConfigSigningKey.key_id == signer,
        )
    ):
        raise HTTPException(
            status_code=409,
            detail={"code": "SIGNING_KEY_EXISTS", "message": "This key is registered."},
        )
    if await active_signing_keys(session, organization_id) >= _MAX_ACTIVE_KEYS:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "SIGNING_KEY_LIMIT",
                "message": f"A tenant holds at most {_MAX_ACTIVE_KEYS} active keys.",
            },
        )
    key = ConfigSigningKey(
        organization_id=organization_id,
        key_id=signer,
        public_key=public_key.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode("ascii"),
        user_id=holder.id,
        name=payload.name,
        created_by=str(user.id),
    )
    session.add(key)
    await session.flush()
    await _audit(
        session,
        user,
        "tenant.config_signing_key_added",
        str(organization_id),
        details={"key_id": signer, "user_id": str(holder.id)},
    )
    # A new key can change policy, so the tenant hears of it.
    await ComplianceForwarderService().send_tenant_alert(
        session,
        TenantId(organization_id),
        body={
            "source": "shim",
            "event_type": "tenant_policy",
            "kind": "config_signing_key_added",
            "key_id": signer,
            "holder": str(holder.id),
            "actor": str(user.id),
            "actor_email": user.email,
            "occurred_at": datetime.now(timezone.utc).isoformat(),
        },
        delivery_key=f"config_signing_key_added:{key.id}",
    )
    await session.commit()
    await session.refresh(key)
    return key


@router.delete("/signing-keys/{signing_key_id}", response_model=SigningKeyView)
async def revoke_signing_key(
    signing_key_id: str = Path(pattern=r"^[0-9a-f]{32}$"),
    user: User = Depends(require("config.manage")),
    session: AsyncSession = Depends(get_db),
) -> ConfigSigningKey:
    organization_id = _tenant_id(user)
    await lock_tenant(session, organization_id)
    key = await session.scalar(
        select(ConfigSigningKey).where(
            ConfigSigningKey.organization_id == organization_id,
            ConfigSigningKey.key_id == signing_key_id,
            ConfigSigningKey.revoked_at.is_(None),
        )
    )
    if key is None:
        raise HTTPException(status_code=404, detail="Signing key not found")
    row = await _mode_row(session, organization_id)
    if (
        row is not None
        and row.mode == "file"
        and await active_signing_keys(session, organization_id) == 1
    ):
        raise HTTPException(
            status_code=409,
            detail={
                "code": "CONFIG_LAST_SIGNING_KEY",
                "message": "This is the last key that can sign the tenant's file.",
                "hint": "Switch to api mode first.",
            },
        )
    key.revoked_at, key.revoked_by = datetime.now(timezone.utc), str(user.id)
    await session.execute(
        update(PolicyPlan)
        .where(
            PolicyPlan.organization_id == organization_id,
            PolicyPlan.source == "file",
            PolicyPlan.status.in_(("draft", "pending_approval")),
            PolicyPlan.context["key_id"].as_string() == signing_key_id,
        )
        .values(status="expired")
    )
    await _audit(
        session,
        user,
        "tenant.config_signing_key_revoked",
        str(organization_id),
        details={"key_id": signing_key_id},
    )
    await session.commit()
    await session.refresh(key)
    return key


@router.get(
    "/export",
    response_class=Response,
    responses={
        200: {
            "description": "The configuration file.",
            "content": {"application/yaml": {"schema": {"type": "string"}}},
        }
    },
)
async def export_config(
    version: int | None = Query(default=None, ge=0, le=_MAX_VERSION),
    user: User = Depends(require("rules.read")),
    session: AsyncSession = Depends(get_db),
) -> Response:
    if "settings.read" not in await user_permissions(session, user):
        raise HTTPException(
            status_code=403, detail="Permission required: settings.read"
        )
    organization_id = _tenant_id(user)
    row = await _mode_row(session, organization_id)
    names = (
        list(row.resources)
        if row is not None and row.mode == "file"
        else list(FILE_MANAGEABLE)
    )
    latest = await current_version(session, organization_id)
    if version is not None and version > latest:
        raise HTTPException(status_code=404, detail="Policy version not found")
    at = (
        await state_at(session, organization_id, version) if version is not None else {}
    )
    states: dict[str, dict[str, State]] = {}
    for name in names:
        current = await REGISTRY[name].snapshot(session, organization_id, None)
        # Items no version touched are as they are now.
        merged = {**current, **at.get(name, {})}
        states[name] = {
            item: state for item, state in merged.items() if state is not None
        }
    rule_set = await session.get(OrganizationRuleSet, organization_id)
    gateway = await session.get(OrganizationGatewaySettings, organization_id)
    resources: dict[str, Any] = {
        name: [{"id": item, **state} for item, state in states[name].items()]
        if name == "rules"
        else states[name]["_"]
        for name in names
    }
    document = {
        "format": "shim.config",
        "version": 1,
        "organization_id": str(organization_id),
        "serial": (row.last_serial if row is not None else 0) + 1,
        "exported_from": {"policy_version": version}
        if version is not None
        else {
            "policy_version": latest,
            "rules_revision": rule_set.revision if rule_set is not None else 0,
            "gateway_settings_revision": gateway.revision if gateway is not None else 0,
        },
        "resources": resources,
    }
    await _audit(
        session,
        user,
        "tenant.config_exported",
        str(organization_id),
        details={"version": version, "resources": names},
    )
    await session.commit()
    # safe_dump quotes strings such as 'off' that would read back as booleans.
    return Response(
        content=yaml.safe_dump(document, sort_keys=False, allow_unicode=True),
        media_type="application/yaml",
        headers={"Content-Disposition": 'attachment; filename="shim-config.yaml"'},
    )


_FILE_ROUTE = bounded_body(
    _MAX_BODY_BYTES, "A configuration push is at most 1,100,000 bytes."
)


async def plan_config(
    payload: FileInput,
    user: User = Depends(require("plans.create")),
    session: AsyncSession = Depends(get_db),
) -> FilePlanView:
    organization_id = _tenant_id(user)
    data = _file_bytes(payload)
    row = await _mode_row(session, organization_id)
    document = await _document(data, organization_id)
    signature = None
    if payload.signature is not None:
        try:
            key = await verify_config_signature(
                session, organization_id, data, payload.signature
            )
            signature = SignatureCheck(valid=True, key_id=key.key_id)
        except HTTPException:
            signature = SignatureCheck(valid=False, key_id=None)
    changes = await _file_changes(
        session,
        user,
        organization_id,
        document,
        list(row.resources) if row is not None and row.mode == "file" else None,
    )
    # Never committed: a dry run stores nothing.
    planned = await _planned(session, organization_id, changes)
    return FilePlanView(
        serial=document.serial,
        risk=combine_risk(change["risk"] for change in planned),
        changes=planned,
        signature=signature,
    )


async def apply_config(
    payload: FileInput,
    request: Request,
    response: Response,
    user: User = Depends(require("plans.apply")),
    session: AsyncSession = Depends(get_db),
) -> FileApplyView:
    organization_id = _tenant_id(user)
    data = _file_bytes(payload)
    await lock_tenant(session, organization_id)
    row = await _mode_row(session, organization_id)
    if row is None or row.mode != "file":
        raise HTTPException(
            status_code=409,
            detail={
                "code": "CONFIG_FILE_MODE_OFF",
                "message": "This tenant does not manage its policy from a file.",
                "hint": "Turn on file mode or use the panel.",
            },
        )
    key = await verify_config_signature(
        session, organization_id, data, payload.signature or ""
    )
    document = await _document(data, organization_id)
    if document.serial <= row.last_serial:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "CONFIG_SERIAL_STALE",
                "last_serial": row.last_serial,
                "message": "The file's serial is not above the last applied one.",
                "hint": "Raise serial above last_serial, sign the file and push it.",
            },
        )
    # A newer file supersedes the ones still waiting.
    await session.execute(
        update(PolicyPlan)
        .where(
            PolicyPlan.organization_id == organization_id,
            PolicyPlan.source == "file",
            PolicyPlan.status.in_(("draft", "pending_approval")),
        )
        .values(status="expired")
    )
    changes = await _file_changes(
        session, user, organization_id, document, list(row.resources)
    )
    file_sha256 = hashlib.sha256(data).hexdigest()
    row.last_serial, row.last_file_sha256 = document.serial, file_sha256
    row.last_applied_at = datetime.now(timezone.utc)
    plan, cleanups = None, None
    if changes:
        plan = await new_plan(
            session,
            user,
            organization_id,
            await _planned(session, organization_id, changes),
            source="file",
            reason=None,
            context={
                "serial": document.serial,
                "key_id": key.key_id,
                "signer_user_id": str(key.user_id),
                "file_sha256": file_sha256,
            },
        )
        cleanups = await _apply_plan(session, user, plan)
    status: Literal["applied", "pending_approval", "unchanged"] = (
        "unchanged"
        if plan is None
        else "pending_approval"
        if cleanups is None
        else "applied"
    )
    await _audit(
        session,
        user,
        "tenant.config_file_applied",
        str(organization_id),
        details={
            "serial": document.serial,
            "key_id": key.key_id,
            "plan_id": str(plan.id) if plan is not None else None,
            "status": status,
            "file_sha256": file_sha256,
        },
    )
    await session.commit()
    if plan is not None and cleanups is None:
        response.status_code = 202
    elif plan is not None and cleanups is not None:
        await _after_commit(request, plan, cleanups)
    return FileApplyView(
        status=status,
        serial=document.serial,
        plan=PlanView.model_validate(plan) if plan is not None else None,
        policy_version=plan.applied_version if plan is not None else None,
    )


router.add_api_route(
    "/plan",
    plan_config,
    methods=["POST"],
    response_model=FilePlanView,
    route_class_override=_FILE_ROUTE,
)
router.add_api_route(
    "/apply",
    apply_config,
    methods=["POST"],
    response_model=FileApplyView,
    responses={202: {"model": FileApplyView, "description": "Waiting for approval"}},
    route_class_override=_FILE_ROUTE,
)
