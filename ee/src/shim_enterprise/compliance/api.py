"""Tenant-scoped compliance connector control plane."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import logging
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import EmailStr, TypeAdapter, ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import InstrumentedAttribute

from shim_enterprise.api.enterprise_deps import get_current_user, get_org_admin
from shim_enterprise.compliance.adapters import (
    ProviderConfigError,
    UnknownProviderError,
    get_adapter,
)
from shim_enterprise.compliance.adapters.openai import validate_openai_event_types
from shim_enterprise.compliance.models import (
    ComplianceConnector,
    ComplianceFinding,
    ComplianceForwardTarget,
    ComplianceIngestCursor,
)
from shim_enterprise.compliance.schemas import (
    ConnectorCreate,
    ConnectorRead,
    ConnectorUpdate,
    FindingPage,
    FindingRead,
    FindingSummary,
    ForwardTargetCreate,
    ForwardTargetRead,
    ForwardTargetUpdate,
    ReportRequest,
    RunResult,
    StreamHealth,
    TopActor,
)
from shim_enterprise.compliance.url_guard import (
    UnsafeForwardURL,
    assert_safe_forward_url,
)
from shim_enterprise.core.config import settings
from shim_enterprise.core.database import get_db
from shim.gateway.contracts.ids import SecretRef, TenantId
from shim_enterprise.outbox.models import OutboxEvent
from shim_enterprise.secrets.migration import assign_secret_reference
from shim_enterprise.secrets.store import SecretStore, get_secret_store
from shim_enterprise.tenants.models import User


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/compliance", tags=["compliance"])

_CONNECTOR_SECRET_PURPOSE = "compliance-connector-api-key"
_FORWARD_SECRET_PURPOSE = "compliance-forward-target-delivery"
_REPORT_RESPONSES: dict[int | str, dict[str, Any]] = {
    200: {
        "description": "PDF or CSV report attachment.",
        "content": {
            "application/pdf": {"schema": {"type": "string", "format": "binary"}},
            "text/csv": {"schema": {"type": "string", "format": "binary"}},
        },
        "headers": {
            "Content-Disposition": {
                "description": "Attachment disposition and filename.",
                "schema": {"type": "string"},
            }
        },
    }
}
_SECRET_CONFIG_KEYS = frozenset(
    {
        "api_key",
        "apikey",
        "authorization",
        "cookie",
        "credential",
        "password",
        "private_key",
        "secret",
        "token",
    }
)
_SECRET_KEY_SUFFIXES = (
    "_api_key",
    "_credential",
    "_password",
    "_private_key",
    "_secret",
    "_token",
)


def _tenant_id(user: User) -> TenantId:
    if user.organization_id is None:
        raise HTTPException(status_code=403, detail="Tenant ownership is required")
    return TenantId(user.organization_id)


def _normalized_key(value: object) -> str:
    return str(value).strip().casefold().replace("-", "_")


def _is_secret_key(value: object) -> bool:
    key = _normalized_key(value)
    return key in _SECRET_CONFIG_KEYS or key.endswith(_SECRET_KEY_SUFFIXES)


def _contains_secret_field(value: object) -> bool:
    if isinstance(value, dict):
        return any(
            _is_secret_key(key) or _contains_secret_field(child)
            for key, child in value.items()
        )
    if isinstance(value, list):
        return any(_contains_secret_field(child) for child in value)
    return False


def _validate_config(provider: str, config: dict[str, Any]) -> None:
    if _contains_secret_field(config):
        raise HTTPException(
            status_code=422,
            detail="Connector config must not contain credential fields",
        )
    if provider != "openai":
        return
    scope_id = config.get("scope_id")
    scope_type = config.get("scope_type")
    if not isinstance(scope_id, str) or not scope_id.strip():
        raise HTTPException(status_code=422, detail="OpenAI scope_id is required")
    if scope_type not in {None, "workspace", "organization"}:
        raise HTTPException(
            status_code=422,
            detail="OpenAI scope_type must be workspace or organization",
        )
    try:
        validate_openai_event_types(config)
    except ProviderConfigError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    try:
        retention_days = int(
            config.get("retention_days", settings.COMPLIANCE_OPENAI_RETENTION_DAYS)
        )
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=422,
            detail="OpenAI retention_days must be a positive integer",
        ) from exc
    if retention_days < 1:
        raise HTTPException(
            status_code=422,
            detail="OpenAI retention_days must be a positive integer",
        )


def _redacted_config(value: dict[str, Any]) -> dict[str, Any]:
    def redact(item: object) -> object:
        if isinstance(item, dict):
            return {
                str(key): "[REDACTED]" if _is_secret_key(key) else redact(child)
                for key, child in item.items()
            }
        if isinstance(item, list):
            return [redact(child) for child in item]
        return item

    return {str(key): redact(child) for key, child in value.items()}


def _masked_key(value: str) -> str:
    if len(value) <= 5:
        return "***"
    if len(value) <= 12:
        return f"{value[:3]}...{value[-2:]}"
    return f"{value[:8]}...{value[-4:]}"


def _connector_view(connector: ComplianceConnector) -> ConnectorRead:
    view = ConnectorRead.model_validate(connector)
    view.config = _redacted_config(connector.config or {})
    if connector.last_success_at is not None:
        now = datetime.now(timezone.utc)
        last_success = connector.last_success_at
        if last_success.tzinfo is None:
            last_success = last_success.replace(tzinfo=timezone.utc)
        view.lag_seconds = max(0.0, (now - last_success).total_seconds())
    view.healthy = connector.status == "active" and connector.consecutive_errors == 0
    return view


def _promote_provider_config(
    connector: ComplianceConnector,
    config: dict[str, Any],
) -> None:
    if connector.provider != "openai":
        connector.scope_type = None
        connector.scope_id = None
        connector.retention_days = None
        return
    connector.scope_type = config.get("scope_type")
    connector.scope_id = str(config["scope_id"])
    connector.retention_days = int(
        config.get("retention_days", settings.COMPLIANCE_OPENAI_RETENTION_DAYS)
    )


async def _load_connector(
    session: AsyncSession,
    tenant_id: UUID,
    connector_id: UUID,
    *,
    for_update: bool = False,
) -> ComplianceConnector:
    statement = select(ComplianceConnector).where(
        ComplianceConnector.id == connector_id,
        ComplianceConnector.organization_id == tenant_id,
    )
    if for_update:
        statement = statement.with_for_update(of=ComplianceConnector)
    connector = (await session.execute(statement)).scalar_one_or_none()
    if connector is None:
        raise HTTPException(status_code=404, detail="Connector not found")
    return connector


async def _probe_credential(
    provider: str,
    credential: str,
    config: dict[str, Any],
) -> None:
    adapter = None
    try:
        adapter = get_adapter(provider, credential, config=config)
        accepted = await adapter.verify_key()
    except ProviderConfigError as exc:
        raise HTTPException(
            status_code=422,
            detail="Provider configuration is invalid",
        ) from exc
    except UnknownProviderError as exc:
        raise HTTPException(
            status_code=400,
            detail="Compliance provider is not supported",
        ) from exc
    except Exception as exc:
        logger.warning("Compliance credential probe failed provider=%s", provider)
        raise HTTPException(
            status_code=502,
            detail="Provider credential validation is unavailable",
        ) from exc
    finally:
        if adapter is not None:
            await adapter.close()
    if not accepted:
        raise HTTPException(status_code=400, detail="Provider rejected the credential")


async def _delete_secret_best_effort(
    store: SecretStore,
    tenant_id: TenantId,
    secret_ref: str,
    purpose: str,
) -> None:
    try:
        await store.delete_secret(
            tenant_id,
            SecretRef(secret_ref),
            expected_purpose=purpose,
        )
    except Exception as exc:
        logger.warning("Secret cleanup failed type=%s", type(exc).__name__)


@router.post(
    "/connectors",
    response_model=ConnectorRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_connector(
    payload: ConnectorCreate,
    current_user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
) -> ConnectorRead:
    tenant_id = _tenant_id(current_user)
    config = dict(payload.config)
    _validate_config(payload.provider, config)
    duplicate = await session.scalar(
        select(ComplianceConnector.id).where(
            ComplianceConnector.organization_id == tenant_id,
            ComplianceConnector.provider == payload.provider,
        )
    )
    if duplicate is not None:
        raise HTTPException(status_code=409, detail="Connector already exists")
    await _probe_credential(payload.provider, payload.api_key, config)

    store = get_secret_store()
    secret_ref = await store.put_secret(
        tenant_id,
        _CONNECTOR_SECRET_PURPOSE,
        payload.api_key,
        metadata={"provider": payload.provider},
    )
    connector = ComplianceConnector(
        organization_id=tenant_id,
        provider=payload.provider,
        status="active",
        masked_key=_masked_key(payload.api_key),
        verified_at=datetime.now(timezone.utc),
        config=config,
    )
    assign_secret_reference(connector, secret_ref)
    _promote_provider_config(connector, config)
    session.add(connector)
    try:
        await session.commit()
    except BaseException:
        await session.rollback()
        await _delete_secret_best_effort(
            store,
            tenant_id,
            secret_ref,
            _CONNECTOR_SECRET_PURPOSE,
        )
        raise
    await session.refresh(connector)
    return _connector_view(connector)


@router.get("/connectors", response_model=list[ConnectorRead])
async def list_connectors(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> list[ConnectorRead]:
    tenant_id = _tenant_id(current_user)
    connectors = (
        await session.execute(
            select(ComplianceConnector)
            .where(ComplianceConnector.organization_id == tenant_id)
            .order_by(ComplianceConnector.created_at.desc())
        )
    ).scalars()
    return [_connector_view(connector) for connector in connectors]


@router.get("/connectors/{connector_id}", response_model=ConnectorRead)
async def get_connector(
    connector_id: UUID,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> ConnectorRead:
    connector = await _load_connector(session, _tenant_id(current_user), connector_id)
    view = _connector_view(connector)
    if connector.provider == "openai":
        view.streams = await _stream_health(session, connector)
    return view


async def _stream_health(
    session: AsyncSession,
    connector: ComplianceConnector,
) -> list[StreamHealth]:
    cursors = (
        await session.execute(
            select(ComplianceIngestCursor)
            .where(ComplianceIngestCursor.connector_id == connector.id)
            .order_by(ComplianceIngestCursor.event_type)
        )
    ).scalars()
    retention_days = (
        connector.retention_days or settings.COMPLIANCE_OPENAI_RETENTION_DAYS
    )
    return [
        StreamHealth(
            event_type=cursor.event_type,
            last_end_time=cursor.last_end_time,
            last_success_at=cursor.last_success_at,
            lag_seconds=cursor.lag_seconds,
            retention_budget_days=(
                None
                if cursor.lag_seconds is None
                else retention_days - (cursor.lag_seconds / 86_400)
            ),
        )
        for cursor in cursors
    ]


@router.patch("/connectors/{connector_id}", response_model=ConnectorRead)
async def update_connector(
    connector_id: UUID,
    payload: ConnectorUpdate,
    current_user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
) -> ConnectorRead:
    connector = await _load_connector(
        session,
        _tenant_id(current_user),
        connector_id,
        for_update=True,
    )
    if payload.status is not None:
        connector.status = payload.status
        if payload.status == "active":
            connector.consecutive_errors = 0
            connector.last_error = None
    if payload.config is not None:
        config = dict(payload.config)
        _validate_config(connector.provider, config)
        connector.config = config
        _promote_provider_config(connector, config)
    await session.commit()
    await session.refresh(connector)
    return _connector_view(connector)


@router.delete(
    "/connectors/{connector_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
)
async def delete_connector(
    connector_id: UUID,
    current_user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
) -> None:
    tenant_id = _tenant_id(current_user)
    connector = await _load_connector(
        session,
        tenant_id,
        connector_id,
        for_update=True,
    )
    target_statement = (
        select(ComplianceForwardTarget)
        .where(ComplianceForwardTarget.connector_id == connector.id)
        .with_for_update(of=ComplianceForwardTarget)
    )
    targets = tuple((await session.execute(target_statement)).scalars())
    refs = [(connector.secret_ref, _CONNECTOR_SECRET_PURPOSE)]
    refs.extend((target.secret_ref, _FORWARD_SECRET_PURPOSE) for target in targets)
    await _cancel_forward_deliveries(
        session,
        tenant_id,
        *(target.id for target in targets),
    )
    await session.delete(connector)
    await session.commit()
    store = get_secret_store()
    for secret_ref, purpose in refs:
        await _delete_secret_best_effort(store, tenant_id, secret_ref, purpose)


@router.post("/connectors/{connector_id}/run", response_model=RunResult)
async def run_connector(
    connector_id: UUID,
    request: Request,
    current_user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
) -> RunResult:
    connector = await _load_connector(session, _tenant_id(current_user), connector_id)
    from shim_enterprise.compliance.services.ingest import ComplianceIngestService

    result = await ComplianceIngestService(cache=request.app.state.cache).run_once(
        connector.id
    )
    return RunResult(**result)


def _finding_scope(tenant_id: UUID, connector_id: UUID | None):
    statement = (
        select(ComplianceFinding)
        .join(
            ComplianceConnector,
            ComplianceFinding.connector_id == ComplianceConnector.id,
        )
        .where(ComplianceConnector.organization_id == tenant_id)
    )
    if connector_id is not None:
        statement = statement.where(ComplianceFinding.connector_id == connector_id)
    return statement


@router.get("/findings", response_model=FindingPage)
async def list_findings(
    connector_id: UUID | None = Query(default=None),
    severity: str | None = Query(default=None),
    entity_type: str | None = Query(default=None),
    actor: str | None = Query(default=None),
    start: datetime | None = Query(default=None),
    end: datetime | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> FindingPage:
    statement = _finding_scope(_tenant_id(current_user), connector_id)
    if severity is not None:
        statement = statement.where(ComplianceFinding.severity == severity)
    if entity_type is not None:
        statement = statement.where(ComplianceFinding.entity_type == entity_type)
    if actor is not None:
        statement = statement.where(ComplianceFinding.actor_email == actor)
    if start is not None:
        statement = statement.where(ComplianceFinding.occurred_at >= start)
    if end is not None:
        statement = statement.where(ComplianceFinding.occurred_at <= end)
    total = await session.scalar(select(func.count()).select_from(statement.subquery()))
    findings = (
        await session.execute(
            statement.order_by(ComplianceFinding.occurred_at.desc().nullslast())
            .limit(limit)
            .offset(offset)
        )
    ).scalars()
    return FindingPage(
        items=[FindingRead.model_validate(finding) for finding in findings],
        total=int(total or 0),
        limit=limit,
        offset=offset,
    )


async def _group_counts(
    session: AsyncSession,
    tenant_id: UUID,
    connector_id: UUID | None,
    column: InstrumentedAttribute[Any],
) -> dict[str, int]:
    statement = (
        select(column, func.count(ComplianceFinding.id))
        .join(
            ComplianceConnector,
            ComplianceFinding.connector_id == ComplianceConnector.id,
        )
        .where(ComplianceConnector.organization_id == tenant_id)
        .group_by(column)
    )
    if connector_id is not None:
        statement = statement.where(ComplianceFinding.connector_id == connector_id)
    rows = (await session.execute(statement)).all()
    return {str(key): int(count) for key, count in rows if key is not None}


@router.get("/findings/summary", response_model=FindingSummary)
async def findings_summary(
    connector_id: UUID | None = Query(default=None),
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> FindingSummary:
    tenant_id = _tenant_id(current_user)
    count_statement = (
        select(func.count(ComplianceFinding.id))
        .join(
            ComplianceConnector,
            ComplianceFinding.connector_id == ComplianceConnector.id,
        )
        .where(ComplianceConnector.organization_id == tenant_id)
    )
    actor_statement = (
        select(
            ComplianceFinding.actor_email,
            func.count(ComplianceFinding.id),
        )
        .join(
            ComplianceConnector,
            ComplianceFinding.connector_id == ComplianceConnector.id,
        )
        .where(ComplianceConnector.organization_id == tenant_id)
        .group_by(ComplianceFinding.actor_email)
        .order_by(func.count(ComplianceFinding.id).desc())
        .limit(10)
    )
    if connector_id is not None:
        count_statement = count_statement.where(
            ComplianceFinding.connector_id == connector_id
        )
        actor_statement = actor_statement.where(
            ComplianceFinding.connector_id == connector_id
        )
    total = int(await session.scalar(count_statement) or 0)
    actor_rows = (await session.execute(actor_statement)).all()
    return FindingSummary(
        total=total,
        by_severity=await _group_counts(
            session,
            tenant_id,
            connector_id,
            ComplianceFinding.severity,
        ),
        by_entity_type=await _group_counts(
            session,
            tenant_id,
            connector_id,
            ComplianceFinding.entity_type,
        ),
        by_kvkk_category=await _group_counts(
            session,
            tenant_id,
            connector_id,
            ComplianceFinding.kvkk_category,
        ),
        top_actors=[
            TopActor(actor_email=email, count=int(count))
            for email, count in actor_rows
            if email is not None
        ],
    )


def _delivery_bundle(
    kind: str,
    endpoint: str,
    signing_secret: str | None,
) -> str:
    return json.dumps(
        {"kind": kind, "endpoint": endpoint, "signing_secret": signing_secret},
        separators=(",", ":"),
        sort_keys=True,
    )


def _parse_delivery_bundle(value: str) -> tuple[str, str, str | None]:
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Invalid forward-target secret payload") from exc
    if (
        not isinstance(payload, dict)
        or payload.get("kind") not in {"siem_webhook", "slack", "email"}
        or not isinstance(payload.get("endpoint"), str)
    ):
        raise RuntimeError("Invalid forward-target secret payload")
    signing_secret = payload.get("signing_secret")
    if signing_secret is not None and not isinstance(signing_secret, str):
        raise RuntimeError("Invalid forward-target secret payload")
    return payload["kind"], payload["endpoint"], signing_secret


def _endpoint_origin(kind: str, endpoint: str) -> str:
    if kind == "email":
        local, domain = endpoint.rsplit("@", 1)
        return f"{local[:1]}***@{domain}"
    parsed = urlsplit(endpoint)
    return f"{parsed.scheme}://{parsed.netloc}"


async def _validate_forward_url(endpoint: str) -> None:
    try:
        await assert_safe_forward_url(endpoint)
    except UnsafeForwardURL as exc:
        raise HTTPException(
            status_code=422,
            detail="Forward target must resolve to a public HTTPS destination",
        ) from exc


async def _validate_target_destination(
    kind: str,
    endpoint: str,
    *,
    enabled: bool,
) -> str:
    if kind == "email":
        try:
            normalized = str(TypeAdapter(EmailStr).validate_python(endpoint))
        except ValidationError as exc:
            raise HTTPException(
                status_code=422,
                detail="Email forward target requires a valid recipient",
            ) from exc
        if enabled:
            _require_email_configuration()
        return normalized
    await _validate_forward_url(endpoint)
    return endpoint


def _require_email_configuration() -> None:
    if not (settings.RESEND_API_KEY and settings.COMPLIANCE_EMAIL_FROM):
        raise HTTPException(
            status_code=503,
            detail="Compliance email forwarding is not configured",
        )


def _target_view(target: ComplianceForwardTarget) -> ForwardTargetRead:
    return ForwardTargetRead.model_validate(target)


async def _load_target(
    session: AsyncSession,
    tenant_id: UUID,
    target_id: UUID,
) -> ComplianceForwardTarget:
    target = (
        await session.execute(
            select(ComplianceForwardTarget)
            .join(
                ComplianceConnector,
                ComplianceForwardTarget.connector_id == ComplianceConnector.id,
            )
            .where(
                ComplianceForwardTarget.id == target_id,
                ComplianceConnector.organization_id == tenant_id,
            )
            .with_for_update(of=ComplianceForwardTarget)
        )
    ).scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="Forward target not found")
    return target


@router.post(
    "/forward-targets",
    response_model=ForwardTargetRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_forward_target(
    connector_id: UUID,
    payload: ForwardTargetCreate,
    current_user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
) -> ForwardTargetRead:
    tenant_id = _tenant_id(current_user)
    connector = await _load_connector(
        session,
        tenant_id,
        connector_id,
        for_update=True,
    )
    endpoint = await _validate_target_destination(
        payload.kind,
        payload.endpoint,
        enabled=payload.enabled,
    )
    store = get_secret_store()
    secret_ref = await store.put_secret(
        tenant_id,
        _FORWARD_SECRET_PURPOSE,
        _delivery_bundle(payload.kind, endpoint, payload.secret),
        metadata={"kind": payload.kind},
    )
    target = ComplianceForwardTarget(
        connector_id=connector.id,
        kind=payload.kind,
        endpoint_origin=_endpoint_origin(payload.kind, endpoint),
        signed=payload.secret is not None,
        min_severity=payload.min_severity,
        enabled=payload.enabled,
    )
    assign_secret_reference(target, secret_ref)
    session.add(target)
    try:
        await session.commit()
    except BaseException:
        await session.rollback()
        await _delete_secret_best_effort(
            store,
            tenant_id,
            str(secret_ref),
            _FORWARD_SECRET_PURPOSE,
        )
        raise
    await session.refresh(target)
    return _target_view(target)


@router.get("/forward-targets", response_model=list[ForwardTargetRead])
async def list_forward_targets(
    connector_id: UUID | None = Query(default=None),
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> list[ForwardTargetRead]:
    tenant_id = _tenant_id(current_user)
    statement = (
        select(ComplianceForwardTarget)
        .join(
            ComplianceConnector,
            ComplianceForwardTarget.connector_id == ComplianceConnector.id,
        )
        .where(ComplianceConnector.organization_id == tenant_id)
    )
    if connector_id is not None:
        statement = statement.where(
            ComplianceForwardTarget.connector_id == connector_id
        )
    targets = (await session.execute(statement)).scalars()
    return [_target_view(target) for target in targets]


@router.patch("/forward-targets/{target_id}", response_model=ForwardTargetRead)
async def update_forward_target(
    target_id: UUID,
    payload: ForwardTargetUpdate,
    current_user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
) -> ForwardTargetRead:
    tenant_id = _tenant_id(current_user)
    target = await _load_target(session, tenant_id, target_id)
    store: SecretStore | None = None
    previous_ref: str | None = None
    replacement_ref: str | None = None
    if payload.endpoint is not None or "secret" in payload.model_fields_set:
        store = get_secret_store()
        previous_ref = target.secret_ref
        current_kind, current_endpoint, current_secret = _parse_delivery_bundle(
            await store.get_secret(
                tenant_id,
                SecretRef(target.secret_ref),
                expected_purpose=_FORWARD_SECRET_PURPOSE,
            )
        )
        if current_kind != target.kind:
            raise RuntimeError("Forward-target kind does not match its secret")
        endpoint = payload.endpoint or current_endpoint
        signing_secret = (
            payload.secret if "secret" in payload.model_fields_set else current_secret
        )
        if target.kind != "siem_webhook" and signing_secret is not None:
            raise HTTPException(
                status_code=422,
                detail="Only SIEM webhooks support signing secrets",
            )
        endpoint = await _validate_target_destination(
            target.kind,
            endpoint,
            enabled=payload.enabled if payload.enabled is not None else target.enabled,
        )
        replacement_ref = await store.rotate_secret(
            tenant_id,
            SecretRef(target.secret_ref),
            _delivery_bundle(target.kind, endpoint, signing_secret),
            expected_purpose=_FORWARD_SECRET_PURPOSE,
        )
        assign_secret_reference(target, replacement_ref)
        target.endpoint_origin = _endpoint_origin(target.kind, endpoint)
        target.signed = signing_secret is not None
    if payload.min_severity is not None:
        target.min_severity = payload.min_severity
    if payload.enabled is not None:
        if payload.enabled and target.kind == "email":
            _require_email_configuration()
        target.enabled = payload.enabled
    try:
        if replacement_ref is not None:
            await _rebind_forward_deliveries(
                session,
                tenant_id,
                target.id,
                str(replacement_ref),
            )
        await session.commit()
    except BaseException:
        await session.rollback()
        if store is not None and replacement_ref is not None:
            await _delete_secret_best_effort(
                store,
                tenant_id,
                replacement_ref,
                _FORWARD_SECRET_PURPOSE,
            )
        raise
    if store is not None and previous_ref is not None:
        await _delete_secret_best_effort(
            store,
            tenant_id,
            previous_ref,
            _FORWARD_SECRET_PURPOSE,
        )
    await session.refresh(target)
    return _target_view(target)


@router.delete(
    "/forward-targets/{target_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
)
async def delete_forward_target(
    target_id: UUID,
    current_user: User = Depends(get_org_admin),
    session: AsyncSession = Depends(get_db),
) -> None:
    tenant_id = _tenant_id(current_user)
    target = await _load_target(session, tenant_id, target_id)
    secret_ref = target.secret_ref
    await _cancel_forward_deliveries(session, tenant_id, target.id)
    await session.delete(target)
    await session.commit()
    await _delete_secret_best_effort(
        get_secret_store(),
        tenant_id,
        secret_ref,
        _FORWARD_SECRET_PURPOSE,
    )


async def _active_forward_deliveries(
    session: AsyncSession,
    tenant_id: TenantId,
    *target_ids: UUID,
) -> tuple[OutboxEvent, ...]:
    statement = (
        select(OutboxEvent)
        .where(
            OutboxEvent.organization_id == tenant_id,
            OutboxEvent.event_type == "compliance.connector_delivery_requested",
            OutboxEvent.status.in_(("pending", "processing", "failed")),
            OutboxEvent.payload["target_id"]
            .as_string()
            .in_([str(target_id) for target_id in target_ids]),
        )
        .with_for_update(of=OutboxEvent)
    )
    return tuple((await session.execute(statement)).scalars())


async def _rebind_forward_deliveries(
    session: AsyncSession,
    tenant_id: TenantId,
    target_id: UUID,
    secret_ref: str,
) -> None:
    for event in await _active_forward_deliveries(session, tenant_id, target_id):
        event.payload = {**event.payload, "secret_ref": secret_ref}


async def _cancel_forward_deliveries(
    session: AsyncSession,
    tenant_id: TenantId,
    *target_ids: UUID,
) -> None:
    if not target_ids:
        return
    now = datetime.now(timezone.utc)
    for event in await _active_forward_deliveries(session, tenant_id, *target_ids):
        event.cancel(now=now)


@router.post(
    "/reports/kvkk",
    response_class=Response,
    responses=_REPORT_RESPONSES,
)
async def generate_kvkk_report(
    payload: ReportRequest,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> Response:
    tenant_id = _tenant_id(current_user)
    end = payload.end or datetime.now(timezone.utc)
    start = payload.start or end - timedelta(days=30)
    if start > end:
        raise HTTPException(status_code=422, detail="start must not exceed end")
    if payload.connector_id is not None:
        await _load_connector(session, tenant_id, payload.connector_id)
    from shim_enterprise.compliance.services.report import (
        ReportLimitExceeded,
        generate_report,
    )

    try:
        content, media_type, filename = await generate_report(
            session,
            org_id=tenant_id,
            start=start,
            end=end,
            connector_id=payload.connector_id,
            fmt=payload.format,
        )
    except ReportLimitExceeded as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
