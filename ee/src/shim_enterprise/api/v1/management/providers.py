"""Provider secrets and their verification."""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
import json
import re
from typing import Literal, cast
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.api.enterprise_deps import ADMIN_REQUIRED, require
from shim_enterprise.aws.sigv4 import AwsCredentials
from shim_enterprise.aws.sts import StsError, get_caller_identity
from shim.gateway.pipeline.provider_execution import ProviderCallError
from shim_enterprise.core.config import settings
from shim_enterprise.core.database import get_db
from shim.gateway.contracts.ids import SecretRef, TenantId
from shim_enterprise.secrets.migration import assign_secret_reference
from shim_enterprise.secrets.store import get_secret_store, provider_secret_purpose
from shim_enterprise.tenants.audit import (
    change_details,
    record_management_action as _audit,
)
from shim_enterprise.tenants.models import ProviderSecret, User
from shim_enterprise.api.v1.management._common import (
    _delete_secret_best_effort,
    _fresh_resolver,
    _owned_provider_secret,
    _tenant_id,
    logger,
)


router = APIRouter()


_PROVIDER_VERIFICATION_REQUESTS: dict[str, tuple[str, str, str, dict[str, str]]] = {
    "openai": (
        "OPENAI_BASE_URL",
        "https://api.openai.com/v1",
        "/models",
        {"authorization": "Bearer {credential}"},
    ),
    "anthropic": (
        "ANTHROPIC_BASE_URL",
        "https://api.anthropic.com",
        "/v1/models",
        {
            "x-api-key": "{credential}",
            "anthropic-version": "2023-06-01",
        },
    ),
    "google": (
        "GOOGLE_BASE_URL",
        "https://generativelanguage.googleapis.com",
        "/v1beta/models",
        {"x-goog-api-key": "{credential}"},
    ),
}


class AzureEntraInput(BaseModel):
    """A Microsoft Entra ID app registration's client secret."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(pattern=r"^[A-Za-z0-9.-]{1,128}$")
    client_id: UUID
    client_secret: SecretStr = Field(min_length=1, max_length=1_024)
    scope: str | None = Field(
        default=None,
        max_length=256,
        pattern=r"^https://\S+/\.default$",
        description="Defaults to the operator's SHIM_AZURE_TOKEN_SCOPE.",
    )

    def stored(self) -> str:
        return json.dumps(
            {
                "tenant_id": self.tenant_id,
                "client_id": str(self.client_id),
                "client_secret": self.client_secret.get_secret_value(),
                "scope": self.scope or settings.SHIM_AZURE_TOKEN_SCOPE,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def masked(self) -> str:
        return f"entra:{_mask(str(self.client_id))}"


class AwsAccessKeyInput(BaseModel):
    """A long-term AWS access key pair; temporary (ASIA) keys expire and are refused."""

    model_config = ConfigDict(extra="forbid")

    access_key_id: str = Field(pattern=r"^AKIA[A-Z0-9]{16}$")
    secret_access_key: SecretStr

    @field_validator("secret_access_key")
    @classmethod
    def forty_characters(cls, value: SecretStr) -> SecretStr:
        # Checked here: a pattern on SecretStr would echo nothing useful anyway.
        if not re.fullmatch(r"[A-Za-z0-9/+=]{40}", value.get_secret_value()):
            raise ValueError(
                "secret_access_key is 40 characters of A-Z, a-z, 0-9, /, + and ="
            )
        return value

    def stored(self) -> str:
        return json.dumps(
            {
                "access_key_id": self.access_key_id,
                "secret_access_key": self.secret_access_key.get_secret_value(),
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def masked(self) -> str:
        return f"aws:{self.access_key_id[:4]}...{self.access_key_id[-4:]}"


CredentialKind = Literal["api_key", "aws_access_key", "aws_bedrock_api_key"]


class ProviderSecretInput(BaseModel):
    provider: Literal["openai", "anthropic", "google", "azure_entra"] = Field(
        description="azure_entra: an Entra ID client credential for Azure OpenAI "
        "deployments."
    )
    name: str | None = Field(default=None, max_length=100)
    credential_kind: CredentialKind = Field(
        default="api_key",
        description="aws_access_key (aws_access_key) or aws_bedrock_api_key (key): "
        "a credential for Amazon Bedrock deployments only, provider anthropic or openai.",
    )
    key: str | None = Field(default=None, min_length=10, max_length=10_000)
    azure_entra: AzureEntraInput | None = None
    aws_access_key: AwsAccessKeyInput | None = None
    monthly_limit_usd: Decimal | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def one_credential_of_its_provider(self) -> ProviderSecretInput:
        entra = self.provider == "azure_entra"
        aws_pair = self.credential_kind == "aws_access_key"
        if self.credential_kind != "api_key" and self.provider not in {
            "anthropic",
            "openai",
        }:
            raise ValueError("An AWS credential's provider is anthropic or openai")
        if (
            (self.key is not None) == (entra or aws_pair)
            or (self.azure_entra is not None) != entra
            or (self.aws_access_key is not None) != aws_pair
        ):
            raise ValueError(
                "azure_entra takes azure_entra, aws_access_key takes aws_access_key, "
                "every other credential a key"
            )
        return self


class ProviderSecretPatch(BaseModel):
    name: str | None = Field(default=None, max_length=100)
    key: str | None = Field(default=None, min_length=10, max_length=10_000)
    azure_entra: AzureEntraInput | None = None
    aws_access_key: AwsAccessKeyInput | None = None
    monthly_limit_usd: Decimal | None = Field(default=None, ge=0)


class ProviderSecretView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    provider: str
    credential_kind: CredentialKind
    name: str | None
    masked_key: str
    created_at: datetime
    monthly_limit_usd: Decimal | None
    verified_at: datetime | None


@router.get("/providers", response_model=list[ProviderSecretView])
async def list_provider_secrets(
    user: User = Depends(require("providers.manage", legacy_detail=ADMIN_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> list[ProviderSecret]:
    statement = select(ProviderSecret).where(
        ProviderSecret.organization_id == _tenant_id(user)
    )
    return list((await session.execute(statement)).scalars().all())


@router.post(
    "/providers",
    response_model=ProviderSecretView,
    status_code=status.HTTP_201_CREATED,
)
async def create_provider_secret(
    payload: ProviderSecretInput,
    user: User = Depends(require("providers.manage", legacy_detail=ADMIN_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> ProviderSecret:
    tenant_id = _tenant_id(user)
    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Verified email required")
    purpose = provider_secret_purpose(payload.provider, payload.credential_kind)
    structured = payload.azure_entra or payload.aws_access_key
    plaintext = structured.stored() if structured is not None else payload.key
    assert plaintext is not None
    reference = await get_secret_store().put_secret(
        TenantId(tenant_id), purpose, plaintext, {"provider": payload.provider}
    )
    row = ProviderSecret(
        organization_id=tenant_id,
        provider=payload.provider,
        credential_kind=payload.credential_kind,
        name=payload.name,
        masked_key=structured.masked() if structured is not None else _mask(plaintext),
        monthly_limit_usd=payload.monthly_limit_usd,
    )
    assign_secret_reference(row, reference)
    session.add(row)
    try:
        await session.flush()
        await _audit(
            session,
            user,
            "tenant.provider_secret_created",
            str(row.id),
            details=_provider_secret_details(row),
        )
        await session.commit()
    except BaseException:
        await session.rollback()
        await _delete_secret_best_effort(tenant_id, reference, purpose)
        raise
    await session.refresh(row)
    return row


@router.put("/providers/{secret_id}", response_model=ProviderSecretView)
async def update_provider_secret(
    secret_id: UUID,
    patch: ProviderSecretPatch,
    user: User = Depends(require("providers.manage", legacy_detail=ADMIN_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> ProviderSecret:
    row = await _owned_provider_secret(session, user, secret_id)
    entra = row.provider == "azure_entra"
    aws_pair = row.credential_kind == "aws_access_key"
    if not entra and row.provider not in _PROVIDER_VERIFICATION_REQUESTS:
        raise HTTPException(
            status_code=409,
            detail="Unsupported provider secrets are read-only.",
        )
    if (
        (patch.key is not None and (entra or aws_pair))
        or (patch.azure_entra is not None and not entra)
        or (patch.aws_access_key is not None and not aws_pair)
    ):
        raise HTTPException(
            status_code=422,
            detail="A credential's kind never changes; create a new provider secret",
        )
    tenant_id = _tenant_id(user)
    purpose = provider_secret_purpose(row.provider, row.credential_kind)
    previous_reference: SecretRef | None = None
    rotated_reference: SecretRef | None = None
    before = _provider_secret_details(row)
    if "name" in patch.model_fields_set:
        row.name = patch.name
    if "monthly_limit_usd" in patch.model_fields_set:
        row.monthly_limit_usd = patch.monthly_limit_usd
    structured = patch.azure_entra or patch.aws_access_key
    rotated = (
        patch.key
        if patch.key is not None
        else (structured.stored() if structured is not None else None)
    )
    if rotated is not None:
        previous_reference = SecretRef(row.secret_ref)
        rotated_reference = await get_secret_store().rotate_secret(
            TenantId(tenant_id),
            previous_reference,
            rotated,
            expected_purpose=purpose,
        )
        assign_secret_reference(row, rotated_reference)
        row.masked_key = (
            structured.masked() if structured is not None else _mask(rotated)
        )
        row.verified_at = None
    try:
        await _audit(
            session,
            user,
            "tenant.provider_secret_updated",
            str(row.id),
            details={
                **change_details(before, _provider_secret_details(row)),
                "key_rotated": rotated is not None,
            },
        )
        await session.commit()
    except BaseException:
        await session.rollback()
        if rotated_reference is not None:
            await _delete_secret_best_effort(
                tenant_id,
                rotated_reference,
                purpose,
            )
        raise
    if previous_reference is not None:
        await _delete_secret_best_effort(tenant_id, previous_reference, purpose)
    await session.refresh(row)
    return row


@router.post("/providers/{secret_id}/verify", response_model=ProviderSecretView)
async def verify_provider_secret(
    secret_id: UUID,
    request: Request,
    user: User = Depends(require("providers.manage", legacy_detail=ADMIN_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> ProviderSecret:
    row = await _owned_provider_secret(session, user, secret_id)
    verification_request = _PROVIDER_VERIFICATION_REQUESTS.get(row.provider)
    if verification_request is None and row.provider != "azure_entra":
        raise HTTPException(status_code=409, detail="Unsupported provider secret")
    if row.credential_kind == "aws_bedrock_api_key":
        raise HTTPException(
            status_code=409,
            detail="Check a Bedrock API key with a deployment health check",
        )
    tenant_id = _tenant_id(user)
    client: httpx.AsyncClient | None = getattr(request.app.state, "http_client", None)
    if client is None:
        raise HTTPException(status_code=503, detail="Provider verification unavailable")
    if row.credential_kind == "aws_access_key":
        rejected = await _aws_rejects(row, tenant_id, client)
    elif verification_request is None:
        rejected = await _entra_rejects(row, tenant_id, client)
    else:
        rejected = await _provider_rejects(row, tenant_id, client, verification_request)
    if rejected:
        row.verified_at = None
        await _audit(
            session,
            user,
            "tenant.provider_secret_rejected",
            str(row.id),
            details=_provider_secret_details(row),
        )
        await session.commit()
        raise HTTPException(status_code=400, detail="Provider rejected the credential")
    row.verified_at = datetime.now(timezone.utc)
    await _audit(
        session,
        user,
        "tenant.provider_secret_verified",
        str(row.id),
        details=_provider_secret_details(row),
    )
    await session.commit()
    await session.refresh(row)
    return row


async def _provider_rejects(
    row: ProviderSecret,
    tenant_id: UUID,
    client: httpx.AsyncClient,
    verification_request: tuple[str, str, str, dict[str, str]],
) -> bool:
    """Whether the provider's model listing refuses the key; 503 when it cannot say."""
    try:
        credential = await get_secret_store().get_secret(
            TenantId(tenant_id),
            SecretRef(row.secret_ref),
            expected_purpose=provider_secret_purpose(row.provider, row.credential_kind),
        )
    except Exception as exc:
        logger.warning("Provider verification secret lookup failed")
        raise HTTPException(
            status_code=503, detail="Provider verification unavailable"
        ) from exc
    setting_name, default_base_url, path, header_templates = verification_request
    base_url = cast(str | None, getattr(settings, setting_name)) or default_base_url
    try:
        response = await client.get(
            f"{base_url.rstrip('/')}{path}",
            headers={
                name: value.format(credential=credential)
                for name, value in header_templates.items()
            },
        )
    except httpx.TransportError as exc:
        raise HTTPException(
            status_code=503, detail="Provider verification unavailable"
        ) from exc
    if response.status_code in {401, 403}:
        return True
    if response.status_code != 200:
        raise HTTPException(status_code=503, detail="Provider verification unavailable")
    return False


async def _aws_rejects(
    row: ProviderSecret, tenant_id: UUID, client: httpx.AsyncClient
) -> bool:
    """Whether STS refuses the access key, asked who it belongs to."""
    try:
        stored = json.loads(
            await get_secret_store().get_secret(
                TenantId(tenant_id),
                SecretRef(row.secret_ref),
                expected_purpose=provider_secret_purpose(
                    row.provider, row.credential_kind
                ),
            )
        )
    except Exception as exc:
        logger.warning("Provider verification secret lookup failed")
        raise HTTPException(
            status_code=503, detail="Provider verification unavailable"
        ) from exc
    credentials = AwsCredentials(
        access_key_id=stored["access_key_id"],
        secret_access_key=SecretStr(stored["secret_access_key"]),
    )
    try:
        # GetCallerIdentity needs no permission: any valid key answers it.
        await get_caller_identity(client, credentials, region="us-east-1")
    except StsError as exc:
        if exc.status == 403:
            return True
        raise HTTPException(
            status_code=503, detail="Provider verification unavailable"
        ) from None
    return False


async def _entra_rejects(
    row: ProviderSecret, tenant_id: UUID, client: httpx.AsyncClient
) -> bool:
    """Whether Entra ID refuses the client credential, asked for a fresh token."""
    try:
        await _fresh_resolver("openai", client).resolve_row(TenantId(tenant_id), row)
    except ProviderCallError as exc:
        if exc.status_code == 401:
            return True
        raise HTTPException(
            status_code=503, detail="Provider verification unavailable"
        ) from None
    except Exception as exc:
        logger.warning("Provider verification secret lookup failed")
        raise HTTPException(
            status_code=503, detail="Provider verification unavailable"
        ) from exc
    return False


@router.delete(
    "/providers/{secret_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
)
async def delete_provider_secret(
    secret_id: UUID,
    user: User = Depends(require("providers.manage", legacy_detail=ADMIN_REQUIRED)),
    session: AsyncSession = Depends(get_db),
) -> None:
    row = await _owned_provider_secret(session, user, secret_id)
    tenant_id = _tenant_id(user)
    secret_ref = SecretRef(row.secret_ref)
    purpose = provider_secret_purpose(row.provider, row.credential_kind)
    details = _provider_secret_details(row)
    await session.delete(row)
    await _audit(
        session, user, "tenant.provider_secret_deleted", str(row.id), details=details
    )
    await session.commit()
    await _delete_secret_best_effort(tenant_id, secret_ref, purpose)


def _provider_secret_details(row: ProviderSecret) -> dict[str, object]:
    return {
        "provider": row.provider,
        "name": row.name,
        "monthly_limit_usd": (
            str(row.monthly_limit_usd) if row.monthly_limit_usd is not None else None
        ),
        "key_rotated": False,
    }


def _mask(value: str) -> str:
    return f"{value[:3]}...{value[-4:]}"
