"""Temporary credentials of a tenant's AWS role, assumed by the gateway's identity.

Nothing secret is stored for a role: the gateway assumes it with the tenant's
external id (or, on the hosted cloud, a Google ID token whose audience carries that
id), and keeps the session until 300 seconds before it ends.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from uuid import UUID

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from shim.gateway.pipeline.provider_execution import ProviderCallError
from shim_enterprise.aws.identity import GatewayIdentity, IdentityUnavailable
from shim_enterprise.aws.sigv4 import AwsCredentials
from shim_enterprise.aws.sts import StsError, assume_role, assume_role_with_web_identity
from shim_enterprise.aws.tokens import ExpiringCache
from shim_enterprise.core.config import settings
from shim_enterprise.tenants.models import OrganizationAwsIdentity

logger = logging.getLogger(__name__)
# What AWS says when the trust policy, the external id or the token does not fit.
REFUSALS = frozenset(
    {
        "AccessDenied",
        "InvalidIdentityToken",
        "IDPRejectedClaim",
        "ExpiredTokenException",
    }
)


def web_identity_audience(external_id: str) -> str:
    return f"shim-aws:{external_id}"


def session_name(tenant_id: UUID, secret_id: UUID) -> str:
    return f"shim-{tenant_id.hex[:8]}-{secret_id.hex[:8]}"


class RoleRefused(Exception):
    """AWS refused the role (`refused`) or could not answer; `step` names where."""

    def __init__(self, step: str, refused: bool, aws_error: str | None) -> None:
        super().__init__(step)
        self.step, self.refused, self.aws_error = step, refused, aws_error

    def provider_error(self, provider: str) -> ProviderCallError:
        if self.step == "not_configured":
            return ProviderCallError(
                503,
                "PROVIDER_NOT_CONFIGURED",
                False,
                provider=provider,
                message="No AWS identity is configured on this gateway.",
            )
        if self.refused:
            return ProviderCallError(
                401,
                "INVALID_PROVIDER_CREDENTIAL",
                False,
                provider=provider,
                message="AWS refused to let shim assume the configured role.",
            )
        return ProviderCallError(503, "PROVIDER_UNAVAILABLE", True, provider=provider)


class AwsRoles:
    def __init__(
        self,
        http_client: httpx.AsyncClient,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        self.http_client = http_client
        self.session_factory = session_factory
        self.identity = GatewayIdentity(http_client)
        self._sessions: ExpiringCache[AwsCredentials] = ExpiringCache()

    async def external_id(self, tenant_id: UUID) -> str | None:
        async with self.session_factory() as session:
            return await session.scalar(
                select(OrganizationAwsIdentity.external_id).where(
                    OrganizationAwsIdentity.organization_id == tenant_id
                )
            )

    async def credentials(
        self,
        tenant_id: UUID,
        secret_id: UUID,
        role_arn: str,
        region: str,
        session_tag: str | None = None,
        *,
        fresh: bool = False,
    ) -> AwsCredentials:
        if fresh:
            return await self._assume(tenant_id, secret_id, role_arn, region)
        now = datetime.now(timezone.utc)

        async def mint() -> tuple[AwsCredentials, datetime]:
            found = await self._assume(tenant_id, secret_id, role_arn, region)
            assert found.expires_at is not None
            return found, found.expires_at

        return await self._sessions.get(
            (tenant_id, secret_id, role_arn, region, session_tag), mint, now=now
        )

    async def gateway_ready(self, tenant_id: UUID, region: str) -> None:
        """The gateway's identity answers (base credentials or a Google ID token)."""
        external_id = await self._external_id(tenant_id)
        try:
            if settings.AWS_GATEWAY_IDENTITY == "gcp_metadata":
                await self.identity.google_id_token(web_identity_audience(external_id))
            else:
                await self.identity.credentials(region)
        except IdentityUnavailable as error:
            logger.warning(
                "AWS gateway identity failed source=%s status=%s",
                error.source,
                error.status,
            )
            raise RoleRefused("gateway_identity", False, None) from None

    async def _external_id(self, tenant_id: UUID) -> str:
        if settings.AWS_GATEWAY_IDENTITY == "none":
            raise RoleRefused("not_configured", False, None)
        external_id = await self.external_id(tenant_id)
        if external_id is None:
            raise RoleRefused("not_configured", False, None)
        return external_id

    async def _assume(
        self, tenant_id: UUID, secret_id: UUID, role_arn: str, region: str
    ) -> AwsCredentials:
        external_id = await self._external_id(tenant_id)
        name = session_name(tenant_id, secret_id)
        action = "AssumeRole"
        try:
            if settings.AWS_GATEWAY_IDENTITY == "gcp_metadata":
                action = "AssumeRoleWithWebIdentity"
                return await assume_role_with_web_identity(
                    self.http_client,
                    region=region,
                    role_arn=role_arn,
                    session_name=name,
                    web_identity_token=await self.identity.google_id_token(
                        web_identity_audience(external_id)
                    ),
                    duration_seconds=settings.AWS_ROLE_SESSION_SECONDS,
                )
            return await assume_role(
                self.http_client,
                await self.identity.credentials(region),
                region=region,
                role_arn=role_arn,
                session_name=name,
                external_id=external_id,
                duration_seconds=settings.AWS_ROLE_SESSION_SECONDS,
            )
        except StsError as error:
            refused = error.status == 403 or error.code in REFUSALS
            # The action, the status and AWS's code: never a credential, token,
            # external id or role ARN.
            logger.warning(
                "AWS role session failed action=%s status=%s code=%s",
                action,
                error.status,
                error.code,
            )
            raise RoleRefused("assume_role", refused, error.code) from None
        except IdentityUnavailable as error:
            logger.warning(
                "AWS gateway identity failed source=%s status=%s",
                error.source,
                error.status,
            )
            raise RoleRefused("gateway_identity", False, None) from None
