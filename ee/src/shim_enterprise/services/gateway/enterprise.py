"""Enterprise gateway errors and provider-free scan dispatch."""

from __future__ import annotations

from typing import Any, Literal

from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import Response

from shim_enterprise.billing.ledger import QuotaLimitExceeded, SpendLimitExceeded
from shim_enterprise.gateway.api.enterprise_errors import (
    raise_accounting_limit,
    raise_audit_intent_error,
    raise_persistence_error,
    raise_tenant_policy_error,
)
from shim_enterprise.gateway.contracts.enterprise_scan import (
    ScanExecutionResult,
    ScanUsageStatus,
)
from shim.gateway.contracts.inference import ScanInput
from shim.gateway.contracts.principal import AuthenticatedPrincipal
from shim.gateway.kernel.gateway_kernel import GatewayKernel
from shim_enterprise.gateway.kernel.scan_pipeline import ScanExecutionPipeline
from shim_enterprise.gateway.pipeline.audit_intent import AuditIntentPersistenceError
from shim.gateway.pipeline.authenticate import GatewayRequestMetadata
from shim_enterprise.gateway.pipeline.quota_reservation import (
    AccountingPersistenceError,
)
from shim.secrets.credentials import EphemeralProviderCredential
from shim.services.gateway.service import GatewayService
from shim_enterprise.tenants.policy import TenantPolicyConfigurationError


class EnterpriseGatewayService(GatewayService):
    def __init__(
        self,
        kernel: GatewayKernel,
        scan_pipeline: ScanExecutionPipeline,
    ) -> None:
        super().__init__(kernel)
        self.scan_pipeline = scan_pipeline

    async def dispatch_inference(
        self,
        *,
        payload: dict[str, Any],
        provider: Literal["openai", "anthropic", "google"],
        protocol: Literal["chat", "responses", "messages", "generate_content"],
        model: str,
        stream: bool,
        headers: dict[str, str],
        provider_credential: EphemeralProviderCredential | None,
        principal: AuthenticatedPrincipal,
        request_metadata: GatewayRequestMetadata,
    ) -> Response:
        try:
            return await super().dispatch_inference(
                payload=payload,
                provider=provider,
                protocol=protocol,
                model=model,
                stream=stream,
                headers=headers,
                provider_credential=provider_credential,
                principal=principal,
                request_metadata=request_metadata,
            )
        except AccountingPersistenceError:
            raise_persistence_error()
        except AuditIntentPersistenceError:
            raise_audit_intent_error()
        except QuotaLimitExceeded:
            raise_accounting_limit("MONTHLY_QUOTA_EXCEEDED")
        except SpendLimitExceeded:
            raise_accounting_limit("SPEND_LIMIT_EXCEEDED")
        except TenantPolicyConfigurationError:
            raise_tenant_policy_error()

    async def dispatch_scan(
        self,
        *,
        payload: ScanInput,
        principal: AuthenticatedPrincipal,
        db: AsyncSession,
    ) -> ScanExecutionResult:
        return await self.scan_pipeline.execute(payload, principal, db)

    async def scan_usage(
        self,
        *,
        principal: AuthenticatedPrincipal,
        db: AsyncSession,
    ) -> ScanUsageStatus:
        return await self.scan_pipeline.usage(principal, db)
