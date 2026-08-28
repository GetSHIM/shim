"""Trusted principal resolution and tenant-context construction."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Literal
from uuid import UUID, uuid4

from fastapi import HTTPException

from shim.gateway.contracts.context import (
    GatewayContext,
    PrivacyPolicy,
)
from shim.gateway.contracts.ids import ApiKeyId, ProviderId, RequestId
from shim.gateway.contracts.principal import AuthenticatedPrincipal
from shim.gateway.kernel.result import PreparedInference
from shim.gateway.kernel.stage import TraceValue
from shim.gateway.request_policy import RequestPolicyResolver
from shim.privacy.pii_scrubber import pii_scrubbing_enabled

if TYPE_CHECKING:
    from shim.secrets.credentials import EphemeralProviderCredential


@dataclass(frozen=True)
class GatewayRequestMetadata:
    endpoint: str
    method: str = "POST"
    query_params: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class GatewayInvocation:
    principal: AuthenticatedPrincipal
    payload: dict[str, Any]
    provider: Literal["openai", "anthropic", "google"]
    protocol: Literal["chat", "responses", "messages", "generate_content"]
    model: str
    stream: bool
    headers: dict[str, str]
    provider_credential: EphemeralProviderCredential | None
    metadata: GatewayRequestMetadata


class AuthenticateStage:
    """Combine trusted identity and tenantless protocol input."""

    name = "resolve_principal"

    def __init__(
        self,
        policy_resolver: RequestPolicyResolver,
    ) -> None:
        self.policy_resolver = policy_resolver

    async def run(self, value: GatewayInvocation) -> PreparedInference:
        policy = await self.policy_resolver.resolve(value.principal)
        request_id = RequestId(f"req_{uuid4().hex}")
        started_at = datetime.now(timezone.utc)
        metadata = value.metadata

        context = GatewayContext(
            request_id=request_id,
            tenant_id=policy.tenant_id,
            actor_type=value.principal.actor_type,
            api_key_id=ApiKeyId(UUID(str(value.principal.api_key_id))),
            user_id=None,
            endpoint=metadata.endpoint,
            started_at=started_at,
            tier_policy=policy.tier_policy,
            privacy_policy=PrivacyPolicy(
                pii_mode=(
                    "scrub" if pii_scrubbing_enabled(policy.pii_config) else "disabled"
                ),
            ),
            audit_policy=policy.audit_policy,
        )
        if policy.tenant_policy.allowed_providers and value.provider not in {
            str(provider) for provider in policy.tenant_policy.allowed_providers
        }:
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "PROVIDER_NOT_ALLOWED",
                    "message": f"{value.provider.title()} is not allowed by tenant policy.",
                },
            )
        if (
            policy.tenant_policy.require_zero_retention
            and not _zero_retention_requested(value)
        ):
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "ZERO_RETENTION_REQUIRED",
                    "message": "Tenant policy requires a provider-enforceable zero-retention request.",
                },
            )
        return PreparedInference(
            context=context,
            payload=dict(value.payload),
            protocol=value.protocol,
            model=value.model,
            stream=value.stream,
            policy=policy.request_policy,
            pii_config=policy.pii_config,
            provider=ProviderId(value.provider),
        )

    def trace_metadata(self, output: PreparedInference) -> Mapping[str, TraceValue]:
        return {
            "actor_type": output.context.actor_type,
            "endpoint": output.context.endpoint,
            "provider": str(output.provider),
            "source_endpoint": output.source_endpoint,
        }


def _zero_retention_requested(invocation: GatewayInvocation) -> bool:
    if invocation.payload.get("store") is not False:
        return False
    if invocation.provider == "openai":
        if invocation.payload.get("prompt_cache_retention") == "24h":
            return False
        if invocation.protocol == "chat":
            return (
                "audio" not in (invocation.payload.get("modalities") or ())
                and invocation.payload.get("audio") is None
                and invocation.payload.get("web_search_options") is None
            )
        if any(
            invocation.payload.get(field) is not None
            for field in ("conversation", "previous_response_id", "prompt")
        ):
            return False
        tools = invocation.payload.get("tools")
        return not isinstance(tools, list) or all(
            isinstance(tool, dict) and tool.get("type") == "function" for tool in tools
        )
    if invocation.provider == "google":
        return (
            "cachedContent" not in invocation.payload
            and invocation.payload.get("tools") is None
        )
    return False
