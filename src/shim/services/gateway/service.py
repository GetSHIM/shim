"""Dispatch boundary for the SDK-native gateway."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal

from starlette.responses import Response

from shim.gateway.api.errors import (
    provider_error_response,
    raise_privacy_continuation_error,
)
from shim.gateway.kernel.gateway_kernel import GatewayKernel
from shim.gateway.pipeline.authenticate import GatewayInvocation
from shim.gateway.pipeline.provider_execution import ProviderCallError
from shim.privacy.continuation import PrivacyContinuationUnavailableError

if TYPE_CHECKING:
    from shim.gateway.contracts.principal import AuthenticatedPrincipal
    from shim.gateway.pipeline.authenticate import GatewayRequestMetadata
    from shim.secrets.credentials import EphemeralProviderCredential


class GatewayService:
    def __init__(self, kernel: GatewayKernel) -> None:
        self.kernel = kernel

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
        invocation = GatewayInvocation(
            principal=principal,
            payload=payload,
            provider=provider,
            protocol=protocol,
            model=model,
            stream=stream,
            headers=headers,
            provider_credential=provider_credential,
            metadata=request_metadata,
        )
        try:
            return await self.kernel.execute(invocation)
        except ProviderCallError as exc:
            return provider_error_response(exc)
        except PrivacyContinuationUnavailableError:
            raise_privacy_continuation_error()
        finally:
            if provider_credential is not None:
                provider_credential.clear()
