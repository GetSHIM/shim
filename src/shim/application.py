"""Community ASGI application composition."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
import sys
from typing import TextIO

import httpx
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.exceptions import HTTPException as StarletteHTTPException

from shim.api.v1.chat import router as chat_router
from shim.api.v1.community_scan import router as community_scan_router
from shim.api.v1.gemini import router as gemini_router
from shim.api.v1.messages import router as messages_router
from shim.api.v1.responses import router as responses_router
from shim.core.circuit_breaker import InMemoryCircuitBreaker
from shim.core.community_config import CommunitySettings
from shim.core.http import install_http_middleware
from shim.core.middleware import LoopbackHostMiddleware
from shim.gateway.admission import InMemoryLoopDetector, InMemoryRateLimiter
from shim.gateway.api.errors import gateway_exception_handler
from shim.gateway.kernel.gateway_kernel import GatewayKernel
from shim.gateway.local_auth import LocalAuthenticator
from shim.gateway.pipeline.anthropic_execution import AnthropicExecution
from shim.gateway.pipeline.google_execution import GoogleExecution
from shim.gateway.pipeline.openai_execution import OpenAIExecution
from shim.gateway.pipeline.privacy import ScanPrivacyStage
from shim.gateway.request_policy import LocalRequestPolicyResolver
from shim.gateway.usage import LocalUsageLifecycle
from shim.privacy.continuation import InMemoryPrivacyContinuationStore
from shim.privacy.pii_scrubber import PIIScrubberService
from shim.secrets.credentials import EnvironmentProviderCredentialResolver
from shim.services.gateway.service import GatewayService


_LOCAL_STATE_CAPACITY = 10_000


def create_community_app(
    settings: CommunitySettings | None = None,
    *,
    http_client: httpx.AsyncClient | None = None,
    event_stream: TextIO | None = None,
) -> FastAPI:
    configured = settings or CommunitySettings()
    rate_limiter = InMemoryRateLimiter(max_entries=_LOCAL_STATE_CAPACITY)
    loop_detector = InMemoryLoopDetector(max_entries=_LOCAL_STATE_CAPACITY)
    chain_store = InMemoryPrivacyContinuationStore(
        ttl_seconds=configured.PRIVACY_CHAIN_TTL_SECONDS,
        max_entries=_LOCAL_STATE_CAPACITY,
    )
    usage = LocalUsageLifecycle(
        event_stream if event_stream is not None else sys.stderr
    )
    pii_scrubber = PIIScrubberService()

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        owns_http_client = http_client is None
        client = http_client or httpx.AsyncClient(
            timeout=httpx.Timeout(
                connect=configured.OPENAI_CONNECT_TIMEOUT_SECONDS,
                read=configured.OPENAI_READ_TIMEOUT_SECONDS,
                write=configured.OPENAI_WRITE_TIMEOUT_SECONDS,
                pool=configured.OPENAI_POOL_TIMEOUT_SECONDS,
            ),
            follow_redirects=False,
        )
        application.state.http_client = client
        application.state.gateway_service = GatewayService(
            GatewayKernel(
                {
                    "anthropic": AnthropicExecution(
                        credential_resolver=EnvironmentProviderCredentialResolver(
                            "anthropic"
                        ),
                        circuit=InMemoryCircuitBreaker(),
                        settings=configured,
                        http_client=client,
                        pii_scrubber=pii_scrubber,
                    ),
                    "google": GoogleExecution(
                        credential_resolver=EnvironmentProviderCredentialResolver(
                            "google"
                        ),
                        circuit=InMemoryCircuitBreaker(),
                        settings=configured,
                        http_client=client,
                        pii_scrubber=pii_scrubber,
                    ),
                    "openai": OpenAIExecution(
                        credential_resolver=EnvironmentProviderCredentialResolver(
                            "openai"
                        ),
                        circuit=InMemoryCircuitBreaker(),
                        settings=configured,
                        http_client=client,
                        chain_store=chain_store,
                        pii_scrubber=pii_scrubber,
                    ),
                },
                chain_store=chain_store,
                policy_resolver=LocalRequestPolicyResolver(
                    rate_limit_rpm=configured.DEFAULT_RPM_LIMIT,
                    rate_limit_tpm=configured.DEFAULT_TPM_LIMIT,
                ),
                rate_limiter=rate_limiter,
                loop_detector=loop_detector,
                loop_repeat_limit=configured.LOOP_REPEAT_LIMIT,
                loop_window_seconds=configured.LOOP_WINDOW_SECONDS,
                cost_tag_max_length=configured.COST_TAG_MAX_LENGTH,
                usage=usage,
            )
        )
        try:
            yield
        finally:
            if owns_http_client:
                await client.aclose()

    application = FastAPI(
        title=configured.PROJECT_NAME,
        version=configured.VERSION,
        lifespan=lifespan,
    )
    application.add_exception_handler(
        StarletteHTTPException,
        gateway_exception_handler,
    )
    application.add_exception_handler(
        RequestValidationError,
        gateway_exception_handler,
    )
    application.state.community_settings = configured
    application.state.scan_privacy = ScanPrivacyStage(pii_scrubber)
    application.state.gateway_authenticator = LocalAuthenticator(
        configured.SHIM_API_KEY
    )
    install_http_middleware(
        application,
        settings=configured,
        rate_limiter=rate_limiter,
        allow_cors=configured.SHIM_API_KEY is not None,
    )
    if configured.SHIM_API_KEY is None:
        application.add_middleware(LoopbackHostMiddleware)
    application.include_router(chat_router, prefix="/v1")
    application.include_router(community_scan_router, prefix="/v1")
    application.include_router(gemini_router)
    application.include_router(messages_router, prefix="/v1")
    application.include_router(responses_router, prefix="/v1")
    application.add_api_route(
        "/health",
        _health,
        methods=["GET"],
        tags=["operations"],
    )
    application.add_api_route(
        "/metrics",
        _metrics,
        methods=["GET"],
        include_in_schema=False,
    )
    return application


async def _health(request: Request) -> dict[str, str]:
    settings: CommunitySettings = request.app.state.community_settings
    return {"status": "ok", "version": settings.VERSION}


async def _metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
