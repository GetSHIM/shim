"""ASGI application composition for shim gateway and control planes."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
import logging

import httpx
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import text
from starlette.exceptions import HTTPException as StarletteHTTPException

from shim_enterprise.api.v1.router import gateway_router, management_router
from shim.api.v1.gemini import router as gemini_router
from shim_enterprise.api.enterprise_deps import DatabaseGatewayAuthenticator
from shim_enterprise.billing.quota import BurstRateLimiter
from shim_enterprise.cache.circuit_breaker import RedisCircuitBreaker
from shim_enterprise.cache.loop_detection import LoopDetectionService
from shim_enterprise.cache.redis_index import CacheManager, CacheService
from shim_enterprise.core.config import settings
from shim_enterprise.core.database import AsyncSessionLocal, engine
from shim_enterprise.core.license import verify_license
from shim.core.http import install_http_middleware
from shim.gateway.api.errors import gateway_exception_handler
from shim.gateway.kernel.gateway_kernel import GatewayKernel
from shim_enterprise.gateway.kernel.scan_pipeline import ScanExecutionPipeline
from shim.gateway.pipeline.anthropic_execution import AnthropicExecution
from shim.gateway.pipeline.google_execution import GoogleExecution
from shim.gateway.pipeline.openai_execution import OpenAIExecution
from shim_enterprise.gateway.pipeline.quota_reservation import (
    DurableAccountingCoordinator,
    DurableUsageLifecycle,
)
from shim_enterprise.manual_test_dashboard import install_manual_test_dashboard
from shim.observability.logging import configure_error_reporting, configure_logging
from shim.observability.tracing import configure_tracing, shutdown_tracing
from shim_enterprise.privacy.chain_store import RedisPrivacyContinuationStore
from shim.privacy.pii_scrubber import PIIScrubberService
from shim_enterprise.secrets.store import (
    ManagedProviderCredentialResolver,
    get_secret_store,
)
from shim_enterprise.services.gateway.enterprise import EnterpriseGatewayService
from shim_enterprise.tenants.policy import (
    TenantPolicyService,
    TenantRequestPolicyResolver,
)


logger = logging.getLogger(__name__)


def create_enterprise_app() -> FastAPI:
    configure_logging(settings.LOG_LEVEL)
    if settings.ENVIRONMENT == "production":
        active_license = verify_license(settings.SHIM_LICENSE_KEY)
        logger.info(
            "shim licence accepted customer=%s expires=%s",
            active_license.customer,
            active_license.expires,
        )
    configure_error_reporting(
        sentry_dsn=settings.SENTRY_DSN,
        environment=settings.ENVIRONMENT,
    )
    configure_tracing(
        endpoint=settings.OTEL_EXPORTER_OTLP_ENDPOINT,
        service_name=settings.OTEL_SERVICE_NAME,
    )

    cache = CacheService()
    application = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        lifespan=_lifespan,
    )
    application.add_exception_handler(
        StarletteHTTPException,
        gateway_exception_handler,
    )
    application.add_exception_handler(
        RequestValidationError,
        gateway_exception_handler,
    )
    application.state.cache = cache
    application.state.gateway_authenticator = DatabaseGatewayAuthenticator(
        AsyncSessionLocal
    )
    install_http_middleware(
        application,
        settings=settings,
        rate_limiter=BurstRateLimiter(cache),
        allow_cors=True,
    )
    application.include_router(gateway_router, prefix="/v1")
    application.include_router(gemini_router)
    application.include_router(management_router, prefix=settings.API_PREFIX)
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
    install_manual_test_dashboard(application)
    return application


@asynccontextmanager
async def _lifespan(application: FastAPI) -> AsyncIterator[None]:
    cache: CacheService = application.state.cache
    timeout = httpx.Timeout(
        connect=settings.OPENAI_CONNECT_TIMEOUT_SECONDS,
        read=settings.OPENAI_READ_TIMEOUT_SECONDS,
        write=settings.OPENAI_WRITE_TIMEOUT_SECONDS,
        pool=settings.OPENAI_POOL_TIMEOUT_SECONDS,
    )
    http_client = httpx.AsyncClient(timeout=timeout, follow_redirects=False)
    application.state.http_client = http_client
    pii_scrubber = PIIScrubberService()
    application.state.gateway_service = EnterpriseGatewayService(
        _create_gateway_kernel(cache, http_client, pii_scrubber),
        ScanExecutionPipeline(scrubber=pii_scrubber),
    )
    await _connect_cache(cache)
    try:
        yield
    finally:
        await http_client.aclose()
        await cache.close()
        await engine.dispose()
        shutdown_tracing()


def _create_gateway_kernel(
    cache: CacheService,
    http_client: httpx.AsyncClient,
    pii_scrubber: PIIScrubberService,
) -> GatewayKernel:
    policy_resolver = TenantRequestPolicyResolver(
        TenantPolicyService(CacheManager(cache)),
        AsyncSessionLocal,
    )
    secret_store = get_secret_store()
    chain_store = RedisPrivacyContinuationStore(cache)
    usage = DurableUsageLifecycle(DurableAccountingCoordinator(), AsyncSessionLocal)
    dependencies = {
        "http_client": http_client,
        "pii_scrubber": pii_scrubber,
    }
    return GatewayKernel(
        {
            "openai": OpenAIExecution(
                credential_resolver=ManagedProviderCredentialResolver(
                    "openai", secret_store, AsyncSessionLocal
                ),
                circuit=RedisCircuitBreaker("openai", cache=cache),
                settings=settings,
                chain_store=chain_store,
                **dependencies,
            ),
            "anthropic": AnthropicExecution(
                credential_resolver=ManagedProviderCredentialResolver(
                    "anthropic", secret_store, AsyncSessionLocal
                ),
                circuit=RedisCircuitBreaker("anthropic", cache=cache),
                settings=settings,
                **dependencies,
            ),
            "google": GoogleExecution(
                credential_resolver=ManagedProviderCredentialResolver(
                    "google", secret_store, AsyncSessionLocal
                ),
                circuit=RedisCircuitBreaker("google", cache=cache),
                settings=settings,
                **dependencies,
            ),
        },
        chain_store=chain_store,
        policy_resolver=policy_resolver,
        rate_limiter=BurstRateLimiter(cache),
        loop_detector=LoopDetectionService(cache),
        loop_repeat_limit=settings.LOOP_REPEAT_LIMIT,
        loop_window_seconds=settings.LOOP_WINDOW_SECONDS,
        cost_tag_max_length=settings.COST_TAG_MAX_LENGTH,
        usage=usage,
        heartbeat_interval_seconds=settings.GATEWAY_RECONCILIATION_INTERVAL_SECONDS,
        output_hash_salt=(
            settings.COMPLIANCE_HASH_SALT or settings.SECRET_KEY
            if settings.AI_ACT_AUDIT_ENABLED
            else None
        ),
    )


async def _connect_cache(
    cache: CacheService,
) -> None:
    try:
        await cache.connect()
    except Exception as exc:
        await cache.close()
        logger.warning("Redis cache unavailable type=%s", type(exc).__name__)


async def _health(request: Request, response: Response) -> dict[str, str]:
    health = {
        "status": "ok",
        "version": settings.VERSION,
        "database": "connected",
        "redis": "connected",
    }
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
    except Exception as exc:
        logger.error("Database health check failed type=%s", type(exc).__name__)
        health["database"] = "error"
        health["status"] = "degraded"

    redis = request.app.state.cache.redis
    try:
        if redis is None or not await redis.ping():
            health["redis"] = "disconnected"
            health["status"] = "degraded"
    except Exception as exc:
        logger.warning("Redis health check failed type=%s", type(exc).__name__)
        health["redis"] = "error"
        health["status"] = "degraded"
    if health["database"] != "connected":
        response.status_code = 503
    return health


async def _metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
