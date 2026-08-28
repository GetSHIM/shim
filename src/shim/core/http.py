"""Shared HTTP middleware composition."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from shim.core.community_config import CommunitySettings
from shim.core.middleware import (
    AsyncRateLimiter,
    BodySizeLimitMiddleware,
    GlobalRateLimitMiddleware,
    SecurityHeadersMiddleware,
)


def install_http_middleware(
    application: FastAPI,
    *,
    settings: CommunitySettings,
    rate_limiter: AsyncRateLimiter,
    allow_cors: bool,
) -> None:
    application.add_middleware(SecurityHeadersMiddleware)
    origins: list[str] = []
    if allow_cors:
        origins = [str(origin) for origin in settings.BACKEND_CORS_ORIGINS]
        if settings.CHROME_EXTENSION_ID:
            origins.append(f"chrome-extension://{settings.CHROME_EXTENSION_ID}")
        elif settings.IS_DEBUG:
            origins.append("chrome-extension://*")
    if origins:
        application.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=[
                "Authorization",
                "Cache-Control",
                "Content-Type",
                "anthropic-beta",
                "anthropic-user-profile-id",
                "anthropic-version",
                "idempotency-key",
                "openai-beta",
                "openai-organization",
                "openai-project",
                "x-client-request-id",
                "x-request-id",
                "x-api-key",
                "x-goog-api-key",
                "x-openai-api-key",
                "x-provider-key",
                "x-shim-key",
                "x-shim-tag",
            ],
            expose_headers=[
                "Content-Disposition",
                "X-Shim-Request-Id",
                "request-id",
                "retry-after",
                "x-goog-request-id",
                "x-request-id",
            ],
        )
    application.add_middleware(
        GlobalRateLimitMiddleware,
        limit=1000,
        window_seconds=60,
        trusted_proxies=settings.TRUSTED_PROXIES,
        limiter=rate_limiter,
    )
    application.add_middleware(
        BodySizeLimitMiddleware,
        max_body_size=settings.MAX_REQUEST_BODY_SIZE,
    )
