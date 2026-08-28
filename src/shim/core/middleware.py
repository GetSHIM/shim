"""Process-wide HTTP resource boundaries."""

from __future__ import annotations

from collections.abc import Iterable
from ipaddress import ip_address
import logging
from typing import Protocol
from urllib.parse import urlsplit

from starlette.datastructures import Headers
from starlette.datastructures import MutableHeaders
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from shim.gateway.api.errors import native_gateway_error_response

logger = logging.getLogger(__name__)


class RequestBodyTooLarge(Exception):
    """The received HTTP body exceeded the configured process boundary."""


class AsyncRateLimiter(Protocol):
    """Structural port for best-effort asynchronous burst admission."""

    async def allow(
        self,
        key: str,
        *,
        limit: int,
        window_seconds: int,
        amount: int = 1,
    ) -> bool: ...


class BodySizeLimitMiddleware:
    """Reject declared and streamed HTTP bodies above a fixed byte limit."""

    def __init__(self, app: ASGIApp, max_body_size: int) -> None:
        if max_body_size < 1:
            raise ValueError("max_body_size must be positive")
        self._app = app
        self._max_body_size = max_body_size

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        declared_size = _content_length(scope)
        if declared_size is not None and declared_size > self._max_body_size:
            await _too_large_response(scope, receive, send)
            return

        received_size = 0

        async def receive_limited() -> Message:
            nonlocal received_size
            message = await receive()
            if message["type"] == "http.request":
                received_size += len(message.get("body", b""))
                if received_size > self._max_body_size:
                    raise RequestBodyTooLarge
            return message

        try:
            await self._app(scope, receive_limited, send)
        except RequestBodyTooLarge:
            await _too_large_response(scope, receive, send)


class GlobalRateLimitMiddleware:
    """Apply a best-effort process-wide IP burst limit before routing."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        limit: int,
        window_seconds: int,
        trusted_proxies: Iterable[str] = (),
        limiter: AsyncRateLimiter,
    ) -> None:
        if limit < 1 or window_seconds < 1:
            raise ValueError("rate-limit bounds must be positive")
        self._app = app
        self._limit = limit
        self._window_seconds = window_seconds
        self._trusted_proxies = frozenset(
            _normalized_ip(value) for value in trusted_proxies
        )
        self._limiter = limiter

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        client_ip = _client_ip(scope, self._trusted_proxies)
        allowed = await self._limiter.allow(
            f"global_ip:{client_ip}",
            limit=self._limit,
            window_seconds=self._window_seconds,
        )
        if allowed:
            await self._app(scope, receive, send)
            return

        logger.warning("Global request burst limit exceeded")
        headers = {"Retry-After": str(self._window_seconds)}
        response = native_gateway_error_response(
            path=scope["path"],
            request_headers=Headers(scope=scope),
            status_code=429,
            detail={
                "code": "RATE_LIMIT_EXCEEDED",
                "message": "Too Many Requests",
            },
            headers=headers,
        ) or JSONResponse(
            {"detail": "Too Many Requests"}, status_code=429, headers=headers
        )
        await response(scope, receive, send)


class SecurityHeadersMiddleware:
    """Attach browser hardening headers to every HTTP response."""

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        async def send_hardened(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["X-Content-Type-Options"] = "nosniff"
                headers["X-Frame-Options"] = "DENY"
                headers["Strict-Transport-Security"] = (
                    "max-age=31536000; includeSubDomains"
                )
                headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
                if headers.get("Content-Security-Policy") is None:
                    headers["Content-Security-Policy"] = (
                        "default-src 'none'; frame-ancestors 'none'"
                    )
            await send(message)

        await self._app(scope, receive, send_hardened)


class LoopbackHostMiddleware:
    """Reject DNS-rebinding hostnames when the local gateway has no key."""

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and not _is_loopback_host(
            Headers(scope=scope).get("host", "")
        ):
            await JSONResponse(
                {"detail": "Invalid host header"},
                status_code=400,
            )(scope, receive, send)
            return
        await self._app(scope, receive, send)


def _content_length(scope: Scope) -> int | None:
    value = Headers(scope=scope).get("content-length")
    if value is None:
        return None
    try:
        size = int(value)
    except ValueError:
        return None
    return max(size, 0)


def _is_loopback_host(value: str) -> bool:
    if not value or any(character in value for character in "/?#@"):
        return False
    try:
        parsed = urlsplit(f"//{value}")
        hostname = parsed.hostname
        parsed.port
    except ValueError:
        return False
    if hostname is None:
        return False
    if hostname.casefold() == "localhost":
        return True
    try:
        return ip_address(hostname).is_loopback
    except ValueError:
        return False


def _client_ip(scope: Scope, trusted_proxies: frozenset[str]) -> str:
    client = scope.get("client")
    direct_ip = _normalized_ip(client[0]) if client else "unknown"
    if direct_ip not in trusted_proxies:
        return direct_ip

    headers = Headers(scope=scope)
    for name in ("cf-connecting-ip", "x-real-ip"):
        candidate = headers.get(name)
        normalized = _optional_ip(candidate)
        if normalized is not None:
            return normalized

    forwarded = headers.get("x-forwarded-for")
    if forwarded:
        for candidate in reversed(forwarded.split(",")):
            normalized = _optional_ip(candidate)
            if normalized is None:
                return direct_ip
            if normalized not in trusted_proxies:
                return normalized
    return direct_ip


def _normalized_ip(value: str) -> str:
    return str(ip_address(value.strip()))


def _optional_ip(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        return _normalized_ip(value)
    except ValueError:
        return None


async def _too_large_response(scope: Scope, receive: Receive, send: Send) -> None:
    logger.warning("HTTP request body exceeded configured byte limit")
    response = native_gateway_error_response(
        path=scope["path"],
        request_headers=Headers(scope=scope),
        status_code=413,
        detail={
            "code": "REQUEST_TOO_LARGE",
            "message": "Request body too large",
        },
    ) or JSONResponse({"detail": "Request body too large"}, status_code=413)
    await response(scope, receive, send)
