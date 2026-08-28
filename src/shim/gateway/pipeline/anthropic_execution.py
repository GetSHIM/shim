"""Invocation-scoped Anthropic SDK execution."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

import httpx
from anthropic import (
    APIConnectionError,
    APIError,
    APIStatusError,
    APITimeoutError,
    AsyncAnthropic,
)

from shim.core.circuit_breaker import CircuitBreaker
from shim.core.community_config import CommunitySettings
from shim.gateway.kernel.result import PreparedInference
from shim.gateway.pipeline.provider_execution import (
    ProviderCallError,
    ProviderNonStream,
    ProviderStream,
    retry_after_header,
    sdk_create_kwargs,
    select_headers,
)
from shim.gateway.streaming.sse import encode_responses_event
from shim.privacy.deanonymizer import (
    AnthropicStreamRestorer,
    restore_anthropic_payload,
)
from shim.privacy.pii_scrubber import PIIScrubberService
from shim.secrets.credentials import ProviderCredentialResolver


_ANTHROPIC_HEADERS = {
    "anthropic-beta": "anthropic-beta",
    "anthropic-version": "anthropic-version",
}


class AnthropicExecution:
    def __init__(
        self,
        *,
        credential_resolver: ProviderCredentialResolver,
        circuit: CircuitBreaker,
        settings: CommunitySettings,
        http_client: httpx.AsyncClient,
        pii_scrubber: PIIScrubberService | None = None,
    ) -> None:
        self.credential_resolver = credential_resolver
        self.pii_scrubber = pii_scrubber or PIIScrubberService()
        self.http_client = http_client
        self.circuit = circuit
        self.settings = settings
        self.timeout = httpx.Timeout(
            connect=settings.ANTHROPIC_CONNECT_TIMEOUT_SECONDS,
            read=settings.ANTHROPIC_READ_TIMEOUT_SECONDS,
            write=settings.ANTHROPIC_WRITE_TIMEOUT_SECONDS,
            pool=settings.ANTHROPIC_POOL_TIMEOUT_SECONDS,
        )

    async def execute(
        self,
        *,
        invocation,
        prepared: PreparedInference,
        provider_start_callback: Callable[[], Awaitable[None]],
    ) -> ProviderNonStream | ProviderStream:
        if prepared.privacy is None:
            raise RuntimeError("privacy stage must run before Anthropic execution")
        try:
            api_key = await self.credential_resolver.resolve(
                prepared.tenant_id,
                invocation.provider_credential,
            )
        except Exception:
            raise ProviderCallError(
                503,
                "PROVIDER_UNAVAILABLE",
                False,
                provider="anthropic",
            ) from None
        if not api_key:
            raise ProviderCallError(
                503,
                "PROVIDER_UNAVAILABLE",
                False,
                provider="anthropic",
            )
        if not await self.circuit.acquire_call():
            raise ProviderCallError(
                503,
                "PROVIDER_UNAVAILABLE",
                True,
                provider="anthropic",
            )
        try:
            client = AsyncAnthropic(
                api_key=api_key,
                base_url=self.settings.ANTHROPIC_BASE_URL
                or "https://api.anthropic.com",
                timeout=self.timeout,
                max_retries=0,
                http_client=self.http_client,
            )
            await provider_start_callback()
        except BaseException:
            await self.circuit.release_probe()
            raise
        try:
            beta = _beta_enabled(invocation)
            create = client.beta.messages.create if beta else client.messages.create
            kwargs = sdk_create_kwargs(
                create,
                prepared.payload,
                reserved=frozenset({"betas"}),
            )
            headers = select_headers(
                getattr(invocation, "headers", {}),
                _ANTHROPIC_HEADERS,
            )
            if headers:
                kwargs["extra_headers"] = headers
            if beta and "anthropic-beta" in headers:
                kwargs["betas"] = [
                    item.strip()
                    for item in headers["anthropic-beta"].split(",")
                    if item.strip()
                ]
            result = await create(**kwargs)
        except asyncio.CancelledError:
            await self.circuit.release_probe()
            raise
        except Exception as exc:
            await self._record_error(exc)
            raise _public_error(exc) from None

        if prepared.stream:
            state = {"closed": False, "recorded": False}

            async def close_stream() -> None:
                if state["closed"]:
                    return
                state["closed"] = True
                try:
                    await result.close()
                except Exception:
                    pass
                finally:
                    if not state["recorded"]:
                        await self.circuit.release_probe()

            return ProviderStream(
                events=self._stream(result, prepared, state, close_stream),
                request_id=_stream_request_id(result),
                close=close_stream,
            )

        payload = _dump_sdk(result)
        if _is_anthropic_failure(payload):
            await self.circuit.record_failure()
            raise ProviderCallError(
                502,
                "PROVIDER_UNAVAILABLE",
                False,
                provider="anthropic",
                request_id=getattr(result, "_request_id", None),
            )
        await self.circuit.record_success()
        payload = restore_anthropic_payload(
            payload,
            prepared.privacy.verification_map,
            self.pii_scrubber,
        )
        return ProviderNonStream(
            payload=payload,
            request_id=getattr(result, "_request_id", None),
        )

    async def _stream(
        self,
        stream,
        prepared: PreparedInference,
        state: dict[str, bool],
        close_stream: Callable[[], Awaitable[None]],
    ) -> AsyncIterator[bytes]:
        assert prepared.privacy is not None
        restorer = AnthropicStreamRestorer(
            prepared.privacy.verification_map,
            self.pii_scrubber,
        )
        try:
            async for event in stream:
                for payload in restorer.restore_events(_dump_sdk(event)):
                    if _is_anthropic_failure(payload):
                        if not state["recorded"]:
                            await self.circuit.record_failure()
                            state["recorded"] = True
                        yield _error_event(
                            ProviderCallError(
                                502,
                                "PROVIDER_UNAVAILABLE",
                                False,
                                provider="anthropic",
                                request_id=_stream_request_id(stream),
                            )
                        )
                        return
                    if payload.get("type") == "message_stop" and not state["recorded"]:
                        await self.circuit.record_success()
                        state["recorded"] = True
                    yield encode_responses_event(payload)
                    if payload.get("type") == "message_stop":
                        return
            if not state["recorded"]:
                await self.circuit.record_failure()
                state["recorded"] = True
                yield _error_event(
                    ProviderCallError(
                        502,
                        "PROVIDER_UNAVAILABLE",
                        False,
                        provider="anthropic",
                    )
                )
        except (asyncio.CancelledError, GeneratorExit):
            raise
        except Exception as exc:
            await self._record_error(exc)
            state["recorded"] = True
            yield _error_event(_public_error(exc))
        finally:
            await close_stream()

    async def _record_error(self, exc: Exception) -> None:
        if (
            isinstance(exc, APIStatusError)
            and 400 <= exc.status_code < 500
            and exc.status_code not in {408, 409, 429}
        ):
            await self.circuit.record_success()
        else:
            await self.circuit.record_failure()


def _dump_sdk(value: Any) -> dict[str, Any]:
    dumped = value.model_dump(mode="json", exclude_unset=True)
    if not isinstance(dumped, dict):
        raise TypeError("Anthropic SDK value did not serialize to an object")
    return dumped


def _stream_request_id(stream: Any) -> str | None:
    response = getattr(stream, "response", None)
    headers = getattr(response, "headers", {})
    return headers.get("request-id") if hasattr(headers, "get") else None


def _beta_enabled(invocation: Any) -> bool:
    headers = getattr(invocation, "headers", {})
    if any(key.casefold() == "anthropic-beta" for key in headers):
        return True
    metadata = getattr(invocation, "metadata", None)
    return any(
        key.casefold() == "beta" and value.casefold() == "true"
        for key, value in getattr(metadata, "query_params", ())
    )


def _is_anthropic_failure(payload: dict[str, Any]) -> bool:
    if payload.get("type") == "error" or payload.get("error") is not None:
        return True
    message = payload.get("message")
    return isinstance(message, dict) and message.get("error") is not None


def _public_error(exc: Exception) -> ProviderCallError:
    if isinstance(exc, APITimeoutError):
        return ProviderCallError(
            504,
            "PROVIDER_TIMEOUT",
            True,
            provider="anthropic",
        )
    if isinstance(exc, APIStatusError):
        return ProviderCallError(
            exc.status_code,
            "PROVIDER_TIMEOUT" if exc.status_code == 408 else "PROVIDER_UNAVAILABLE",
            exc.status_code in {408, 409, 429} or exc.status_code >= 500,
            provider="anthropic",
            request_id=getattr(exc, "request_id", None),
            retry_after=retry_after_header(exc),
        )
    if isinstance(exc, APIConnectionError):
        return ProviderCallError(
            503,
            "PROVIDER_UNAVAILABLE",
            True,
            provider="anthropic",
        )
    if isinstance(exc, (httpx.TimeoutException, TimeoutError)):
        return ProviderCallError(
            504,
            "PROVIDER_TIMEOUT",
            True,
            provider="anthropic",
        )
    if isinstance(exc, (APIError, httpx.TransportError)):
        return ProviderCallError(
            503,
            "PROVIDER_UNAVAILABLE",
            True,
            provider="anthropic",
        )
    return ProviderCallError(
        502,
        "PROVIDER_UNAVAILABLE",
        False,
        provider="anthropic",
    )


def _error_event(error: ProviderCallError) -> bytes:
    message = (
        "The Anthropic stream timed out."
        if error.error_code == "PROVIDER_TIMEOUT"
        else "The Anthropic stream ended with an error."
    )
    payload = {
        "type": "error",
        "error": {
            "type": "api_error",
            "message": message,
        },
    }
    if error.request_id:
        payload["request_id"] = error.request_id
    return encode_responses_event(payload)
