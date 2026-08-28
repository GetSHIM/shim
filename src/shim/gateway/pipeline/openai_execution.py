"""Invocation-scoped OpenAI SDK execution."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

import httpx
from openai import (
    APIConnectionError,
    APIError,
    APIStatusError,
    APITimeoutError,
    AsyncOpenAI,
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
from shim.gateway.streaming.sse import encode_data, encode_responses_event
from shim.privacy.continuation import (
    PrivacyContinuationStore,
    PrivacyContinuationUnavailableError,
)
from shim.privacy.deanonymizer import OpenAIStreamRestorer, restore_openai_payload
from shim.privacy.pii_scrubber import PIIScrubberService
from shim.secrets.credentials import ProviderCredentialResolver


_OPENAI_HEADERS = {
    "idempotency-key": "Idempotency-Key",
    "openai-beta": "OpenAI-Beta",
    "openai-organization": "OpenAI-Organization",
    "openai-project": "OpenAI-Project",
    "x-client-request-id": "X-Client-Request-Id",
}


class OpenAIExecution:
    def __init__(
        self,
        *,
        credential_resolver: ProviderCredentialResolver,
        circuit: CircuitBreaker,
        settings: CommunitySettings,
        http_client: httpx.AsyncClient,
        chain_store: PrivacyContinuationStore,
        pii_scrubber: PIIScrubberService | None = None,
    ) -> None:
        self.credential_resolver = credential_resolver
        self.pii_scrubber = pii_scrubber or PIIScrubberService()
        self.http_client = http_client
        self.chain_store = chain_store
        self.circuit = circuit
        self.settings = settings
        self.timeout = httpx.Timeout(
            connect=settings.OPENAI_CONNECT_TIMEOUT_SECONDS,
            read=settings.OPENAI_READ_TIMEOUT_SECONDS,
            write=settings.OPENAI_WRITE_TIMEOUT_SECONDS,
            pool=settings.OPENAI_POOL_TIMEOUT_SECONDS,
        )

    async def execute(
        self,
        *,
        invocation,
        prepared: PreparedInference,
        provider_start_callback: Callable[[], Awaitable[None]],
    ) -> ProviderNonStream | ProviderStream:
        if prepared.privacy is None:
            raise RuntimeError("privacy stage must run before OpenAI execution")
        try:
            api_key = await self.credential_resolver.resolve(
                prepared.tenant_id,
                invocation.provider_credential,
            )
        except Exception:
            raise _error(503, "PROVIDER_UNAVAILABLE", False) from None
        if not api_key:
            raise _error(503, "PROVIDER_UNAVAILABLE", False)
        if not await self.circuit.acquire_call():
            raise _error(503, "PROVIDER_UNAVAILABLE", True)
        try:
            client = AsyncOpenAI(
                api_key=api_key,
                base_url=self.settings.OPENAI_BASE_URL or "https://api.openai.com/v1",
                timeout=self.timeout,
                max_retries=0,
                http_client=self.http_client,
            )
            await provider_start_callback()
        except BaseException:
            await self.circuit.release_probe()
            raise
        try:
            create = (
                client.responses.create
                if prepared.protocol == "responses"
                else client.chat.completions.create
            )
            kwargs = sdk_create_kwargs(create, prepared.payload)
            headers = select_headers(
                getattr(invocation, "headers", {}),
                _OPENAI_HEADERS,
            )
            if headers:
                kwargs["extra_headers"] = headers
            result = await create(**kwargs)
        except asyncio.CancelledError:
            await self.circuit.release_probe()
            raise
        except Exception as exc:
            await self._record_error(exc)
            raise _public_error(exc) from None

        if prepared.stream:
            request_id = _stream_request_id(result)
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

            events = (
                self._responses_stream(result, prepared, state, close_stream)
                if prepared.protocol == "responses"
                else self._chat_stream(result, prepared, state, close_stream)
            )
            return ProviderStream(
                events=events,
                request_id=request_id,
                close=close_stream,
            )

        payload = _dump_sdk(result)
        if _is_openai_failure(payload) and not (
            prepared.protocol == "responses" and payload.get("status") == "failed"
        ):
            await self.circuit.record_failure()
            raise _error(
                502,
                "PROVIDER_UNAVAILABLE",
                False,
                request_id=getattr(result, "_request_id", None),
            )
        if prepared.protocol == "responses" and payload.get("status") == "failed":
            await self.circuit.record_failure()
        else:
            await self.circuit.record_success()
        response_id = payload.get("id")
        if prepared.protocol == "responses" and isinstance(response_id, str):
            await self.chain_store.save(
                prepared.tenant_id,
                response_id,
                prepared.privacy.verification_map,
            )
        restored = restore_openai_payload(
            payload,
            prepared.privacy.verification_map,
            self.pii_scrubber,
        )
        if prepared.protocol == "responses":
            restored = _sanitize_responses_failure(restored)
        return ProviderNonStream(
            payload=restored,
            request_id=getattr(result, "_request_id", None),
        )

    async def _responses_stream(
        self,
        stream,
        prepared: PreparedInference,
        state: dict[str, bool],
        close_stream: Callable[[], Awaitable[None]],
    ) -> AsyncIterator[bytes]:
        assert prepared.privacy is not None
        restorer = OpenAIStreamRestorer(
            prepared.privacy.verification_map,
            self.pii_scrubber,
        )
        next_sequence_number = 0
        saved_response_ids: set[str] = set()
        try:
            async for event in stream:
                payload = _dump_sdk(event)
                event_type = str(payload.get("type", ""))
                sequence_number = payload.get("sequence_number")
                if isinstance(sequence_number, int):
                    next_sequence_number = max(
                        next_sequence_number,
                        sequence_number + 1,
                    )
                if _is_openai_failure(payload) and event_type != "response.failed":
                    if not state["recorded"]:
                        await self.circuit.record_failure()
                        state["recorded"] = True
                    yield _responses_error_event(
                        "PROVIDER_UNAVAILABLE",
                        "The OpenAI stream ended with an error.",
                        next_sequence_number,
                    )
                    return
                response = payload.get("response")
                response_id = response.get("id") if isinstance(response, dict) else None
                if (
                    isinstance(response_id, str)
                    and response_id not in saved_response_ids
                ):
                    await self.chain_store.save(
                        prepared.tenant_id,
                        response_id,
                        prepared.privacy.verification_map,
                    )
                    saved_response_ids.add(response_id)
                restored = _sanitize_responses_failure(
                    restorer.restore_response_event(payload)
                )
                if (
                    event_type in {"response.completed", "response.incomplete"}
                    and not state["recorded"]
                ):
                    await self.circuit.record_success()
                    state["recorded"] = True
                elif (
                    event_type in {"error", "response.failed"} and not state["recorded"]
                ):
                    await self.circuit.record_failure()
                    state["recorded"] = True
                elif event_type == "response.cancelled" and not state["recorded"]:
                    await self.circuit.record_success()
                    state["recorded"] = True
                yield encode_responses_event(restored)
                if event_type in {
                    "error",
                    "response.cancelled",
                    "response.completed",
                    "response.failed",
                    "response.incomplete",
                }:
                    return
            if not state["recorded"]:
                await self.circuit.record_failure()
                state["recorded"] = True
        except (asyncio.CancelledError, GeneratorExit):
            raise
        except PrivacyContinuationUnavailableError:
            if not state["recorded"]:
                await self.circuit.record_success()
                state["recorded"] = True
            yield _responses_error_event(
                "PRIVACY_STATE_UNAVAILABLE",
                "Privacy continuation state is unavailable.",
                next_sequence_number,
            )
        except Exception as exc:
            await self._record_error(exc)
            state["recorded"] = True
            error = _public_error(exc)
            yield _responses_error_event(
                error.error_code,
                "The OpenAI stream ended with an error.",
                next_sequence_number,
            )
        finally:
            await close_stream()

    async def _chat_stream(
        self,
        stream,
        prepared: PreparedInference,
        state: dict[str, bool],
        close_stream: Callable[[], Awaitable[None]],
    ) -> AsyncIterator[bytes]:
        assert prepared.privacy is not None
        restorer = OpenAIStreamRestorer(
            prepared.privacy.verification_map,
            self.pii_scrubber,
        )
        expected_choices = _expected_chat_choices(prepared.payload)
        finished_choices: set[int] = set()
        try:
            async for chunk in stream:
                payload = _dump_sdk(chunk)
                if _is_openai_failure(payload):
                    if not state["recorded"]:
                        await self.circuit.record_failure()
                        state["recorded"] = True
                    yield _chat_error_event(
                        _error(
                            502,
                            "PROVIDER_UNAVAILABLE",
                            False,
                            request_id=_stream_request_id(stream),
                        )
                    )
                    return
                finished_choices.update(_finished_chat_choices(payload))
                if len(finished_choices) >= expected_choices and not state["recorded"]:
                    await self.circuit.record_success()
                    state["recorded"] = True
                restored = restorer.restore_chat_chunk(payload)
                yield encode_data(restored)
            if len(finished_choices) >= expected_choices:
                yield b"data: [DONE]\n\n"
            else:
                await self.circuit.record_failure()
                state["recorded"] = True
                yield _chat_error_event(_error(502, "PROVIDER_UNAVAILABLE", False))
        except (asyncio.CancelledError, GeneratorExit):
            raise
        except Exception as exc:
            if state["recorded"]:
                yield b"data: [DONE]\n\n"
                return
            await self._record_error(exc)
            state["recorded"] = True
            yield _chat_error_event(_public_error(exc))
        finally:
            await close_stream()

    async def _record_error(self, exc: Exception) -> None:
        if (
            isinstance(exc, APIStatusError)
            and exc.status_code < 500
            and exc.status_code not in {408, 409, 429}
        ):
            await self.circuit.record_success()
        else:
            await self.circuit.record_failure()


def _dump_sdk(value: Any) -> dict[str, Any]:
    dumped = value.model_dump(mode="json")
    if not isinstance(dumped, dict):
        raise TypeError("OpenAI SDK value did not serialize to an object")
    return dumped


def _stream_request_id(stream: Any) -> str | None:
    response = getattr(stream, "response", None)
    headers = getattr(response, "headers", {})
    return headers.get("x-request-id") if hasattr(headers, "get") else None


def _is_openai_failure(payload: dict[str, Any]) -> bool:
    if payload.get("type") == "error" or payload.get("error") is not None:
        return True
    response = payload.get("response")
    return isinstance(response, dict) and response.get("error") is not None


def _finished_chat_choices(payload: dict[str, Any]) -> set[int]:
    choices = payload.get("choices")
    if not isinstance(choices, list):
        return set()
    finished: set[int] = set()
    for position, choice in enumerate(choices):
        if not isinstance(choice, dict) or choice.get("finish_reason") is None:
            continue
        index = choice.get("index", position)
        if isinstance(index, int) and not isinstance(index, bool):
            finished.add(index)
    return finished


def _expected_chat_choices(payload: dict[str, Any]) -> int:
    count = payload.get("n", 1)
    return (
        count
        if isinstance(count, int) and not isinstance(count, bool) and count > 0
        else 1
    )


def _public_error(exc: Exception) -> ProviderCallError:
    if isinstance(exc, APITimeoutError):
        return _error(504, "PROVIDER_TIMEOUT", True)
    if isinstance(exc, APIStatusError):
        retryable = exc.status_code in {408, 409, 429} or exc.status_code >= 500
        return _error(
            exc.status_code,
            "PROVIDER_TIMEOUT" if exc.status_code == 408 else "PROVIDER_UNAVAILABLE",
            retryable,
            request_id=getattr(exc, "request_id", None),
            retry_after=retry_after_header(exc),
        )
    if isinstance(exc, APIConnectionError):
        return _error(503, "PROVIDER_UNAVAILABLE", True)
    if isinstance(exc, (httpx.TimeoutException, TimeoutError)):
        return _error(504, "PROVIDER_TIMEOUT", True)
    if isinstance(exc, (APIError, httpx.TransportError)):
        return _error(503, "PROVIDER_UNAVAILABLE", True)
    return _error(502, "PROVIDER_UNAVAILABLE", False)


def _error(
    status_code: int,
    error_code: str,
    retryable: bool,
    *,
    request_id: str | None = None,
    retry_after: str | None = None,
) -> ProviderCallError:
    return ProviderCallError(
        status_code,
        error_code,
        retryable,
        provider="openai",
        request_id=request_id,
        retry_after=retry_after,
    )


def _responses_error_event(
    code: str,
    message: str,
    sequence_number: int,
) -> bytes:
    return encode_responses_event(
        {
            "type": "error",
            "code": code,
            "message": message,
            "param": None,
            "sequence_number": sequence_number,
        }
    )


def _sanitize_responses_failure(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("type") == "error":
        sanitized: dict[str, Any] = {
            "type": "error",
            "code": "PROVIDER_UNAVAILABLE",
            "message": "The OpenAI stream ended with an error.",
            "param": None,
        }
        if isinstance(payload.get("sequence_number"), int):
            sanitized["sequence_number"] = payload["sequence_number"]
        return sanitized

    response = payload.get("response")
    if payload.get("type") == "response.failed" and isinstance(response, dict):
        sanitized = {
            "type": "response.failed",
            "response": _sanitize_failed_response(response),
        }
        if isinstance(payload.get("sequence_number"), int):
            sanitized["sequence_number"] = payload["sequence_number"]
        return sanitized
    if payload.get("status") == "failed":
        return _sanitize_failed_response(payload)
    return payload


def _sanitize_failed_response(response: dict[str, Any]) -> dict[str, Any]:
    sanitized = {
        "id": response["id"] if isinstance(response.get("id"), str) else "resp_failed",
        "object": "response",
        "created_at": (
            response["created_at"]
            if isinstance(response.get("created_at"), int | float)
            else 0.0
        ),
        "status": "failed",
        "model": (
            response["model"] if isinstance(response.get("model"), str) else "unknown"
        ),
        "output": [],
        "parallel_tool_calls": bool(response.get("parallel_tool_calls", True)),
        "tool_choice": "auto",
        "tools": [],
        "error": {
            "code": "server_error",
            "message": "The OpenAI response failed.",
        },
    }
    usage = _sanitize_responses_usage(response.get("usage"))
    if usage is not None:
        sanitized["usage"] = usage
    return sanitized


def _sanitize_responses_usage(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    input_tokens = _nonnegative_int(value.get("input_tokens"))
    output_tokens = _nonnegative_int(value.get("output_tokens"))
    total_tokens = _nonnegative_int(value.get("total_tokens"))
    if input_tokens is None or output_tokens is None or total_tokens is None:
        return None
    input_details = value.get("input_tokens_details")
    output_details = value.get("output_tokens_details")
    return {
        "input_tokens": input_tokens,
        "input_tokens_details": {
            "cached_tokens": _nested_count(input_details, "cached_tokens"),
            "cache_write_tokens": _nested_count(
                input_details,
                "cache_write_tokens",
            ),
        },
        "output_tokens": output_tokens,
        "output_tokens_details": {
            "reasoning_tokens": _nested_count(
                output_details,
                "reasoning_tokens",
            )
        },
        "total_tokens": total_tokens,
    }


def _nested_count(value: Any, key: str) -> int:
    return _nonnegative_int(value.get(key)) or 0 if isinstance(value, dict) else 0


def _nonnegative_int(value: Any) -> int | None:
    return (
        value
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0
        else None
    )


def _chat_error_event(error: ProviderCallError) -> bytes:
    return encode_data(
        {
            "error": {
                "type": "server_error",
                "code": error.error_code,
                "message": "The OpenAI stream ended with an error.",
                "param": None,
            }
        }
    )
