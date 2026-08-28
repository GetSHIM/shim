"""Invocation-scoped Google Gen AI SDK execution."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from typing import Any, cast

import httpx
from google import genai
from google.genai import errors, types

from shim.core.circuit_breaker import CircuitBreaker
from shim.core.community_config import CommunitySettings
from shim.gateway.kernel.result import PreparedInference
from shim.gateway.pipeline.provider_execution import (
    ProviderCallError,
    ProviderNonStream,
    ProviderStream,
)
from shim.gateway.streaming.sse import encode_data
from shim.privacy.deanonymizer import _split_placeholder_prefix
from shim.privacy.pii_scrubber import PIIScrubberService
from shim.secrets.credentials import ProviderCredentialResolver

_SDK_ONLY_RESPONSE_FIELDS = {
    "sdk_http_response",
    "automatic_function_calling_history",
    "parsed",
}
_RESTORABLE_FIELDS = frozenset({"args", "code", "output", "response", "text"})


class GoogleExecution:
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

    async def execute(
        self,
        *,
        invocation,
        prepared: PreparedInference,
        provider_start_callback: Callable[[], Awaitable[None]],
    ) -> ProviderNonStream | ProviderStream:
        if prepared.privacy is None:
            raise RuntimeError("privacy stage must run before Google execution")
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

        client: genai.Client | None = None
        try:
            client = genai.Client(
                api_key=api_key,
                http_options=types.HttpOptions(
                    base_url=self.settings.GOOGLE_BASE_URL,
                    api_version="v1beta",
                    timeout=int(self.settings.GOOGLE_TIMEOUT_SECONDS * 1_000),
                    retry_options=types.HttpRetryOptions(attempts=1),
                    httpx_async_client=self.http_client,
                    extra_body={
                        key: value
                        for key, value in prepared.payload.items()
                        if key != "contents"
                    }
                    or None,
                ),
            )
            await provider_start_callback()
        except BaseException:
            if client is not None:
                await _close_client(client)
            await self.circuit.release_probe()
            raise

        handed_to_stream = False
        stream = None
        try:
            if prepared.stream:
                stream = await client.aio.models.generate_content_stream(
                    model=prepared.model,
                    contents=prepared.payload["contents"],
                )
                first_chunk = await anext(stream)
                state = {"closed": False, "recorded": False}
                restorer = GoogleStreamRestorer(
                    prepared.privacy.verification_map,
                    self.pii_scrubber,
                )
                expected_candidates = _expected_candidates(prepared.payload)
                first_payload = _dump_sdk(first_chunk)
                finished_candidates = _finished_candidates(first_payload)
                blocked = _has_block_reason(first_payload)
                if blocked or len(finished_candidates) >= expected_candidates:
                    await self.circuit.record_success()
                    state["recorded"] = True
                first_event = encode_data(restorer.restore_chunk(first_payload))

                async def close_stream() -> None:
                    if state["closed"]:
                        return
                    state["closed"] = True
                    try:
                        await _close_stream(stream)
                    finally:
                        try:
                            await _close_client(client)
                        finally:
                            if not state["recorded"]:
                                await self.circuit.release_probe()

                handed_to_stream = True
                return ProviderStream(
                    events=self._stream(
                        stream,
                        first_event,
                        restorer,
                        expected_candidates,
                        finished_candidates,
                        blocked,
                        state,
                        close_stream,
                    ),
                    request_id=_request_id(first_chunk),
                    close=close_stream,
                    prefetched_events=(first_event,),
                )

            result = await client.aio.models.generate_content(
                model=prepared.model,
                contents=prepared.payload["contents"],
            )
            payload = restore_google_payload(
                _dump_sdk(result),
                prepared.privacy.verification_map,
                self.pii_scrubber,
            )
            if not _has_block_reason(payload) and len(
                _finished_candidates(payload)
            ) < _expected_candidates(prepared.payload):
                raise _error(502, "PROVIDER_UNAVAILABLE", False)
            await self.circuit.record_success()
            return ProviderNonStream(
                payload=payload,
                request_id=_request_id(result),
            )
        except asyncio.CancelledError:
            await self.circuit.release_probe()
            raise
        except Exception as exc:
            await self._record_error(exc)
            raise _public_error(exc) from None
        finally:
            if not handed_to_stream:
                if stream is not None:
                    await _close_stream(stream)
                await _close_client(client)

    async def _stream(
        self,
        stream,
        first_event: bytes,
        restorer: GoogleStreamRestorer,
        expected_candidates: int,
        finished_candidates: set[int],
        blocked: bool,
        state: dict[str, bool],
        close_stream: Callable[[], Awaitable[None]],
    ) -> AsyncIterator[bytes]:
        try:
            yield first_event
            async for chunk in stream:
                payload = _dump_sdk(chunk)
                finished_candidates.update(_finished_candidates(payload))
                blocked = blocked or _has_block_reason(payload)
                if (
                    blocked or len(finished_candidates) >= expected_candidates
                ) and not state["recorded"]:
                    await self.circuit.record_success()
                    state["recorded"] = True
                yield encode_data(restorer.restore_chunk(payload))
            if not state["recorded"]:
                await self.circuit.record_failure()
                state["recorded"] = True
                yield _stream_error(_error(502, "PROVIDER_UNAVAILABLE", False))
        except (asyncio.CancelledError, GeneratorExit):
            raise
        except Exception as exc:
            if state["recorded"]:
                return
            await self._record_error(exc)
            state["recorded"] = True
            yield _stream_error(_public_error(exc))
        finally:
            await close_stream()

    async def _record_error(self, exc: Exception) -> None:
        if (
            isinstance(exc, errors.APIError)
            and 400 <= exc.code < 500
            and exc.code not in {408, 409, 429}
        ):
            await self.circuit.record_success()
        else:
            await self.circuit.record_failure()


class GoogleStreamRestorer:
    def __init__(
        self,
        verification_map: Mapping[str, str],
        scrubber: PIIScrubberService,
    ) -> None:
        self._verification_map = verification_map
        self._scrubber = scrubber
        self._buffers: dict[tuple[object, ...], str] = {}

    def restore_chunk(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self._verification_map:
            return payload
        candidates = payload.get("candidates")
        if isinstance(candidates, list):
            for position, candidate in enumerate(candidates):
                if not isinstance(candidate, dict):
                    continue
                candidate_dict = cast(dict[str, Any], candidate)
                candidate_index = candidate_dict.get("index", position)
                content = candidate_dict.get("content")
                parts = content.get("parts") if isinstance(content, dict) else None
                if isinstance(parts, list):
                    for part_index, part in enumerate(parts):
                        parts[part_index] = self._restore_value(
                            part,
                            (candidate_index, part_index),
                        )
                if candidate_dict.get("finishReason") is not None:
                    self._flush_candidate(candidate_index, candidate_dict)
        return restore_google_payload(
            payload,
            self._verification_map,
            self._scrubber,
        )

    def _restore_value(
        self,
        value: Any,
        path: tuple[object, ...],
        *,
        content: bool = False,
    ) -> Any:
        if isinstance(value, str):
            return self._restore_fragment(path, value) if content else value
        if isinstance(value, list):
            return [
                self._restore_value(item, (*path, index), content=content)
                for index, item in enumerate(value)
            ]
        if isinstance(value, dict):
            return {
                key: self._restore_value(
                    item,
                    (*path, key),
                    content=content or key in _RESTORABLE_FIELDS,
                )
                if content or key not in {"metadata", "partMetadata"}
                else item
                for key, item in value.items()
            }
        return value

    def _restore_fragment(self, key: tuple[object, ...], fragment: str) -> str:
        text = self._buffers.pop(key, "") + fragment
        ready, carry = _split_placeholder_prefix(text, self._verification_map)
        if carry:
            self._buffers[key] = carry
        return self._scrubber.deanonymize(ready, self._verification_map)

    def _flush_candidate(
        self,
        candidate_index: object,
        candidate: dict[str, Any],
    ) -> None:
        keys = [key for key in self._buffers if key[0] == candidate_index]
        if not keys:
            return
        content = candidate.setdefault("content", {})
        parts = content.setdefault("parts", [])
        for key in keys:
            part_index = key[1]
            if not isinstance(part_index, int):
                continue
            while len(parts) <= part_index:
                parts.append({})
            if not isinstance(parts[part_index], dict):
                parts[part_index] = {}
            _append_path(
                parts[part_index],
                key[2:],
                self._scrubber.deanonymize(
                    self._buffers.pop(key),
                    self._verification_map,
                ),
            )


def restore_google_payload(
    payload: dict[str, Any],
    verification_map: Mapping[str, str],
    scrubber: PIIScrubberService,
) -> dict[str, Any]:
    if not verification_map:
        return payload

    def visit(value: Any, *, content: bool = False) -> Any:
        if isinstance(value, str) and content:
            return scrubber.deanonymize(value, verification_map)
        if isinstance(value, list):
            return [visit(item, content=content) for item in value]
        if isinstance(value, dict):
            return {
                key: visit(item, content=content or key in _RESTORABLE_FIELDS)
                if content or key not in {"metadata", "partMetadata"}
                else item
                for key, item in value.items()
            }
        return value

    return visit(payload)


def _append_path(root: dict[str, Any], path: tuple[object, ...], suffix: str) -> None:
    if not path:
        return
    current: Any = root
    for position, segment in enumerate(path[:-1]):
        next_segment = path[position + 1]
        if isinstance(segment, str) and isinstance(current, dict):
            expected = [] if isinstance(next_segment, int) else {}
            child = current.get(segment)
            if not isinstance(child, type(expected)):
                child = expected
                current[segment] = child
            current = child
        elif isinstance(segment, int) and isinstance(current, list):
            while len(current) <= segment:
                current.append({} if isinstance(next_segment, str) else [])
            current = current[segment]
        else:
            return
    leaf = path[-1]
    if isinstance(leaf, str) and isinstance(current, dict):
        current[leaf] = str(current.get(leaf) or "") + suffix
    elif isinstance(leaf, int) and isinstance(current, list):
        while len(current) <= leaf:
            current.append("")
        current[leaf] = str(current[leaf] or "") + suffix


def _dump_sdk(value: Any) -> dict[str, Any]:
    dumped = value.model_dump(
        mode="json",
        by_alias=True,
        exclude_unset=True,
        exclude=_SDK_ONLY_RESPONSE_FIELDS,
    )
    if not isinstance(dumped, dict):
        raise TypeError("Google SDK value did not serialize to an object")
    return dumped


def _request_id(value: Any) -> str | None:
    response = getattr(value, "sdk_http_response", None)
    headers = getattr(response, "headers", {})
    if not hasattr(headers, "get"):
        return None
    return headers.get("x-request-id") or headers.get("x-goog-request-id")


def _error(
    status_code: int,
    error_code: str,
    retryable: bool,
    request_id: str | None = None,
) -> ProviderCallError:
    return ProviderCallError(
        status_code,
        error_code,
        retryable,
        provider="google",
        request_id=request_id,
    )


def _public_error(exc: Exception) -> ProviderCallError:
    if isinstance(exc, ProviderCallError):
        return exc
    if isinstance(exc, (httpx.TimeoutException, TimeoutError)):
        return _error(504, "PROVIDER_TIMEOUT", True)
    if isinstance(exc, errors.APIError):
        status_code = exc.code if exc.code >= 400 else 502
        if status_code in {408, 504}:
            return _error(504, "PROVIDER_TIMEOUT", True, _error_request_id(exc))
        return _error(
            status_code,
            "PROVIDER_UNAVAILABLE",
            status_code in {409, 429} or status_code >= 500,
            _error_request_id(exc),
        )
    if isinstance(exc, httpx.TransportError):
        return _error(503, "PROVIDER_UNAVAILABLE", True)
    return _error(502, "PROVIDER_UNAVAILABLE", False)


def _error_request_id(exc: errors.APIError) -> str | None:
    headers = getattr(getattr(exc, "response", None), "headers", {})
    if not hasattr(headers, "get"):
        return None
    return headers.get("x-request-id") or headers.get("x-goog-request-id")


def _finished_candidates(payload: Mapping[str, Any]) -> set[int]:
    candidates = payload.get("candidates")
    if not isinstance(candidates, list):
        return set()
    finished: set[int] = set()
    for position, candidate in enumerate(candidates):
        if not isinstance(candidate, dict) or not candidate.get("finishReason"):
            continue
        index = candidate.get("index", position)
        if isinstance(index, int) and not isinstance(index, bool):
            finished.add(index)
    return finished


def _expected_candidates(payload: Mapping[str, Any]) -> int:
    config = payload.get("generationConfig")
    count = config.get("candidateCount") if isinstance(config, Mapping) else None
    return (
        count
        if isinstance(count, int) and not isinstance(count, bool) and count > 0
        else 1
    )


def _has_block_reason(payload: Mapping[str, Any]) -> bool:
    feedback = payload.get("promptFeedback")
    return isinstance(feedback, dict) and bool(feedback.get("blockReason"))


def _stream_error(error: ProviderCallError) -> bytes:
    return encode_data(
        {
            "error": {
                "code": error.status_code,
                "message": "The Google stream ended with an error.",
                "status": error.error_code,
            }
        }
    )


async def _close_client(client: genai.Client) -> None:
    try:
        await client.aio.aclose()
    except Exception:
        pass
    try:
        client.close()
    except Exception:
        pass


async def _close_stream(stream) -> None:
    try:
        await stream.aclose()
    except Exception:
        pass
