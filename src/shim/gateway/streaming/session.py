"""One streaming request's provider iterator and terminal lifecycle."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncGenerator, AsyncIterator, Awaitable, Callable
from datetime import datetime, timezone
from inspect import isawaitable
from time import monotonic
from typing import Any

from opentelemetry import context as otel_context
from opentelemetry.context import Context

from shim.observability.metrics import STREAM_TERMINAL_STATE_TOTAL, bounded_label
from shim.observability.tracing import start_span

from .finalization import StreamFinalization, StreamTerminalStatus
from .meter import StreamMeter


logger = logging.getLogger(__name__)

_DETACHED_FINALIZERS: set[asyncio.Task[Any]] = set()

TerminalObserver = Callable[[StreamTerminalStatus], None]


class StreamSession:
    """Own streaming state and serialize in-process finalization attempts.

    A failed attempt may be retried with the same terminal record. The durable
    finalizer remains independently idempotent, so another process or the
    stale-reservation sweeper can safely race or replay this session.
    """

    def __init__(
        self,
        *,
        meter: StreamMeter,
        finalizer: Callable[[StreamFinalization], Awaitable[Any]],
        stream_start_recorder: Callable[[], Awaitable[None]],
        stream_heartbeat_recorder: Callable[[], Awaitable[None]] | None = None,
        heartbeat_interval_seconds: float = 30,
        monotonic_clock: Callable[[], float] = monotonic,
        clock: Callable[[], datetime] | None = None,
        parent_context: Context | None = None,
        terminal_observer: TerminalObserver | None = None,
    ) -> None:
        self.meter = meter
        self._finalizer = finalizer
        self._stream_start_recorder = stream_start_recorder
        self._stream_heartbeat_recorder = stream_heartbeat_recorder
        self._heartbeat_interval_seconds = heartbeat_interval_seconds
        self._monotonic_clock = monotonic_clock
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._parent_context = (
            parent_context if parent_context is not None else otel_context.get_current()
        )
        self._terminal_observer = terminal_observer
        self._provider_stream: AsyncIterator[bytes] | None = None
        self._provider_close: Callable[[], Awaitable[None]] | None = None
        self._premetered_events: list[bytes] = []
        self._provider_closed = False
        self._output_iterator: AsyncGenerator[bytes, None] | None = None
        self._stream_started = False
        self._last_heartbeat_at: float | None = None
        self._consumed = False
        self._terminal: StreamFinalization | None = None
        self._pending_terminal: StreamFinalization | None = None
        self._finalizer_result: Any = None
        self._finalization_lock = asyncio.Lock()
        self._internal_failure = False

    @property
    def terminal_status(self) -> StreamTerminalStatus | None:
        return self._terminal.terminal_status if self._terminal is not None else None

    def bind(
        self,
        provider_stream: AsyncIterator[bytes],
        *,
        close: Callable[[], Awaitable[None]] | None = None,
        prefetched_events: tuple[bytes, ...] = (),
    ) -> None:
        if self._provider_stream is not None:
            raise RuntimeError("stream session already owns a provider iterator")
        self._provider_stream = provider_stream
        self._provider_close = close
        self._premetered_events = list(prefetched_events)
        for event in prefetched_events:
            self.meter.observe_sse(event)

    def __aiter__(self) -> StreamSession:
        return self

    async def __anext__(self) -> bytes:
        if self._output_iterator is None:
            self._output_iterator = self._iterate()
        return await anext(self._output_iterator)

    async def aclose(self) -> None:
        """Close and finalize even when no response byte was requested."""

        try:
            if self._output_iterator is not None:
                await self._output_iterator.aclose()
        finally:
            if self._terminal is None:
                self.meter.finish()
                await self._close_provider_stream()
                await self._finalize_safely("client_disconnected")

    async def record_stream_start(self) -> None:
        if self._stream_started:
            return
        try:
            await self._stream_start_recorder()
        except Exception:
            self._internal_failure = True
            raise
        self._stream_started = True
        self._last_heartbeat_at = self._monotonic_clock()

    async def record_stream_heartbeat(self) -> None:
        if self._stream_heartbeat_recorder is None or self._last_heartbeat_at is None:
            return
        now = self._monotonic_clock()
        if now - self._last_heartbeat_at < self._heartbeat_interval_seconds:
            return
        try:
            await self._stream_heartbeat_recorder()
        except Exception:
            self._internal_failure = True
            raise
        self._last_heartbeat_at = now

    async def _iterate(self) -> AsyncGenerator[bytes, None]:
        token = otel_context.attach(self._parent_context)
        try:
            with start_span(
                "gateway.stream",
                provider=bounded_label("provider", self.meter.provider),
                model=bounded_label("model", self.meter.requested_model),
            ) as span:
                try:
                    async for chunk in self._iterate_stream():
                        yield chunk
                finally:
                    if self.terminal_status is not None:
                        span.set_attribute("terminal_state", self.terminal_status)
        finally:
            otel_context.detach(token)

    async def _iterate_stream(self) -> AsyncIterator[bytes]:
        if self._provider_stream is None:
            raise RuntimeError("stream session has no provider iterator")
        if self._consumed:
            raise RuntimeError("stream session can only be consumed once")
        self._consumed = True

        terminal: StreamTerminalStatus | None = None
        try:
            async for chunk in self._rendered_chunks():
                await self.record_stream_start()
                await self.record_stream_heartbeat()
                self.meter.observe_emitted_output(chunk)
                yield chunk
            terminal = self._terminal_from_hint()
        except (asyncio.CancelledError, GeneratorExit):
            terminal = "client_disconnected"
            raise
        except BaseException as exc:
            if self._internal_failure:
                terminal = "internal_error"
            else:
                terminal = "timeout" if self._is_timeout(exc) else "provider_error"
            raise
        finally:
            terminal = terminal or "client_disconnected"
            self.meter.finish()
            await self._close_provider_stream()
            await self._finalize_safely(terminal)

    async def _rendered_chunks(self) -> AsyncIterator[bytes]:
        if self._provider_stream is None:
            return
        async for chunk in self._provider_stream:
            if self._premetered_events and chunk == self._premetered_events[0]:
                self._premetered_events.pop(0)
            else:
                self.meter.observe_sse(chunk)
            yield chunk

    async def finalize(
        self,
        terminal_status: StreamTerminalStatus,
        *,
        error_message: str | None = None,
    ) -> tuple[StreamFinalization, Any]:
        """Finalize once successfully; retry a failed attempt unchanged."""

        async with self._finalization_lock:
            if self._terminal is not None:
                return self._terminal, self._finalizer_result
            if self._pending_terminal is None:
                completed_at = self._now()
                error_code, default_message = self._terminal_error(terminal_status)
                self._pending_terminal = StreamFinalization(
                    terminal_status=terminal_status,
                    usage=self.meter.snapshot(),
                    completed_at=completed_at,
                    error_code=error_code,
                    error_message=(error_message or default_message),
                )
                STREAM_TERMINAL_STATE_TOTAL.labels(
                    terminal_state=bounded_label("terminal_state", terminal_status)
                ).inc()
                if self._terminal_observer is not None:
                    self._terminal_observer(terminal_status)
            terminal = self._pending_terminal
            result = await self._finalizer(terminal)
            self._terminal = terminal
            self._finalizer_result = result
            return terminal, result

    async def _finalize_safely(
        self,
        terminal_status: StreamTerminalStatus,
        *,
        error_message: str | None = None,
    ) -> None:
        task = asyncio.create_task(
            self.finalize(terminal_status, error_message=error_message)
        )
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            _DETACHED_FINALIZERS.add(task)
            task.add_done_callback(_observe_detached_finalizer)
            logger.debug("Stream finalization continuing after response cancellation")
            raise
        except Exception as exc:
            logger.error(
                "Stream finalization failed; durable stale recovery retained type=%s",
                type(exc).__name__,
            )

    async def _close_provider_stream(self) -> None:
        if self._provider_stream is None or self._provider_closed:
            return
        self._provider_closed = True
        close = self._provider_close or getattr(self._provider_stream, "aclose", None)
        if close is None:
            close = getattr(self._provider_stream, "close", None)
        if not callable(close):
            return
        try:
            result = close()
            if isawaitable(result):
                await result
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            logger.debug("Provider stream close failed type=%s", type(exc).__name__)

    def _terminal_from_hint(self) -> StreamTerminalStatus:
        hint = self.meter.terminal_hint
        if hint in {"provider_error", "timeout", "cancelled", "internal_error"}:
            return hint
        if hint == "completed":
            return "completed"
        return "provider_error"

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("stream session clock must return a timezone-aware time")
        return now

    @staticmethod
    def _is_timeout(exc: BaseException) -> bool:
        return isinstance(exc, TimeoutError) or "timeout" in type(exc).__name__.lower()

    @staticmethod
    def _terminal_error(
        terminal_status: StreamTerminalStatus,
    ) -> tuple[str | None, str | None]:
        return {
            "completed": (None, None),
            "provider_error": (
                "PROVIDER_STREAM_ERROR",
                "The provider stream ended with an error.",
            ),
            "client_disconnected": (
                "CLIENT_DISCONNECTED",
                "The client disconnected before stream completion.",
            ),
            "timeout": ("PROVIDER_TIMEOUT", "The provider stream timed out."),
            "cancelled": ("STREAM_CANCELLED", "The stream was cancelled."),
            "internal_error": (
                "INTERNAL_STREAM_ERROR",
                "The gateway stream ended with an internal error.",
            ),
        }[terminal_status]


def _observe_detached_finalizer(task: asyncio.Task[Any]) -> None:
    _DETACHED_FINALIZERS.discard(task)
    if task.cancelled():
        logger.error(
            "Detached stream finalization was cancelled; durable stale recovery retained"
        )
        return
    exception = task.exception()
    if exception is not None:
        logger.error(
            "Detached stream finalization failed; durable stale recovery retained "
            "type=%s",
            type(exception).__name__,
        )
