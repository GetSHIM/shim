"""Work on hostile files (PDF text, image decoding) in two child processes.

Each worker has a memory cap and every call a hard deadline, so a crafted file can
neither block the event loop nor hold the default thread pool, the memory of the
gateway or another tenant's request beyond that deadline.
"""

from __future__ import annotations

import atexit
from collections.abc import Callable
import logging
import multiprocessing
from multiprocessing.pool import Pool
import signal
import threading
import time
import warnings

WORKERS = 2
# Per worker; a 64M-pixel image decodes to at most 256 MB, twice over during conversion.
MEMORY_BYTES = 1024**3
CALL_SECONDS = 10.0
REQUEST_SECONDS = 20.0
# How long past its deadline a call may stay in native code before its worker is killed.
_GRACE_SECONDS = 2.0

# A call waits here, not in the pool's queue, so a submitted call is always running.
_slots = threading.BoundedSemaphore(WORKERS)
# Calls inside run(), running or waiting for a slot. Each holds a thread of the default
# executor that every request's privacy stage shares, so a call beyond these fails at once.
_callers = threading.BoundedSemaphore(2 * WORKERS)
# How often a waiting call checks that another call has not discarded its pool.
_POLL_SECONDS = 0.1
_lock = threading.Lock()
_pool: Pool | None = None


class _Expired(BaseException):
    # Not an Exception: hostile-input handlers that catch everything must let it through.
    pass


def request_deadline() -> float:
    """The `time.monotonic()` by which all isolated work of one request ends."""
    return time.monotonic() + REQUEST_SECONDS


def run[T](function: Callable[..., T], *args: object, deadline: float) -> T:
    """`function(*args)` in a worker, by `deadline` and at most `CALL_SECONDS`.

    `TimeoutError` once the deadline passes, `MemoryError` over the worker's memory
    cap, and whatever `function` raises. Blocks the calling thread, never the loop.
    """
    deadline = min(deadline, time.monotonic() + CALL_SECONDS)
    if not _callers.acquire(blocking=False):
        raise TimeoutError
    try:
        if not _slots.acquire(timeout=max(0.0, deadline - time.monotonic())):
            raise TimeoutError
        try:
            return _await(function, args, deadline)
        finally:
            _slots.release()
    finally:
        _callers.release()


def _await[T](
    function: Callable[..., T], args: tuple[object, ...], deadline: float
) -> T:
    pool = _get()
    try:
        pending = pool.apply_async(_call, (function, args, deadline))
    except ValueError:
        # Another call discarded this pool a moment ago.
        raise TimeoutError from None
    end = deadline + _GRACE_SECONDS
    while True:
        try:
            return pending.get(min(_POLL_SECONDS, max(0.0, end - time.monotonic())))
        except multiprocessing.TimeoutError:
            if _pool is not pool:
                # Another call's timeout killed this call's worker with its pool.
                raise TimeoutError from None
            if time.monotonic() >= end:
                # Stuck in native code past its own alarm, or its worker died.
                _discard(pool)
                raise TimeoutError from None


def _get() -> Pool:
    global _pool
    with _lock:
        if _pool is None:
            # spawn: the gateway's threads and sockets are never forked into a worker.
            _pool = multiprocessing.get_context("spawn").Pool(
                WORKERS, initializer=_start
            )
        return _pool


def _discard(pool: Pool) -> None:
    global _pool
    with _lock:
        if _pool is pool:
            _pool = None
    # The other worker's call goes too; it sees the pool gone and fails as too slow.
    pool.terminate()


@atexit.register
def _close() -> None:
    if _pool is not None:
        _discard(_pool)


def _start() -> None:
    signal.signal(signal.SIGALRM, _expire)
    # Parsers log and warn with tokens taken from the file; nothing leaves a worker.
    logging.disable(logging.CRITICAL)
    warnings.simplefilter("ignore")
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_AS, (MEMORY_BYTES, MEMORY_BYTES))
    except (ImportError, ValueError, OSError):
        # macOS does not enforce an address-space limit; Linux, where this runs, does.
        pass


def _expire(signum: int, frame: object) -> None:
    raise _Expired


def _call[T](
    function: Callable[..., T], args: tuple[object, ...], deadline: float
) -> T:
    # time.monotonic() is the system's monotonic clock on Linux and macOS, shared by
    # the gateway and its workers.
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    try:
        try:
            signal.setitimer(signal.ITIMER_REAL, remaining)
            return function(*args)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
    except _Expired:
        raise TimeoutError from None
