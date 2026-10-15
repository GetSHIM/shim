from concurrent.futures import ThreadPoolExecutor
import logging
import os
import signal
import time

import pytest

from shim.core import isolation


def test_a_call_runs_in_another_process() -> None:
    assert (
        isolation.run(os.getpid, deadline=isolation.request_deadline()) != os.getpid()
    )


def test_a_call_past_its_deadline_is_stopped_and_the_pool_stays_usable() -> None:
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        isolation.run(time.sleep, 5, deadline=time.monotonic() + 0.2)

    assert time.monotonic() - started < 2
    assert isolation.run(os.getpid, deadline=isolation.request_deadline())


def test_a_deadline_already_past_never_reaches_a_worker() -> None:
    with pytest.raises(TimeoutError):
        isolation.run(os.getpid, deadline=time.monotonic() - 1)


def test_parsers_in_a_worker_log_nothing() -> None:
    # pypdf logs tokens taken from the file; a worker writes no log at all.
    enabled = logging.getLogger("pypdf").isEnabledFor

    assert not isolation.run(
        enabled, logging.CRITICAL, deadline=isolation.request_deadline()
    )


def _stuck(seconds: float) -> None:
    # Native code that ignores the worker's alarm: only killing the worker stops it.
    signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
    time.sleep(seconds)


def test_a_call_whose_worker_another_call_killed_fails_at_once() -> None:
    assert isolation.run(os.getpid, deadline=isolation.request_deadline())
    with ThreadPoolExecutor(2) as threads:
        stuck = threads.submit(
            isolation.run, _stuck, 30, deadline=time.monotonic() + 0.5
        )
        time.sleep(0.1)
        innocent = threads.submit(
            isolation.run, time.sleep, 6, deadline=time.monotonic() + 9
        )
        started = time.monotonic()
        with pytest.raises(TimeoutError):
            stuck.result()
        with pytest.raises(TimeoutError):
            innocent.result()

    # Not at its own deadline (11 s): as soon as its pool is gone.
    assert time.monotonic() - started < 4
    assert isolation.run(os.getpid, deadline=isolation.request_deadline())


def test_callers_beyond_two_waiting_fail_at_once_and_hold_no_thread() -> None:
    with ThreadPoolExecutor(4) as threads:
        busy = [
            threads.submit(
                isolation.run, time.sleep, 1.5, deadline=time.monotonic() + 8
            )
            for _ in range(4)
        ]
        time.sleep(0.3)
        started = time.monotonic()
        with pytest.raises(TimeoutError):
            isolation.run(os.getpid, deadline=time.monotonic() + 8)
        assert time.monotonic() - started < 0.5
        for call in busy:
            call.result()
