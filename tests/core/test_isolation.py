import logging
import os
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
