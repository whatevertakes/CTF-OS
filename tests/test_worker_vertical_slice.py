from __future__ import annotations

from threading import Event

import pytest

from ctf_os.local_worker_pool import LocalWorkerPool, WorkerCapacityError
from ctf_os.models import Attempt


def _attempt(identifier: str, challenge_id: str) -> Attempt:
    return Attempt(id=identifier, challenge_id=challenge_id, profile="recon_fast", role="recon", backend="mock", workdir="/work")


def test_pool_enforces_global_and_per_challenge_limits() -> None:
    release = Event()
    pool = LocalWorkerPool(max_workers_total=2, max_workers_per_challenge=1)
    runner = lambda _: release.wait(1)
    one = pool.submit(_attempt("a1", "one"), runner)
    with pytest.raises(WorkerCapacityError):
        pool.submit(_attempt("a2", "one"), runner)
    two = pool.submit(_attempt("a3", "two"), runner)
    with pytest.raises(WorkerCapacityError):
        pool.submit(_attempt("a4", "three"), runner)
    release.set()
    assert one.wait(1) and two.wait(1)


def test_verified_solve_cancellation_is_limited_to_same_local_challenge() -> None:
    release = Event()
    pool = LocalWorkerPool(max_workers_total=3, max_workers_per_challenge=3)
    runner = lambda _: release.wait(1)
    one = pool.submit(_attempt("a1", "chal-a"), runner)
    two = pool.submit(_attempt("a2", "chal-a"), runner)
    other = pool.submit(_attempt("b1", "chal-b"), runner)

    assert set(pool.cancel_challenge("chal-a", except_attempt_id="a1")) == {"a2"}
    assert not one.cancel_event.is_set()
    assert two.cancel_event.is_set()
    assert not other.cancel_event.is_set()
    release.set()
    assert pool.wait_all(1)
