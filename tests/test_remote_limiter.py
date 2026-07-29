from __future__ import annotations

import json
import multiprocessing
import os
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from unittest import mock

import ctf_os.remote_limiter as remote_limiter_module
from ctf_os.codex import BatchRunner
from ctf_os.config import load_config
from ctf_os.engine.challenge import ChallengeEngine, EngineError
from ctf_os.models import (
    ChallengeIdentity,
    ChallengeStatus,
    ExperimentStatus,
)
from ctf_os.remote_limiter import (
    MAX_STATE_BYTES,
    RemoteCommandStartCancelled,
    RemoteCommandStartLimiter,
    RemoteCommandStartTimeout,
    RemoteLimiterQueueFull,
    RemoteLimiterStateError,
    normalize_remote_hostname,
)
from ctf_os.store.atomic import atomic_write_bytes
from tests.test_engine import FakeSandbox, RoleExecutor


def _process_wait_for_start(
    runtime_root: str,
    interval: float,
    hostname: str,
    ordinal: int,
    output: multiprocessing.Queue,
) -> None:
    try:
        permit = RemoteCommandStartLimiter(
            runtime_root,
            interval,
            poll_interval_seconds=0.005,
        ).wait_for_start(hostname, timeout=5)
        output.put(("ok", ordinal, permit.started_monotonic))
    except (OSError, RuntimeError, TimeoutError, ValueError) as error:
        output.put(("error", ordinal, repr(error)))


def _hold_remote_limiter_lock(
    lock_path: str,
    ready_event,
    hold_seconds: float,
) -> None:
    path = Path(lock_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_RDWR | os.O_CREAT | os.O_CLOEXEC,
        0o600,
    )
    try:
        remote_limiter_module.fcntl.flock(
            descriptor,
            remote_limiter_module.fcntl.LOCK_EX,
        )
        ready_event.set()
        time.sleep(hold_seconds)
    finally:
        remote_limiter_module.fcntl.flock(
            descriptor,
            remote_limiter_module.fcntl.LOCK_UN,
        )
        os.close(descriptor)


class RemoteCommandStartLimiterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.runtime_root = Path(self.temporary_directory.name) / "runtime"

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    @staticmethod
    def _wait_for_waiters(
        limiter: RemoteCommandStartLimiter,
        hostname: str,
        expected: int,
        *,
        timeout: float = 2,
    ) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if limiter.snapshot(hostname).waiting == expected:
                return
            time.sleep(0.005)
        raise AssertionError(
            f"remote limiter did not reach {expected} queued waiter(s)"
        )

    @staticmethod
    def _stop_process(process: multiprocessing.Process) -> None:
        if process.is_alive():
            process.terminate()
        process.join(timeout=2)

    def test_hostname_normalization_is_host_only_and_stable(self) -> None:
        self.assertEqual(
            normalize_remote_hostname(" Example.COM. "),
            "example.com",
        )
        self.assertEqual(
            normalize_remote_hostname("[2001:0db8::1]"),
            "2001:db8::1",
        )
        self.assertEqual(
            normalize_remote_hostname("BÜCHER.example"),
            "xn--bcher-kva.example",
        )
        for invalid in (
            "",
            "https://example.com",
            "example.com:443",
            "[::1]:443",
            "under_score.example",
            "example.com/path",
            "bad\nhost",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                normalize_remote_hostname(invalid)
        with self.assertRaises(TypeError):
            normalize_remote_hostname(123)  # type: ignore[arg-type]

    def test_lock_descriptor_close_interrupt_is_not_retried(
        self,
    ) -> None:
        limiter = RemoteCommandStartLimiter(
            self.runtime_root,
            0.3,
            poll_interval_seconds=0.005,
        )
        limiter.wait_for_start("example.test")
        interruption = KeyboardInterrupt(
            "synthetic remote lock descriptor close interrupt"
        )
        real_open = remote_limiter_module.builtins.open
        close_calls: list[int] = []

        class InterruptingCloseStream:
            def __init__(self, stream) -> None:
                self._stream = stream

            def fileno(self) -> int:
                return self._stream.fileno()

            def close(self) -> None:
                descriptor = self._stream.fileno()
                close_calls.append(descriptor)
                raise interruption

            def force_close(self) -> None:
                self._stream.close()

        wrapped_streams: list[InterruptingCloseStream] = []

        def open_with_interrupt(*args, **kwargs):
            stream = real_open(*args, **kwargs)
            if str(args[0]).endswith(".json.lock"):
                wrapped = InterruptingCloseStream(stream)
                wrapped_streams.append(wrapped)
                return wrapped
            return stream

        try:
            with (
                mock.patch.object(
                    remote_limiter_module.builtins,
                    "open",
                    side_effect=open_with_interrupt,
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                limiter.snapshot("example.test")

            self.assertIs(raised.exception, interruption)
            self.assertEqual(len(wrapped_streams), 1)
            self.assertEqual(
                close_calls,
                [wrapped_streams[0].fileno()],
            )
            self.assertTrue(
                Path(
                    f"/proc/self/fd/{wrapped_streams[0].fileno()}"
                ).exists()
            )
        finally:
            for wrapped in wrapped_streams:
                wrapped.force_close()
        self.assertFalse(
            Path(f"/proc/self/fd/{close_calls[0]}").exists()
        )
        self.assertEqual(limiter.snapshot("example.test").waiting, 0)

    def test_lock_close_never_recloses_same_inode_peer_descriptor(
        self,
    ) -> None:
        limiter = RemoteCommandStartLimiter(
            self.runtime_root,
            0.3,
            poll_interval_seconds=0.005,
        )
        limiter.wait_for_start("example.test")
        interruption = OSError(
            "synthetic ambiguous remote lock close error"
        )
        real_open = remote_limiter_module.builtins.open

        class CloseThenReuseSameInodeStream:
            def __init__(self, path: Path) -> None:
                flags = (
                    os.O_RDWR
                    | os.O_CREAT
                    | os.O_APPEND
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                self.path = path
                self.flags = flags
                self.descriptor = os.open(path, flags, 0o600)
                opened = os.fstat(self.descriptor)
                self.opened_identity = (opened.st_dev, opened.st_ino)
                self.peer_descriptor: int | None = None
                self.close_calls = 0

            def fileno(self) -> int:
                return self.descriptor

            def close(self) -> None:
                self.close_calls += 1
                if self.close_calls == 1:
                    os.close(self.descriptor)
                    peer_descriptor = os.open(
                        self.path,
                        self.flags,
                        0o600,
                    )
                    if peer_descriptor != self.descriptor:
                        os.dup2(peer_descriptor, self.descriptor)
                        os.close(peer_descriptor)
                        peer_descriptor = self.descriptor
                    self.peer_descriptor = peer_descriptor
                    raise interruption
                os.close(self.descriptor)

        wrapped_streams: list[CloseThenReuseSameInodeStream] = []

        def open_with_reuse(*args, **kwargs):
            if str(args[0]).endswith(".json.lock"):
                wrapped = CloseThenReuseSameInodeStream(Path(args[0]))
                wrapped_streams.append(wrapped)
                return wrapped
            return real_open(*args, **kwargs)

        try:
            with (
                mock.patch.object(
                    remote_limiter_module.builtins,
                    "open",
                    side_effect=open_with_reuse,
                ),
                self.assertRaises(OSError) as raised,
            ):
                limiter.snapshot("example.test")

            self.assertIs(raised.exception, interruption)
            self.assertEqual(len(wrapped_streams), 1)
            wrapped = wrapped_streams[0]
            self.assertEqual(wrapped.close_calls, 1)
            self.assertEqual(
                wrapped.peer_descriptor,
                wrapped.descriptor,
            )
            peer = os.fstat(wrapped.peer_descriptor)
            self.assertEqual(
                (peer.st_dev, peer.st_ino),
                wrapped.opened_identity,
            )
        finally:
            for wrapped in wrapped_streams:
                if (
                    wrapped.peer_descriptor is not None
                    and wrapped.close_calls == 1
                ):
                    os.close(wrapped.peer_descriptor)
        self.assertEqual(limiter.snapshot("example.test").waiting, 0)

    def test_locked_state_return_interrupt_cleans_ticket_and_recovers(
        self,
    ) -> None:
        target_code = RemoteCommandStartLimiter._locked_state.__code__

        for ordinal, interruption in enumerate(
            (
                KeyboardInterrupt(
                    "synthetic locked-state return interrupt"
                ),
                SystemExit("synthetic locked-state return exit"),
            ),
        ):
            with self.subTest(interruption=type(interruption).__name__):
                limiter = RemoteCommandStartLimiter(
                    self.runtime_root / str(ordinal),
                    0.3,
                    poll_interval_seconds=0.005,
                )
                hostname = f"return-{ordinal}.example"
                injected = False
                released_descriptors: list[int] = []

                def interrupt_return(frame, event, arg):
                    del arg
                    nonlocal injected
                    if (
                        not injected
                        and frame.f_code is target_code
                        and event == "return"
                    ):
                        injected = True
                        released_descriptors.append(
                            frame.f_locals["descriptor"]
                        )
                        sys.settrace(None)
                        raise interruption
                    return interrupt_return

                sys.settrace(interrupt_return)
                try:
                    with self.assertRaises(
                        type(interruption)
                    ) as raised:
                        limiter.wait_for_start(hostname, timeout=0)
                finally:
                    sys.settrace(None)

                self.assertTrue(injected)
                self.assertIs(raised.exception, interruption)
                self.assertEqual(len(released_descriptors), 1)
                self.assertFalse(
                    Path(
                        f"/proc/self/fd/{released_descriptors[0]}"
                    ).exists()
                )
                self.assertEqual(limiter.snapshot(hostname).waiting, 0)
                permit = limiter.wait_for_start(hostname, timeout=0)
                self.assertTrue(permit.enabled)
                self.assertEqual(limiter.snapshot(hostname).waiting, 0)

    def test_flock_acquire_return_interrupt_closes_fd_and_recovers(
        self,
    ) -> None:
        real_flock = remote_limiter_module.fcntl.flock

        for ordinal, interruption in enumerate(
            (
                KeyboardInterrupt(
                    "synthetic flock acquire return interrupt"
                ),
                SystemExit("synthetic flock acquire return exit"),
            ),
        ):
            with self.subTest(interruption=type(interruption).__name__):
                limiter = RemoteCommandStartLimiter(
                    self.runtime_root / f"flock-{ordinal}",
                    0.3,
                    poll_interval_seconds=0.005,
                )
                hostname = f"acquire-{ordinal}.example"
                acquired_descriptors: list[int] = []
                injected = False

                def traced_flock(descriptor: int, operation: int) -> None:
                    real_flock(descriptor, operation)
                    if operation == remote_limiter_module.fcntl.LOCK_EX:
                        acquired_descriptors.append(descriptor)

                target_code = traced_flock.__code__

                def interrupt_acquire_return(frame, event, arg):
                    del arg
                    nonlocal injected
                    if (
                        not injected
                        and frame.f_code is target_code
                        and event == "return"
                        and frame.f_locals.get("operation")
                        == remote_limiter_module.fcntl.LOCK_EX
                    ):
                        injected = True
                        sys.settrace(None)
                        raise interruption
                    return interrupt_acquire_return

                with mock.patch.object(
                    remote_limiter_module.fcntl,
                    "flock",
                    side_effect=traced_flock,
                ):
                    sys.settrace(interrupt_acquire_return)
                    try:
                        with self.assertRaises(
                            type(interruption)
                        ) as raised:
                            limiter.snapshot(hostname)
                    finally:
                        sys.settrace(None)

                self.assertTrue(injected)
                self.assertIs(raised.exception, interruption)
                self.assertEqual(len(acquired_descriptors), 1)
                self.assertFalse(
                    Path(
                        f"/proc/self/fd/{acquired_descriptors[0]}"
                    ).exists()
                )
                self.assertEqual(limiter.snapshot(hostname).waiting, 0)

    def test_zero_explicitly_disables_without_creating_state(self) -> None:
        limiter = RemoteCommandStartLimiter(self.runtime_root, 0)
        permit = limiter.wait_for_start("example.test", timeout=0)
        self.assertFalse(permit.enabled)
        self.assertEqual(permit.wait_seconds, 0)
        self.assertFalse(self.runtime_root.exists())

        cancelled = threading.Event()
        cancelled.set()
        with self.assertRaises(RemoteCommandStartCancelled):
            limiter.wait_for_start(
                "example.test",
                cancel_event=cancelled,
            )
        self.assertFalse(self.runtime_root.exists())

    def test_same_normalized_host_is_spaced_and_other_host_is_independent(
        self,
    ) -> None:
        interval = 0.06
        limiter = RemoteCommandStartLimiter(
            self.runtime_root,
            interval,
            poll_interval_seconds=0.003,
        )
        first = limiter.wait_for_start("Example.TEST")
        independent = limiter.wait_for_start("other.example")
        second = limiter.wait_for_start("example.test.")

        self.assertLess(
            independent.started_monotonic - first.started_monotonic,
            interval / 2,
        )
        self.assertGreaterEqual(
            second.started_monotonic - first.started_monotonic,
            interval - 0.01,
        )
        self.assertEqual(
            limiter.state_path("Example.TEST"),
            limiter.state_path("example.test."),
        )

    def test_timeout_and_cancellation_remove_waiter(self) -> None:
        limiter = RemoteCommandStartLimiter(
            self.runtime_root,
            0.3,
            poll_interval_seconds=0.005,
        )
        limiter.wait_for_start("example.test")
        with self.assertRaises(RemoteCommandStartTimeout):
            limiter.wait_for_start("example.test", timeout=0.02)
        self.assertEqual(limiter.snapshot("example.test").waiting, 0)

        cancelled = threading.Event()
        failures: list[BaseException] = []

        def wait_until_cancelled() -> None:
            try:
                limiter.wait_for_start(
                    "example.test",
                    timeout=2,
                    cancel_event=cancelled,
                )
            except RemoteCommandStartCancelled as error:
                failures.append(error)

        waiter = threading.Thread(target=wait_until_cancelled)
        waiter.start()
        self._wait_for_waiters(limiter, "example.test", 1)
        cancelled.set()
        waiter.join(timeout=2)

        self.assertFalse(waiter.is_alive())
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], RemoteCommandStartCancelled)
        self.assertEqual(limiter.snapshot("example.test").waiting, 0)

    def test_state_lock_wait_honors_start_deadline(self) -> None:
        context = multiprocessing.get_context("fork")
        limiter = RemoteCommandStartLimiter(
            self.runtime_root,
            0.3,
            poll_interval_seconds=0.005,
        )
        ready = context.Event()
        blocker = context.Process(
            target=_hold_remote_limiter_lock,
            args=(
                str(limiter._lock_path("example.test")),
                ready,
                0.6,
            ),
        )
        blocker.start()
        self.addCleanup(self._stop_process, blocker)
        self.assertTrue(ready.wait(timeout=1))

        started = time.monotonic()
        with self.assertRaises(RemoteCommandStartTimeout):
            limiter.wait_for_start("example.test", timeout=0.05)
        elapsed = time.monotonic() - started

        self.assertLess(elapsed, 0.3)
        self.assertTrue(blocker.is_alive())
        blocker.join(timeout=1)
        self.assertFalse(blocker.is_alive())
        self.assertEqual(blocker.exitcode, 0)
        self.assertEqual(limiter.snapshot("example.test").waiting, 0)

    def test_grant_commit_crossing_deadline_returns_no_permit(self) -> None:
        limiter = RemoteCommandStartLimiter(
            self.runtime_root,
            0.3,
            poll_interval_seconds=0.005,
        )
        writes = 0

        def delay_grant_commit(path, payload, **kwargs):
            nonlocal writes
            writes += 1
            atomic_write_bytes(path, payload, **kwargs)
            if writes == 2:
                time.sleep(0.06)

        with (
            mock.patch(
                "ctf_os.remote_limiter.atomic_write_bytes",
                side_effect=delay_grant_commit,
            ),
            self.assertRaises(RemoteCommandStartTimeout),
        ):
            limiter.wait_for_start("example.test", timeout=0.02)

        self.assertEqual(writes, 2)
        self.assertEqual(limiter.snapshot("example.test").waiting, 0)

    def test_grant_commit_observes_concurrent_cancellation(self) -> None:
        limiter = RemoteCommandStartLimiter(
            self.runtime_root,
            0.3,
            poll_interval_seconds=0.005,
        )
        cancelled = threading.Event()
        writes = 0

        def cancel_after_grant_commit(path, payload, **kwargs):
            nonlocal writes
            writes += 1
            atomic_write_bytes(path, payload, **kwargs)
            if writes == 2:
                cancelled.set()

        with (
            mock.patch(
                "ctf_os.remote_limiter.atomic_write_bytes",
                side_effect=cancel_after_grant_commit,
            ),
            self.assertRaises(RemoteCommandStartCancelled),
        ):
            limiter.wait_for_start(
                "example.test",
                timeout=1,
                cancel_event=cancelled,
            )

        self.assertEqual(writes, 2)
        self.assertEqual(limiter.snapshot("example.test").waiting, 0)

    def test_lock_cleanup_control_supersedes_active_ordinary_error(
        self,
    ) -> None:
        limiter = RemoteCommandStartLimiter(
            self.runtime_root,
            0.3,
            poll_interval_seconds=0.005,
        )
        interruption = KeyboardInterrupt(
            "synthetic remote lock cleanup control"
        )
        real_open = remote_limiter_module.builtins.open

        class InterruptingCloseStream:
            def __init__(self, stream) -> None:
                self._stream = stream

            def fileno(self) -> int:
                return self._stream.fileno()

            def close(self) -> None:
                raise interruption

            def force_close(self) -> None:
                self._stream.close()

        wrapped_streams: list[InterruptingCloseStream] = []

        def open_with_interrupt(*args, **kwargs):
            stream = real_open(*args, **kwargs)
            if str(args[0]).endswith(".json.lock"):
                wrapped = InterruptingCloseStream(stream)
                wrapped_streams.append(wrapped)
                return wrapped
            return stream

        def fail_operation(_state) -> None:
            raise OSError("synthetic remote state failure")

        try:
            with (
                mock.patch.object(
                    remote_limiter_module.builtins,
                    "open",
                    side_effect=open_with_interrupt,
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                limiter._locked_state(
                    "example.test",
                    fail_operation,
                )
            self.assertIs(raised.exception, interruption)
        finally:
            for wrapped in wrapped_streams:
                wrapped.force_close()

    def test_post_persist_interrupt_removes_exact_ticket_and_next_starts(
        self,
    ) -> None:
        limiter = RemoteCommandStartLimiter(
            self.runtime_root,
            0.3,
            poll_interval_seconds=0.005,
        )
        interruption = KeyboardInterrupt(
            "synthetic remote ticket persistence interrupt"
        )
        injected = False

        def write_then_interrupt(path, payload, **kwargs):
            nonlocal injected
            atomic_write_bytes(path, payload, **kwargs)
            if not injected and b'"ticket"' in payload:
                injected = True
                raise interruption

        with (
            mock.patch(
                "ctf_os.remote_limiter.atomic_write_bytes",
                side_effect=write_then_interrupt,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            limiter.wait_for_start("example.test", timeout=0)

        self.assertIs(raised.exception, interruption)
        self.assertEqual(limiter.snapshot("example.test").waiting, 0)
        permit = limiter.wait_for_start("example.test", timeout=0)
        self.assertTrue(permit.enabled)
        self.assertEqual(limiter.snapshot("example.test").waiting, 0)

    def test_pre_start_commit_interrupt_removes_persisted_head_ticket(
        self,
    ) -> None:
        limiter = RemoteCommandStartLimiter(
            self.runtime_root,
            0.3,
            poll_interval_seconds=0.005,
        )
        interruption = KeyboardInterrupt(
            "synthetic remote start commit interrupt"
        )
        writes = 0

        def interrupt_before_second_write(path, payload, **kwargs):
            nonlocal writes
            writes += 1
            if writes == 2:
                raise interruption
            atomic_write_bytes(path, payload, **kwargs)

        with (
            mock.patch(
                "ctf_os.remote_limiter.atomic_write_bytes",
                side_effect=interrupt_before_second_write,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            limiter.wait_for_start("example.test", timeout=0)

        self.assertIs(raised.exception, interruption)
        self.assertEqual(limiter.snapshot("example.test").waiting, 0)
        permit = limiter.wait_for_start("example.test", timeout=0)
        self.assertTrue(permit.enabled)
        self.assertEqual(limiter.snapshot("example.test").waiting, 0)

    def test_cleanup_interrupt_retries_ticket_removal_and_propagates(
        self,
    ) -> None:
        limiter = RemoteCommandStartLimiter(
            self.runtime_root,
            0.3,
            poll_interval_seconds=0.005,
        )
        limiter.wait_for_start("example.test")
        interruption = KeyboardInterrupt(
            "synthetic remote ticket cleanup interrupt"
        )
        writes = 0

        def interrupt_cleanup_write(path, payload, **kwargs):
            nonlocal writes
            writes += 1
            if writes == 2:
                raise interruption
            atomic_write_bytes(path, payload, **kwargs)

        with (
            mock.patch(
                "ctf_os.remote_limiter.atomic_write_bytes",
                side_effect=interrupt_cleanup_write,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            limiter.wait_for_start("example.test", timeout=0)

        self.assertIs(raised.exception, interruption)
        self.assertGreaterEqual(writes, 3)
        self.assertEqual(limiter.snapshot("example.test").waiting, 0)
        with self.assertRaises(RemoteCommandStartTimeout):
            limiter.wait_for_start("example.test", timeout=0)
        self.assertEqual(limiter.snapshot("example.test").waiting, 0)

    def test_transient_cleanup_error_is_retried(
        self,
    ) -> None:
        limiter = RemoteCommandStartLimiter(
            self.runtime_root,
            0.3,
            poll_interval_seconds=0.005,
        )
        limiter.wait_for_start("example.test")
        writes = 0

        def fail_cleanup_write_once(path, payload, **kwargs):
            nonlocal writes
            writes += 1
            if writes == 2:
                raise OSError("synthetic transient remote cleanup error")
            atomic_write_bytes(path, payload, **kwargs)

        with (
            mock.patch(
                "ctf_os.remote_limiter.atomic_write_bytes",
                side_effect=fail_cleanup_write_once,
            ),
            self.assertRaises(RemoteCommandStartTimeout),
        ):
            limiter.wait_for_start("example.test", timeout=0)

        self.assertGreaterEqual(writes, 3)
        self.assertEqual(limiter.snapshot("example.test").waiting, 0)
        with self.assertRaises(RemoteCommandStartTimeout):
            limiter.wait_for_start("example.test", timeout=0)
        self.assertEqual(limiter.snapshot("example.test").waiting, 0)

    def test_cross_process_fifo_is_ordered_and_atomic(self) -> None:
        context = multiprocessing.get_context("fork")
        output = context.Queue()
        interval = 0.16
        limiter = RemoteCommandStartLimiter(
            self.runtime_root,
            interval,
            poll_interval_seconds=0.005,
        )
        limiter.wait_for_start("example.test")

        first = context.Process(
            target=_process_wait_for_start,
            args=(
                str(self.runtime_root),
                interval,
                "Example.TEST.",
                1,
                output,
            ),
        )
        second = context.Process(
            target=_process_wait_for_start,
            args=(
                str(self.runtime_root),
                interval,
                "example.test",
                2,
                output,
            ),
        )
        self.addCleanup(self._stop_process, first)
        self.addCleanup(self._stop_process, second)

        first.start()
        self._wait_for_waiters(limiter, "example.test", 1)
        second.start()
        self._wait_for_waiters(limiter, "example.test", 2)
        results = [output.get(timeout=5), output.get(timeout=5)]
        first.join(timeout=2)
        second.join(timeout=2)

        self.assertEqual([result[0] for result in results], ["ok", "ok"])
        self.assertEqual([result[1] for result in results], [1, 2])
        self.assertGreaterEqual(
            float(results[1][2]) - float(results[0][2]),
            interval - 0.02,
        )
        self.assertEqual(first.exitcode, 0)
        self.assertEqual(second.exitcode, 0)
        state_path = limiter.state_path("example.test")
        payload = state_path.read_bytes()
        self.assertLessEqual(len(payload), MAX_STATE_BYTES)
        state = json.loads(payload)
        self.assertEqual(state["hostname"], "example.test")
        self.assertEqual(state["queue"], [])

    def test_dead_process_waiter_is_reclaimed(self) -> None:
        context = multiprocessing.get_context("fork")
        output = context.Queue()
        limiter = RemoteCommandStartLimiter(
            self.runtime_root,
            5,
            poll_interval_seconds=0.005,
        )
        limiter.wait_for_start("example.test")
        process = context.Process(
            target=_process_wait_for_start,
            args=(
                str(self.runtime_root),
                5,
                "example.test",
                1,
                output,
            ),
        )
        self.addCleanup(self._stop_process, process)
        process.start()
        self._wait_for_waiters(limiter, "example.test", 1)
        process.terminate()
        process.join(timeout=2)
        self.assertFalse(process.is_alive())

        state_path = limiter.state_path("example.test")
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["last_start_monotonic"] = 0.0
        atomic_write_bytes(
            state_path,
            (
                json.dumps(
                    state,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode(),
        )

        permit = limiter.wait_for_start("example.test", timeout=0.5)
        self.assertTrue(permit.enabled)
        self.assertEqual(limiter.snapshot("example.test").waiting, 0)

    def test_queue_and_state_size_are_bounded(self) -> None:
        limiter = RemoteCommandStartLimiter(
            self.runtime_root,
            5,
            poll_interval_seconds=0.005,
            max_waiters=1,
        )
        limiter.wait_for_start("example.test")
        cancelled = threading.Event()

        def occupy_queue() -> None:
            with self.assertRaises(RemoteCommandStartCancelled):
                limiter.wait_for_start(
                    "example.test",
                    timeout=2,
                    cancel_event=cancelled,
                )

        waiter = threading.Thread(target=occupy_queue)
        waiter.start()
        self._wait_for_waiters(limiter, "example.test", 1)
        with self.assertRaises(RemoteLimiterQueueFull):
            limiter.wait_for_start("example.test", timeout=0)
        cancelled.set()
        waiter.join(timeout=2)
        self.assertFalse(waiter.is_alive())
        self.assertEqual(limiter.snapshot("example.test").waiting, 0)

        oversized = limiter.state_path("oversized.example")
        oversized.parent.mkdir(parents=True, exist_ok=True)
        oversized.write_bytes(b"x" * (MAX_STATE_BYTES + 1))
        with self.assertRaises(RemoteLimiterStateError):
            limiter.snapshot("oversized.example")
        self.assertEqual(oversized.stat().st_size, MAX_STATE_BYTES + 1)

    def test_wall_clock_rollback_is_irrelevant(self) -> None:
        interval = 0.04
        limiter = RemoteCommandStartLimiter(
            self.runtime_root,
            interval,
            poll_interval_seconds=0.003,
        )
        with mock.patch(
            "ctf_os.remote_limiter.time.time",
            side_effect=(1000.0, -1000.0),
        ) as wall_clock:
            first = limiter.wait_for_start("example.test")
            second = limiter.wait_for_start("example.test")

        wall_clock.assert_not_called()
        self.assertGreaterEqual(
            second.started_monotonic - first.started_monotonic,
            interval - 0.01,
        )

    def test_future_monotonic_state_waits_one_conservative_interval(
        self,
    ) -> None:
        interval = 0.04
        limiter = RemoteCommandStartLimiter(
            self.runtime_root,
            interval,
            poll_interval_seconds=0.003,
        )
        limiter.wait_for_start("example.test")
        state_path = limiter.state_path("example.test")
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["last_start_monotonic"] = time.monotonic() + 100
        atomic_write_bytes(
            state_path,
            (
                json.dumps(
                    state,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode(),
        )

        started = time.monotonic()
        limiter.wait_for_start("example.test")
        self.assertGreaterEqual(time.monotonic() - started, interval - 0.01)


class _FailingRemoteLimiter:
    def __init__(self, engine: ChallengeEngine) -> None:
        self.engine = engine
        self.calls: list[tuple[str, float | None, bool]] = []

    def wait_for_start(
        self,
        hostname: str,
        timeout: float | None = None,
        *,
        cancel_event: object | None = None,
    ) -> None:
        del cancel_event
        lease_held = not self.engine.lease_broker.status().used.is_empty()
        self.calls.append((hostname, timeout, lease_held))
        raise RemoteCommandStartTimeout("synthetic remote wait timeout")


class _PausingRemoteLimiter:
    def __init__(
        self,
        engine: ChallengeEngine,
        identity: ChallengeIdentity,
    ) -> None:
        self.engine = engine
        self.identity = identity
        self.calls = 0

    def wait_for_start(
        self,
        hostname: str,
        timeout: float | None = None,
        *,
        cancel_event: object | None = None,
    ) -> None:
        del hostname, timeout, cancel_event
        self.calls += 1
        self.engine.pause(self.identity)


class EngineRemoteLimiterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        base = load_config(self.root)
        self.config = replace(
            base,
            resources=replace(
                base.resources,
                max_standard_jobs=2,
                remote_command_min_interval_s=0.12,
            ),
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _engine(
        self,
        starts: list[tuple[str, float]],
        starts_lock: threading.Lock,
    ) -> ChallengeEngine:
        def sandbox_factory(state, work, policy):
            del state, policy

            class TimedSandbox(FakeSandbox):
                def run(inner_self, spec):
                    assert spec.network_target is not None
                    with starts_lock:
                        starts.append(
                            (
                                spec.network_target.host,
                                time.monotonic(),
                            )
                        )
                    return super().run(spec)

            return TimedSandbox(work)

        return ChallengeEngine(
            self.root,
            config=self.config,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=sandbox_factory,
        )

    def _run_two_challenges(
        self,
        first_target: str,
        second_target: str,
    ) -> list[tuple[str, float]]:
        starts: list[tuple[str, float]] = []
        starts_lock = threading.Lock()
        first_engine = self._engine(starts, starts_lock)
        second_engine = self._engine(starts, starts_lock)
        first_identity = ChallengeIdentity("contest", "web", "first")
        second_identity = ChallengeIdentity("contest", "web", "second")
        first_engine.add_challenge(
            first_identity,
            prompt="solve",
            budget_seconds=30,
        )
        first_engine.add_network_target(
            first_identity,
            first_target,
            docker_network="test-restricted-proxy",
            enforcement="proxy",
        )
        second_engine.add_challenge(
            second_identity,
            prompt="solve",
            budget_seconds=30,
        )
        second_engine.add_network_target(
            second_identity,
            second_target,
            docker_network="test-restricted-proxy",
            enforcement="proxy",
        )
        _state, first_experiment = first_engine.register_experiment(
            first_identity,
            command=("true",),
            expected_observation="exit zero",
            keep_if="zero",
            drop_if="nonzero",
            network_target=first_target,
        )
        _state, second_experiment = second_engine.register_experiment(
            second_identity,
            command=("true",),
            expected_observation="exit zero",
            keep_if="zero",
            drop_if="nonzero",
            network_target=second_target,
        )
        barrier = threading.Barrier(3)

        def execute(
            engine: ChallengeEngine,
            identity: ChallengeIdentity,
            experiment_id: str,
        ) -> None:
            barrier.wait()
            engine.execute_registered_experiments(
                identity,
                experiment_ids=(experiment_id,),
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = (
                executor.submit(
                    execute,
                    first_engine,
                    first_identity,
                    first_experiment,
                ),
                executor.submit(
                    execute,
                    second_engine,
                    second_identity,
                    second_experiment,
                ),
            )
            barrier.wait()
            for future in futures:
                future.result(timeout=5)

        self.assertEqual(len(starts), 2)
        return sorted(starts, key=lambda item: item[1])

    def test_same_host_two_challenges_space_actual_command_starts(self) -> None:
        starts = self._run_two_challenges(
            "https://Example.TEST:443",
            "example.test:8443",
        )
        self.assertEqual(
            {hostname for hostname, _started in starts},
            {"example.test"},
        )
        self.assertGreaterEqual(
            starts[1][1] - starts[0][1],
            self.config.resources.remote_command_min_interval_s - 0.02,
        )

    def test_different_hosts_do_not_share_command_start_interval(self) -> None:
        starts = self._run_two_challenges(
            "first.example:443",
            "second.example:443",
        )
        self.assertEqual(
            {hostname for hostname, _started in starts},
            {"first.example", "second.example"},
        )
        self.assertLess(
            starts[1][1] - starts[0][1],
            self.config.resources.remote_command_min_interval_s / 2,
        )

    def test_tool_remote_timeout_is_failed_after_lease_and_budget_clamped(
        self,
    ) -> None:
        starts: list[tuple[str, float]] = []
        engine = self._engine(starts, threading.Lock())
        identity = ChallengeIdentity("contest", "web", "tool-timeout")
        engine.add_challenge(
            identity,
            prompt="solve",
            budget_seconds=30,
        )
        engine.add_network_target(
            identity,
            "example.test:443",
            docker_network="test-restricted-proxy",
            enforcement="proxy",
        )
        _state, experiment_id = engine.register_experiment(
            identity,
            command=("true",),
            expected_observation="exit zero",
            keep_if="zero",
            drop_if="nonzero",
            network_target="example.test:443",
        )
        limiter = _FailingRemoteLimiter(engine)
        engine.remote_command_limiter = limiter  # type: ignore[assignment]

        state = engine.execute_registered_experiments(
            identity,
            experiment_ids=(experiment_id,),
        )

        experiment = next(
            item for item in state.experiments if item.id == experiment_id
        )
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        self.assertIn("remote command start", experiment.result["error"])
        self.assertEqual(len(limiter.calls), 1)
        hostname, timeout, lease_held = limiter.calls[0]
        self.assertEqual(hostname, "example.test")
        self.assertIsNotNone(timeout)
        assert timeout is not None
        self.assertGreater(timeout, 0)
        self.assertLessEqual(timeout, 30)
        self.assertTrue(lease_held)
        self.assertTrue(engine.lease_broker.status().used.is_empty())
        self.assertEqual(starts, [])

    def test_proof_remote_timeout_surfaces_and_releases_lease(self) -> None:
        starts: list[tuple[str, float]] = []
        engine = self._engine(starts, threading.Lock())
        identity = ChallengeIdentity("contest", "web", "proof-timeout")
        engine.add_challenge(
            identity,
            prompt="solve",
            budget_seconds=30,
        )
        engine.add_network_target(
            identity,
            "example.test:443",
            docker_network="test-restricted-proxy",
            enforcement="proxy",
        )
        state = engine.record_candidate(
            identity,
            "KCTF{proof_flag}",
            print_immediately=False,
        )
        limiter = _FailingRemoteLimiter(engine)
        engine.remote_command_limiter = limiter  # type: ignore[assignment]

        with self.assertRaisesRegex(EngineError, "remote command start"):
            engine.prove_candidate(
                identity,
                state.candidates[0].id,
                ("true",),
                network_target="example.test:443",
            )

        self.assertEqual(len(limiter.calls), 1)
        self.assertEqual(limiter.calls[0][0], "example.test")
        self.assertTrue(limiter.calls[0][2])
        self.assertTrue(engine.lease_broker.status().used.is_empty())

    def test_tool_rechecks_pause_after_remote_start_wait(self) -> None:
        starts: list[tuple[str, float]] = []
        engine = self._engine(starts, threading.Lock())
        identity = ChallengeIdentity("contest", "web", "tool-paused")
        engine.add_challenge(identity, prompt="solve", budget_seconds=30)
        engine.add_network_target(
            identity,
            "example.test:443",
            docker_network="test-restricted-proxy",
            enforcement="proxy",
        )
        _state, experiment_id = engine.register_experiment(
            identity,
            command=("true",),
            expected_observation="exit zero",
            keep_if="zero",
            drop_if="nonzero",
            network_target="example.test:443",
        )
        limiter = _PausingRemoteLimiter(engine, identity)
        engine.remote_command_limiter = limiter  # type: ignore[assignment]

        paused = engine.execute_registered_experiments(
            identity,
            experiment_ids=(experiment_id,),
        )

        self.assertIs(paused.status, ChallengeStatus.PAUSED)
        experiment = next(
            item for item in paused.experiments
            if item.id == experiment_id
        )
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        self.assertEqual(limiter.calls, 1)
        self.assertEqual(starts, [])
        self.assertTrue(engine.lease_broker.status().used.is_empty())

    def test_proof_rechecks_pause_after_remote_start_wait(self) -> None:
        starts: list[tuple[str, float]] = []
        engine = self._engine(starts, threading.Lock())
        identity = ChallengeIdentity("contest", "pwn", "proof-paused")
        engine.add_challenge(identity, prompt="solve", budget_seconds=30)
        engine.add_network_target(
            identity,
            "example.test:443",
            docker_network="test-restricted-proxy",
            enforcement="proxy",
        )
        state = engine.record_candidate(
            identity,
            "KCTF{proof_flag}",
            print_immediately=False,
        )
        limiter = _PausingRemoteLimiter(engine, identity)
        engine.remote_command_limiter = limiter  # type: ignore[assignment]

        with self.assertRaisesRegex(EngineError, "concurrent PAUSED"):
            engine.prove_candidate(
                identity,
                state.candidates[0].id,
                ("true",),
                network_target="example.test:443",
            )

        paused = engine.store.load(identity)
        self.assertIs(paused.status, ChallengeStatus.PAUSED)
        self.assertIs(paused.resume_status, ChallengeStatus.PROVING)
        self.assertEqual(limiter.calls, 1)
        self.assertEqual(starts, [])
        self.assertTrue(engine.lease_broker.status().used.is_empty())


if __name__ == "__main__":
    unittest.main()
