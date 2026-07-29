from __future__ import annotations

import gc
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import ctf_os.store.locks as locks_module
from ctf_os.store import FileLock


class FileLockInterruptTests(unittest.TestCase):
    def test_timeout_and_poll_interval_require_finite_numbers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lock_path = Path(temporary) / "state.lock"
            invalid_timeouts = (
                True,
                "1",
                float("nan"),
                float("inf"),
                float("-inf"),
                -0.01,
            )
            for value in invalid_timeouts:
                with (
                    self.subTest(argument="timeout", value=value),
                    self.assertRaisesRegex(ValueError, "timeout"),
                ):
                    FileLock(lock_path, timeout=value)

            invalid_poll_intervals = (
                True,
                "0.05",
                float("nan"),
                float("inf"),
                float("-inf"),
                0,
                -0.01,
            )
            for value in invalid_poll_intervals:
                with (
                    self.subTest(argument="poll_interval", value=value),
                    self.assertRaisesRegex(ValueError, "poll_interval"),
                ):
                    FileLock(lock_path, poll_interval=value)

            with FileLock(lock_path, timeout=0) as immediate:
                immediate.acquire()
            with FileLock(lock_path, timeout=None) as unbounded:
                unbounded.acquire()

    def test_poll_interval_is_clamped_to_the_remaining_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lock_path = Path(temporary) / "state.lock"
            with FileLock(lock_path) as holder:
                holder.acquire()
                contender = FileLock(
                    lock_path,
                    timeout=0.01,
                    poll_interval=0.2,
                )
                interruption = RuntimeError("stop after first bounded sleep")
                with (
                    patch.object(
                        locks_module.time,
                        "monotonic",
                        side_effect=(100.0, 100.0),
                    ),
                    patch.object(
                        locks_module.time,
                        "sleep",
                        side_effect=interruption,
                    ) as sleep,
                    self.assertRaises(RuntimeError) as raised,
                ):
                    contender.acquire()

            self.assertIs(raised.exception, interruption)
            sleep.assert_called_once()
            self.assertAlmostEqual(sleep.call_args.args[0], 0.01)

    def test_context_enter_return_is_resource_free_and_single_use(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lock_path = Path(temporary) / "state.lock"
            lock = FileLock(lock_path)
            interruption = KeyboardInterrupt(
                "synthetic resource-free enter return interrupt"
            )
            injected = False

            def trace(frame, event, _argument):
                nonlocal injected
                if (
                    frame.f_code is FileLock.__enter__.__code__
                    and event == "return"
                    and not injected
                ):
                    injected = True
                    raise interruption
                return trace

            previous_trace = sys.gettrace()
            try:
                sys.settrace(trace)
                with self.assertRaises(KeyboardInterrupt) as raised:
                    with lock as guarded:
                        guarded.acquire()
            finally:
                sys.settrace(previous_trace)

            self.assertTrue(injected)
            self.assertIs(raised.exception, interruption)
            self.assertFalse(lock.acquired)
            self.assertFalse(lock_path.exists())
            with self.assertRaisesRegex(RuntimeError, "already used"):
                lock.__enter__()

            with FileLock(lock_path, timeout=0) as probe:
                probe.acquire()

    def test_context_guard_releases_acquire_return_interruption(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lock_path = Path(temporary) / "state.lock"
            real_acquire = FileLock.acquire

            for interruption in (
                KeyboardInterrupt(
                    "synthetic context acquire handoff interrupt"
                ),
                SystemExit(41),
            ):
                with self.subTest(
                    interruption=type(interruption).__name__
                ):
                    lock = FileLock(lock_path)
                    injected = False

                    def acquire_then_interrupt(actual_lock):
                        nonlocal injected
                        acquired = real_acquire(actual_lock)
                        if actual_lock is lock and not injected:
                            injected = True
                            raise interruption
                        return acquired

                    with (
                        patch.object(
                            FileLock,
                            "acquire",
                            new=acquire_then_interrupt,
                        ),
                        self.assertRaises(type(interruption)) as raised,
                    ):
                        with lock as guarded:
                            guarded.acquire()

                    self.assertTrue(injected)
                    self.assertIs(raised.exception, interruption)
                    self.assertFalse(lock.acquired)
                    with FileLock(lock_path, timeout=0) as probe:
                        probe.acquire()

    def test_public_return_handoff_closes_lost_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lock_path = Path(temporary) / "state.lock"
            interruption = KeyboardInterrupt(
                "synthetic file lock return handoff interrupt"
            )

            def acquire_then_interrupt() -> None:
                lock = FileLock(lock_path).acquire()
                self.assertTrue(lock.acquired)
                raise interruption

            try:
                acquire_then_interrupt()
            except KeyboardInterrupt as error:
                self.assertIs(error, interruption)
                interruption.__traceback__ = None
            else:
                self.fail("file lock return handoff did not interrupt")
            gc.collect()

            with FileLock(lock_path, timeout=0) as probe:
                probe.acquire()
                pass

    def test_lost_return_finalizer_consumes_ambiguous_close_once(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lock_path = Path(temporary) / "state.lock"
            interruption = KeyboardInterrupt(
                "synthetic file lock return handoff interrupt"
            )
            real_close = locks_module.os.close
            interrupted_descriptor: list[int] = []

            def fail_first_lock_close(descriptor: int) -> None:
                try:
                    target = Path(
                        f"/proc/self/fd/{descriptor}"
                    ).readlink()
                except OSError:
                    target = Path()
                if (
                    not interrupted_descriptor
                    and target == lock_path
                ):
                    interrupted_descriptor.append(descriptor)
                    raise OSError(
                        "synthetic transient finalizer close error"
                    )
                real_close(descriptor)

            def acquire_then_interrupt() -> None:
                lock = FileLock(lock_path).acquire()
                self.assertTrue(lock.acquired)
                raise interruption

            with patch.object(
                locks_module.os,
                "close",
                side_effect=fail_first_lock_close,
            ):
                try:
                    acquire_then_interrupt()
                except KeyboardInterrupt as error:
                    self.assertIs(error, interruption)
                    interruption.__traceback__ = None
                else:
                    self.fail("file lock return handoff did not interrupt")
                gc.collect()

            self.assertEqual(len(interrupted_descriptor), 1)
            leaked_descriptor = interrupted_descriptor[0]
            try:
                # The injected wrapper failed before close(2).  Ownership was
                # still consumed and the flock was explicitly unlocked, so the
                # ambiguous integer is deliberately not retried.
                self.assertTrue(
                    Path(f"/proc/self/fd/{leaked_descriptor}").exists()
                )
                with FileLock(lock_path, timeout=0) as probe:
                    probe.acquire()
                    pass
            finally:
                real_close(leaked_descriptor)

    def test_post_acquire_interrupt_closes_and_forgets_descriptor(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lock_path = Path(temporary) / "state.lock"
            lock = FileLock(lock_path)
            interruption = KeyboardInterrupt(
                "synthetic post-acquire interrupt"
            )
            real_flock = locks_module.fcntl.flock
            descriptors: list[int] = []
            interrupted = False

            def interrupt_after_lock(descriptor: int, operation: int) -> None:
                nonlocal interrupted
                real_flock(descriptor, operation)
                if (
                    not interrupted
                    and operation
                    & (locks_module.fcntl.LOCK_EX | locks_module.fcntl.LOCK_SH)
                ):
                    interrupted = True
                    descriptors.append(descriptor)
                    raise interruption

            with (
                patch.object(
                    locks_module.fcntl,
                    "flock",
                    side_effect=interrupt_after_lock,
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                lock.acquire()

            self.assertIs(raised.exception, interruption)
            self.assertFalse(lock.acquired)
            self.assertEqual(len(descriptors), 1)
            self.assertFalse(
                Path(f"/proc/self/fd/{descriptors[0]}").exists()
            )
            with FileLock(lock_path, timeout=0) as probe:
                probe.acquire()
                pass

    def test_acquire_cleanup_never_recloses_reused_descriptor(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lock_path = Path(temporary) / "state.lock"
            foreign_path = Path(temporary) / "foreign.txt"
            foreign_path.write_text("foreign", encoding="utf-8")
            real_flock = locks_module.fcntl.flock
            real_close = locks_module.os.close

            for interruption in (
                KeyboardInterrupt("synthetic acquire interruption"),
                SystemExit(43),
            ):
                with self.subTest(
                    interruption=type(interruption).__name__
                ):
                    lock = FileLock(lock_path)
                    target_descriptor: int | None = None
                    foreign_descriptor: int | None = None
                    close_interruption = type(interruption)(
                        "synthetic post-close interruption"
                        if isinstance(interruption, KeyboardInterrupt)
                        else 44
                    )
                    close_calls: list[int] = []

                    def interrupt_after_flock(
                        descriptor: int,
                        operation: int,
                    ) -> None:
                        nonlocal target_descriptor
                        real_flock(descriptor, operation)
                        target_descriptor = descriptor
                        raise interruption

                    def close_then_reuse(descriptor: int) -> None:
                        nonlocal foreign_descriptor
                        close_calls.append(descriptor)
                        if (
                            descriptor == target_descriptor
                            and foreign_descriptor is None
                        ):
                            real_close(descriptor)
                            replacement = locks_module.os.open(
                                foreign_path,
                                locks_module.os.O_RDONLY,
                            )
                            if replacement != descriptor:
                                locks_module.os.dup2(
                                    replacement,
                                    descriptor,
                                )
                                real_close(replacement)
                            foreign_descriptor = descriptor
                            raise close_interruption
                        real_close(descriptor)

                    try:
                        with (
                            patch.object(
                                locks_module.fcntl,
                                "flock",
                                side_effect=interrupt_after_flock,
                            ),
                            patch.object(
                                locks_module.os,
                                "close",
                                side_effect=close_then_reuse,
                            ),
                            self.assertRaises(type(interruption)) as raised,
                        ):
                            lock.acquire()

                        self.assertIs(raised.exception, interruption)
                        self.assertFalse(lock.acquired)
                        self.assertIsNotNone(target_descriptor)
                        self.assertEqual(
                            foreign_descriptor,
                            target_descriptor,
                        )
                        self.assertEqual(
                            close_calls,
                            [target_descriptor],
                        )
                        assert foreign_descriptor is not None
                        self.assertEqual(
                            locks_module.os.read(
                                foreign_descriptor,
                                len("foreign"),
                            ),
                            b"foreign",
                        )
                    finally:
                        if foreign_descriptor is not None:
                            try:
                                real_close(foreign_descriptor)
                            except OSError:
                                pass

                    with FileLock(lock_path, timeout=0) as probe:
                        probe.acquire()

    def test_acquire_cleanup_never_recloses_same_inode_peer_descriptor(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lock_path = Path(temporary) / "state.lock"
            real_flock = locks_module.fcntl.flock
            real_close = locks_module.os.close

            for interruption in (
                KeyboardInterrupt(
                    "synthetic same-inode acquire interruption"
                ),
                SystemExit(46),
            ):
                with self.subTest(
                    interruption=type(interruption).__name__
                ):
                    lock = FileLock(lock_path)
                    target_descriptor: int | None = None
                    peer_descriptor: int | None = None
                    contender_descriptor: int | None = None
                    identity: tuple[int, int] | None = None
                    close_calls: list[int] = []
                    close_interruption = type(interruption)(
                        "synthetic same-inode acquire close interrupt"
                        if isinstance(interruption, KeyboardInterrupt)
                        else 47
                    )

                    def interrupt_after_flock(
                        descriptor: int,
                        operation: int,
                    ) -> None:
                        nonlocal target_descriptor
                        real_flock(descriptor, operation)
                        if (
                            target_descriptor is None
                            and operation
                            & (
                                locks_module.fcntl.LOCK_EX
                                | locks_module.fcntl.LOCK_SH
                            )
                        ):
                            target_descriptor = descriptor
                            raise interruption

                    def close_then_reopen_same_inode(
                        descriptor: int,
                    ) -> None:
                        nonlocal peer_descriptor, contender_descriptor
                        nonlocal identity
                        close_calls.append(descriptor)
                        if (
                            descriptor == target_descriptor
                            and peer_descriptor is None
                        ):
                            opened = locks_module.os.fstat(descriptor)
                            identity = (opened.st_dev, opened.st_ino)
                            real_close(descriptor)
                            replacement = locks_module.os.open(
                                lock_path,
                                locks_module.os.O_RDWR,
                            )
                            if replacement != descriptor:
                                locks_module.os.dup2(
                                    replacement,
                                    descriptor,
                                    inheritable=False,
                                )
                                real_close(replacement)
                            peer_descriptor = descriptor
                            real_flock(
                                peer_descriptor,
                                locks_module.fcntl.LOCK_EX
                                | locks_module.fcntl.LOCK_NB,
                            )
                            contender_descriptor = locks_module.os.open(
                                lock_path,
                                locks_module.os.O_RDWR,
                            )
                            reopened = locks_module.os.fstat(descriptor)
                            self.assertEqual(
                                (reopened.st_dev, reopened.st_ino),
                                identity,
                            )
                            raise close_interruption
                        real_close(descriptor)

                    try:
                        with (
                            patch.object(
                                locks_module.fcntl,
                                "flock",
                                side_effect=interrupt_after_flock,
                            ),
                            patch.object(
                                locks_module.os,
                                "close",
                                side_effect=close_then_reopen_same_inode,
                            ),
                            self.assertRaises(
                                type(interruption)
                            ) as raised,
                        ):
                            lock.acquire()

                        self.assertIs(raised.exception, interruption)
                        self.assertFalse(lock.acquired)
                        assert target_descriptor is not None
                        assert peer_descriptor is not None
                        assert contender_descriptor is not None
                        assert identity is not None
                        self.assertEqual(
                            close_calls,
                            [target_descriptor],
                        )
                        peer = locks_module.os.fstat(peer_descriptor)
                        self.assertEqual(
                            (peer.st_dev, peer.st_ino),
                            identity,
                        )
                        with self.assertRaises(BlockingIOError):
                            locks_module.fcntl.flock(
                                contender_descriptor,
                                locks_module.fcntl.LOCK_EX
                                | locks_module.fcntl.LOCK_NB,
                            )
                    finally:
                        if contender_descriptor is not None:
                            try:
                                real_close(contender_descriptor)
                            except OSError:
                                pass
                        if peer_descriptor is not None:
                            try:
                                real_flock(
                                    peer_descriptor,
                                    locks_module.fcntl.LOCK_UN,
                                )
                            finally:
                                real_close(peer_descriptor)

                    with FileLock(lock_path, timeout=0) as probe:
                        probe.acquire()

    def test_normal_close_return_interrupt_cannot_leave_stale_owner(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lock_path = Path(temporary) / "state.lock"
            foreign_path = Path(temporary) / "foreign.txt"
            foreign_path.write_text("foreign", encoding="utf-8")
            real_close = locks_module.os.close

            for interruption in (
                KeyboardInterrupt("synthetic normal close return interrupt"),
                SystemExit(45),
            ):
                with self.subTest(
                    interruption=type(interruption).__name__
                ):
                    lock = FileLock(lock_path).acquire()
                    descriptor = lock._descriptor
                    assert descriptor is not None
                    foreign_source = locks_module.os.open(
                        foreign_path,
                        locks_module.os.O_RDONLY,
                    )
                    self.assertNotEqual(foreign_source, descriptor)
                    injected = False
                    release_code = FileLock.release.__code__

                    def interrupt_after_normal_close(
                        frame,
                        event,
                        _argument,
                    ):
                        nonlocal injected
                        if (
                            frame.f_code is release_code
                            and event == "line"
                            and lock._descriptor is None
                            and not injected
                        ):
                            try:
                                locks_module.os.fstat(descriptor)
                            except OSError as error:
                                if error.errno == locks_module.errno.EBADF:
                                    injected = True
                                    sys.settrace(None)
                                    raise interruption
                        return interrupt_after_normal_close

                    previous_trace = sys.gettrace()
                    try:
                        sys.settrace(interrupt_after_normal_close)
                        with self.assertRaises(
                            type(interruption)
                        ) as raised:
                            lock.release()
                    finally:
                        sys.settrace(previous_trace)

                    self.assertTrue(injected)
                    self.assertIs(raised.exception, interruption)
                    self.assertFalse(lock.acquired)
                    self.assertEqual(
                        locks_module.os.dup2(
                            foreign_source,
                            descriptor,
                            inheritable=False,
                        ),
                        descriptor,
                    )
                    try:
                        lock.release()
                        self.assertEqual(
                            locks_module.os.fstat(descriptor).st_ino,
                            locks_module.os.fstat(foreign_source).st_ino,
                        )
                    finally:
                        for value in (descriptor, foreign_source):
                            try:
                                real_close(value)
                            except OSError:
                                pass

                    with FileLock(lock_path, timeout=0) as probe:
                        probe.acquire()

    def test_post_release_interrupt_still_closes_descriptor(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lock_path = Path(temporary) / "state.lock"
            lock = FileLock(lock_path).acquire()
            descriptor = lock._descriptor
            assert descriptor is not None
            interruption = KeyboardInterrupt(
                "synthetic post-release interrupt"
            )
            real_flock = locks_module.fcntl.flock

            def interrupt_after_unlock(
                actual_descriptor: int,
                operation: int,
            ) -> None:
                real_flock(actual_descriptor, operation)
                if operation & locks_module.fcntl.LOCK_UN:
                    raise interruption

            with (
                patch.object(
                    locks_module.fcntl,
                    "flock",
                    side_effect=interrupt_after_unlock,
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                lock.release()

            self.assertIs(raised.exception, interruption)
            self.assertFalse(lock.acquired)
            self.assertFalse(Path(f"/proc/self/fd/{descriptor}").exists())
            with FileLock(lock_path, timeout=0) as probe:
                probe.acquire()
                pass

    def test_descriptor_close_interrupt_is_not_retried(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lock_path = Path(temporary) / "state.lock"
            lock = FileLock(lock_path).acquire()
            descriptor = lock._descriptor
            assert descriptor is not None
            interruption = KeyboardInterrupt(
                "synthetic file lock descriptor close interrupt"
            )
            real_close = locks_module.os.close
            injected = False

            def interrupt_first_close(actual_descriptor: int) -> None:
                nonlocal injected
                if actual_descriptor == descriptor and not injected:
                    injected = True
                    raise interruption
                real_close(actual_descriptor)

            with (
                patch.object(
                    locks_module.os,
                    "close",
                    side_effect=interrupt_first_close,
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                lock.release()

            self.assertIs(raised.exception, interruption)
            self.assertFalse(lock.acquired)
            try:
                self.assertTrue(Path(f"/proc/self/fd/{descriptor}").exists())
                with FileLock(lock_path, timeout=0) as probe:
                    probe.acquire()
                    pass
            finally:
                real_close(descriptor)

    def test_transient_descriptor_close_error_is_not_retried(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lock_path = Path(temporary) / "state.lock"
            lock = FileLock(lock_path).acquire()
            descriptor = lock._descriptor
            assert descriptor is not None
            real_close = locks_module.os.close
            injected = False

            def fail_first_close(actual_descriptor: int) -> None:
                nonlocal injected
                if actual_descriptor == descriptor and not injected:
                    injected = True
                    raise OSError(
                        "synthetic transient file lock close error"
                    )
                real_close(actual_descriptor)

            with (
                patch.object(
                    locks_module.os,
                    "close",
                    side_effect=fail_first_close,
                ),
                self.assertRaisesRegex(
                    OSError,
                    "synthetic transient file lock close error",
                ),
            ):
                lock.release()

            self.assertFalse(lock.acquired)
            try:
                self.assertTrue(Path(f"/proc/self/fd/{descriptor}").exists())
                with FileLock(lock_path, timeout=0) as probe:
                    probe.acquire()
                    pass
            finally:
                real_close(descriptor)

    def test_release_never_recloses_same_inode_peer_descriptor(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lock_path = Path(temporary) / "state.lock"
            real_close = locks_module.os.close
            for interruption in (
                KeyboardInterrupt("synthetic same-inode close interrupt"),
                SystemExit(61),
            ):
                with self.subTest(
                    interruption=type(interruption).__name__
                ):
                    lock = FileLock(lock_path).acquire()
                    descriptor = lock._descriptor
                    assert descriptor is not None
                    peer_descriptor: int | None = None
                    close_calls: list[int] = []

                    def close_then_reopen_same_inode(
                        actual_descriptor: int,
                    ) -> None:
                        nonlocal peer_descriptor
                        close_calls.append(actual_descriptor)
                        if (
                            actual_descriptor == descriptor
                            and peer_descriptor is None
                        ):
                            real_close(actual_descriptor)
                            replacement = locks_module.os.open(
                                lock_path,
                                locks_module.os.O_CREAT
                                | locks_module.os.O_RDWR,
                                0o600,
                            )
                            if replacement != actual_descriptor:
                                locks_module.os.dup2(
                                    replacement,
                                    actual_descriptor,
                                )
                                real_close(replacement)
                            peer_descriptor = actual_descriptor
                            locks_module.fcntl.flock(
                                peer_descriptor,
                                locks_module.fcntl.LOCK_EX,
                            )
                            raise interruption
                        real_close(actual_descriptor)

                    try:
                        with (
                            patch.object(
                                locks_module.os,
                                "close",
                                side_effect=close_then_reopen_same_inode,
                            ),
                            self.assertRaises(
                                type(interruption)
                            ) as raised,
                        ):
                            lock.release()

                        self.assertIs(raised.exception, interruption)
                        self.assertEqual(close_calls, [descriptor])
                        self.assertFalse(lock.acquired)
                        assert peer_descriptor is not None
                        locks_module.os.fstat(peer_descriptor)
                        contender = locks_module.os.open(
                            lock_path,
                            locks_module.os.O_RDWR,
                        )
                        try:
                            with self.assertRaises(BlockingIOError):
                                locks_module.fcntl.flock(
                                    contender,
                                    locks_module.fcntl.LOCK_EX
                                    | locks_module.fcntl.LOCK_NB,
                                )
                        finally:
                            real_close(contender)
                    finally:
                        if peer_descriptor is not None:
                            try:
                                locks_module.fcntl.flock(
                                    peer_descriptor,
                                    locks_module.fcntl.LOCK_UN,
                                )
                            finally:
                                real_close(peer_descriptor)

                    with FileLock(lock_path, timeout=0) as probe:
                        probe.acquire()


if __name__ == "__main__":
    unittest.main()
