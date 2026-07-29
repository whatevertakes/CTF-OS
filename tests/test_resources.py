from __future__ import annotations

import gc
import inspect
import multiprocessing
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from ctf_os.director import leases as leases_module
from ctf_os.director.leases import LeaseBroker, LeaseError, LeaseOwnershipError
from ctf_os.director.resources import (
    ResourceLimits,
    ResourceVector,
    tool_profile,
)


def _acquire_then_exit(root: str, ready: multiprocessing.synchronize.Event) -> None:
    broker = LeaseBroker(
        Path(root),
        ResourceLimits(cpu=1, memory_mib=1, gpu=0, kvm=0, network=0),
    )
    lease = broker.acquire("cpu", 1, timeout=1)
    if lease is None:
        raise SystemExit(2)
    ready.set()
    # Deliberately skip release. Process exit must close the flock descriptor.


def _hold_resource_mutex(
    lock_path: str,
    ready_event,
    hold_seconds: float,
) -> None:
    descriptor = os.open(
        lock_path,
        os.O_RDWR | os.O_CLOEXEC,
    )
    try:
        leases_module.fcntl.flock(
            descriptor,
            leases_module.fcntl.LOCK_EX,
        )
        ready_event.set()
        time.sleep(hold_seconds)
    finally:
        leases_module.fcntl.flock(
            descriptor,
            leases_module.fcntl.LOCK_UN,
        )
        os.close(descriptor)


def _stop_test_process(process: multiprocessing.Process) -> None:
    if process.is_alive():
        process.terminate()
    process.join(timeout=2)


class ResourceBrokerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name).resolve()
        self.limits = ResourceLimits(
            cpu=4,
            memory_mib=8192,
            gpu=1,
            kvm=1,
            network=2,
        )
        self.broker = LeaseBroker(self.root, self.limits, poll_interval=0.01)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_timeout_and_poll_interval_require_finite_numbers(self) -> None:
        invalid_poll_intervals = (
            True,
            "0.01",
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
                LeaseBroker(
                    self.root / "invalid-poll",
                    self.limits,
                    poll_interval=value,
                )

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
                self.broker.acquire("cpu", 1, timeout=value)

        immediate = self.broker.acquire("cpu", 1, timeout=0)
        self.assertIsNotNone(immediate)
        assert immediate is not None
        immediate.release()
        unbounded = self.broker.acquire("cpu", 1, timeout=None)
        self.assertIsNotNone(unbounded)
        assert unbounded is not None
        unbounded.release()

    def test_mutex_lock_wait_honors_acquire_deadline(self) -> None:
        context = multiprocessing.get_context("fork")
        ready = context.Event()
        blocker = context.Process(
            target=_hold_resource_mutex,
            args=(str(self.broker._mutex_path), ready, 0.6),
        )
        blocker.start()
        self.addCleanup(_stop_test_process, blocker)
        self.assertTrue(ready.wait(timeout=1))

        started = time.monotonic()
        lease = self.broker.acquire("cpu", 1, timeout=0.05)
        elapsed = time.monotonic() - started

        self.assertIsNone(lease)
        self.assertLess(elapsed, 0.3)
        self.assertTrue(blocker.is_alive())
        blocker.join(timeout=1)
        self.assertFalse(blocker.is_alive())
        self.assertEqual(blocker.exitcode, 0)
        self.assertEqual(self.broker.status().queued, 0)
        self.assertEqual(self.broker.status().used.cpu, 0)

    def test_allocation_crossing_deadline_is_released(self) -> None:
        real_allocate = self.broker._allocate_locked

        def delay_completed_allocation(*args, **kwargs):
            lease = real_allocate(*args, **kwargs)
            time.sleep(0.06)
            return lease

        with mock.patch.object(
            self.broker,
            "_allocate_locked",
            side_effect=delay_completed_allocation,
        ):
            lease = self.broker.acquire("cpu", 1, timeout=0.02)

        self.assertIsNone(lease)
        status = self.broker.status()
        self.assertEqual(status.queued, 0)
        self.assertEqual(status.used.cpu, 0)
        self.assertEqual(status.leases, ())

    def test_successful_grant_does_not_reenter_blocked_global_mutex(
        self,
    ) -> None:
        context = multiprocessing.get_context("fork")
        ready = context.Event()
        blocker: multiprocessing.Process | None = None
        real_with_mutex = self.broker._with_mutex

        def block_mutex_after_grant(operation, **kwargs):
            nonlocal blocker
            result = real_with_mutex(operation, **kwargs)
            if isinstance(result, leases_module.Lease) and blocker is None:
                blocker = context.Process(
                    target=_hold_resource_mutex,
                    args=(str(self.broker._mutex_path), ready, 0.6),
                )
                blocker.start()
                self.addCleanup(_stop_test_process, blocker)
                self.assertTrue(ready.wait(timeout=1))
            return result

        started = time.monotonic()
        with mock.patch.object(
            self.broker,
            "_with_mutex",
            side_effect=block_mutex_after_grant,
        ):
            lease = self.broker.acquire("cpu", 1, timeout=0)
        elapsed = time.monotonic() - started

        self.assertIsNotNone(lease)
        self.assertLess(elapsed, 0.3)
        assert blocker is not None
        self.assertTrue(blocker.is_alive())
        assert lease is not None
        lease.release()
        blocker.join(timeout=1)
        self.assertFalse(blocker.is_alive())
        self.assertEqual(blocker.exitcode, 0)
        self.assertEqual(self.broker.status().queued, 0)
        self.assertEqual(self.broker.status().used.cpu, 0)

    def test_ticket_loader_skips_concurrent_exact_unlink(self) -> None:
        ticket_id = f"ticket-{'c' * 32}"
        request = ResourceVector(cpu=1)
        self.broker._with_mutex(
            lambda: self.broker._create_ticket_locked(
                ticket_id,
                request,
                "concurrent-retirement",
            )
        )
        ticket_path = self.broker._ticket_path(ticket_id)
        real_load_json = self.broker._load_json

        def unlink_before_open(path, **kwargs):
            if path == ticket_path:
                path.unlink()
                raise FileNotFoundError(path)
            return real_load_json(path, **kwargs)

        with mock.patch.object(
            self.broker,
            "_load_json",
            side_effect=unlink_before_open,
        ):
            tickets = self.broker._with_mutex(
                self.broker._load_tickets_locked
            )

        self.assertEqual(tickets, [])
        self.assertFalse(ticket_path.exists())

    def test_ticket_order_survives_monotonic_clock_rollback(self) -> None:
        first_ticket = f"ticket-{'a' * 32}"
        second_ticket = f"ticket-{'b' * 32}"
        request = ResourceVector(cpu=1)

        try:
            with mock.patch.object(
                leases_module.time,
                "monotonic_ns",
                side_effect=(200, 100),
            ):
                self.broker._with_mutex(
                    lambda: self.broker._create_ticket_locked(
                        first_ticket,
                        request,
                        "first",
                    )
                )
                self.broker._with_mutex(
                    lambda: self.broker._create_ticket_locked(
                        second_ticket,
                        request,
                        "second",
                    )
                )

            tickets = self.broker._with_mutex(
                self.broker._load_tickets_locked
            )
            self.assertEqual(
                [ticket["ticket_id"] for ticket in tickets],
                [first_ticket, second_ticket],
            )
            self.assertLess(
                int(tickets[0]["created_ns"]),
                int(tickets[1]["created_ns"]),
            )
        finally:
            self.broker._with_mutex(
                lambda: (
                    self.broker._ticket_path(first_ticket).unlink(
                        missing_ok=True
                    ),
                    self.broker._ticket_path(second_ticket).unlink(
                        missing_ok=True
                    ),
                )
            )

    def test_mutex_cleanup_control_supersedes_ordinary_error(self) -> None:
        handle = self.broker._lock_mutex()
        descriptor = handle._fd
        assert descriptor is not None
        real_flock = leases_module.fcntl.flock
        real_close = leases_module.os.close
        interruption = KeyboardInterrupt(
            "synthetic resource mutex cleanup control"
        )

        def fail_unlock(actual_descriptor, operation):
            if (
                actual_descriptor == descriptor
                and operation == leases_module.fcntl.LOCK_UN
            ):
                raise OSError("synthetic mutex unlock failure")
            return real_flock(actual_descriptor, operation)

        def interrupt_close(actual_descriptor):
            if actual_descriptor == descriptor:
                raise interruption
            return real_close(actual_descriptor)

        try:
            with (
                mock.patch.object(
                    leases_module.fcntl,
                    "flock",
                    side_effect=fail_unlock,
                ),
                mock.patch.object(
                    leases_module.os,
                    "close",
                    side_effect=interrupt_close,
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                handle.release()
            self.assertIs(raised.exception, interruption)
        finally:
            real_flock(descriptor, leases_module.fcntl.LOCK_UN)
            real_close(descriptor)

    def test_atomic_bundle_waits_instead_of_fragmenting(self) -> None:
        first = self.broker.acquire(
            ResourceVector(cpu=3, memory_mib=4096),
            timeout=0,
        )
        self.assertIsNotNone(first)
        blocked = self.broker.acquire(
            ResourceVector(cpu=2, memory_mib=4096),
            timeout=0.02,
        )
        self.assertIsNone(blocked)
        assert first is not None
        first.release()

        complete = self.broker.acquire(
            ResourceVector(cpu=2, memory_mib=4096),
            timeout=0,
        )
        self.assertIsNotNone(complete)
        assert complete is not None
        self.assertFalse(complete.partial)
        complete.release()

    def test_atomic_json_retries_partial_write_to_complete_canonical(
        self,
    ) -> None:
        root = self.root / "partial-write"
        real_write = leases_module.os.write
        shortened = False

        def write_partial_once(descriptor, payload):
            nonlocal shortened
            if not shortened and len(payload) > 2:
                shortened = True
                partial = memoryview(payload)[: len(payload) // 2]
                return real_write(descriptor, partial)
            return real_write(descriptor, payload)

        with mock.patch.object(
            leases_module.os,
            "write",
            side_effect=write_partial_once,
        ):
            broker = LeaseBroker(
                root,
                self.limits,
                poll_interval=0.01,
            )

        self.assertTrue(shortened)
        capacity = LeaseBroker._load_json(root / "capacity.json")
        self.assertEqual(
            ResourceVector.from_mapping(capacity["capacity"]),
            self.limits.as_vector(),
        )
        self.assertEqual(
            list(root.glob(".capacity.json.tmp.*")),
            [],
        )
        restarted = LeaseBroker(
            root,
            self.limits,
            poll_interval=0.01,
        )
        self.assertEqual(restarted.status().capacity, self.limits.as_vector())

    def test_atomic_json_never_recloses_same_inode_peer_descriptor(
        self,
    ) -> None:
        target = self.root / "atomic-close-target.json"
        real_close = leases_module.os.close

        for index, interruption in enumerate(
            (
                KeyboardInterrupt(
                    "synthetic resource JSON normal close interrupt"
                ),
                SystemExit(53),
            ),
            start=1,
        ):
            with self.subTest(interruption=type(interruption).__name__):
                close_calls: list[int] = []
                peer_descriptor: int | None = None
                peer_identity: tuple[int, int] | None = None

                def close_then_reopen_same_inode(
                    descriptor: int,
                ) -> None:
                    nonlocal peer_descriptor, peer_identity
                    close_calls.append(descriptor)
                    if peer_descriptor is None:
                        opened = leases_module.os.fstat(descriptor)
                        peer_identity = (opened.st_dev, opened.st_ino)
                        descriptor_path = Path(
                            leases_module.os.readlink(
                                f"/proc/self/fd/{descriptor}"
                            )
                        )
                        real_close(descriptor)
                        replacement = leases_module.os.open(
                            descriptor_path,
                            leases_module.os.O_RDONLY
                            | leases_module.os.O_CLOEXEC,
                        )
                        if replacement != descriptor:
                            leases_module.os.dup2(
                                replacement,
                                descriptor,
                                inheritable=False,
                            )
                            real_close(replacement)
                        peer_descriptor = descriptor
                        reopened = leases_module.os.fstat(descriptor)
                        self.assertEqual(
                            (reopened.st_dev, reopened.st_ino),
                            peer_identity,
                        )
                        raise interruption
                    real_close(descriptor)

                try:
                    with (
                        mock.patch.object(
                            leases_module.os,
                            "close",
                            side_effect=close_then_reopen_same_inode,
                        ),
                        self.assertRaises(
                            type(interruption)
                        ) as raised,
                    ):
                        LeaseBroker._atomic_json(
                            target,
                            {"attempt": index},
                        )
                    self.assertIs(raised.exception, interruption)
                    self.assertIsNotNone(peer_descriptor)
                    assert peer_descriptor is not None
                    assert peer_identity is not None
                    self.assertEqual(close_calls, [peer_descriptor])
                    peer = leases_module.os.fstat(peer_descriptor)
                    self.assertEqual(
                        (peer.st_dev, peer.st_ino),
                        peer_identity,
                    )
                finally:
                    if peer_descriptor is not None:
                        try:
                            real_close(peer_descriptor)
                        except OSError:
                            pass

                self.assertEqual(
                    list(self.root.glob(".atomic-close-target.json.tmp.*")),
                    [],
                )

                LeaseBroker._atomic_json(target, {"attempt": index})
                self.assertEqual(
                    leases_module.json.loads(
                        target.read_text(encoding="utf-8")
                    ),
                    {"attempt": index},
                )

    def test_atomic_json_zero_write_preserves_canonical_and_cleans_temp(
        self,
    ) -> None:
        capacity_path = self.root / "capacity.json"
        before = capacity_path.read_bytes()

        with (
            mock.patch.object(
                leases_module.os,
                "write",
                return_value=0,
            ),
            self.assertRaisesRegex(
                OSError,
                "resource JSON write made no progress",
            ),
        ):
            self.broker._atomic_json(
                capacity_path,
                {
                    "schema_version": 1,
                    "capacity": ResourceVector(cpu=99).as_dict(),
                },
            )

        self.assertEqual(capacity_path.read_bytes(), before)
        self.assertEqual(
            list(self.root.glob(".capacity.json.tmp.*")),
            [],
        )
        restarted = LeaseBroker(
            self.root,
            self.limits,
            poll_interval=0.01,
        )
        self.assertEqual(restarted.status().capacity, self.limits.as_vector())

    def test_short_read_preserves_live_tickets_and_fifo_order(self) -> None:
        first_ticket = f"ticket-{'0' * 32}"
        second_ticket = f"ticket-{'1' * 32}"
        mutex = self.broker._lock_mutex()
        try:
            with mock.patch.object(
                leases_module.time,
                "time_ns",
                side_effect=(100, 200),
            ):
                self.broker._create_ticket_locked(
                    first_ticket,
                    ResourceVector(cpu=1),
                    "first",
                )
                self.broker._create_ticket_locked(
                    second_ticket,
                    ResourceVector(cpu=1),
                    "second",
                )

            real_read = leases_module.os.read
            shortened = False

            def read_half_once(descriptor, requested):
                nonlocal shortened
                if not shortened:
                    shortened = True
                    half_size = max(1, os.fstat(descriptor).st_size // 2)
                    return real_read(descriptor, min(requested, half_size))
                return real_read(descriptor, requested)

            with mock.patch.object(
                leases_module.os,
                "read",
                side_effect=read_half_once,
            ):
                tickets = self.broker._load_tickets_locked()
        finally:
            self.broker._unlock_close(mutex)

        self.assertTrue(shortened)
        self.assertEqual(
            [ticket["ticket_id"] for ticket in tickets],
            [first_ticket, second_ticket],
        )
        self.assertTrue(self.broker._ticket_path(first_ticket).exists())
        self.assertTrue(self.broker._ticket_path(second_ticket).exists())

    def test_short_reads_preserve_capacity_and_live_lease_metadata(
        self,
    ) -> None:
        lease = self.broker.acquire("cpu", 1, timeout=0, owner="live")
        self.assertIsNotNone(lease)
        assert lease is not None

        real_read = leases_module.os.read

        def read_half_once():
            shortened = False

            def partial_read(descriptor, requested):
                nonlocal shortened
                if not shortened:
                    shortened = True
                    half_size = max(1, os.fstat(descriptor).st_size // 2)
                    return real_read(descriptor, min(requested, half_size))
                return real_read(descriptor, requested)

            return partial_read

        with mock.patch.object(
            leases_module.os,
            "read",
            side_effect=read_half_once(),
        ):
            restarted = LeaseBroker(
                self.root,
                self.limits,
                poll_interval=0.01,
            )
        self.assertEqual(restarted.capacity, self.limits.as_vector())

        with mock.patch.object(
            leases_module.os,
            "read",
            side_effect=read_half_once(),
        ):
            status = restarted.status()
        self.assertEqual(
            [record.lease_id for record in status.leases],
            [lease.lease_id],
        )
        self.assertEqual(status.used.cpu, 1)
        lease.release()

    def test_truncated_ticket_remains_malformed_and_is_removed(self) -> None:
        ticket_id = f"ticket-{'2' * 32}"
        mutex = self.broker._lock_mutex()
        try:
            self.broker._create_ticket_locked(
                ticket_id,
                ResourceVector(cpu=1),
                "truncated",
            )
            path = self.broker._ticket_path(ticket_id)
            payload = path.read_bytes()
            path.write_bytes(payload[: len(payload) // 2])

            self.assertEqual(self.broker._load_tickets_locked(), [])
            self.assertFalse(path.exists())
        finally:
            self.broker._unlock_close(mutex)

    def test_waiter_obtains_resource_after_release(self) -> None:
        held = self.broker.acquire("gpu", 1, timeout=0)
        self.assertIsNotNone(held)
        acquired: list[object] = []

        def wait() -> None:
            acquired.append(
                self.broker.acquire("gpu", 1, timeout=1, owner="waiter")
            )

        thread = threading.Thread(target=wait)
        thread.start()
        deadline = time.monotonic() + 1
        while self.broker.status().queued == 0 and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertEqual(self.broker.status().queued, 1)
        assert held is not None
        held.release()
        thread.join(timeout=1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(acquired), 1)
        self.assertIsNotNone(acquired[0])
        acquired[0].release()

    def test_ticket_post_persist_interrupt_cleans_and_next_acquires(
        self,
    ) -> None:
        real_atomic_json = self.broker._atomic_json
        interruption = KeyboardInterrupt(
            "synthetic resource ticket persistence interrupt"
        )
        injected = False

        def write_then_interrupt(path, value):
            nonlocal injected
            real_atomic_json(path, value)
            if not injected and path.parent.name == "queue":
                injected = True
                raise interruption

        with (
            mock.patch.object(
                self.broker,
                "_atomic_json",
                side_effect=write_then_interrupt,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            self.broker.acquire("cpu", 1, timeout=0)

        self.assertIs(raised.exception, interruption)
        self.assertEqual(self.broker.status().queued, 0)
        lease = self.broker.acquire("cpu", 1, timeout=0)
        self.assertIsNotNone(lease)
        assert lease is not None
        lease.release()

    def test_ticket_pre_replace_interrupt_removes_exact_temporary(
        self,
    ) -> None:
        interruption = KeyboardInterrupt(
            "synthetic resource ticket pre-replace interrupt"
        )

        with (
            mock.patch.object(
                leases_module.os,
                "replace",
                side_effect=interruption,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            self.broker.acquire("cpu", 1, timeout=0)

        self.assertIs(raised.exception, interruption)
        self.assertEqual(list(self.root.rglob(".*.tmp.*")), [])
        status = self.broker.status()
        self.assertEqual(status.queued, 0)
        self.assertEqual(status.used.cpu, 0)
        lease = self.broker.acquire("cpu", 1, timeout=0)
        self.assertIsNotNone(lease)
        assert lease is not None
        lease.release()

    def test_post_allocation_interrupt_releases_exact_pending_lease(
        self,
    ) -> None:
        real_allocate = self.broker._allocate_locked
        interruption = KeyboardInterrupt(
            "synthetic post-allocation handoff interrupt"
        )

        def allocate_then_interrupt(*args, **kwargs):
            real_allocate(*args, **kwargs)
            raise interruption

        with (
            mock.patch.object(
                self.broker,
                "_allocate_locked",
                side_effect=allocate_then_interrupt,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            self.broker.acquire("cpu", 1, timeout=0)

        self.assertIs(raised.exception, interruption)
        status = self.broker.status()
        self.assertEqual(status.queued, 0)
        self.assertEqual(status.used.cpu, 0)
        self.assertEqual(status.leases, ())
        lease = self.broker.acquire("cpu", 1, timeout=0)
        self.assertIsNotNone(lease)
        assert lease is not None
        lease.release()

    def test_allocation_handoff_never_recloses_same_inode_peer_fd(
        self,
    ) -> None:
        real_close = leases_module.os.close

        for interruption in (
            KeyboardInterrupt("synthetic allocation handoff interrupt"),
            SystemExit(44),
        ):
            with self.subTest(interruption=type(interruption).__name__):
                captured_leases: list[object] = []

                class InterruptingHandoff(list):
                    def append(self, value) -> None:
                        super().append(value)
                        captured_leases.append(value)
                        raise interruption

                pending_handoff = InterruptingHandoff()
                peer_descriptor: int | None = None
                contender_descriptor: int | None = None
                target_descriptor: int | None = None
                identity: tuple[int, int] | None = None
                close_calls: list[int] = []
                close_interruption = type(interruption)(
                    "synthetic allocation descriptor close interrupt"
                    if isinstance(interruption, KeyboardInterrupt)
                    else 45
                )

                def close_then_reopen_same_inode(
                    descriptor: int,
                ) -> None:
                    nonlocal peer_descriptor, contender_descriptor
                    nonlocal target_descriptor, identity
                    if captured_leases and target_descriptor is None:
                        target_descriptor = captured_leases[0]._fd
                    if descriptor != target_descriptor:
                        real_close(descriptor)
                        return
                    close_calls.append(descriptor)
                    if peer_descriptor is None:
                        opened = leases_module.os.fstat(descriptor)
                        identity = (opened.st_dev, opened.st_ino)
                        lock_path, _metadata_path = (
                            self.broker._lease_paths(
                                captured_leases[0].lease_id
                            )
                        )
                        real_close(descriptor)
                        replacement = leases_module.os.open(
                            lock_path,
                            leases_module.os.O_RDWR
                            | leases_module.os.O_CLOEXEC,
                        )
                        if replacement != descriptor:
                            leases_module.os.dup2(
                                replacement,
                                descriptor,
                                inheritable=False,
                            )
                            real_close(replacement)
                        peer_descriptor = descriptor
                        leases_module.fcntl.flock(
                            peer_descriptor,
                            leases_module.fcntl.LOCK_EX
                            | leases_module.fcntl.LOCK_NB,
                        )
                        contender_descriptor = leases_module.os.open(
                            lock_path,
                            leases_module.os.O_RDWR
                            | leases_module.os.O_CLOEXEC,
                        )
                        reopened = leases_module.os.fstat(descriptor)
                        self.assertEqual(
                            (reopened.st_dev, reopened.st_ino),
                            identity,
                        )
                        raise close_interruption
                    real_close(descriptor)

                try:
                    with (
                        mock.patch.object(
                            leases_module.os,
                            "close",
                            side_effect=close_then_reopen_same_inode,
                        ),
                        self.assertRaises(
                            type(interruption)
                        ) as raised,
                    ):
                        self.broker._allocate_locked(
                            ResourceVector(cpu=1),
                            ResourceVector(cpu=1),
                            "allocation-handoff-test",
                            pending_handoff=pending_handoff,
                        )

                    self.assertIs(raised.exception, interruption)
                    self.assertEqual(pending_handoff, [])
                    self.assertEqual(len(captured_leases), 1)
                    abandoned_lease = captured_leases[0]
                    self.assertTrue(abandoned_lease.released)
                    assert target_descriptor is not None
                    assert peer_descriptor is not None
                    assert contender_descriptor is not None
                    assert identity is not None
                    self.assertEqual(
                        close_calls,
                        [target_descriptor],
                    )
                    peer = leases_module.os.fstat(peer_descriptor)
                    self.assertEqual(
                        (peer.st_dev, peer.st_ino),
                        identity,
                    )
                    with self.assertRaises(BlockingIOError):
                        leases_module.fcntl.flock(
                            contender_descriptor,
                            leases_module.fcntl.LOCK_EX
                            | leases_module.fcntl.LOCK_NB,
                        )
                    abandoned_lease.__del__()
                    leases_module.os.fstat(peer_descriptor)
                finally:
                    if contender_descriptor is not None:
                        try:
                            real_close(contender_descriptor)
                        except OSError:
                            pass
                    if peer_descriptor is not None:
                        try:
                            leases_module.fcntl.flock(
                                peer_descriptor,
                                leases_module.fcntl.LOCK_UN,
                            )
                        except OSError:
                            pass
                        try:
                            real_close(peer_descriptor)
                        except OSError:
                            pass

                self.assertEqual(self.broker.status().used.cpu, 0)

    def test_lease_constructor_store_interrupt_is_resource_free(
        self,
    ) -> None:
        real_lease_type = leases_module.Lease

        for interruption in (
            KeyboardInterrupt("synthetic lease constructor store interrupt"),
            SystemExit(46),
        ):
            with self.subTest(interruption=type(interruption).__name__):
                release_calls: list[object] = []

                def interrupting_lease_factory(*args, **kwargs):
                    # Raise after construction but before the caller can store
                    # the returned owner, matching the CALL -> STORE window.
                    lease = real_lease_type(*args, **kwargs)
                    raise interruption

                def unexpected_reentrant_release(
                    _broker,
                    lease,
                ) -> None:
                    release_calls.append(lease)

                with (
                    mock.patch.object(
                        leases_module,
                        "Lease",
                        new=interrupting_lease_factory,
                    ),
                    mock.patch.object(
                        LeaseBroker,
                        "release",
                        new=unexpected_reentrant_release,
                    ),
                    self.assertRaises(
                        type(interruption)
                    ) as raised,
                ):
                    self.broker._with_mutex(
                        lambda: self.broker._allocate_locked(
                            ResourceVector(cpu=1),
                            ResourceVector(cpu=1),
                            "constructor-store-test",
                        )
                    )

                self.assertIs(raised.exception, interruption)
                self.assertEqual(release_calls, [])
                self.assertEqual(self.broker.status().used.cpu, 0)
                self.assertEqual(
                    list(self.broker._leases_dir.iterdir()),
                    [],
                )

    def test_late_ticket_cleanup_interrupt_retries_and_releases_lease(
        self,
    ) -> None:
        real_unlink = Path.unlink
        interruption = KeyboardInterrupt(
            "synthetic late resource ticket cleanup interrupt"
        )
        ticket_unlinks = 0

        def interrupt_second_ticket_unlink(path, *args, **kwargs):
            nonlocal ticket_unlinks
            if (
                path.parent == self.broker._queue_dir
                and path.name.startswith("ticket-")
            ):
                ticket_unlinks += 1
                if ticket_unlinks == 2:
                    raise interruption
            return real_unlink(path, *args, **kwargs)

        with (
            mock.patch.object(
                Path,
                "unlink",
                new=interrupt_second_ticket_unlink,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            self.broker.acquire("cpu", 1, timeout=0)

        self.assertIs(raised.exception, interruption)
        self.assertGreaterEqual(ticket_unlinks, 3)
        status = self.broker.status()
        self.assertEqual(status.queued, 0)
        self.assertEqual(status.used.cpu, 0)
        self.assertEqual(status.leases, ())
        lease = self.broker.acquire("cpu", 1, timeout=0)
        self.assertIsNotNone(lease)
        assert lease is not None
        lease.release()

    def test_late_ticket_cleanup_transient_error_is_retried(
        self,
    ) -> None:
        real_unlink = Path.unlink
        ticket_unlinks = 0

        def fail_second_ticket_unlink_once(path, *args, **kwargs):
            nonlocal ticket_unlinks
            if (
                path.parent == self.broker._queue_dir
                and path.name.startswith("ticket-")
            ):
                ticket_unlinks += 1
                if ticket_unlinks == 2:
                    raise OSError("synthetic transient ticket cleanup error")
            return real_unlink(path, *args, **kwargs)

        with mock.patch.object(
            Path,
            "unlink",
            new=fail_second_ticket_unlink_once,
        ):
            lease = self.broker.acquire("cpu", 1, timeout=0)

        self.assertIsNotNone(lease)
        self.assertGreaterEqual(ticket_unlinks, 3)
        self.assertEqual(self.broker.status().queued, 0)
        self.assertEqual(self.broker.status().used.cpu, 1)
        assert lease is not None
        lease.release()
        self.assertEqual(self.broker.status().used.cpu, 0)

    def test_ticket_cleanup_success_transition_control_releases_lease(
        self,
    ) -> None:
        source_lines, source_start = inspect.getsourcelines(
            LeaseBroker.acquire
        )
        cleanup_success_line = source_start + next(
            offset
            for offset, line in enumerate(source_lines)
            if line.strip() == "cleanup_succeeded = True"
        )

        for interruption in (
            KeyboardInterrupt(
                "synthetic ticket cleanup success transition interrupt"
            ),
            SystemExit(
                "synthetic ticket cleanup success transition exit"
            ),
        ):
            with self.subTest(interruption=type(interruption).__name__):
                injected = False

                def interrupt_after_ticket_retirement(
                    frame,
                    event,
                    _argument,
                ):
                    nonlocal injected
                    if (
                        frame.f_code is LeaseBroker.acquire.__code__
                        and event == "line"
                        and frame.f_lineno == cleanup_success_line
                        and frame.f_locals.get("pending_leases")
                        and not injected
                    ):
                        injected = True
                        sys.settrace(None)
                        raise interruption
                    return interrupt_after_ticket_retirement

                previous_trace = sys.gettrace()
                try:
                    sys.settrace(interrupt_after_ticket_retirement)
                    with self.assertRaises(
                        type(interruption)
                    ) as raised:
                        self.broker.acquire("cpu", 1, timeout=0)
                finally:
                    sys.settrace(previous_trace)

                self.assertTrue(injected)
                self.assertIs(raised.exception, interruption)
                status = self.broker.status()
                self.assertEqual(status.queued, 0)
                self.assertEqual(status.used.cpu, 0)
                self.assertEqual(status.leases, ())

    def test_public_lease_return_handoff_releases_lost_value(
        self,
    ) -> None:
        real_acquire = self.broker.acquire
        interruption = KeyboardInterrupt(
            "synthetic public lease return handoff interrupt"
        )

        def acquire_then_interrupt():
            lease = real_acquire("cpu", 1, timeout=0)
            self.assertIsNotNone(lease)
            raise interruption

        try:
            acquire_then_interrupt()
        except KeyboardInterrupt as error:
            self.assertIs(error, interruption)
            interruption.__traceback__ = None
        else:
            self.fail("public lease return handoff did not interrupt")
        gc.collect()

        status = self.broker.status()
        self.assertEqual(status.queued, 0)
        self.assertEqual(status.used.cpu, 0)
        self.assertEqual(status.leases, ())
        replacement = self.broker.acquire("cpu", 1, timeout=0)
        self.assertIsNotNone(replacement)
        assert replacement is not None
        replacement.release()

    def test_waiter_mutex_transaction_return_interrupt_cleans_ticket(
        self,
    ) -> None:
        transaction_code = LeaseBroker._with_mutex.__code__

        for interruption in (
            KeyboardInterrupt(
                "synthetic second waiter mutex transaction interrupt"
            ),
            SystemExit(
                "synthetic second waiter mutex transaction exit"
            ),
        ):
            with self.subTest(interruption=type(interruption).__name__):
                held = self.broker.acquire("cpu", 4, timeout=0)
                self.assertIsNotNone(held)
                transaction_returns = 0
                released_handles: list[object] = []

                def interrupt_second_waiter_transaction(
                    frame,
                    event,
                    _argument,
                ):
                    nonlocal transaction_returns
                    operation = frame.f_locals.get("operation")
                    if (
                        frame.f_code is transaction_code
                        and event == "return"
                        and getattr(operation, "__name__", None)
                        == "try_allocate"
                    ):
                        transaction_returns += 1
                        if transaction_returns == 2:
                            released_handles.append(
                                frame.f_locals.get("handle")
                            )
                            sys.settrace(None)
                            raise interruption
                    return interrupt_second_waiter_transaction

                previous_trace = sys.gettrace()
                try:
                    sys.settrace(
                        interrupt_second_waiter_transaction
                    )
                    with self.assertRaises(
                        type(interruption)
                    ) as raised:
                        self.broker.acquire("cpu", 1, timeout=1)
                finally:
                    sys.settrace(previous_trace)

                self.assertIs(raised.exception, interruption)
                interruption.__traceback__ = None
                self.assertEqual(transaction_returns, 2)
                self.assertEqual(len(released_handles), 1)
                self.assertIsNone(released_handles[0]._fd)
                status = self.broker.status()
                self.assertEqual(status.queued, 0)
                self.assertEqual(status.used.cpu, 4)

                assert held is not None
                held.release()
                replacement = self.broker.acquire(
                    "cpu",
                    1,
                    timeout=0,
                )
                self.assertIsNotNone(replacement)
                assert replacement is not None
                replacement.release()

    def test_mutex_owner_constructor_store_interrupt_is_resource_free(
        self,
    ) -> None:
        cases = (
            (
                "_lock_mutex",
                lambda: self.broker._lock_mutex(),
            ),
            (
                "_with_mutex",
                lambda: self.broker._with_mutex(lambda: None),
            ),
        )
        real_close = leases_module.os.close
        real_handle_type = leases_module._MutexHandle

        for label, operation in cases:
            for exception_type in (KeyboardInterrupt, SystemExit):
                interruption = exception_type(
                    "synthetic mutex owner constructor store interrupt"
                )
                with self.subTest(
                    operation=label,
                    interruption=exception_type.__name__,
                ):
                    close_calls: list[int] = []
                    peer_descriptor: int | None = None

                    def close_then_reopen_same_mutex(
                        descriptor: int,
                    ) -> None:
                        nonlocal peer_descriptor
                        try:
                            target = Path(
                                leases_module.os.readlink(
                                    f"/proc/self/fd/{descriptor}"
                                )
                            )
                        except OSError:
                            target = None
                        if target == self.broker._mutex_path:
                            close_calls.append(descriptor)
                            if peer_descriptor is None:
                                real_close(descriptor)
                                replacement = leases_module.os.open(
                                    self.broker._mutex_path,
                                    leases_module.os.O_RDWR
                                    | leases_module.os.O_CLOEXEC,
                                )
                                if replacement != descriptor:
                                    leases_module.os.dup2(
                                        replacement,
                                        descriptor,
                                        inheritable=False,
                                    )
                                    real_close(replacement)
                                peer_descriptor = descriptor
                                leases_module.fcntl.flock(
                                    peer_descriptor,
                                    leases_module.fcntl.LOCK_EX
                                    | leases_module.fcntl.LOCK_NB,
                                )
                                return
                        real_close(descriptor)

                    def interrupting_handle_factory(*args, **kwargs):
                        # Raise after construction but before the caller can
                        # store the returned owner.
                        handle = real_handle_type(*args, **kwargs)
                        raise interruption

                    try:
                        with (
                            mock.patch.object(
                                leases_module,
                                "_MutexHandle",
                                new=interrupting_handle_factory,
                            ),
                            mock.patch.object(
                                leases_module.os,
                                "close",
                                side_effect=close_then_reopen_same_mutex,
                            ),
                            self.assertRaises(
                                exception_type
                            ) as raised,
                        ):
                            operation()
                    finally:
                        if peer_descriptor is not None:
                            try:
                                leases_module.fcntl.flock(
                                    peer_descriptor,
                                    leases_module.fcntl.LOCK_UN,
                                )
                            except OSError:
                                pass
                            try:
                                real_close(peer_descriptor)
                            except OSError:
                                pass

                    self.assertIs(raised.exception, interruption)
                    self.assertEqual(close_calls, [])
                    self.assertIsNone(peer_descriptor)
                    self.assertEqual(self.broker.status().used.cpu, 0)

    def test_mutex_close_interrupt_is_not_retried(
        self,
    ) -> None:
        handle = self.broker._lock_mutex()
        descriptor = handle._fd
        assert descriptor is not None
        real_close = leases_module.os.close
        interruption = KeyboardInterrupt(
            "synthetic resource mutex descriptor close interrupt"
        )
        injected = False

        def interrupt_first_exact_close(actual_descriptor):
            nonlocal injected
            if actual_descriptor == descriptor and not injected:
                injected = True
                raise interruption
            return real_close(actual_descriptor)

        with (
            mock.patch.object(
                leases_module.os,
                "close",
                side_effect=interrupt_first_exact_close,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            handle.release()

        self.assertIs(raised.exception, interruption)
        self.assertIsNone(handle._fd)
        try:
            self.assertTrue(Path(f"/proc/self/fd/{descriptor}").exists())
            status = self.broker.status()
            self.assertEqual(status.queued, 0)
            self.assertEqual(status.used.cpu, 0)
        finally:
            real_close(descriptor)

    def test_mutex_transient_close_error_is_not_retried(
        self,
    ) -> None:
        handle = self.broker._lock_mutex()
        descriptor = handle._fd
        assert descriptor is not None
        real_close = leases_module.os.close
        injected = False

        def fail_first_exact_close(actual_descriptor):
            nonlocal injected
            if actual_descriptor == descriptor and not injected:
                injected = True
                raise OSError("synthetic transient mutex close error")
            return real_close(actual_descriptor)

        with (
            mock.patch.object(
                leases_module.os,
                "close",
                side_effect=fail_first_exact_close,
            ),
            self.assertRaisesRegex(
                OSError,
                "synthetic transient mutex close error",
            ),
        ):
            handle.release()

        self.assertIsNone(handle._fd)
        try:
            self.assertTrue(Path(f"/proc/self/fd/{descriptor}").exists())
            self.assertEqual(self.broker.status().used.cpu, 0)
        finally:
            real_close(descriptor)

    def test_mutex_never_recloses_same_inode_peer_descriptor(
        self,
    ) -> None:
        real_close = leases_module.os.close
        for interruption in (
            KeyboardInterrupt("synthetic same-inode mutex interrupt"),
            SystemExit(63),
        ):
            with self.subTest(interruption=type(interruption).__name__):
                handle = self.broker._lock_mutex()
                descriptor = handle._fd
                assert descriptor is not None
                peer_descriptor: int | None = None
                close_calls: list[int] = []

                def close_then_reopen_mutex(
                    actual_descriptor: int,
                ) -> None:
                    nonlocal peer_descriptor
                    close_calls.append(actual_descriptor)
                    if (
                        actual_descriptor == descriptor
                        and peer_descriptor is None
                    ):
                        real_close(actual_descriptor)
                        replacement = leases_module.os.open(
                            self.broker._mutex_path,
                            leases_module.os.O_RDWR,
                        )
                        if replacement != actual_descriptor:
                            leases_module.os.dup2(
                                replacement,
                                actual_descriptor,
                            )
                            real_close(replacement)
                        peer_descriptor = actual_descriptor
                        leases_module.fcntl.flock(
                            peer_descriptor,
                            leases_module.fcntl.LOCK_EX,
                        )
                        raise interruption
                    real_close(actual_descriptor)

                try:
                    with (
                        mock.patch.object(
                            leases_module.os,
                            "close",
                            side_effect=close_then_reopen_mutex,
                        ),
                        self.assertRaises(
                            type(interruption)
                        ) as raised,
                    ):
                        handle.release()

                    self.assertIs(raised.exception, interruption)
                    self.assertEqual(close_calls, [descriptor])
                    self.assertIsNone(handle._fd)
                    assert peer_descriptor is not None
                    leases_module.os.fstat(peer_descriptor)
                    contender = leases_module.os.open(
                        self.broker._mutex_path,
                        leases_module.os.O_RDWR,
                    )
                    try:
                        with self.assertRaises(BlockingIOError):
                            leases_module.fcntl.flock(
                                contender,
                                leases_module.fcntl.LOCK_EX
                                | leases_module.fcntl.LOCK_NB,
                            )
                    finally:
                        real_close(contender)
                finally:
                    if peer_descriptor is not None:
                        try:
                            leases_module.fcntl.flock(
                                peer_descriptor,
                                leases_module.fcntl.LOCK_UN,
                            )
                        finally:
                            real_close(peer_descriptor)

                self.assertEqual(self.broker.status().used.cpu, 0)

    def test_mutex_normal_close_return_interrupt_cannot_reclose_foreign_fd(
        self,
    ) -> None:
        foreign_path = self.root / "foreign-mutex-normal-close.txt"
        foreign_path.write_text("foreign", encoding="utf-8")
        real_close = leases_module.os.close

        for interruption in (
            KeyboardInterrupt("synthetic mutex normal close interrupt"),
            SystemExit(55),
        ):
            with self.subTest(interruption=type(interruption).__name__):
                handle = self.broker._lock_mutex()
                descriptor = handle._fd
                assert descriptor is not None
                foreign_source = leases_module.os.open(
                    foreign_path,
                    leases_module.os.O_RDONLY,
                )
                self.assertNotEqual(foreign_source, descriptor)
                injected = False
                release_code = type(handle).release.__code__

                def interrupt_after_normal_close(
                    frame,
                    event,
                    _argument,
                ):
                    nonlocal injected
                    if (
                        frame.f_code is release_code
                        and event == "line"
                        and handle._fd is None
                        and not injected
                    ):
                        try:
                            leases_module.os.fstat(descriptor)
                        except OSError as error:
                            if error.errno == leases_module.errno.EBADF:
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
                        handle.release()
                finally:
                    sys.settrace(previous_trace)

                self.assertTrue(injected)
                self.assertIs(raised.exception, interruption)
                self.assertIsNone(handle._fd)
                self.assertEqual(
                    leases_module.os.dup2(
                        foreign_source,
                        descriptor,
                        inheritable=False,
                    ),
                    descriptor,
                )
                try:
                    handle.release()
                    self.assertEqual(
                        leases_module.os.fstat(descriptor).st_ino,
                        leases_module.os.fstat(foreign_source).st_ino,
                    )
                finally:
                    for value in (descriptor, foreign_source):
                        try:
                            real_close(value)
                        except OSError:
                            pass

                status = self.broker.status()
                self.assertEqual(status.queued, 0)
                self.assertEqual(status.used.cpu, 0)

    def test_release_interrupt_finishes_exact_cleanup_and_is_idempotent(
        self,
    ) -> None:
        lease = self.broker.acquire("cpu", 1, timeout=0)
        self.assertIsNotNone(lease)
        assert lease is not None
        lock_path, metadata_path = self.broker._lease_paths(lease.lease_id)
        real_unlink = Path.unlink
        interruption = KeyboardInterrupt(
            "synthetic post-metadata-unlink interrupt"
        )
        injected = False

        def unlink_then_interrupt(path, *args, **kwargs):
            nonlocal injected
            result = real_unlink(path, *args, **kwargs)
            if not injected and path == metadata_path:
                injected = True
                raise interruption
            return result

        with (
            mock.patch.object(Path, "unlink", new=unlink_then_interrupt),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            lease.release()

        self.assertIs(raised.exception, interruption)
        self.assertTrue(lease.released)
        self.assertFalse(lock_path.exists())
        self.assertFalse(metadata_path.exists())
        self.assertEqual(self.broker.status().used.cpu, 0)
        lease.release()
        replacement = self.broker.acquire("cpu", 1, timeout=0)
        self.assertIsNotNone(replacement)
        assert replacement is not None
        replacement.release()

    def test_release_never_recloses_reused_descriptor(self) -> None:
        foreign_path = self.root / "foreign.txt"
        foreign_path.write_text("foreign", encoding="utf-8")

        for interruption in (
            KeyboardInterrupt("synthetic lease close interruption"),
            SystemExit(47),
        ):
            with self.subTest(
                interruption=type(interruption).__name__
            ):
                lease = self.broker.acquire("cpu", 1, timeout=0)
                self.assertIsNotNone(lease)
                assert lease is not None
                descriptor = lease._fd
                real_close = leases_module.os.close
                foreign_descriptor: int | None = None
                close_calls: list[int] = []

                def close_then_reuse(actual_descriptor: int) -> None:
                    nonlocal foreign_descriptor
                    close_calls.append(actual_descriptor)
                    if (
                        actual_descriptor == descriptor
                        and foreign_descriptor is None
                    ):
                        real_close(actual_descriptor)
                        replacement = leases_module.os.open(
                            foreign_path,
                            leases_module.os.O_RDONLY,
                        )
                        if replacement != actual_descriptor:
                            leases_module.os.dup2(
                                replacement,
                                actual_descriptor,
                            )
                            real_close(replacement)
                        foreign_descriptor = actual_descriptor
                        raise interruption
                    real_close(actual_descriptor)

                try:
                    with (
                        mock.patch.object(
                            leases_module.os,
                            "close",
                            side_effect=close_then_reuse,
                        ),
                        self.assertRaises(type(interruption)) as raised,
                    ):
                        lease.release()

                    self.assertIs(raised.exception, interruption)
                    self.assertTrue(lease.released)
                    self.assertEqual(close_calls.count(descriptor), 1)
                    self.assertEqual(foreign_descriptor, descriptor)
                    assert foreign_descriptor is not None
                    self.assertEqual(
                        leases_module.os.read(
                            foreign_descriptor,
                            len("foreign"),
                        ),
                        b"foreign",
                    )
                    # A release that completed descriptor cleanup may still
                    # propagate the original interruption.  The finalizer
                    # must observe `_released` and leave the reused fd alone.
                    lease.__del__()
                    leases_module.os.fstat(foreign_descriptor)
                finally:
                    if foreign_descriptor is not None:
                        try:
                            real_close(foreign_descriptor)
                        except OSError:
                            pass

                self.assertEqual(self.broker.status().used.cpu, 0)
                replacement_lease = self.broker.acquire(
                    "cpu",
                    1,
                    timeout=0,
                )
                self.assertIsNotNone(replacement_lease)
                assert replacement_lease is not None
                replacement_lease.release()

    def test_release_never_recloses_same_inode_peer_descriptor(
        self,
    ) -> None:
        for interruption in (
            KeyboardInterrupt("synthetic same-inode lease close interrupt"),
            SystemExit(48),
        ):
            with self.subTest(
                interruption=type(interruption).__name__
            ):
                lease = self.broker.acquire("cpu", 1, timeout=0)
                self.assertIsNotNone(lease)
                assert lease is not None
                descriptor = lease._fd
                lock_path, _metadata_path = self.broker._lease_paths(
                    lease.lease_id
                )
                opened = leases_module.os.fstat(descriptor)
                identity = (opened.st_dev, opened.st_ino)
                real_close = leases_module.os.close
                peer_descriptor: int | None = None
                contender_descriptor: int | None = None
                close_calls: list[int] = []

                def close_then_reopen_same_inode(
                    actual_descriptor: int,
                ) -> None:
                    nonlocal peer_descriptor, contender_descriptor
                    if actual_descriptor != descriptor:
                        real_close(actual_descriptor)
                        return
                    close_calls.append(actual_descriptor)
                    if peer_descriptor is None:
                        real_close(actual_descriptor)
                        replacement = leases_module.os.open(
                            lock_path,
                            leases_module.os.O_RDWR
                            | leases_module.os.O_CLOEXEC,
                        )
                        if replacement != actual_descriptor:
                            leases_module.os.dup2(
                                replacement,
                                actual_descriptor,
                                inheritable=False,
                            )
                            real_close(replacement)
                        peer_descriptor = actual_descriptor
                        leases_module.fcntl.flock(
                            peer_descriptor,
                            leases_module.fcntl.LOCK_EX
                            | leases_module.fcntl.LOCK_NB,
                        )
                        contender_descriptor = leases_module.os.open(
                            lock_path,
                            leases_module.os.O_RDWR
                            | leases_module.os.O_CLOEXEC,
                        )
                        reopened = leases_module.os.fstat(peer_descriptor)
                        self.assertEqual(
                            (reopened.st_dev, reopened.st_ino),
                            identity,
                        )
                        raise interruption
                    real_close(actual_descriptor)

                try:
                    with (
                        mock.patch.object(
                            leases_module.os,
                            "close",
                            side_effect=close_then_reopen_same_inode,
                        ),
                        self.assertRaises(type(interruption)) as raised,
                    ):
                        lease.release()

                    self.assertIs(raised.exception, interruption)
                    self.assertTrue(lease.released)
                    self.assertEqual(close_calls, [descriptor])
                    assert peer_descriptor is not None
                    assert contender_descriptor is not None
                    peer = leases_module.os.fstat(peer_descriptor)
                    self.assertEqual(
                        (peer.st_dev, peer.st_ino),
                        identity,
                    )
                    with self.assertRaises(BlockingIOError):
                        leases_module.fcntl.flock(
                            contender_descriptor,
                            leases_module.fcntl.LOCK_EX
                            | leases_module.fcntl.LOCK_NB,
                        )
                    lease.__del__()
                    leases_module.os.fstat(peer_descriptor)
                finally:
                    if contender_descriptor is not None:
                        try:
                            real_close(contender_descriptor)
                        except OSError:
                            pass
                    if peer_descriptor is not None:
                        try:
                            leases_module.fcntl.flock(
                                peer_descriptor,
                                leases_module.fcntl.LOCK_UN,
                            )
                        except OSError:
                            pass
                        try:
                            real_close(peer_descriptor)
                        except OSError:
                            pass

                self.assertEqual(self.broker.status().used.cpu, 0)

    def test_lease_normal_close_return_interrupt_keeps_finalizer_safe(
        self,
    ) -> None:
        foreign_path = self.root / "foreign-lease-normal-close.txt"
        foreign_path.write_text("foreign", encoding="utf-8")
        real_close = leases_module.os.close

        for interruption in (
            KeyboardInterrupt("synthetic lease normal close interrupt"),
            SystemExit(57),
        ):
            with self.subTest(interruption=type(interruption).__name__):
                lease = self.broker.acquire("cpu", 1, timeout=0)
                self.assertIsNotNone(lease)
                assert lease is not None
                descriptor = lease._fd
                foreign_source = leases_module.os.open(
                    foreign_path,
                    leases_module.os.O_RDONLY,
                )
                self.assertNotEqual(foreign_source, descriptor)
                injected = False

                def interrupt_after_normal_close(
                    frame,
                    event,
                    _argument,
                ):
                    nonlocal injected
                    if (
                        frame.f_code.co_name == "release_locked"
                        and event == "line"
                        and lease._released
                        and not injected
                    ):
                        try:
                            leases_module.os.fstat(descriptor)
                        except OSError as error:
                            if error.errno == leases_module.errno.EBADF:
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
                        lease.release()
                finally:
                    sys.settrace(previous_trace)

                self.assertTrue(injected)
                self.assertIs(raised.exception, interruption)
                self.assertTrue(lease.released)
                self.assertEqual(
                    leases_module.os.dup2(
                        foreign_source,
                        descriptor,
                        inheritable=False,
                    ),
                    descriptor,
                )
                try:
                    lease.__del__()
                    lease.release()
                    self.assertEqual(
                        leases_module.os.fstat(descriptor).st_ino,
                        leases_module.os.fstat(foreign_source).st_ino,
                    )
                finally:
                    for value in (descriptor, foreign_source):
                        try:
                            real_close(value)
                        except OSError:
                            pass

                status = self.broker.status()
                self.assertEqual(status.used.cpu, 0)
                replacement = self.broker.acquire("cpu", 1, timeout=0)
                self.assertIsNotNone(replacement)
                assert replacement is not None
                replacement.release()

    def test_lease_finalizer_never_closes_a_stale_reused_descriptor(
        self,
    ) -> None:
        lease = self.broker.acquire("cpu", 1, timeout=0)
        self.assertIsNotNone(lease)
        assert lease is not None
        descriptor = lease._fd
        foreign_path = self.root / "foreign-finalizer-identity.txt"
        foreign_path.write_text("foreign", encoding="utf-8")
        foreign_source = leases_module.os.open(
            foreign_path,
            leases_module.os.O_RDONLY,
        )
        real_close = leases_module.os.close
        self.assertNotEqual(foreign_source, descriptor)

        real_close(descriptor)
        self.assertEqual(
            leases_module.os.dup2(
                foreign_source,
                descriptor,
                inheritable=False,
            ),
            descriptor,
        )
        try:
            lease.__del__()
            self.assertTrue(lease.released)
            self.assertEqual(
                leases_module.os.fstat(descriptor).st_ino,
                leases_module.os.fstat(foreign_source).st_ino,
            )
        finally:
            for value in (descriptor, foreign_source):
                try:
                    real_close(value)
                except OSError:
                    pass

        self.assertEqual(self.broker.status().used.cpu, 0)
        replacement = self.broker.acquire("cpu", 1, timeout=0)
        self.assertIsNotNone(replacement)
        assert replacement is not None
        replacement.release()

    def test_mutex_post_flock_interrupt_closes_fd_and_next_operation_works(
        self,
    ) -> None:
        real_flock = leases_module.fcntl.flock

        for interruption in (
            KeyboardInterrupt(
                "synthetic resource mutex post-flock interrupt"
            ),
            SystemExit(
                "synthetic resource mutex post-flock exit"
            ),
        ):
            with self.subTest(interruption=type(interruption).__name__):
                interrupted_descriptors: list[int] = []

                def flock_then_interrupt(fd, operation):
                    result = real_flock(fd, operation)
                    if (
                        not interrupted_descriptors
                        and operation == leases_module.fcntl.LOCK_EX
                    ):
                        interrupted_descriptors.append(fd)
                        raise interruption
                    return result

                with (
                    mock.patch.object(
                        leases_module.fcntl,
                        "flock",
                        side_effect=flock_then_interrupt,
                    ),
                    self.assertRaises(
                        type(interruption)
                    ) as raised,
                ):
                    self.broker.status()

                self.assertIs(raised.exception, interruption)
                interruption.__traceback__ = None
                self.assertEqual(len(interrupted_descriptors), 1)
                self.assertFalse(
                    Path(
                        f"/proc/self/fd/{interrupted_descriptors[0]}"
                    ).exists()
                )
                status = self.broker.status()
                self.assertEqual(status.queued, 0)
                self.assertEqual(status.used.cpu, 0)

    def test_unrelated_resources_do_not_head_of_line_block(self) -> None:
        held_gpu = self.broker.acquire("gpu", 1, timeout=0)
        self.assertIsNotNone(held_gpu)
        waiting: list[object] = []

        thread = threading.Thread(
            target=lambda: waiting.append(
                self.broker.acquire("gpu", 1, timeout=1)
            )
        )
        thread.start()
        deadline = time.monotonic() + 1
        while self.broker.status().queued == 0 and time.monotonic() < deadline:
            time.sleep(0.005)

        cpu = self.broker.acquire("cpu", 1, timeout=0)
        self.assertIsNotNone(cpu)
        assert cpu is not None
        cpu.release()
        assert held_gpu is not None
        held_gpu.release()
        thread.join(timeout=1)
        assert waiting[0] is not None
        waiting[0].release()

    def test_single_kind_can_opt_into_partial_lease(self) -> None:
        lease = self.broker.acquire(
            "network",
            3,
            timeout=0,
            allow_partial=True,
        )
        self.assertIsNotNone(lease)
        assert lease is not None
        self.assertTrue(lease.partial)
        self.assertEqual(lease.resources.network, 2)
        lease.release()

    def test_process_exit_releases_flock_lease(self) -> None:
        child_root = self.root / "child"
        ready = multiprocessing.Event()
        process = multiprocessing.Process(
            target=_acquire_then_exit,
            args=(str(child_root), ready),
        )
        process.start()
        self.assertTrue(ready.wait(timeout=2))
        process.join(timeout=2)
        self.assertEqual(process.exitcode, 0)

        broker = LeaseBroker(
            child_root,
            ResourceLimits(cpu=1, memory_mib=1, gpu=0, kvm=0, network=0),
        )
        self.assertEqual(broker.status().used.cpu, 0)
        lease = broker.acquire("cpu", 1, timeout=0)
        self.assertIsNotNone(lease)
        assert lease is not None
        lease.release()

    def test_foreign_broker_cannot_release_lease_object(self) -> None:
        lease = self.broker.acquire("cpu", 1, timeout=0)
        self.assertIsNotNone(lease)
        other = LeaseBroker(self.root / "other", self.limits)
        with self.assertRaises(LeaseOwnershipError):
            other.release(lease)
        assert lease is not None
        lease.release()

    def test_same_root_rejects_a_different_capacity(self) -> None:
        with self.assertRaisesRegex(LeaseError, "capacity differs"):
            LeaseBroker(
                self.root,
                ResourceLimits(
                    cpu=3,
                    memory_mib=8192,
                    gpu=1,
                    kvm=1,
                    network=2,
                ),
            )

    def test_profiles_are_tool_resources_not_model_roles(self) -> None:
        profile = tool_profile("gpu", needs_kvm=True, network=True)
        self.assertEqual(profile.gpu, 1)
        self.assertEqual(profile.kvm, 1)
        self.assertEqual(profile.network, 1)
        self.assertNotIn("worker", profile.as_dict())


if __name__ == "__main__":
    unittest.main()
