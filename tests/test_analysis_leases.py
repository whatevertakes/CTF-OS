from __future__ import annotations

import copy
import gc
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import ctf_os.analysis_leases as analysis_leases
from ctf_os.analysis_leases import (
    AnalysisLeaseBusy,
    AnalysisLeaseError,
    AnalysisLeaseManager,
)
from ctf_os.models import (
    ChallengeIdentity,
    SessionMode,
    SessionStatus,
    SolveSession,
    utc_now,
)
from ctf_os.storage import StorageQuotaError, storage_inventory
from ctf_os.store import ChallengeLock, StateStore


class AnalysisLeaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.store = StateStore(self.root)
        self.identity = ChallengeIdentity("contest", "rev", "analysis")
        self.store.create_challenge(self.identity, schema_version=2)
        self.scope = "a" * 64

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def manager(self, **kwargs: object) -> AnalysisLeaseManager:
        arguments: dict[str, object] = {
            "scope_fingerprint": self.scope,
            "quota_bytes": 64 * 1024 * 1024,
            "max_scan_bytes": 64 * 1024 * 1024,
        }
        arguments.update(kwargs)
        return AnalysisLeaseManager(
            self.store,
            self.identity,
            **arguments,
        )

    @staticmethod
    def background_record() -> dict[str, object]:
        return {
            "schema_version": 2,
            "supervisor_id": "bg-" + "1" * 32,
            "job_id": "job-00000001",
            "scope_fingerprint": "2" * 64,
            "runtime_id": "ctfos-job",
            "status": "running",
            "command": ["true"],
            "name": None,
            "resource_class": "light",
            "resource_request": {
                "cpu": 1,
                "memory_mib": 2048,
                "gpu": 0,
                "kvm": 0,
                "network": 0,
            },
            "network_target": None,
            "intent_created_at": utc_now(),
            "work_tree_limit_bytes": 4096,
            "storage_reservation_bytes": 4096,
            "exit_code": None,
            "reason_code": None,
            "timed_out": False,
            "cancelled": False,
            "started_at": utc_now(),
            "finished_at": None,
            "observed_at": utc_now(),
        }

    def test_normal_finalize_releases_only_after_tree_absence(self) -> None:
        manager = self.manager()
        self.assertEqual(manager.prepare_root(), manager.analysis_root)
        lease = manager.acquire(reservation_bytes=8192)
        record = self.store.load(self.identity).extra["analysis_leases"][0]
        self.assertEqual(record["status"], "running")
        self.assertEqual(record["storage_reservation_bytes"], 8192)
        self.assertEqual(record["work_device"], lease._work_tree.device)
        self.assertTrue(lease.work_dir.is_dir())
        inventory = storage_inventory(
            self.store,
            self.identity,
            quota_bytes=64 * 1024 * 1024,
            max_scan_bytes=64 * 1024 * 1024,
        )
        self.assertEqual(
            inventory["quota"]["active_reservation_bytes"], 8192
        )

        state = lease.finalize()

        record = state.extra["analysis_leases"][0]
        self.assertEqual(record["status"], "completed")
        self.assertEqual(record["storage_reservation_bytes"], 0)
        self.assertFalse(lease.root.exists())
        self.assertFalse(
            (manager.lock_root / f"{lease.ref.analysis_id}.lock").exists()
        )

    def test_prepare_root_never_mutates_while_writer_owns_session(self) -> None:
        manager = self.manager()
        paths = self.store.challenge_paths(self.identity)
        writer = ChallengeLock(
            paths.runtime / "session.lock",
            timeout=0,
        ).acquire()
        try:
            with self.assertRaisesRegex(
                AnalysisLeaseBusy,
                "workspace writer",
            ):
                manager.prepare_root()
            self.assertFalse(manager.analysis_root.exists())
            self.assertFalse(manager.lock_root.exists())
            self.assertFalse(
                (paths.runtime / analysis_leases.ANALYSIS_ADMISSION_LOCK)
                .exists()
            )
        finally:
            writer.release()

        self.assertEqual(manager.prepare_root(), manager.analysis_root)
        self.assertTrue(manager.analysis_root.is_dir())
        self.assertTrue(manager.lock_root.is_dir())

    def test_lost_return_finalizer_cleans_unbound_lease_exactly(self) -> None:
        manager = self.manager()

        # Deliberately discard the public return.  This models a control
        # exception between CALL and the caller's STORE without retaining a
        # second reference that would hide a leaked owner flock.
        manager.acquire(reservation_bytes=8192)
        gc.collect()

        state = self.store.load(self.identity)
        records = state.extra["analysis_leases"]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["status"], "failed")
        self.assertEqual(records[0]["reason_code"], "analysis_handoff_lost")
        self.assertEqual(records[0]["storage_reservation_bytes"], 0)
        self.assertEqual(list(manager.analysis_root.iterdir()), [])
        self.assertEqual(list(manager.lock_root.iterdir()), [])
        report = manager.recover()
        self.assertEqual(report.recovered, ())
        self.assertEqual(report.live, ())
        self.assertEqual(report.cleanup_pending, ())

    def test_owner_lock_lost_return_releases_flock_once(self) -> None:
        manager = self.manager()
        manager.prepare_root()
        lock_path = manager.lock_root / (
            "analysis-" + "e" * 32 + ".lock"
        )

        analysis_leases._OwnerLock.acquire(lock_path, blocking=False)
        gc.collect()

        probe = analysis_leases._OwnerLock.acquire(
            lock_path,
            blocking=False,
        )
        probe.release()

    def test_constructor_interrupt_persists_recoverable_handoff(
        self,
    ) -> None:
        manager = self.manager()
        interruption = KeyboardInterrupt(
            "synthetic analysis lease constructor interruption"
        )

        with (
            mock.patch.object(
                analysis_leases,
                "AnalysisLease",
                side_effect=interruption,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            manager.acquire(reservation_bytes=8192)
        self.assertIs(raised.exception, interruption)
        interruption.__traceback__ = None

        state = self.store.load(self.identity)
        records = state.extra["analysis_leases"]
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["status"], "cleanup_pending")
        self.assertEqual(
            record["reason_code"],
            "analysis_acquire_handoff_failed",
        )
        self.assertEqual(record["storage_reservation_bytes"], 8192)
        lease_root = manager.analysis_root / record["analysis_id"]
        self.assertTrue(lease_root.is_dir())

        report = manager.recover()
        self.assertEqual(report.recovered, (record["analysis_id"],))
        recovered = self.store.load(self.identity).extra[
            "analysis_leases"
        ][0]
        self.assertEqual(recovered["status"], "recovered")
        self.assertEqual(recovered["storage_reservation_bytes"], 0)
        self.assertFalse(lease_root.exists())
        self.assertFalse(
            (manager.lock_root / f"{record['analysis_id']}.lock").exists()
        )

    def test_reservation_commit_return_interrupt_reconciles_canonical_state(
        self,
    ) -> None:
        manager = self.manager()
        interruption = KeyboardInterrupt(
            "synthetic post-replacement reservation interruption"
        )
        real_update = self.store.update
        injected = False

        def update_then_interrupt(*args, **kwargs):
            nonlocal injected
            mutator = (
                args[1]
                if len(args) > 1
                else kwargs.get("mutator")
            )
            result = real_update(*args, **kwargs)
            if (
                not injected
                and getattr(mutator, "__name__", "") == "reserve"
            ):
                injected = True
                raise interruption
            return result

        with (
            mock.patch.object(
                self.store,
                "update",
                side_effect=update_then_interrupt,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            manager.acquire(reservation_bytes=8192)
        self.assertIs(raised.exception, interruption)
        interruption.__traceback__ = None
        self.assertTrue(injected)

        state = self.store.load(self.identity)
        record = state.extra["analysis_leases"][0]
        self.assertEqual(record["status"], "cleanup_pending")
        self.assertEqual(
            record["reason_code"],
            "analysis_acquire_handoff_failed",
        )
        self.assertEqual(record["storage_reservation_bytes"], 8192)
        lease_root = manager.analysis_root / record["analysis_id"]
        self.assertTrue(lease_root.is_dir())

        report = manager.recover()
        self.assertEqual(report.recovered, (record["analysis_id"],))
        recovered = self.store.load(self.identity).extra[
            "analysis_leases"
        ][0]
        self.assertEqual(recovered["status"], "recovered")
        self.assertEqual(recovered["storage_reservation_bytes"], 0)
        self.assertFalse(lease_root.exists())

    def test_post_mkdir_control_interrupt_cleans_exact_precommit_tree(
        self,
    ) -> None:
        for target in ("root", "work"):
            with self.subTest(target=target):
                manager = self.manager()
                interruption = KeyboardInterrupt(
                    f"synthetic post-{target}-mkdir interruption"
                )
                real_mkdir = os.mkdir
                injected = False

                def mkdir_then_interrupt(path, mode=0o777, *, dir_fd=None):
                    nonlocal injected
                    result = real_mkdir(path, mode, dir_fd=dir_fd)
                    is_target = (
                        target == "root"
                        and type(path) is str
                        and analysis_leases.ANALYSIS_ID.fullmatch(path)
                        is not None
                    ) or (target == "work" and path == "work")
                    if not injected and is_target:
                        injected = True
                        raise interruption
                    return result

                with (
                    mock.patch.object(
                        analysis_leases.os,
                        "mkdir",
                        side_effect=mkdir_then_interrupt,
                    ),
                    self.assertRaises(KeyboardInterrupt) as raised,
                ):
                    manager.acquire(reservation_bytes=8192)
                self.assertIs(raised.exception, interruption)
                interruption.__traceback__ = None
                self.assertTrue(injected)

                state = self.store.load(self.identity)
                self.assertEqual(
                    state.extra.get("analysis_leases", []),
                    [],
                )
                self.assertEqual(list(manager.analysis_root.iterdir()), [])
                self.assertEqual(list(manager.lock_root.iterdir()), [])
                report = manager.recover()
                self.assertEqual(report.recovered, ())
                self.assertEqual(report.live, ())
                self.assertEqual(report.cleanup_pending, ())

    def test_post_identity_publish_interrupt_uses_pending_descriptor(
        self,
    ) -> None:
        manager = self.manager()
        interruption = KeyboardInterrupt(
            "synthetic post-identity-publish interruption"
        )
        real_publish = analysis_leases._PendingAnalysisTree._publish_entry
        injected = False

        def publish_then_interrupt(pending, **kwargs):
            nonlocal injected
            result = real_publish(pending, **kwargs)
            if (
                not injected
                and kwargs["reference_attribute"] == "_root_reference"
            ):
                injected = True
                raise interruption
            return result

        with (
            mock.patch.object(
                analysis_leases._PendingAnalysisTree,
                "_publish_entry",
                autospec=True,
                side_effect=publish_then_interrupt,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            manager.acquire(reservation_bytes=8192)
        self.assertIs(raised.exception, interruption)
        interruption.__traceback__ = None
        self.assertTrue(injected)
        self.assertEqual(
            self.store.load(self.identity).extra.get(
                "analysis_leases", []
            ),
            [],
        )
        self.assertEqual(list(manager.analysis_root.iterdir()), [])
        self.assertEqual(list(manager.lock_root.iterdir()), [])

    def test_precommit_path_substitution_is_never_deleted_by_restat(
        self,
    ) -> None:
        manager = self.manager()
        interruption = KeyboardInterrupt(
            "synthetic post-root-substitution interruption"
        )
        real_create_root = analysis_leases._PendingAnalysisTree.create_root
        displaced: Path | None = None
        replacement: Path | None = None

        def create_then_substitute(pending):
            nonlocal displaced, replacement
            real_create_root(pending)
            replacement = pending.root_path
            displaced = pending.root_path.with_name(
                pending.analysis_id + ".displaced"
            )
            pending.root_path.rename(displaced)
            pending.root_path.mkdir(mode=0o700)
            raise interruption

        with (
            mock.patch.object(
                analysis_leases._PendingAnalysisTree,
                "create_root",
                autospec=True,
                side_effect=create_then_substitute,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            manager.acquire(reservation_bytes=8192)
        self.assertIs(raised.exception, interruption)
        interruption.__traceback__ = None
        assert displaced is not None
        assert replacement is not None
        self.assertTrue(displaced.is_dir())
        self.assertTrue(replacement.is_dir())
        self.assertNotEqual(
            displaced.stat().st_ino,
            replacement.stat().st_ino,
        )
        self.assertEqual(
            self.store.load(self.identity).extra.get(
                "analysis_leases", []
            ),
            [],
        )

    def test_cleanup_control_exception_outranks_operation_error(self) -> None:
        manager = self.manager()
        interruption = SystemExit(73)
        real_close = analysis_leases._PendingAnalysisTree.close
        injected = False

        def close_then_interrupt(pending) -> None:
            nonlocal injected
            real_close(pending)
            if not injected:
                injected = True
                raise interruption

        with (
            mock.patch.object(
                analysis_leases,
                "enforce_storage_quota",
                side_effect=AnalysisLeaseError(
                    "synthetic storage admission failure"
                ),
            ),
            mock.patch.object(
                analysis_leases._PendingAnalysisTree,
                "close",
                autospec=True,
                side_effect=close_then_interrupt,
            ),
            self.assertRaises(SystemExit) as raised,
        ):
            manager.acquire(reservation_bytes=8192)
        self.assertIs(raised.exception, interruption)
        interruption.__traceback__ = None
        self.assertTrue(injected)
        self.assertEqual(list(manager.analysis_root.iterdir()), [])
        self.assertEqual(list(manager.lock_root.iterdir()), [])
        self.assertEqual(
            self.store.load(self.identity).extra.get(
                "analysis_leases", []
            ),
            [],
        )

    def test_runtime_cleanup_none_return_is_success(self) -> None:
        calls: list[str] = []

        def cleanup(ref) -> None:
            calls.append(ref.analysis_id)

        manager = self.manager()
        manager.set_runtime_absence_probe(cleanup)
        lease = manager.acquire(reservation_bytes=8192)
        lease.bind_runtime("ctfos-analysis-runtime")
        state = lease.finalize()
        self.assertEqual(calls, [lease.ref.analysis_id])
        self.assertEqual(
            state.extra["analysis_leases"][0]["status"], "completed"
        )

    def test_owner_receipt_descriptor_is_closed_exactly_once(self) -> None:
        manager = self.manager()
        lease = manager.acquire(reservation_bytes=8192)
        owner_path = lease.root / "owner.json"
        with mock.patch.object(
            analysis_leases.os,
            "close",
            wraps=os.close,
        ) as close:
            analysis_leases._read_owner(owner_path)
        self.assertEqual(close.call_count, 1)
        lease.finalize()

    def test_runtime_cleanup_error_retains_tree_and_reservation(self) -> None:
        def cleanup(_ref) -> None:
            raise AnalysisLeaseError("runtime still exists")

        manager = self.manager(runtime_absence_probe=cleanup)
        lease = manager.acquire(reservation_bytes=8192)
        lease.bind_runtime("ctfos-analysis-runtime")
        with self.assertRaisesRegex(
            AnalysisLeaseError, "absence could not be proven"
        ):
            lease.finalize()
        record = self.store.load(self.identity).extra["analysis_leases"][0]
        self.assertEqual(record["status"], "cleanup_pending")
        self.assertEqual(record["storage_reservation_bytes"], 8192)
        self.assertTrue(lease.root.is_dir())

    def test_active_background_and_managed_sessions_fail_closed(self) -> None:
        def add_background(state) -> None:
            state.extra["background_jobs"] = [self.background_record()]

        self.store.update(self.identity, add_background)
        with self.assertRaisesRegex(AnalysisLeaseBusy, "background"):
            self.manager().acquire(reservation_bytes=4096)

        def replace_with_managed(state) -> None:
            state.extra.pop("background_jobs", None)
            session = SolveSession(
                id="S-active",
                mode=SessionMode.MANAGED,
                status=SessionStatus.RUNNING,
                configuration_epoch=state.configuration_epoch,
                start_revision=state.revision,
                started_at=utc_now(),
            )
            state.sessions.append(session)
            state.active_managed_session_id = session.id

        self.store.update(self.identity, replace_with_managed)
        with self.assertRaisesRegex(AnalysisLeaseBusy, "managed"):
            self.manager().acquire(reservation_bytes=4096)

    def test_concurrent_admission_counts_first_active_reservation(self) -> None:
        baseline = storage_inventory(
            self.store,
            self.identity,
            quota_bytes=64 * 1024 * 1024,
            max_scan_bytes=64 * 1024 * 1024,
        )["total_bytes"]
        reservation = 1024 * 1024
        quota = baseline + reservation + reservation // 2
        barrier = threading.Barrier(2)
        successes = []
        failures: list[BaseException] = []

        def admit() -> None:
            manager = self.manager(quota_bytes=quota)
            barrier.wait()
            try:
                successes.append(
                    manager.acquire(reservation_bytes=reservation)
                )
            except BaseException as error:
                failures.append(error)

        threads = [threading.Thread(target=admit) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], StorageQuotaError)
        active = [
            item
            for item in self.store.load(self.identity).extra["analysis_leases"]
            if item["status"] == "running"
        ]
        self.assertEqual(len(active), 1)
        successes[0].finalize()

    def test_interruption_and_dead_process_recovery(self) -> None:
        manager = self.manager()
        lease = manager.acquire(reservation_bytes=8192)
        analysis_id = lease.ref.analysis_id
        lease.abandon()
        report = manager.recover()
        self.assertEqual(report.recovered, (analysis_id,))
        self.assertFalse(lease.root.exists())
        record = self.store.load(self.identity).extra["analysis_leases"][0]
        self.assertEqual(record["status"], "recovered")
        self.assertEqual(record["storage_reservation_bytes"], 0)

        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:  # pragma: no cover - assertions run in parent.
            try:
                os.close(read_fd)
                child_store = StateStore(self.root)
                child_manager = AnalysisLeaseManager(
                    child_store,
                    self.identity,
                    scope_fingerprint=self.scope,
                    quota_bytes=64 * 1024 * 1024,
                    max_scan_bytes=64 * 1024 * 1024,
                )
                child_lease = child_manager.acquire(
                    reservation_bytes=8192
                )
                os.write(write_fd, child_lease.ref.analysis_id.encode("ascii"))
            finally:
                os.close(write_fd)
                os._exit(0)
        os.close(write_fd)
        child_id = os.read(read_fd, 128).decode("ascii")
        os.close(read_fd)
        os.waitpid(pid, 0)
        report = manager.recover()
        self.assertIn(child_id, report.recovered)
        child_record = next(
            item
            for item in self.store.load(self.identity).extra["analysis_leases"]
            if item["analysis_id"] == child_id
        )
        self.assertEqual(child_record["status"], "recovered")

    def test_symlink_fifo_and_internal_hardlinks_are_unlinked_safely(self) -> None:
        manager = self.manager()
        lease = manager.acquire(reservation_bytes=8192)
        external = self.root / "external-target"
        external.write_bytes(b"keep")
        source = lease.work_dir / "source"
        source.write_bytes(b"payload")
        os.link(source, lease.work_dir / "internal-link")
        os.mkfifo(lease.work_dir / "pipe")
        (lease.work_dir / "outside-link").symlink_to(external)

        lease.finalize()

        self.assertEqual(external.read_bytes(), b"keep")
        self.assertFalse(lease.root.exists())

    def test_external_hardlink_and_work_substitution_retain_reservation(
        self,
    ) -> None:
        manager = self.manager()
        lease = manager.acquire(reservation_bytes=8192)
        source = lease.work_dir / "source"
        source.write_bytes(b"payload")
        outside = self.store.challenge_paths(self.identity).runtime / "outside"
        os.link(source, outside)
        with self.assertRaisesRegex(AnalysisLeaseError, "cleanup"):
            lease.finalize()
        record = self.store.load(self.identity).extra["analysis_leases"][-1]
        self.assertEqual(record["status"], "cleanup_pending")
        self.assertEqual(record["storage_reservation_bytes"], 8192)
        self.assertTrue(source.exists())
        outside.unlink()
        manager.recover()

        lease = manager.acquire(reservation_bytes=8192)
        original = lease.work_dir.with_name("original-work")
        lease.work_dir.rename(original)
        lease.work_dir.mkdir(mode=0o700)
        with self.assertRaisesRegex(AnalysisLeaseError, "identity changed"):
            lease.finalize()
        record = self.store.load(self.identity).extra["analysis_leases"][-1]
        self.assertEqual(record["status"], "cleanup_pending")
        self.assertEqual(record["storage_reservation_bytes"], 8192)

    def test_owner_and_lock_external_hardlinks_fail_closed(self) -> None:
        manager = self.manager()
        lease = manager.acquire(reservation_bytes=8192)
        lease.abandon()
        owner = lease.root / "owner.json"
        owner_link = self.root / "owner-external-link"
        os.link(owner, owner_link)
        with self.assertRaisesRegex(AnalysisLeaseError, "owner receipt"):
            manager.recover()
        self.assertTrue(lease.root.is_dir())
        self.assertEqual(
            self.store.load(self.identity).extra["analysis_leases"][0][
                "storage_reservation_bytes"
            ],
            8192,
        )
        owner_link.unlink()

        lock_path = manager.lock_root / f"{lease.ref.analysis_id}.lock"
        lock_link = self.root / "lock-external-link"
        os.link(lock_path, lock_link)
        with self.assertRaisesRegex(AnalysisLeaseError, "owner lock"):
            manager.recover()
        self.assertTrue(lease.root.is_dir())
        lock_link.unlink()
        manager.recover()

    def test_terminal_lock_reconciliation_is_bounded_and_exact(self) -> None:
        manager = self.manager()
        lease = manager.acquire(reservation_bytes=8192)
        analysis_id = lease.ref.analysis_id
        lease.finalize()
        stale = manager.lock_root / f"{analysis_id}.lock"
        stale.touch(mode=0o600)
        unknown = manager.lock_root / ("analysis-" + "f" * 32 + ".lock")
        unknown.touch(mode=0o600)

        manager.recover()

        self.assertFalse(stale.exists())
        self.assertTrue(unknown.exists())

    def test_entry_and_byte_caps_fail_before_first_unlink(self) -> None:
        manager = self.manager(cleanup_max_entries=3)
        lease = manager.acquire(reservation_bytes=8192)
        first = lease.work_dir / "first"
        second = lease.work_dir / "second"
        first.write_bytes(b"1")
        second.write_bytes(b"2")
        with self.assertRaisesRegex(AnalysisLeaseError, "cleanup"):
            lease.finalize()
        self.assertTrue(first.exists())
        self.assertTrue(second.exists())
        self.manager().recover()

        manager = self.manager(cleanup_max_bytes=8)
        lease = manager.acquire(reservation_bytes=8192)
        payload = lease.work_dir / "payload"
        payload.write_bytes(b"x" * 32)
        with self.assertRaisesRegex(AnalysisLeaseError, "cleanup"):
            lease.finalize()
        self.assertEqual(payload.read_bytes(), b"x" * 32)

        self.manager().recover()
        manager = self.manager(cleanup_max_depth=2)
        lease = manager.acquire(reservation_bytes=8192)
        deep = lease.work_dir / "one" / "two"
        deep.mkdir(parents=True)
        (deep / "payload").write_bytes(b"deep")
        with self.assertRaisesRegex(AnalysisLeaseError, "cleanup"):
            lease.finalize()
        self.assertTrue((deep / "payload").exists())

    def test_terminal_pruning_removes_oldest_and_never_active(self) -> None:
        manager = self.manager()
        first = manager.acquire(reservation_bytes=4096)
        first.finalize()
        template = self.store.load(self.identity).extra["analysis_leases"][0]

        def fill(state) -> None:
            records = []
            for index in range(1024):
                record = copy.deepcopy(template)
                record["analysis_id"] = f"analysis-{index:032x}"
                records.append(record)
            state.extra["analysis_leases"] = records

        self.store.update(self.identity, fill)
        lease = manager.acquire(reservation_bytes=4096)
        records = self.store.load(self.identity).extra["analysis_leases"]
        self.assertEqual(len(records), 1024)
        self.assertNotIn("analysis-" + "0" * 32, {
            item["analysis_id"] for item in records
        })
        self.assertIn(lease.ref.analysis_id, {
            item["analysis_id"] for item in records
        })
        lease.finalize()


if __name__ == "__main__":
    unittest.main()
