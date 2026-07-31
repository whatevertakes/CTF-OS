from __future__ import annotations

import copy
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.models import ArtifactReference, ChallengeIdentity
from ctf_os.storage import (
    StorageError,
    StorageQuotaError,
    enforce_storage_quota,
    prepare_quarantine_purge,
    purge_quarantine,
    quarantine_unreachable,
    restore_quarantine,
    storage_inventory,
    storage_plan,
)
from ctf_os.store import ChallengeLock, StateStore, sha256_file
from ctf_os.store.atomic import atomic_write_json, read_json


class StorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.store = StateStore(self.root)
        self.identity = ChallengeIdentity("contest", "rev", "challenge")
        self.store.create_challenge(self.identity)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def orphan(self, relative: str, payload: bytes) -> Path:
        paths = self.store.challenge_paths(self.identity)
        destination = paths.root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
        destination.chmod(0o600)
        return destination

    def gc_control(self, quarantine_id: str) -> Path:
        return (
            self.store.challenge_paths(self.identity).root
            / ".storage-gc"
            / quarantine_id
        )

    @staticmethod
    def background_record(
        *,
        status: str = "running",
        reservation: int = 10,
    ) -> dict[str, object]:
        terminal = status in {
            "completed",
            "failed",
            "timed_out",
            "cancelled",
            "recovered",
        }
        return {
            "schema_version": 2,
            "supervisor_id": "bg-" + "1" * 32,
            "job_id": "job-00000001",
            "scope_fingerprint": "2" * 64,
            "runtime_id": "none",
            "status": status,
            "command": ["true"],
            "name": None,
            "resource_class": "light",
            "resource_request": {
                "cpu": 1,
                "memory_mib": 1,
                "gpu": 0,
                "kvm": 0,
                "network": 0,
            },
            "network_target": None,
            "intent_created_at": "2026-07-31T00:00:00+00:00",
            "work_tree_limit_bytes": 10,
            "storage_reservation_bytes": (
                0 if terminal else reservation
            ),
            "exit_code": 0 if terminal else None,
            "reason_code": None,
            "timed_out": status == "timed_out",
            "cancelled": status == "cancelled",
            "started_at": None,
            "finished_at": None,
            "observed_at": None,
        }

    def test_inventory_uses_one_canonical_state_revision(self) -> None:
        with mock.patch.object(
            self.store,
            "read_snapshot",
            wraps=self.store.read_snapshot,
        ) as read_snapshot:
            report = storage_inventory(self.store, self.identity)

        self.assertEqual(read_snapshot.call_count, 1)
        self.assertEqual(
            report["state_revision"],
            self.store.load(self.identity).revision,
        )

    def test_proof_root_orphans_are_quarantined_but_references_survive(
        self,
    ) -> None:
        paths = self.store.challenge_paths(self.identity)
        kept = paths.proof / "candidate" / "evaluation" / "kept.log"
        kept.parent.mkdir(parents=True)
        kept.write_bytes(b"proof evidence\n")
        kept.chmod(0o400)
        orphan = paths.proof / "abandoned" / "orphan.log"
        orphan.parent.mkdir(parents=True)
        orphan.write_bytes(b"abandoned proof staging\n")
        orphan.chmod(0o400)

        relative_kept = kept.relative_to(paths.root).as_posix()

        def register(state) -> None:
            state.artifacts.append(
                ArtifactReference(
                    id="A-proof-kept",
                    path=relative_kept,
                    sha256=sha256_file(kept),
                    size=kept.stat().st_size,
                )
            )

        self.store.update(self.identity, register)
        plan = storage_plan(self.store, self.identity)
        candidates = {
            item["path"] for item in plan["candidates"]
        }

        self.assertNotIn(relative_kept, candidates)
        self.assertIn(
            orphan.relative_to(paths.root).as_posix(),
            candidates,
        )

        manifest = quarantine_unreachable(
            self.store,
            self.identity,
        )
        self.assertTrue(kept.is_file())
        self.assertFalse(orphan.exists())

        restored = restore_quarantine(
            self.store,
            self.identity,
            manifest["quarantine_id"],
        )
        self.assertIn(
            orphan.relative_to(paths.root).as_posix(),
            restored["restored"],
        )
        self.assertEqual(
            orphan.read_bytes(),
            b"abandoned proof staging\n",
        )

    def test_inventory_accounts_all_storage_classes_and_quota(self) -> None:
        paths = self.store.challenge_paths(self.identity)
        canonical = self.orphan(
            "artifacts/workspace/operator.bin",
            b"canonical",
        )
        noncanonical = self.orphan(
            "runs/abandoned/raw/stdout.bin",
            b"noncanonical",
        )
        proof = self.orphan("proof/orphan.bin", b"proof")

        report = storage_inventory(
            self.store,
            self.identity,
            quota_bytes=1,
        )

        by_path = {item["path"]: item for item in report["files"]}
        self.assertEqual(
            by_path[canonical.relative_to(paths.root).as_posix()][
                "storage_class"
            ],
            "canonical",
        )
        self.assertEqual(
            by_path[noncanonical.relative_to(paths.root).as_posix()][
                "storage_class"
            ],
            "noncanonical",
        )
        self.assertEqual(
            by_path[proof.relative_to(paths.root).as_posix()][
                "storage_class"
            ],
            "noncanonical",
        )
        self.assertTrue(report["scan_complete"])
        self.assertEqual(report["quota"]["status"], "exceeded")
        with self.assertRaises(StorageQuotaError):
            enforce_storage_quota(
                self.store,
                self.identity,
                quota_bytes=1,
            )

        quarantine_unreachable(self.store, self.identity)
        detached = storage_inventory(self.store, self.identity)
        self.assertGreater(detached["roots"]["quarantine"]["bytes"], 0)
        self.assertTrue(
            any(
                item["storage_class"] == "quarantine"
                for item in detached["files"]
            )
        )

    def test_current_context_is_bounded_exempt_but_history_is_accounted(
        self,
    ) -> None:
        paths = self.store.challenge_paths(self.identity)
        before = storage_inventory(self.store, self.identity)
        engine = ChallengeEngine(self.root)
        engine.update_prompt(
            self.identity,
            "operator prompt " + ("x" * 20_000),
        )
        after_prompt = storage_inventory(self.store, self.identity)
        self.assertEqual(after_prompt["total_bytes"], before["total_bytes"])
        self.assertGreater(
            after_prompt["control"]["quota_exempt_bytes"],
            before["control"]["quota_exempt_bytes"],
        )
        self.assertNotIn(
            "context/current.md",
            {item["path"] for item in after_prompt["files"]},
        )
        self.assertEqual(
            after_prompt["quota"]["observed_physical_bytes"],
            after_prompt["total_bytes"]
            + after_prompt["control"]["quota_exempt_bytes"],
        )

        history = paths.context_history / "run.jsonl"
        history.write_bytes(b"immutable model context\n")
        after_history = storage_inventory(self.store, self.identity)
        self.assertEqual(
            after_history["total_bytes"] - after_prompt["total_bytes"],
            history.stat().st_size,
        )

        with paths.current_context.open("r+b") as stream:
            stream.truncate(16 * 1024 * 1024 + 1)
        oversized = storage_inventory(self.store, self.identity)
        self.assertFalse(oversized["scan_complete"])
        self.assertIn(
            "derived_control_file_exceeds_limit",
            {item["code"] for item in oversized["scan"]["issues"]},
        )

    def test_preserved_roots_count_toward_quota_but_never_enter_gc(
        self,
    ) -> None:
        paths = self.store.challenge_paths(self.identity)
        baseline = storage_inventory(self.store, self.identity)
        preserved = {
            "runtime/managed-thread-lanes/lane/work/payload.bin": b"lane",
            "context/history/cycle.md": b"context",
            "knowledge/operator-note.bin": b"knowledge",
            "exports/report.bin": b"export",
        }
        preserved_paths = {
            relative: self.orphan(relative, payload)
            for relative, payload in preserved.items()
        }
        collectable = self.orphan(
            "artifacts/orphan/collectable.bin",
            b"collectable",
        )

        report = storage_inventory(self.store, self.identity)
        indexed = {item["path"]: item for item in report["files"]}
        expected_preserved_bytes = sum(
            len(payload) for payload in preserved.values()
        )
        expected_delta = expected_preserved_bytes + len(b"collectable")
        for relative in preserved:
            self.assertEqual(indexed[relative]["storage_class"], "canonical")
            self.assertTrue(indexed[relative]["reachable"])
            self.assertEqual(
                indexed[relative]["scope"],
                relative.split("/", 1)[0],
            )
        self.assertEqual(
            report["total_bytes"] - baseline["total_bytes"],
            expected_delta,
        )
        self.assertEqual(
            report["totals"]["canonical_bytes"]
            - baseline["totals"]["canonical_bytes"],
            expected_preserved_bytes,
        )
        self.assertEqual(
            sum(report["totals"].values()),
            report["total_bytes"],
        )
        for scope in ("runtime", "context", "knowledge", "exports"):
            self.assertEqual(
                report["roots"][scope]["bytes"]
                - baseline["roots"][scope]["bytes"],
                sum(
                    len(payload)
                    for relative, payload in preserved.items()
                    if relative.startswith(scope + "/")
                ),
            )

        candidates = {
            item["path"]
            for item in storage_plan(
                self.store,
                self.identity,
            )["candidates"]
        }
        self.assertEqual(
            candidates.intersection(preserved),
            set(),
        )
        self.assertIn(
            collectable.relative_to(paths.root).as_posix(),
            candidates,
        )

        manifest = quarantine_unreachable(self.store, self.identity)
        moved = {item["path"] for item in manifest["files"]}
        self.assertIn(
            collectable.relative_to(paths.root).as_posix(),
            moved,
        )
        self.assertEqual(moved.intersection(preserved), set())
        self.assertFalse(collectable.exists())
        self.assertTrue(
            all(path.is_file() for path in preserved_paths.values())
        )

    def test_preserved_root_special_file_makes_quota_indeterminate(
        self,
    ) -> None:
        paths = self.store.challenge_paths(self.identity)
        fifo = paths.runtime / "unexpected.pipe"
        os.mkfifo(fifo)

        report = storage_inventory(
            self.store,
            self.identity,
            quota_bytes=1024,
        )

        self.assertFalse(report["scan_complete"])
        self.assertEqual(report["quota"]["status"], "indeterminate")
        self.assertIn(
            "special_file_forbidden",
            {item["code"] for item in report["scan"]["issues"]},
        )
        with self.assertRaisesRegex(StorageQuotaError, "cannot be proven"):
            enforce_storage_quota(
                self.store,
                self.identity,
                quota_bytes=1024,
            )
        with self.assertRaisesRegex(StorageError, "incomplete"):
            quarantine_unreachable(self.store, self.identity)

    def test_quota_admission_checks_projected_known_write_bytes(self) -> None:
        self.orphan("artifacts/existing.bin", b"12345678")
        observed = storage_inventory(
            self.store,
            self.identity,
        )["total_bytes"]

        admitted = enforce_storage_quota(
            self.store,
            self.identity,
            quota_bytes=observed + 4,
            additional_bytes=4,
        )
        self.assertEqual(
            admitted["quota"]["projected_bytes"],
            observed + 4,
        )
        self.assertEqual(admitted["quota"]["additional_bytes"], 4)

        with self.assertRaisesRegex(
            StorageQuotaError,
            "requested write",
        ):
            enforce_storage_quota(
                self.store,
                self.identity,
                quota_bytes=observed + 4,
                additional_bytes=5,
            )
        for invalid in (-1, True, 1.5):
            with (
                self.subTest(additional_bytes=invalid),
                self.assertRaises(ValueError),
            ):
                enforce_storage_quota(
                    self.store,
                    self.identity,
                    additional_bytes=invalid,
                )

    def test_active_reservations_share_the_inventory_state_snapshot(
        self,
    ) -> None:
        def add_active(state) -> None:
            state.extra["background_jobs"] = [
                self.background_record()
            ]

        self.store.update(self.identity, add_active)
        report = storage_inventory(self.store, self.identity)
        physical = report["total_bytes"]
        self.assertEqual(
            report["quota"]["active_reservation_bytes"],
            10,
        )
        self.assertEqual(
            report["quota"]["conservative_projected_bytes"],
            physical + 10,
        )
        self.assertFalse(report["quota"]["exact"])
        admitted = enforce_storage_quota(
            self.store,
            self.identity,
            quota_bytes=physical + 14,
            additional_bytes=4,
        )
        self.assertEqual(
            admitted["quota"]["requested_bytes"],
            4,
        )
        with self.assertRaisesRegex(
            StorageQuotaError,
            "requested write",
        ):
            enforce_storage_quota(
                self.store,
                self.identity,
                quota_bytes=physical + 14,
                additional_bytes=5,
            )

        def release(state) -> None:
            state.extra["background_jobs"] = [
                self.background_record(status="completed")
            ]

        self.store.update(self.identity, release)
        released = storage_inventory(self.store, self.identity)
        self.assertEqual(
            released["quota"]["active_reservation_bytes"],
            0,
        )
        self.assertTrue(released["quota"]["exact"])

    def test_legacy_active_background_record_fails_admission_closed(
        self,
    ) -> None:
        def add_legacy(state) -> None:
            state.extra["background_jobs"] = [
                {
                    "schema_version": 1,
                    "supervisor_id": "bg-" + "1" * 32,
                    "status": "running",
                }
            ]

        self.store.update(self.identity, add_legacy)
        report = storage_inventory(self.store, self.identity)
        self.assertEqual(report["quota"]["status"], "indeterminate")
        self.assertIn(
            "background_reservation_indeterminate",
            {item["code"] for item in report["scan"]["issues"]},
        )
        with self.assertRaisesRegex(StorageQuotaError, "cannot be proven"):
            enforce_storage_quota(self.store, self.identity)

    def test_scan_rechecks_an_early_closed_subtree(self) -> None:
        self.orphan("artifacts/trigger.bin", b"trigger")
        paths = self.store.challenge_paths(self.identity)
        real_storage_class = __import__(
            "ctf_os.storage",
            fromlist=["_storage_class"],
        )._storage_class
        injected = False

        def inject_after_runs(relative, reachable, prefixes):
            nonlocal injected
            if not injected and relative == "artifacts/trigger.bin":
                injected = True
                late = paths.runs / "late.bin"
                late.write_bytes(b"late")
                late.chmod(0o600)
            return real_storage_class(relative, reachable, prefixes)

        with mock.patch(
            "ctf_os.storage._storage_class",
            side_effect=inject_after_runs,
        ):
            report = storage_inventory(self.store, self.identity)
        self.assertTrue(injected)
        self.assertFalse(report["scan_complete"])
        self.assertIn(
            "directory_changed_during_scan",
            {item["code"] for item in report["scan"]["issues"]},
        )

    def test_quota_admission_retries_only_transient_scan_changes(
        self,
    ) -> None:
        exact = storage_inventory(self.store, self.identity)
        transient = copy.deepcopy(exact)
        transient["scan_complete"] = False
        transient["quota"]["status"] = "indeterminate"
        transient["quota"]["exact"] = False
        transient["scan"]["issues"] = [
            {
                "code": "directory_changed_during_scan",
                "path": "runtime/live-mailboxes",
            }
        ]
        with mock.patch(
            "ctf_os.storage.storage_inventory",
            side_effect=(transient, exact),
        ) as inventory:
            admitted = enforce_storage_quota(
                self.store,
                self.identity,
            )
        self.assertEqual(inventory.call_count, 2)
        self.assertEqual(
            admitted["quota"]["transient_scan_retries_used"],
            1,
        )

        unsafe = copy.deepcopy(transient)
        unsafe["scan"]["issues"] = [
            {
                "code": "special_file_forbidden",
                "path": "runtime/unexpected.pipe",
            }
        ]
        with (
            mock.patch(
                "ctf_os.storage.storage_inventory",
                return_value=unsafe,
            ) as inventory,
            self.assertRaisesRegex(StorageQuotaError, "cannot be proven"),
        ):
            enforce_storage_quota(
                self.store,
                self.identity,
            )
        self.assertEqual(inventory.call_count, 1)

    def test_inventory_bounds_are_fail_closed(self) -> None:
        self.orphan("artifacts/a.bin", b"A" * 8)
        self.orphan("proof/b.bin", b"B" * 8)

        entry_limited = storage_inventory(
            self.store,
            self.identity,
            quota_bytes=1024,
            max_entries=1,
        )
        self.assertFalse(entry_limited["scan_complete"])
        self.assertEqual(entry_limited["quota"]["status"], "indeterminate")
        self.assertIn(
            "entry_limit_exceeded",
            {item["code"] for item in entry_limited["scan"]["issues"]},
        )
        with self.assertRaisesRegex(StorageError, "incomplete"):
            storage_plan(
                self.store,
                self.identity,
                quota_bytes=1024,
                max_entries=1,
            )

        byte_limited = storage_inventory(
            self.store,
            self.identity,
            quota_bytes=1024,
            max_scan_bytes=4,
        )
        self.assertFalse(byte_limited["scan_complete"])
        self.assertEqual(byte_limited["quota"]["status"], "indeterminate")
        self.assertIn(
            "byte_limit_exceeded",
            {item["code"] for item in byte_limited["scan"]["issues"]},
        )

    def test_inventory_never_follows_symlink_fifo_or_hardlink(self) -> None:
        paths = self.store.challenge_paths(self.identity)
        outside = self.root / "outside-secret"
        outside.write_bytes(b"do not read or delete")
        (paths.artifacts / "link").symlink_to(outside)
        os.mkfifo(paths.proof / "pipe")
        hardlink_source = self.orphan("runs/orphan/source.bin", b"hard")
        os.link(hardlink_source, self.root / "outside-hardlink")

        report = storage_inventory(
            self.store,
            self.identity,
            quota_bytes=1024,
        )

        self.assertFalse(report["scan_complete"])
        self.assertEqual(report["quota"]["status"], "indeterminate")
        codes = {item["code"] for item in report["scan"]["issues"]}
        self.assertIn("symlink_forbidden", codes)
        self.assertIn("special_file_forbidden", codes)
        self.assertIn("hardlink_forbidden", codes)
        self.assertEqual(outside.read_bytes(), b"do not read or delete")
        with self.assertRaisesRegex(StorageError, "incomplete"):
            quarantine_unreachable(self.store, self.identity)

    def test_inventory_detects_file_replacement_race(self) -> None:
        self.orphan("artifacts/race.bin", b"before")
        from ctf_os import storage as storage_module

        real_stat = storage_module.os.stat
        target_calls = 0

        def mutate_before_final_stat(path, *args, **kwargs):
            nonlocal target_calls
            if path == "race.bin" and kwargs.get("dir_fd") is not None:
                target_calls += 1
                if target_calls == 2:
                    descriptor = os.open(
                        path,
                        os.O_WRONLY | os.O_TRUNC,
                        dir_fd=kwargs["dir_fd"],
                    )
                    try:
                        os.write(descriptor, b"after replacement")
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
            return real_stat(path, *args, **kwargs)

        with mock.patch.object(
            storage_module.os,
            "stat",
            side_effect=mutate_before_final_stat,
        ):
            report = storage_inventory(
                self.store,
                self.identity,
                quota_bytes=1024,
            )

        self.assertFalse(report["scan_complete"])
        self.assertIn(
            "file_changed_during_scan",
            {item["code"] for item in report["scan"]["issues"]},
        )
        self.assertEqual(report["quota"]["status"], "indeterminate")

    def test_purge_requires_exact_preparation_and_reclaims_bytes(self) -> None:
        paths = self.store.challenge_paths(self.identity)
        first = self.orphan("artifacts/orphan/first.bin", b"A" * 8192)
        second = self.orphan("proof/orphan/second.bin", b"B" * 4096)
        expected_bytes = first.stat().st_size + second.stat().st_size
        quarantined = quarantine_unreachable(self.store, self.identity)
        quarantine_id = quarantined["quarantine_id"]
        prepared = prepare_quarantine_purge(
            self.store,
            self.identity,
            quarantine_id,
        )
        quarantine_root = (
            paths.artifacts / "quarantine" / quarantine_id
        )
        before = storage_inventory(
            self.store,
            self.identity,
        )["total_bytes"]

        with self.assertRaisesRegex(StorageError, "confirmation"):
            purge_quarantine(
                self.store,
                self.identity,
                quarantine_id,
                manifest_sha256=prepared["manifest_sha256"],
                confirmation="PURGE something else",
            )
        with self.assertRaisesRegex(StorageError, "digest changed"):
            purge_quarantine(
                self.store,
                self.identity,
                quarantine_id,
                manifest_sha256="0" * 64,
                confirmation=(
                    f"PURGE {self.identity.key} {quarantine_id} "
                    f"{'0' * 64}"
                ),
            )

        purged = purge_quarantine(
            self.store,
            self.identity,
            quarantine_id,
            manifest_sha256=prepared["manifest_sha256"],
            confirmation=prepared["confirmation"],
        )
        self.assertEqual(purged["status"], "purged")
        self.assertEqual(purged["reclaimed_bytes"], expected_bytes)
        self.assertTrue(purged["permanent_delete_performed"])
        self.assertFalse(first.exists())
        self.assertFalse(second.exists())
        control_root = self.gc_control(quarantine_id)
        self.assertTrue((control_root / "manifest.json").is_file())
        self.assertTrue((control_root / "purge.json").is_file())
        self.assertFalse(
            any(
                path.is_file()
                for path in (quarantine_root / "files").rglob("*")
            )
        )
        after = storage_inventory(
            self.store,
            self.identity,
        )["total_bytes"]
        self.assertLess(after, before)

        repeated = purge_quarantine(
            self.store,
            self.identity,
            quarantine_id,
            manifest_sha256=prepared["manifest_sha256"],
            confirmation=prepared["confirmation"],
        )
        self.assertTrue(repeated["already_purged"])
        status = prepare_quarantine_purge(
            self.store,
            self.identity,
            quarantine_id,
        )
        self.assertEqual(status["status"], "purged")

    def test_gc_control_plane_recovers_an_already_exceeded_quota(self) -> None:
        baseline = storage_inventory(self.store, self.identity)["total_bytes"]
        orphan = self.orphan(
            "artifacts/orphan/quota-recovery.bin",
            b"R" * 8192,
        )
        quota = baseline + orphan.stat().st_size - 1
        exceeded = storage_inventory(
            self.store,
            self.identity,
            quota_bytes=quota,
        )
        self.assertEqual(exceeded["quota"]["status"], "exceeded")

        quarantined = quarantine_unreachable(self.store, self.identity)
        after_quarantine = storage_inventory(
            self.store,
            self.identity,
            quota_bytes=quota,
        )
        self.assertEqual(
            after_quarantine["total_bytes"],
            exceeded["total_bytes"],
        )
        control = self.gc_control(quarantined["quarantine_id"])
        self.assertTrue((control / "manifest.json").is_file())
        self.assertGreater(
            after_quarantine["control"]["gc_recovery_bytes"],
            0,
        )
        self.assertEqual(
            after_quarantine["quota"]["observed_physical_bytes"],
            after_quarantine["total_bytes"]
            + after_quarantine["control"]["quota_exempt_bytes"],
        )
        self.assertNotIn(
            ".storage-gc",
            {item["path"].split("/", 1)[0] for item in after_quarantine["files"]},
        )

        prepared = prepare_quarantine_purge(
            self.store,
            self.identity,
            quarantined["quarantine_id"],
        )
        self.assertTrue((control / "purge.json").is_file())
        purge_quarantine(
            self.store,
            self.identity,
            quarantined["quarantine_id"],
            manifest_sha256=prepared["manifest_sha256"],
            confirmation=prepared["confirmation"],
        )
        recovered = storage_inventory(
            self.store,
            self.identity,
            quota_bytes=quota,
        )
        self.assertEqual(recovered["quota"]["status"], "within")
        self.assertLess(recovered["total_bytes"], exceeded["total_bytes"])

    def test_gc_control_plane_cap_and_legacy_fallback_fail_closed(self) -> None:
        from ctf_os import storage as storage_module

        orphan = self.orphan(
            "artifacts/orphan/control-cap.bin",
            b"control-cap",
        )
        with (
            mock.patch.object(storage_module, "MAX_GC_CONTROL_BYTES", 1),
            self.assertRaisesRegex(StorageError, "control byte cap"),
        ):
            quarantine_unreachable(self.store, self.identity)
        self.assertEqual(orphan.read_bytes(), b"control-cap")
        paths = self.store.challenge_paths(self.identity)
        self.assertEqual(
            list((paths.artifacts / "quarantine").iterdir()),
            [],
        )
        self.assertEqual(
            list((paths.root / ".storage-gc").iterdir()),
            [],
        )

        # A failed first publish must not consume one control-plane entry per
        # retry and eventually deadlock GC at its bounded entry cap.
        for _attempt in range(3):
            with (
                mock.patch.object(storage_module, "MAX_GC_CONTROL_BYTES", 1),
                self.assertRaisesRegex(StorageError, "control byte cap"),
            ):
                quarantine_unreachable(self.store, self.identity)
        self.assertEqual(
            list((paths.artifacts / "quarantine").iterdir()),
            [],
        )
        self.assertEqual(
            list((paths.root / ".storage-gc").iterdir()),
            [],
        )

        quarantined = quarantine_unreachable(self.store, self.identity)
        quarantine_id = quarantined["quarantine_id"]
        data_root = (
            self.store.challenge_paths(self.identity).artifacts
            / "quarantine"
            / quarantine_id
        )
        control_root = self.gc_control(quarantine_id)
        (control_root / "manifest.json").replace(
            data_root / "manifest.json"
        )
        control_root.rmdir()
        prepared = prepare_quarantine_purge(
            self.store,
            self.identity,
            quarantine_id,
        )
        self.assertTrue((data_root / "purge.json").is_file())
        self.assertEqual(prepared["status"], "prepared")

        outside = self.root / "legacy-manifest-hardlink"
        os.link(data_root / "manifest.json", outside)
        with self.assertRaisesRegex(StorageError, "unsafe"):
            prepare_quarantine_purge(
                self.store,
                self.identity,
                quarantine_id,
            )
        plane = self.store.challenge_paths(self.identity).root / ".storage-gc"
        plane.chmod(0o755)
        unsafe_control = storage_inventory(self.store, self.identity)
        self.assertFalse(unsafe_control["scan_complete"])
        self.assertIn(
            "gc_control_integrity_failed",
            {item["code"] for item in unsafe_control["scan"]["issues"]},
        )

    def test_pre_manifest_interrupt_removes_partial_transaction(self) -> None:
        from ctf_os import storage as storage_module

        orphan = self.orphan(
            "artifacts/orphan/pre-manifest.bin",
            b"must remain reachable after the interruption",
        )
        paths = self.store.challenge_paths(self.identity)
        real_open_directory_at = storage_module._open_directory_at

        def interrupt_after_files_mkdir(
            directory_fd,
            name,
            *,
            create=False,
        ):
            descriptor = real_open_directory_at(
                directory_fd,
                name,
                create=create,
            )
            if name == "files" and create:
                os.close(descriptor)
                raise KeyboardInterrupt(
                    "synthetic pre-manifest interruption"
                )
            return descriptor

        with (
            mock.patch.object(
                storage_module,
                "_open_directory_at",
                side_effect=interrupt_after_files_mkdir,
            ),
            self.assertRaisesRegex(
                KeyboardInterrupt,
                "synthetic pre-manifest interruption",
            ),
        ):
            quarantine_unreachable(self.store, self.identity)

        self.assertEqual(
            orphan.read_bytes(),
            b"must remain reachable after the interruption",
        )
        for plane in (
            paths.artifacts / "quarantine",
            paths.root / ".storage-gc",
        ):
            self.assertEqual(
                tuple(plane.iterdir()) if plane.exists() else (),
                (),
            )

    def test_gc_recovers_exact_crash_orphan_before_noop(self) -> None:
        paths = self.store.challenge_paths(self.identity)
        quarantine_id = "Q-" + "a" * 32
        data_plane = paths.artifacts / "quarantine"
        data_plane.mkdir(mode=0o700, parents=True, exist_ok=True)
        data_plane.chmod(0o700)
        data_root = data_plane / quarantine_id
        data_files = data_root / "files"
        data_files.mkdir(mode=0o700, parents=True)
        data_root.chmod(0o700)
        control_plane = paths.root / ".storage-gc"
        control_plane.mkdir(mode=0o700)
        control_root = control_plane / quarantine_id
        control_root.mkdir(mode=0o700)
        temporary = control_root / (
            ".manifest.json." + "b" * 32 + ".tmp"
        )
        temporary.write_bytes(b"interrupted initial manifest")
        temporary.chmod(0o600)

        result = quarantine_unreachable(self.store, self.identity)

        self.assertEqual(result["status"], "noop")
        self.assertEqual(result["reason"], "no_unreachable_files")
        self.assertFalse((data_plane / quarantine_id).exists())
        self.assertFalse(control_root.exists())

    def test_gc_control_entry_admission_precedes_transaction_mkdir(self) -> None:
        from ctf_os import storage as storage_module

        orphan = self.orphan(
            "artifacts/orphan/control-entry-cap.bin",
            b"entry-cap",
        )
        paths = self.store.challenge_paths(self.identity)
        with (
            mock.patch.object(storage_module, "MAX_GC_CONTROL_ENTRIES", 1),
            self.assertRaisesRegex(StorageError, "control entry cap"),
        ):
            quarantine_unreachable(self.store, self.identity)

        self.assertEqual(orphan.read_bytes(), b"entry-cap")
        for plane in (
            paths.artifacts / "quarantine",
            paths.root / ".storage-gc",
        ):
            self.assertEqual(
                tuple(plane.iterdir()) if plane.exists() else (),
                (),
            )

    def test_gc_recovery_uses_one_global_control_entry_budget(self) -> None:
        from ctf_os import storage as storage_module

        paths = self.store.challenge_paths(self.identity)
        quarantine_id = "Q-" + "c" * 32
        control_root = paths.root / ".storage-gc" / quarantine_id
        control_root.mkdir(mode=0o700, parents=True)
        (paths.root / ".storage-gc").chmod(0o700)
        temporary = control_root / (
            ".manifest.json." + "d" * 32 + ".tmp"
        )
        temporary.write_bytes(b"bounded recovery")
        temporary.chmod(0o600)

        with (
            mock.patch.object(storage_module, "MAX_GC_CONTROL_ENTRIES", 1),
            self.assertRaisesRegex(StorageError, "entry limit"),
        ):
            quarantine_unreachable(self.store, self.identity)

        self.assertEqual(temporary.read_bytes(), b"bounded recovery")

    def test_gc_recovery_never_removes_unknown_unpublished_data(self) -> None:
        paths = self.store.challenge_paths(self.identity)
        quarantine_id = "Q-" + "e" * 32
        data_root = paths.artifacts / "quarantine" / quarantine_id
        data_root.mkdir(mode=0o700, parents=True)
        (paths.artifacts / "quarantine").chmod(0o700)
        unknown = data_root / "operator-note.bin"
        unknown.write_bytes(b"preserve unknown data")
        unknown.chmod(0o600)
        control_root = paths.root / ".storage-gc" / quarantine_id
        control_root.mkdir(mode=0o700, parents=True)
        (paths.root / ".storage-gc").chmod(0o700)

        with self.assertRaisesRegex(StorageError, "unknown entry"):
            quarantine_unreachable(self.store, self.identity)

        self.assertEqual(unknown.read_bytes(), b"preserve unknown data")
        self.assertTrue(control_root.is_dir())

    def test_empty_gc_is_bounded_idempotent_noop(self) -> None:
        paths = self.store.challenge_paths(self.identity)
        data_plane = paths.artifacts / "quarantine"
        control_plane = paths.root / ".storage-gc"
        data_before = (
            tuple(data_plane.iterdir()) if data_plane.exists() else ()
        )
        control_before = (
            tuple(control_plane.iterdir())
            if control_plane.exists()
            else ()
        )

        for _attempt in range(8):
            result = quarantine_unreachable(self.store, self.identity)
            self.assertEqual(result["status"], "noop")
            self.assertEqual(result["reason"], "no_unreachable_files")
            self.assertIsNone(result["quarantine_id"])
            self.assertEqual(result["files"], [])

        self.assertEqual(
            tuple(data_plane.iterdir()) if data_plane.exists() else (),
            data_before,
        )
        self.assertEqual(
            (
                tuple(control_plane.iterdir())
                if control_plane.exists()
                else ()
            ),
            control_before,
        )

    def test_purge_recovers_crash_after_unlink(self) -> None:
        self.orphan("artifacts/orphan/one.bin", b"one")
        self.orphan("artifacts/orphan/two.bin", b"two")
        quarantined = quarantine_unreachable(self.store, self.identity)
        prepared = prepare_quarantine_purge(
            self.store,
            self.identity,
            quarantined["quarantine_id"],
        )
        from ctf_os import storage as storage_module

        real_unlink = storage_module._unlink_tombstone
        calls = 0

        def unlink_then_crash(*args, **kwargs):
            nonlocal calls
            real_unlink(*args, **kwargs)
            calls += 1
            if calls == 1:
                raise KeyboardInterrupt("synthetic process interruption")

        with (
            mock.patch.object(
                storage_module,
                "_unlink_tombstone",
                side_effect=unlink_then_crash,
            ),
            self.assertRaisesRegex(
                KeyboardInterrupt,
                "synthetic process interruption",
            ),
        ):
            purge_quarantine(
                self.store,
                self.identity,
                quarantined["quarantine_id"],
                manifest_sha256=prepared["manifest_sha256"],
                confirmation=prepared["confirmation"],
            )

        resumed = purge_quarantine(
            self.store,
            self.identity,
            quarantined["quarantine_id"],
            manifest_sha256=prepared["manifest_sha256"],
            confirmation=prepared["confirmation"],
        )
        self.assertEqual(resumed["status"], "purged")
        self.assertEqual(len(resumed["purged"]), 2)

    def test_prepare_rejects_traversal_symlink_and_hardlink(self) -> None:
        paths = self.store.challenge_paths(self.identity)
        outside = self.root / "outside"
        outside.write_bytes(b"outside")

        self.orphan("artifacts/orphan/traversal.bin", b"payload")
        quarantined = quarantine_unreachable(self.store, self.identity)
        root = paths.artifacts / "quarantine" / quarantined["quarantine_id"]
        manifest_path = (
            self.gc_control(quarantined["quarantine_id"])
            / "manifest.json"
        )
        manifest = read_json(manifest_path)
        original_path = manifest["files"][0]["path"]
        manifest["files"][0]["path"] = "../outside"
        atomic_write_json(manifest_path, manifest)
        with self.assertRaisesRegex(StorageError, "unsafe path"):
            prepare_quarantine_purge(
                self.store,
                self.identity,
                quarantined["quarantine_id"],
            )
        self.assertEqual(outside.read_bytes(), b"outside")
        manifest["files"][0]["path"] = original_path
        atomic_write_json(manifest_path, manifest)

        self.orphan("artifacts/orphan/symlink.bin", b"payload")
        symlinked = quarantine_unreachable(self.store, self.identity)
        symlink_root = (
            paths.artifacts
            / "quarantine"
            / symlinked["quarantine_id"]
        )
        symlink_manifest = read_json(
            self.gc_control(symlinked["quarantine_id"])
            / "manifest.json"
        )
        relative = Path(symlink_manifest["files"][0]["path"])
        detached = symlink_root / "files" / relative
        detached.unlink()
        detached.symlink_to(outside)
        with self.assertRaises(StorageError):
            prepare_quarantine_purge(
                self.store,
                self.identity,
                symlinked["quarantine_id"],
            )
        self.assertEqual(outside.read_bytes(), b"outside")
        detached.unlink()
        detached.write_bytes(b"payload")

        self.orphan("artifacts/orphan/hardlink.bin", b"payload")
        hardlinked = quarantine_unreachable(self.store, self.identity)
        hardlink_root = (
            paths.artifacts
            / "quarantine"
            / hardlinked["quarantine_id"]
        )
        hardlink_manifest = read_json(
            self.gc_control(hardlinked["quarantine_id"])
            / "manifest.json"
        )
        relative = Path(hardlink_manifest["files"][0]["path"])
        os.link(
            hardlink_root / "files" / relative,
            self.root / "outside-link",
        )
        with self.assertRaisesRegex(StorageError, "hard-linked"):
            prepare_quarantine_purge(
                self.store,
                self.identity,
                hardlinked["quarantine_id"],
            )

    def test_prepare_binds_identity_and_exact_file_set(self) -> None:
        paths = self.store.challenge_paths(self.identity)
        self.orphan("artifacts/orphan/exact.bin", b"exact")
        quarantined = quarantine_unreachable(self.store, self.identity)
        root = paths.artifacts / "quarantine" / quarantined["quarantine_id"]
        manifest_path = (
            self.gc_control(quarantined["quarantine_id"])
            / "manifest.json"
        )
        manifest = read_json(manifest_path)
        manifest["identity"]["challenge_id"] = "different"
        atomic_write_json(manifest_path, manifest)
        with self.assertRaisesRegex(StorageError, "identity"):
            prepare_quarantine_purge(
                self.store,
                self.identity,
                quarantined["quarantine_id"],
            )

        manifest["identity"] = self.identity.to_dict()
        atomic_write_json(manifest_path, manifest)
        extra = root / "files" / "proof" / "unmanifested.bin"
        extra.parent.mkdir(parents=True)
        extra.write_bytes(b"must not be silently deleted")
        with self.assertRaisesRegex(StorageError, "exactly match"):
            prepare_quarantine_purge(
                self.store,
                self.identity,
                quarantined["quarantine_id"],
            )

    def test_purge_rechecks_hardlink_after_preparation(self) -> None:
        paths = self.store.challenge_paths(self.identity)
        self.orphan("artifacts/orphan/linked-late.bin", b"linked")
        quarantined = quarantine_unreachable(self.store, self.identity)
        root = paths.artifacts / "quarantine" / quarantined["quarantine_id"]
        prepared = prepare_quarantine_purge(
            self.store,
            self.identity,
            quarantined["quarantine_id"],
        )
        manifest = read_json(
            self.gc_control(quarantined["quarantine_id"])
            / "manifest.json"
        )
        relative = Path(manifest["files"][0]["path"])
        external_link = self.root / "late-hardlink"
        os.link(root / "files" / relative, external_link)

        with self.assertRaisesRegex(StorageError, "unsafe purge source"):
            purge_quarantine(
                self.store,
                self.identity,
                quarantined["quarantine_id"],
                manifest_sha256=prepared["manifest_sha256"],
                confirmation=prepared["confirmation"],
            )
        self.assertEqual(external_link.read_bytes(), b"linked")

    def test_canonical_quarantine_reference_blocks_prepare_and_purge(
        self,
    ) -> None:
        paths = self.store.challenge_paths(self.identity)
        self.orphan("artifacts/orphan/canonical-later.bin", b"keep")
        quarantined = quarantine_unreachable(self.store, self.identity)
        quarantine_id = quarantined["quarantine_id"]
        record = quarantined["files"][0]
        detached = (
            paths.artifacts
            / "quarantine"
            / quarantine_id
            / "files"
            / record["path"]
        )
        detached_relative = detached.relative_to(paths.root).as_posix()

        def register(state) -> None:
            state.artifacts.append(
                ArtifactReference(
                    id="A-quarantine-canonical",
                    path=detached_relative,
                    sha256=record["sha256"],
                    size=record["bytes"],
                )
            )

        self.store.update(self.identity, register)
        inventory = storage_inventory(self.store, self.identity)
        indexed = {item["path"]: item for item in inventory["files"]}
        self.assertEqual(
            indexed[detached_relative]["storage_class"],
            "canonical",
        )
        with self.assertRaisesRegex(
            StorageError,
            "canonical state references quarantine",
        ):
            prepare_quarantine_purge(
                self.store,
                self.identity,
                quarantine_id,
            )
        self.assertEqual(detached.read_bytes(), b"keep")

        def unregister(state) -> None:
            state.artifacts = [
                item
                for item in state.artifacts
                if item.id != "A-quarantine-canonical"
            ]

        self.store.update(self.identity, unregister)
        prepared = prepare_quarantine_purge(
            self.store,
            self.identity,
            quarantine_id,
        )
        self.store.update(self.identity, register)
        with self.assertRaisesRegex(
            StorageError,
            "canonical state references quarantine",
        ):
            purge_quarantine(
                self.store,
                self.identity,
                quarantine_id,
                manifest_sha256=prepared["manifest_sha256"],
                confirmation=prepared["confirmation"],
            )
        self.assertEqual(detached.read_bytes(), b"keep")

    def test_restore_recovers_interrupted_moving_quarantine(self) -> None:
        paths = self.store.challenge_paths(self.identity)
        first = self.orphan("artifacts/orphan/first.bin", b"first")
        second = self.orphan("proof/orphan/second.bin", b"second")
        quarantined = quarantine_unreachable(self.store, self.identity)
        quarantine_root = (
            paths.artifacts
            / "quarantine"
            / quarantined["quarantine_id"]
        )
        manifest_path = (
            self.gc_control(quarantined["quarantine_id"])
            / "manifest.json"
        )
        manifest = read_json(manifest_path)
        manifest["status"] = "moving"
        atomic_write_json(manifest_path, manifest)

        second_relative = second.relative_to(paths.root)
        detached_second = quarantine_root / "files" / second_relative
        second.parent.mkdir(parents=True, exist_ok=True)
        detached_second.rename(second)

        restored = restore_quarantine(
            self.store,
            self.identity,
            quarantined["quarantine_id"],
        )
        self.assertIn(
            first.relative_to(paths.root).as_posix(),
            restored["restored"],
        )
        self.assertEqual(first.read_bytes(), b"first")
        self.assertEqual(second.read_bytes(), b"second")
        self.assertEqual(
            read_json(manifest_path)["status"],
            "restored",
        )

    def test_detected_unlink_hardlink_race_faults_purge(self) -> None:
        paths = self.store.challenge_paths(self.identity)
        self.orphan("artifacts/orphan/race.bin", b"do not misreport")
        quarantined = quarantine_unreachable(self.store, self.identity)
        prepared = prepare_quarantine_purge(
            self.store,
            self.identity,
            quarantined["quarantine_id"],
        )
        quarantine_root = (
            paths.artifacts
            / "quarantine"
            / quarantined["quarantine_id"]
        )
        from ctf_os import storage as storage_module

        real_unlink = storage_module.os.unlink
        external = self.root / "raced-hardlink"

        def link_before_unlink(path, *args, **kwargs):
            directory_fd = kwargs.get("dir_fd")
            if (
                directory_fd is not None
                and str(path).endswith(".pending")
                and not external.exists()
            ):
                os.link(
                    path,
                    external,
                    src_dir_fd=directory_fd,
                )
            return real_unlink(path, *args, **kwargs)

        with (
            mock.patch.object(
                storage_module.os,
                "unlink",
                side_effect=link_before_unlink,
            ),
            self.assertRaisesRegex(StorageError, "did not reclaim"),
        ):
            purge_quarantine(
                self.store,
                self.identity,
                quarantined["quarantine_id"],
                manifest_sha256=prepared["manifest_sha256"],
                confirmation=prepared["confirmation"],
            )

        self.assertEqual(
            read_json(
                self.gc_control(quarantined["quarantine_id"])
                / "purge.json"
            )["status"],
            "faulted",
        )
        self.assertEqual(external.read_bytes(), b"do not misreport")
        with self.assertRaisesRegex(StorageError, "faulted"):
            purge_quarantine(
                self.store,
                self.identity,
                quarantined["quarantine_id"],
                manifest_sha256=prepared["manifest_sha256"],
                confirmation=prepared["confirmation"],
            )

    def test_restore_cancels_prepared_purge_and_remains_idempotent(
        self,
    ) -> None:
        original = self.orphan(
            "artifacts/orphan/restorable.bin",
            b"restorable",
        )
        quarantined = quarantine_unreachable(self.store, self.identity)
        prepared = prepare_quarantine_purge(
            self.store,
            self.identity,
            quarantined["quarantine_id"],
        )

        restored = restore_quarantine(
            self.store,
            self.identity,
            quarantined["quarantine_id"],
        )
        self.assertIn(
            original.relative_to(
                self.store.challenge_paths(self.identity).root
            ).as_posix(),
            restored["restored"],
        )
        self.assertEqual(original.read_bytes(), b"restorable")
        repeated = restore_quarantine(
            self.store,
            self.identity,
            quarantined["quarantine_id"],
        )
        self.assertEqual(repeated["restored"], [])
        with self.assertRaises(StorageError):
            purge_quarantine(
                self.store,
                self.identity,
                quarantined["quarantine_id"],
                manifest_sha256=prepared["manifest_sha256"],
                confirmation=prepared["confirmation"],
            )

    def test_purge_obeys_session_then_state_exclusion(self) -> None:
        self.orphan("artifacts/orphan/locked.bin", b"locked")
        quarantined = quarantine_unreachable(self.store, self.identity)
        paths = self.store.challenge_paths(self.identity)
        session_lock = ChallengeLock(
            paths.runtime / "session.lock",
            timeout=0,
        )
        session_lock.acquire()
        try:
            with self.assertRaisesRegex(StorageError, "active challenge"):
                prepare_quarantine_purge(
                    self.store,
                    self.identity,
                    quarantined["quarantine_id"],
                )
        finally:
            session_lock.release()


if __name__ == "__main__":
    unittest.main()
