from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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
        self.assertTrue((quarantine_root / "manifest.json").is_file())
        self.assertTrue((quarantine_root / "purge.json").is_file())
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
        manifest_path = root / "manifest.json"
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
        symlink_manifest = read_json(symlink_root / "manifest.json")
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
        hardlink_manifest = read_json(hardlink_root / "manifest.json")
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
        manifest_path = root / "manifest.json"
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
        manifest = read_json(root / "manifest.json")
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
        manifest_path = quarantine_root / "manifest.json"
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
            read_json(quarantine_root / "purge.json")["status"],
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
