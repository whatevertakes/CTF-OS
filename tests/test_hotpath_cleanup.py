from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.engine.hotpath_cleanup import (
    HotPathCleanupError,
    HotPathCleanupTracker,
)
from ctf_os.models import (
    ChallengeIdentity,
    RunOrigin,
    RunReference,
    RunStatus,
)


class HotPathCleanupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.identity = ChallengeIdentity("cleanup", "web", "exact")
        incoming = (
            self.root
            / "incoming"
            / self.identity.contest_id
            / self.identity.category
            / self.identity.challenge_id
        )
        incoming.mkdir(parents=True)
        (incoming / "challenge.txt").write_text(
            "bounded cleanup\n",
            encoding="utf-8",
        )
        self.engine = ChallengeEngine(self.root)
        self.engine.add_challenge(
            self.identity,
            prompt="test exact hot-path cleanup",
        )
        self.paths = self.engine.store.challenge_paths(self.identity)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_uncommitted_run_tree_is_removed_but_canonical_run_is_kept(
        self,
    ) -> None:
        removed_id = "uncommitted-run"
        kept_id = "canonical-run"
        removed = self.engine.store.create_run(
            self.identity,
            removed_id,
            request={"attempt_id": "attempt"},
        )
        kept = self.engine.store.create_run(
            self.identity,
            kept_id,
            request={"attempt_id": "attempt"},
        )
        root = self.paths.root

        def add_canonical_run(state) -> None:
            state.runs.append(
                RunReference(
                    id=kept_id,
                    base_revision=state.revision,
                    status=RunStatus.CREATED,
                    request_path=kept.request.relative_to(root).as_posix(),
                    role="test",
                    origin=RunOrigin.OPERATOR_TOOL,
                    configuration_epoch=state.configuration_epoch,
                )
            )

        self.engine.store.update(self.identity, add_canonical_run)
        tracker = HotPathCleanupTracker(
            maximum_entries=32,
            maximum_bytes=1024 * 1024,
        )
        tracker.track_tree(root, removed.root, run_id=removed_id)
        tracker.track_tree(root, kept.root, run_id=kept_id)
        tracker.cleanup(self.engine, self.identity)
        self.assertFalse(removed.root.exists())
        self.assertTrue(kept.root.is_dir())
        self.assertTrue(kept.request.is_file())

    def test_entry_bound_rejects_before_any_deletion_and_chains_cause(
        self,
    ) -> None:
        owned = self.paths.runtime / "owned-entry-bound"
        owned.mkdir()
        (owned / "first").write_bytes(b"1")
        (owned / "second").write_bytes(b"2")
        tracker = HotPathCleanupTracker(
            maximum_entries=2,
            maximum_bytes=1024,
        )
        tracker.track_tree(self.paths.root, owned)
        interruption = KeyboardInterrupt("synthetic interruption")
        with self.assertRaises(HotPathCleanupError) as raised:
            tracker.cleanup(
                self.engine,
                self.identity,
                cause=interruption,
            )
        self.assertIs(raised.exception.__cause__, interruption)
        self.assertTrue((owned / "first").is_file())
        self.assertTrue((owned / "second").is_file())

    def test_byte_bound_rejects_before_deletion(self) -> None:
        owned = self.paths.runtime / "owned-byte-bound"
        owned.mkdir()
        payload = b"four"
        (owned / "payload.bin").write_bytes(payload)
        tracker = HotPathCleanupTracker(
            maximum_entries=8,
            maximum_bytes=len(payload) - 1,
        )
        tracker.track_tree(self.paths.root, owned)
        with self.assertRaisesRegex(
            HotPathCleanupError,
            "byte bound exceeded before deletion",
        ):
            tracker.cleanup(self.engine, self.identity)
        self.assertEqual((owned / "payload.bin").read_bytes(), payload)

    def test_symlink_leaf_is_unlinked_without_following_target(self) -> None:
        outside = self.root / "outside.txt"
        outside.write_bytes(b"preserve")
        owned = self.paths.runtime / "owned-link"
        owned.mkdir()
        (owned / "link").symlink_to(outside)
        tracker = HotPathCleanupTracker(
            maximum_entries=8,
            maximum_bytes=1024,
        )
        tracker.track_tree(self.paths.root, owned)
        tracker.cleanup(self.engine, self.identity)
        self.assertFalse(owned.exists())
        self.assertEqual(outside.read_bytes(), b"preserve")


if __name__ == "__main__":
    unittest.main()
