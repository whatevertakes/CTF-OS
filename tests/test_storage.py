from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ctf_os.models import ArtifactReference, ChallengeIdentity
from ctf_os.storage import (
    quarantine_unreachable,
    restore_quarantine,
    storage_inventory,
    storage_plan,
)
from ctf_os.store import StateStore, sha256_file


class StorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.store = StateStore(self.root)
        self.identity = ChallengeIdentity("contest", "rev", "challenge")
        self.store.create_challenge(self.identity)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_inventory_uses_one_canonical_state_revision(self) -> None:
        with mock.patch.object(
            self.store,
            "load",
            wraps=self.store.load,
        ) as load:
            report = storage_inventory(self.store, self.identity)

        self.assertEqual(load.call_count, 1)
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


if __name__ == "__main__":
    unittest.main()
