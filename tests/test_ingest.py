from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from ctf_os.stages.ingest import IngestError, inventory_challenge


class IngestTests(unittest.TestCase):
    def test_inventory_is_deterministic_and_hashes_contents(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "b.bin").write_bytes(b"b")
            (root / "a.txt").write_text("a", encoding="utf-8")
            first = inventory_challenge(root)
            second = inventory_challenge(root)
        self.assertEqual(first, second)
        self.assertEqual([item.path for item in first.files], ["a.txt", "b.bin"])
        self.assertEqual(first.total_bytes, 2)

    def test_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root.parent / f"{root.name}-outside"
            outside.write_text("secret", encoding="utf-8")
            self.addCleanup(outside.unlink)
            (root / "link").symlink_to(outside)
            with self.assertRaisesRegex(IngestError, "symlink"):
                inventory_challenge(root)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFO")
    def test_rejects_special_files_without_opening_them(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.mkfifo(root / "input.fifo")
            with self.assertRaisesRegex(IngestError, "special-file"):
                inventory_challenge(root)


if __name__ == "__main__":
    unittest.main()
