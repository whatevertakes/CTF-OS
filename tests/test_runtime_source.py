from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import ctf_os.runtime_source as runtime_source
from ctf_os.runtime_source import (
    RuntimeSourceError,
    runtime_source_inventory,
)


class RuntimeSourceInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "source"
        self.payloads = {
            "ctf_os/__init__.py": b'"""fixture."""\n',
            "ctf_os/__main__.py": b"from ctf_os.cli import main\n",
            "ctf_os/benchmark.py": b"SCHEMA = 3\n",
            "ctf_os/cli.py": b"def main(): return 0\n",
            "ctf_os/container_tools.py": b"def main(): return 0\n",
            "ctf_os/promotion_bundles.py": b"PROMOTION = 2\n",
            "ctf_os/runtime_source.py": b"INVENTORY = 1\n",
            "ctf_os/engine/core.py": b"ENGINE = 'clean'\n",
            "pyproject.toml": b"[project]\nname='fixture'\nversion='1'\n",
            "ctfos": b"#!/bin/sh\nexec python -m ctf_os \"$@\"\n",
            "ctf-container": b"#!/bin/sh\nexit 0\n",
        }
        for relative, payload in self.payloads.items():
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
        self.excluded_payloads = {
            "tests/tracked_test.py": b"TRACKED_TEST = True\n",
            "docs/tracked.md": b"tracked documentation\n",
            "incoming/tracked.bin": b"untrusted challenge input\n",
            "state/tracked.json": b'{"mutable":true}\n',
        }
        for relative, payload in self.excluded_payloads.items():
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
        self._git("init", "-q")
        self._git("add", "--all")
        self._git(
            "-c",
            "user.name=CTF-OS Tests",
            "-c",
            "user.email=ctfos-tests@example.invalid",
            "commit",
            "-q",
            "--no-gpg-sign",
            "-m",
            "fixture",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _git(self, *arguments: str) -> None:
        subprocess.run(
            ("git", "-C", str(self.root), *arguments),
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def test_inventory_is_deterministic_path_bound_and_excludes_untracked(
        self,
    ) -> None:
        first = runtime_source_inventory(self.root)
        second = runtime_source_inventory(self.root)
        self.assertEqual(first, second)
        self.assertEqual(first.sha256, second.sha256)
        self.assertEqual(
            {item.path for item in first.files},
            set(self.payloads),
        )
        self.assertEqual(
            first.total_bytes,
            sum(len(value) for value in self.payloads.values()),
        )
        self.assertTrue(
            set(self.excluded_payloads).isdisjoint(
                item.path for item in first.files
            )
        )

        with mock.patch.dict(
            os.environ,
            {"GIT_INDEX_FILE": str(self.root / "hostile-index")},
        ):
            self.assertEqual(runtime_source_inventory(self.root), first)

        for relative in (
            "ctf_os/untracked.py",
            "tests/test_untracked.py",
            "docs/untracked.md",
            "incoming/challenge.bin",
        ):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"excluded\n")
        excluded = runtime_source_inventory(self.root)
        self.assertEqual(excluded, first)

        tracked = self.root / "ctf_os" / "new_runtime.py"
        tracked.write_bytes(b"NEW_RUNTIME = True\n")
        self._git("add", "ctf_os/new_runtime.py")
        self._git(
            "-c",
            "user.name=CTF-OS Tests",
            "-c",
            "user.email=ctfos-tests@example.invalid",
            "commit",
            "-q",
            "--no-gpg-sign",
            "-m",
            "add runtime",
        )
        changed = runtime_source_inventory(self.root)
        self.assertNotEqual(changed.sha256, first.sha256)
        self.assertIn(
            "ctf_os/new_runtime.py",
            {item.path for item in changed.files},
        )

    def test_one_byte_unstaged_or_staged_change_fails_closed(self) -> None:
        source = self.root / "ctf_os" / "engine" / "core.py"
        original = source.read_bytes()
        source.write_bytes(original.replace(b"clean", b"cleao"))
        with self.assertRaisesRegex(RuntimeSourceError, "changes"):
            runtime_source_inventory(self.root)

        self._git("add", "ctf_os/engine/core.py")
        with self.assertRaisesRegex(RuntimeSourceError, "changes"):
            runtime_source_inventory(self.root)

    def test_hidden_index_flags_cannot_mask_one_byte_change(self) -> None:
        source = self.root / "ctf_os" / "engine" / "core.py"
        original = source.read_bytes()
        changed = original.replace(b"clean", b"cleao")

        self._git(
            "update-index",
            "--assume-unchanged",
            "ctf_os/engine/core.py",
        )
        source.write_bytes(changed)
        with self.assertRaisesRegex(RuntimeSourceError, "tracked Git blob"):
            runtime_source_inventory(self.root)

        source.write_bytes(original)
        self._git(
            "update-index",
            "--no-assume-unchanged",
            "ctf_os/engine/core.py",
        )
        self._git(
            "update-index",
            "--skip-worktree",
            "ctf_os/engine/core.py",
        )
        source.write_bytes(changed)
        with self.assertRaisesRegex(RuntimeSourceError, "tracked Git blob"):
            runtime_source_inventory(self.root)

    def test_ignored_executable_mode_change_fails_closed(self) -> None:
        entrypoint = self.root / "ctfos"
        self._git("config", "core.filemode", "false")
        entrypoint.chmod(0o755)
        with self.assertRaisesRegex(RuntimeSourceError, "executable mode"):
            runtime_source_inventory(self.root)

    def test_tracked_leaf_and_intermediate_symlinks_fail_closed(self) -> None:
        source = self.root / "ctf_os" / "engine" / "core.py"
        source.unlink()
        source.symlink_to("/etc/passwd")
        self._git("add", "ctf_os/engine/core.py")
        self._git(
            "-c",
            "user.name=CTF-OS Tests",
            "-c",
            "user.email=ctfos-tests@example.invalid",
            "commit",
            "-q",
            "--no-gpg-sign",
            "-m",
            "symlink leaf",
        )
        with self.assertRaisesRegex(
            RuntimeSourceError,
            "index is not canonical",
        ):
            runtime_source_inventory(self.root)

        source.unlink()
        source.write_bytes(self.payloads["ctf_os/engine/core.py"])
        self._git("add", "ctf_os/engine/core.py")
        self._git(
            "-c",
            "user.name=CTF-OS Tests",
            "-c",
            "user.email=ctfos-tests@example.invalid",
            "commit",
            "-q",
            "--no-gpg-sign",
            "-m",
            "restore regular leaf",
        )
        engine = self.root / "ctf_os" / "engine"
        moved = self.root / "engine-real"
        engine.rename(moved)
        engine.symlink_to(moved, target_is_directory=True)
        with (
            mock.patch.object(
                runtime_source,
                "_require_clean_tracked_source",
            ),
            self.assertRaisesRegex(
                RuntimeSourceError,
                "opened safely",
            ),
        ):
            runtime_source_inventory(self.root)

    def test_same_size_cross_pass_mutation_is_detected(self) -> None:
        source = self.root / "ctf_os" / "engine" / "core.py"
        original_scan = runtime_source._scan
        calls = 0

        def mutate_after_first(root, entries):
            nonlocal calls
            result = original_scan(root, entries)
            calls += 1
            if calls == 1:
                payload = source.read_bytes()
                source.write_bytes(
                    payload.replace(b"clean", b"cleao")
                )
            return result

        with (
            mock.patch.object(
                runtime_source,
                "_require_clean_tracked_source",
            ),
            mock.patch.object(
                runtime_source,
                "_scan",
                side_effect=mutate_after_first,
            ),
            self.assertRaisesRegex(
                RuntimeSourceError,
                "tracked Git blob|changed during inventory",
            ),
        ):
            runtime_source_inventory(self.root)

    def test_file_count_and_total_bytes_are_bounded(self) -> None:
        with (
            mock.patch.object(
                runtime_source,
                "MAX_RUNTIME_SOURCE_FILES",
                1,
            ),
            self.assertRaisesRegex(RuntimeSourceError, "oversized"),
        ):
            runtime_source_inventory(self.root)
        with (
            mock.patch.object(
                runtime_source,
                "MAX_RUNTIME_SOURCE_TOTAL_BYTES",
                1,
            ),
            self.assertRaisesRegex(RuntimeSourceError, "total byte"),
        ):
            runtime_source_inventory(self.root)
        with (
            mock.patch.object(
                runtime_source,
                "MAX_RUNTIME_SOURCE_FILE_BYTES",
                1,
            ),
            self.assertRaisesRegex(RuntimeSourceError, "bounded regular"),
        ):
            runtime_source_inventory(self.root)


if __name__ == "__main__":
    unittest.main()
