#!/usr/bin/env python3
"""Focused source tests for the bounded Rev inventory producer."""

from __future__ import annotations

import importlib.util
import json
import os
import signal
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


REPOSITORY = Path(__file__).resolve().parent.parent
REV_TEMPLATES = REPOSITORY / "templates" / "rev"
sys.path.insert(0, str(REV_TEMPLATES))
import safe_output  # noqa: E402


module_spec = importlib.util.spec_from_file_location(
    "ctf_rev_inventory_under_test",
    REV_TEMPLATES / "inventory.py",
)
assert module_spec is not None and module_spec.loader is not None
inventory = importlib.util.module_from_spec(module_spec)
sys.modules[module_spec.name] = inventory
module_spec.loader.exec_module(inventory)


class RevInventoryProducerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="ctf-rev-inventory-"
        )
        self.root = Path(self.temporary.name)
        self.source = self.root / "sample.bin"
        self.source.write_bytes(b"\x7fELFbounded-rev-inventory")
        self.output = self.root / "work" / "rev"
        self.output.parent.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def rabin_payload(
        self,
        *,
        arch: object = "x86",
        bits: object = 64,
        bintype: object = "elf",
        endian: object = "little",
        havecode: object = True,
    ) -> bytes:
        return json.dumps(
            {
                "info": {
                    "arch": arch,
                    "binsz": self.source.stat().st_size,
                    "bintype": bintype,
                    "bits": bits,
                    "endian": endian,
                    "havecode": havecode,
                }
            },
            separators=(",", ":"),
        ).encode("utf-8")

    def fake_executable(
        self,
        stdout: bytes,
        *,
        stderr: bytes = b"",
        sleep_seconds: float = 0,
        exit_code: int = 0,
        name: str = "fake-rabin2",
    ) -> Path:
        path = self.root / name
        path.write_text(
            "\n".join(
                (
                    "#!/usr/bin/python3",
                    "import sys",
                    "import time",
                    f"time.sleep({sleep_seconds!r})",
                    f"sys.stdout.buffer.write({stdout!r})",
                    f"sys.stderr.buffer.write({stderr!r})",
                    f"raise SystemExit({exit_code})",
                    "",
                )
            ),
            encoding="utf-8",
        )
        path.chmod(0o755)
        return path

    def read_inventory(self) -> tuple[bytes, dict[str, object]]:
        path = self.output / inventory.OUTPUT_NAME
        payload = path.read_bytes()
        value = json.loads(payload)
        assert isinstance(value, dict)
        return payload, value

    def assert_descendant_stopped(self, pid_path: Path) -> int:
        descendant_pid: int | None = None
        for _ in range(100):
            if pid_path.exists():
                descendant_pid = int(pid_path.read_text())
                break
            time.sleep(0.01)
        self.assertIsNotNone(descendant_pid)
        assert descendant_pid is not None
        for _ in range(100):
            stat_path = Path(f"/proc/{descendant_pid}/stat")
            if not stat_path.exists():
                return descendant_pid
            fields = stat_path.read_text(encoding="ascii").split()
            if fields[2] == "Z":
                return descendant_pid
            time.sleep(0.01)
        self.fail("rabin2 descendant survived process-group cleanup")

    def test_success_is_canonical_source_bound_and_bounded(self) -> None:
        executable = self.fake_executable(self.rabin_payload())

        observed = inventory.produce_inventory(
            self.source,
            self.output,
            rabin2_executable=str(executable),
        )

        self.assertTrue(observed)
        payload, document = self.read_inventory()
        self.assertEqual(
            payload,
            inventory._canonical_json_bytes(document),
        )
        self.assertLessEqual(len(payload), inventory.MAX_INVENTORY_BYTES)
        self.assertEqual(document["schema_version"], inventory.SCHEMA_VERSION)
        self.assertEqual(document["status"], "ok")
        self.assertEqual(
            document["contract"]["fingerprint"],
            inventory.CONTRACT_FINGERPRINT,
        )
        self.assertEqual(
            document["source"]["size_bytes"],
            self.source.stat().st_size,
        )
        self.assertEqual(
            document["binary"],
            {
                "arch": "x86",
                "bits": 64,
                "bintype": "elf",
                "endian": "little",
                "havecode": True,
            },
        )
        output_stat = (self.output / inventory.OUTPUT_NAME).lstat()
        self.assertTrue(stat.S_ISREG(output_stat.st_mode))

    def test_duplicate_rabin_key_replaces_prior_success_with_error(self) -> None:
        good = self.fake_executable(
            self.rabin_payload(),
            name="good-rabin2",
        )
        self.assertTrue(
            inventory.produce_inventory(
                self.source,
                self.output,
                rabin2_executable=str(good),
            )
        )
        duplicate = (
            b'{"info":{"arch":"x86","arch":"arm","binsz":'
            + str(self.source.stat().st_size).encode("ascii")
            + b',"bintype":"elf","bits":64,"endian":"little",'
            b'"havecode":true}}'
        )
        bad = self.fake_executable(
            duplicate,
            name="duplicate-rabin2",
        )

        observed = inventory.produce_inventory(
            self.source,
            self.output,
            rabin2_executable=str(bad),
        )

        self.assertFalse(observed)
        _payload, document = self.read_inventory()
        self.assertEqual(document["status"], "error")
        self.assertEqual(
            document["error"],
            {"code": "rabin2_invalid_json"},
        )
        self.assertNotIn("binary", document)

    def test_bool_is_not_accepted_as_rabin_integer(self) -> None:
        executable = self.fake_executable(
            self.rabin_payload(bits=True),
        )

        observed = inventory.produce_inventory(
            self.source,
            self.output,
            rabin2_executable=str(executable),
        )

        self.assertFalse(observed)
        _payload, document = self.read_inventory()
        self.assertEqual(
            document["error"],
            {"code": "rabin2_invalid_schema"},
        )

    def test_rabin_root_must_contain_only_the_info_object(self) -> None:
        base = json.loads(self.rabin_payload())
        base["unexpected"] = {}
        executable = self.fake_executable(
            json.dumps(base, separators=(",", ":")).encode("utf-8"),
        )

        observed = inventory.produce_inventory(
            self.source,
            self.output,
            rabin2_executable=str(executable),
        )

        self.assertFalse(observed)
        _payload, document = self.read_inventory()
        self.assertEqual(
            document["error"],
            {"code": "rabin2_invalid_schema"},
        )

    def test_fatal_source_error_cannot_leave_stale_success(self) -> None:
        executable = self.fake_executable(self.rabin_payload())
        self.assertTrue(
            inventory.produce_inventory(
                self.source,
                self.output,
                rabin2_executable=str(executable),
            )
        )
        destination = self.output / inventory.OUTPUT_NAME
        self.assertTrue(destination.is_file())
        self.source.unlink()
        self.source.mkdir()

        with self.assertRaises(OSError):
            inventory.produce_inventory(
                self.source,
                self.output,
                rabin2_executable=str(executable),
            )

        self.assertFalse(destination.exists())

    def test_subprocess_stdout_and_deadline_are_hard_bounded(self) -> None:
        noisy = self.fake_executable(b"x" * 4096, name="noisy-rabin2")
        with self.assertRaises(inventory.InventoryError) as limit_context:
            inventory._run_bounded(
                (str(noisy),),
                timeout_seconds=1,
                stdout_limit_bytes=128,
                stderr_limit_bytes=128,
            )
        self.assertEqual(
            limit_context.exception.code,
            "rabin2_stdout_limit",
        )

        hanging = self.fake_executable(
            b"",
            sleep_seconds=2,
            name="hanging-rabin2",
        )
        started = time.monotonic()
        with self.assertRaises(inventory.InventoryError) as timeout_context:
            inventory._run_bounded(
                (str(hanging),),
                timeout_seconds=0.05,
                stdout_limit_bytes=128,
                stderr_limit_bytes=128,
            )
        self.assertLess(time.monotonic() - started, 1)
        self.assertEqual(
            timeout_context.exception.code,
            "rabin2_timeout",
        )

    def test_timeout_kills_the_entire_rabin_process_group(self) -> None:
        descendant_pid_path = self.root / "descendant.pid"
        executable = self.root / "forking-rabin2"
        executable.write_text(
            "\n".join(
                (
                    "#!/usr/bin/python3",
                    "import os",
                    "import signal",
                    "import time",
                    "from pathlib import Path",
                    "child = os.fork()",
                    "if child == 0:",
                    "    signal.signal(signal.SIGTERM, signal.SIG_IGN)",
                    "    while True:",
                    "        time.sleep(10)",
                    f"Path({str(descendant_pid_path)!r}).write_text(str(child))",
                    "raise SystemExit(0)",
                    "",
                )
            ),
            encoding="utf-8",
        )
        executable.chmod(0o755)

        descendant_pid: int | None = None
        try:
            with self.assertRaises(inventory.InventoryError) as context:
                inventory._run_bounded(
                    (str(executable),),
                    timeout_seconds=0.5,
                    stdout_limit_bytes=128,
                    stderr_limit_bytes=128,
                )
            self.assertEqual(context.exception.code, "rabin2_timeout")
            descendant_pid = self.assert_descendant_stopped(
                descendant_pid_path
            )
        finally:
            if descendant_pid is not None:
                try:
                    os.kill(descendant_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_stream_limit_kills_the_entire_rabin_process_group(self) -> None:
        descendant_pid_path = self.root / "limit-descendant.pid"
        executable = self.root / "forking-noisy-rabin2"
        executable.write_text(
            "\n".join(
                (
                    "#!/usr/bin/python3",
                    "import os",
                    "import signal",
                    "import time",
                    "from pathlib import Path",
                    "child = os.fork()",
                    "if child == 0:",
                    "    signal.signal(signal.SIGTERM, signal.SIG_IGN)",
                    "    while True:",
                    "        time.sleep(10)",
                    f"Path({str(descendant_pid_path)!r}).write_text(str(child))",
                    "os.write(1, b'x' * 4096)",
                    "raise SystemExit(0)",
                    "",
                )
            ),
            encoding="utf-8",
        )
        executable.chmod(0o755)

        descendant_pid: int | None = None
        try:
            with self.assertRaises(inventory.InventoryError) as context:
                inventory._run_bounded(
                    (str(executable),),
                    timeout_seconds=1,
                    stdout_limit_bytes=128,
                    stderr_limit_bytes=128,
                )
            self.assertEqual(context.exception.code, "rabin2_stdout_limit")
            descendant_pid = self.assert_descendant_stopped(
                descendant_pid_path
            )
        finally:
            if descendant_pid is not None:
                try:
                    os.kill(descendant_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_symlink_and_fifo_outputs_are_refused_without_following(self) -> None:
        executable = self.fake_executable(self.rabin_payload())
        self.output.mkdir()
        destination = self.output / inventory.OUTPUT_NAME
        sentinel = self.root / "sentinel"
        sentinel.write_bytes(b"unchanged")
        destination.symlink_to(sentinel)

        with self.assertRaises(OSError):
            inventory.produce_inventory(
                self.source,
                self.output,
                rabin2_executable=str(executable),
            )
        self.assertTrue(destination.is_symlink())
        self.assertEqual(sentinel.read_bytes(), b"unchanged")

        destination.unlink()
        os.mkfifo(destination)
        started = time.monotonic()
        with self.assertRaises(OSError):
            inventory.produce_inventory(
                self.source,
                self.output,
                rabin2_executable=str(executable),
            )
        self.assertLess(time.monotonic() - started, 1)
        self.assertTrue(stat.S_ISFIFO(destination.lstat().st_mode))
        self.assertEqual(sentinel.read_bytes(), b"unchanged")

        destination.unlink()
        destination.mkdir()
        with self.assertRaises(OSError):
            inventory.produce_inventory(
                self.source,
                self.output,
                rabin2_executable=str(executable),
            )
        self.assertTrue(destination.is_dir())
        self.assertEqual(sentinel.read_bytes(), b"unchanged")

    def test_atomic_publish_fsyncs_file_and_directory(self) -> None:
        output = self.root / "fsync-output"
        output.mkdir()
        descriptor = safe_output.open_output_dir(output)
        try:
            with mock.patch.object(
                safe_output.os,
                "fsync",
                wraps=os.fsync,
            ) as fsync:
                safe_output.atomic_write(
                    descriptor,
                    "inventory-v1.json",
                    b"{}\n",
                )
            self.assertGreaterEqual(fsync.call_count, 2)
            self.assertEqual(fsync.call_args_list[-1].args, (descriptor,))
        finally:
            os.close(descriptor)

    def test_symlink_output_directory_and_source_are_refused(self) -> None:
        executable = self.fake_executable(self.rabin_payload())
        real_output = self.root / "real-output"
        real_output.mkdir()
        linked_output = self.root / "linked-output"
        linked_output.symlink_to(real_output, target_is_directory=True)
        with self.assertRaises(OSError):
            inventory.produce_inventory(
                self.source,
                linked_output,
                rabin2_executable=str(executable),
            )

        source_link = self.root / "source-link"
        source_link.symlink_to(self.source)
        with self.assertRaises(OSError):
            inventory.produce_inventory(
                source_link,
                self.output,
                rabin2_executable=str(executable),
            )


if __name__ == "__main__":
    unittest.main()
