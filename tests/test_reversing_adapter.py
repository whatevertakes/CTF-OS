from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from ctf_os.adapters import get_adapter
from ctf_os.sandbox.types import CommandSpec, ensure_foreground_command


class ReversingAdapterProbeTests(unittest.TestCase):
    @staticmethod
    def _probe(probe_id: str):
        return next(
            experiment
            for experiment in get_adapter("rev").initial_observations()
            if experiment.id == probe_id
        )

    @classmethod
    def _argv(
        cls,
        probe_id: str,
        target: Path | str,
        *,
        work_root: Path | str | None = None,
    ) -> tuple[str, ...]:
        argv = tuple(
            argument.replace("{primary}", str(target))
            for argument in cls._probe(probe_id).command_template
        )
        if work_root is not None:
            argv += (str(work_root),)
        return argv

    def test_elf_probes_skip_java_class_before_tool_execution(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="ctfos-rev-java-probe-test-"
        ) as temporary:
            target = Path(temporary) / "chall.class"
            target.write_bytes(b"\xca\xfe\xba\xbe\x00\x00\x00\x34")
            os.chmod(target, 0o400)

            for probe_id in (
                "assembly_observation",
                "dynamic_observation",
            ):
                with self.subTest(probe_id=probe_id):
                    argv = self._argv(probe_id, target)
                    CommandSpec.create(argv)
                    ensure_foreground_command(argv)
                    result = subprocess.run(
                        argv,
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=10,
                    )

                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(
                        result.stdout,
                        f"ctfos_rev_probe={probe_id}\n".encode("ascii")
                        + b"ctfos_rev_probe_status=skipped\n"
                        + b"ctfos_rev_probe_reason=java_class_non_elf\n",
                    )
                    self.assertEqual(result.stderr, b"")
                    self.assertEqual(target.stat().st_mode & 0o777, 0o400)

    def test_elf_probes_skip_other_unsupported_regular_format(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="ctfos-rev-unsupported-probe-test-"
        ) as temporary:
            target = Path(temporary) / "notes.txt"
            target.write_bytes(b"plain text input\n")

            for probe_id in (
                "assembly_observation",
                "dynamic_observation",
            ):
                with self.subTest(probe_id=probe_id):
                    result = subprocess.run(
                        self._argv(probe_id, target),
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=10,
                    )

                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn(
                        b"ctfos_rev_probe_status=skipped\n",
                        result.stdout,
                    )
                    self.assertIn(
                        b"ctfos_rev_probe_reason="
                        b"unsupported_non_elf_primary\n",
                        result.stdout,
                    )
                    self.assertEqual(result.stderr, b"")

    def test_followup_probes_skip_directory_without_traversal(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="ctfos-rev-directory-probe-test-"
        ) as temporary:
            target = Path(temporary) / "challenge"
            target.mkdir()
            sentinel = b"nested-content-must-not-be-read"
            (target / "chall.class").write_bytes(b"\xca\xfe\xba\xbe" + sentinel)

            for probe_id in (
                "assembly_observation",
                "decompiler_observation",
                "dynamic_observation",
            ):
                with self.subTest(probe_id=probe_id):
                    result = subprocess.run(
                        self._argv(probe_id, target),
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=10,
                    )

                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(
                        result.stdout,
                        f"ctfos_rev_probe={probe_id}\n".encode("ascii")
                        + b"ctfos_rev_probe_status=skipped\n"
                        + b"ctfos_rev_probe_reason="
                        + b"no_regular_primary_binding\n",
                    )
                    self.assertEqual(result.stderr, b"")
                    self.assertNotIn(sentinel, result.stdout)

    def test_followup_probes_reject_symlink_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="ctfos-rev-symlink-probe-test-"
        ) as temporary:
            root = Path(temporary)
            source = root / "source"
            source.write_bytes(b"\x7fELF")
            target = root / "primary"
            target.symlink_to(source)

            for probe_id in (
                "assembly_observation",
                "decompiler_observation",
                "dynamic_observation",
            ):
                with self.subTest(probe_id=probe_id):
                    result = subprocess.run(
                        self._argv(probe_id, target),
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=10,
                    )

                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, b"")
                    self.assertEqual(
                        result.stderr,
                        f"ctfos_rev_probe={probe_id}\n".encode("ascii")
                        + b"ctfos_rev_probe_error="
                        + b"symlink_primary_binding\n",
                    )

    def test_regular_elf_assembly_keeps_objdump_behavior(self) -> None:
        result = subprocess.run(
            self._argv("assembly_observation", "/bin/true"),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"file format elf", result.stdout)

    def test_mode_0400_elf_dynamic_uses_private_executable_copy(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="ctfos-rev-dynamic-probe-test-"
        ) as temporary:
            root = Path(temporary)
            target = root / "immutable-true"
            target.write_bytes(Path("/bin/true").read_bytes())
            os.chmod(target, 0o400)
            wrapper = root / "ctfwrap"
            wrapper.write_text(
                "#!/bin/sh\n"
                "printf 'ctfwrap_target=%s\\n' \"$2\"\n"
                "/usr/bin/stat --format='ctfwrap_mode=%a' -- \"$2\"\n"
                "\"$2\"\n"
                "printf 'ctfwrap_child_exit=%s\\n' \"$?\"\n"
                "exit 7\n",
                encoding="utf-8",
            )
            os.chmod(wrapper, 0o700)
            environment = dict(os.environ)
            environment["PATH"] = temporary + os.pathsep + environment["PATH"]

            result = subprocess.run(
                self._argv(
                    "dynamic_observation",
                    target,
                    work_root=root,
                ),
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                env=environment,
            )
            self.assertEqual(target.stat().st_mode & 0o777, 0o400)
            self.assertEqual(
                list(root.glob("ctfos-rev-dynamic.*")),
                [],
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        output = result.stdout.decode("utf-8")
        self.assertIn("ctfwrap_target=", output)
        self.assertIn("/ctfos-rev-dynamic.", output)
        self.assertNotIn(f"ctfwrap_target={target}\n", output)
        self.assertIn("ctfwrap_mode=500\n", output)
        self.assertIn("ctfwrap_child_exit=0\n", output)
        self.assertIn("ctfos_rev_dynamic_exit=7\n", output)

    def test_dynamic_probe_missing_ctfwrap_fails_before_staging(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="ctfos-rev-missing-wrapper-test-"
        ) as temporary:
            root = Path(temporary)
            target = root / "immutable-true"
            target.write_bytes(Path("/bin/true").read_bytes())
            os.chmod(target, 0o400)
            environment = dict(os.environ)
            environment["PATH"] = "/usr/bin:/bin"

            result = subprocess.run(
                self._argv(
                    "dynamic_observation",
                    target,
                    work_root=root,
                ),
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                env=environment,
            )

            self.assertEqual(target.stat().st_mode & 0o777, 0o400)
            self.assertEqual(
                list(root.glob("ctfos-rev-dynamic.*")),
                [],
            )

        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(
            result.stderr,
            b"ctfos_rev_probe=dynamic_observation\n"
            b"ctfos_rev_probe_error=missing_ctfwrap\n",
        )

    def test_probe_shell_keeps_primary_out_of_shell_source(self) -> None:
        primary = "/challenge/name with 'quotes' and $shell"
        for probe_id in (
            "assembly_observation",
            "decompiler_observation",
            "dynamic_observation",
        ):
            with self.subTest(probe_id=probe_id):
                argv = self._argv(probe_id, primary)
                self.assertEqual(argv[:2], ("/bin/sh", "-lc"))
                self.assertNotIn(primary, argv[2])
                self.assertEqual(argv[-2], primary)
                self.assertEqual(argv[-1], probe_id)
                self.assertFalse(self._probe(probe_id).requires_network)
                if probe_id == "dynamic_observation":
                    self.assertIn(
                        '/usr/bin/cp -- "$target" "$staged"',
                        argv[2],
                    )
                    self.assertIn(
                        '/usr/bin/chmod 0500 -- "$staged"',
                        argv[2],
                    )
                    self.assertNotIn(
                        'chmod 0500 -- "$target"',
                        argv[2],
                    )
                CommandSpec.create(argv)
                ensure_foreground_command(argv)


if __name__ == "__main__":
    unittest.main()
