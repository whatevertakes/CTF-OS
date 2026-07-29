#!/usr/bin/env python3
"""Focused tests for the fixed Rev stdin executor."""

from __future__ import annotations

import importlib.util
import io
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPOSITORY = Path(__file__).resolve().parent.parent
REV_TEMPLATES = REPOSITORY / "templates" / "rev"
module_spec = importlib.util.spec_from_file_location(
    "ctf_rev_stdin_exec_under_test",
    REV_TEMPLATES / "stdin_exec.py",
)
assert module_spec is not None and module_spec.loader is not None
stdin_exec = importlib.util.module_from_spec(module_spec)
sys.modules[module_spec.name] = stdin_exec
module_spec.loader.exec_module(stdin_exec)


class RevStdinExecTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="ctf-rev-stdin-exec-"
        )
        self.root = Path(self.temporary.name)
        self.challenge = self.root / "challenge"
        self.work = self.root / "work"
        self.challenge.mkdir()
        self.work.mkdir()
        self.cat = self._copy_executable("cat", "bin/cat")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _copy_executable(self, name: str, relative: str) -> Path:
        source = shutil.which(name)
        if source is None:
            self.skipTest(f"{name} is unavailable")
        destination = self.challenge / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        destination.chmod(0o500)
        return destination

    def _invoke(
        self,
        binary: str,
        input_path: str,
    ) -> subprocess.CompletedProcess[bytes]:
        helper = (
            "import pathlib,sys,stdin_exec;"
            "raise SystemExit(stdin_exec._preserve_target_status("
            "stdin_exec.execute_stdin("
            "sys.argv[1],sys.argv[2],"
            "challenge_root=pathlib.Path(sys.argv[3]),"
            "work_root=pathlib.Path(sys.argv[4]))))"
        )
        environment = {
            "PYTHONPATH": str(REV_TEMPLATES),
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        }
        return subprocess.run(
            (
                sys.executable,
                "-c",
                helper,
                binary,
                input_path,
                str(self.challenge),
                str(self.work),
            ),
            capture_output=True,
            env=environment,
            check=False,
        )

    def test_no_args_and_unknown_candidate_option_print_bounded_usage(
        self,
    ) -> None:
        for argv in (
            (),
            ("--candidate", "flag{not-an-option}"),
            (
                "--binary",
                "/challenge/bin/cat",
                "--input",
                "/work/input.bin",
                "extra",
            ),
        ):
            stream = io.StringIO()
            with (
                self.subTest(argv=argv),
                mock.patch.object(sys, "stderr", stream),
            ):
                self.assertEqual(stdin_exec.main(argv), 2)
            self.assertIn("Usage: stdin_exec.py", stream.getvalue())
            self.assertLessEqual(
                len(stream.getvalue().encode("utf-8")),
                512,
            )

    def test_exact_binary_input_including_nul_reaches_inherited_output(
        self,
    ) -> None:
        payload = b"prefix\x00suffix\n"
        (self.work / "input.bin").write_bytes(payload)
        result = self._invoke(
            "/challenge/bin/cat",
            "/work/input.bin",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, payload)
        self.assertEqual(result.stderr, b"")

    def test_target_exit_status_is_returned(self) -> None:
        self._copy_executable("false", "bin/false")
        (self.work / "input.bin").write_bytes(b"unused")
        result = self._invoke(
            "/challenge/bin/false",
            "/work/input.bin",
        )
        self.assertEqual(result.returncode, 1)

    def test_fixed_environment_replaces_parent_environment(self) -> None:
        self._copy_executable("env", "bin/env")
        (self.work / "input.bin").write_bytes(b"")
        result = self._invoke(
            "/challenge/bin/env",
            "/work/input.bin",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        observed = set(result.stdout.decode("utf-8").splitlines())
        expected = {
            f"{name}={value}"
            for name, value in stdin_exec.FIXED_ENVIRONMENT.items()
        }
        self.assertEqual(observed, expected)

    def test_subprocess_contract_has_no_shell_target_args_or_candidate(
        self,
    ) -> None:
        (self.work / "input.bin").write_bytes(b"input")
        completed = subprocess.CompletedProcess((), 0)
        with mock.patch.object(
            stdin_exec.subprocess,
            "run",
            return_value=completed,
        ) as run:
            status = stdin_exec.execute_stdin(
                "/challenge/bin/cat",
                "/work/input.bin",
                challenge_root=self.challenge,
                work_root=self.work,
            )
        self.assertEqual(status, 0)
        positional, keywords = run.call_args
        command = positional[0]
        self.assertEqual(len(command), 1)
        self.assertRegex(command[0], r"^/proc/self/fd/[0-9]+$")
        self.assertEqual(keywords["executable"], command[0])
        self.assertIs(keywords["shell"], False)
        self.assertEqual(
            keywords["env"],
            stdin_exec.FIXED_ENVIRONMENT,
        )
        rendered = repr(run.call_args).casefold()
        self.assertNotIn("candidate", rendered)
        self.assertNotIn("success", rendered)

    def test_traversal_and_paths_outside_fixed_roots_are_rejected(
        self,
    ) -> None:
        (self.work / "input.bin").write_bytes(b"input")
        cases = (
            ("/challenge/../bin/cat", "/work/input.bin"),
            ("/challenge/bin//cat", "/work/input.bin"),
            (str(self.cat), "/work/input.bin"),
            ("/challenge/bin/cat", "/tmp/input.bin"),
            ("/challenge/bin/cat", "/work/../input.bin"),
        )
        for binary, input_path in cases:
            with (
                self.subTest(binary=binary, input=input_path),
                self.assertRaises(stdin_exec.StdinExecError) as raised,
            ):
                stdin_exec.execute_stdin(
                    binary,
                    input_path,
                    challenge_root=self.challenge,
                    work_root=self.work,
                )
            self.assertEqual(raised.exception.exit_code, 2)

    def test_leaf_and_intermediate_symlinks_are_rejected(self) -> None:
        (self.work / "input.bin").write_bytes(b"input")
        (self.challenge / "cat-link").symlink_to(self.cat)
        real_directory = self.challenge / "real"
        real_directory.mkdir()
        linked_cat = real_directory / "cat"
        shutil.copyfile(self.cat, linked_cat)
        linked_cat.chmod(0o500)
        (self.challenge / "dir-link").symlink_to(
            real_directory,
            target_is_directory=True,
        )
        (self.work / "input-link").symlink_to(self.work / "input.bin")

        for binary, input_path in (
            ("/challenge/cat-link", "/work/input.bin"),
            ("/challenge/dir-link/cat", "/work/input.bin"),
            ("/challenge/bin/cat", "/work/input-link"),
        ):
            with (
                self.subTest(binary=binary, input=input_path),
                self.assertRaises(stdin_exec.StdinExecError),
            ):
                stdin_exec.execute_stdin(
                    binary,
                    input_path,
                    challenge_root=self.challenge,
                    work_root=self.work,
                )

    def test_non_elf_and_non_executable_files_are_rejected(self) -> None:
        (self.work / "input.bin").write_bytes(b"input")
        text = self.challenge / "text"
        text.write_bytes(b"#!/bin/sh\nexit 0\n")
        text.chmod(0o500)
        non_executable = self.challenge / "non-executable"
        shutil.copyfile(self.cat, non_executable)
        non_executable.chmod(0o400)

        for binary, reason in (
            ("/challenge/text", "binary_not_elf"),
            (
                "/challenge/non-executable",
                "binary_not_executable",
            ),
        ):
            with (
                self.subTest(binary=binary),
                self.assertRaisesRegex(
                    stdin_exec.StdinExecError,
                    reason,
                ),
            ):
                stdin_exec.execute_stdin(
                    binary,
                    "/work/input.bin",
                    challenge_root=self.challenge,
                    work_root=self.work,
                )

    def test_oversized_input_is_rejected_without_reading_it(self) -> None:
        oversized = self.work / "oversized.bin"
        oversized.touch()
        os.truncate(
            oversized,
            stdin_exec.MAX_ACCEPTED_INPUT_BYTES + 1,
        )
        with self.assertRaisesRegex(
            stdin_exec.StdinExecError,
            "input_size_limit_exceeded",
        ):
            stdin_exec.execute_stdin(
                "/challenge/bin/cat",
                "/work/oversized.bin",
                challenge_root=self.challenge,
                work_root=self.work,
            )

    @unittest.skipUnless(shutil.which("cc"), "cc is unavailable")
    def test_signal_status_and_cli_signal_forwarding(self) -> None:
        source = self.root / "raise-signal.c"
        source.write_text(
            "#include <signal.h>\n"
            "int main(void) { raise(SIGTERM); return 0; }\n",
            encoding="utf-8",
        )
        target = self.challenge / "raise-signal"
        compiled = subprocess.run(
            (shutil.which("cc"), str(source), "-o", str(target)),
            capture_output=True,
            check=False,
        )
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        target.chmod(0o500)
        (self.work / "input.bin").write_bytes(b"")

        status = stdin_exec.execute_stdin(
            "/challenge/raise-signal",
            "/work/input.bin",
            challenge_root=self.challenge,
            work_root=self.work,
        )
        self.assertEqual(status, -signal.SIGTERM)
        propagated = self._invoke(
            "/challenge/raise-signal",
            "/work/input.bin",
        )
        self.assertEqual(propagated.returncode, -signal.SIGTERM)
        with (
            mock.patch.object(signal, "signal") as reset,
            mock.patch.object(os, "kill") as kill,
            mock.patch.object(os, "getpid", return_value=4242),
        ):
            fallback = stdin_exec._preserve_target_status(status)
        reset.assert_called_once_with(signal.SIGTERM, signal.SIG_DFL)
        kill.assert_called_once_with(4242, signal.SIGTERM)
        self.assertEqual(fallback, 128 + signal.SIGTERM)


if __name__ == "__main__":
    unittest.main()
