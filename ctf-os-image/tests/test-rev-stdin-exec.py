#!/usr/bin/env python3
"""Focused tests for the fixed Rev stdin executor."""

from __future__ import annotations

import fcntl
import importlib.util
import io
import os
import resource
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

    def _compile_c(self, relative: str, source_text: str) -> Path:
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("cc is unavailable")
        source = self.root / (Path(relative).name + ".c")
        source.write_text(source_text, encoding="utf-8")
        target = self.challenge / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        compiled = subprocess.run(
            (compiler, str(source), "-o", str(target)),
            capture_output=True,
            check=False,
        )
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        target.chmod(0o500)
        return target

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
        input_file = self.work / "input.bin"
        input_file.write_bytes(b"input")
        source_metadata = input_file.stat()
        completed = subprocess.CompletedProcess((), 0)
        call_order: list[str] = []

        def inspect_spawn(
            command: tuple[str, ...],
            **keywords: object,
        ) -> subprocess.CompletedProcess[tuple[()]]:
            call_order.append("spawn")
            stdin_descriptor = keywords["stdin"]
            self.assertIsInstance(stdin_descriptor, int)
            stdin_flags = fcntl.fcntl(
                stdin_descriptor,
                fcntl.F_GETFL,
            )
            self.assertEqual(
                stdin_flags & os.O_ACCMODE,
                os.O_RDONLY,
            )
            _, required_seals = stdin_exec._memfd_contract()
            self.assertEqual(
                fcntl.fcntl(
                    stdin_descriptor,
                    stdin_exec._F_GET_SEALS,
                )
                & required_seals,
                required_seals,
            )
            stdin_metadata = os.fstat(stdin_descriptor)
            memfd_descriptors: list[int] = []
            for descriptor_name in os.listdir("/proc/self/fd"):
                try:
                    descriptor = int(descriptor_name)
                    metadata = os.fstat(descriptor)
                except (OSError, ValueError):
                    continue
                if (
                    metadata.st_dev,
                    metadata.st_ino,
                ) == (
                    stdin_metadata.st_dev,
                    stdin_metadata.st_ino,
                ):
                    memfd_descriptors.append(descriptor)
                self.assertNotEqual(
                    (metadata.st_dev, metadata.st_ino),
                    (source_metadata.st_dev, source_metadata.st_ino),
                    "the mutable source FD remained open at spawn",
                )
            self.assertEqual(
                memfd_descriptors,
                [stdin_descriptor],
                "a writable memfd descriptor remained open at spawn",
            )
            return completed

        with (
            mock.patch.object(
                stdin_exec,
                "_disable_core_dumps",
                side_effect=lambda: call_order.append("core-limit"),
            ) as disable_core,
            mock.patch.object(
                stdin_exec.subprocess,
                "run",
                side_effect=inspect_spawn,
            ) as run,
        ):
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
        self.assertEqual(command, ("/challenge/bin/cat",))
        self.assertRegex(
            keywords["executable"],
            r"^/proc/self/fd/[0-9]+$",
        )
        self.assertIs(keywords["shell"], False)
        self.assertEqual(
            keywords["env"],
            stdin_exec.FIXED_ENVIRONMENT,
        )
        self.assertEqual(len(keywords["pass_fds"]), 1)
        disable_core.assert_called_once_with()
        self.assertEqual(call_order, ["core-limit", "spawn"])
        self.assertNotIn("preexec_fn", keywords)
        rendered = repr(run.call_args).casefold()
        self.assertNotIn("candidate", rendered)
        self.assertNotIn("success", rendered)

    def test_core_limit_is_set_verified_and_fail_closed(self) -> None:
        with (
            mock.patch.object(
                stdin_exec.resource,
                "setrlimit",
            ) as setrlimit,
            mock.patch.object(
                stdin_exec.resource,
                "getrlimit",
                return_value=(0, 0),
            ) as getrlimit,
        ):
            stdin_exec._disable_core_dumps()
        setrlimit.assert_called_once_with(
            resource.RLIMIT_CORE,
            (0, 0),
        )
        getrlimit.assert_called_once_with(resource.RLIMIT_CORE)

        with (
            mock.patch.object(
                stdin_exec.resource,
                "setrlimit",
            ),
            mock.patch.object(
                stdin_exec.resource,
                "getrlimit",
                return_value=(0, 1),
            ),
            self.assertRaisesRegex(
                stdin_exec.StdinExecError,
                "core_limit_not_enforced",
            ),
        ):
            stdin_exec._disable_core_dumps()

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

    def test_same_size_change_during_read_is_rejected(self) -> None:
        input_file = self.work / "changing.bin"
        input_file.write_bytes(b"first-version")
        descriptor = os.open(input_file, os.O_RDONLY)
        before = os.fstat(descriptor)
        original_pread = os.pread
        changed = False

        def mutate_after_read(
            selected: int,
            count: int,
            offset: int,
        ) -> bytes:
            nonlocal changed
            chunk = original_pread(selected, count, offset)
            if selected == descriptor and not changed:
                changed = True
                with input_file.open("r+b") as stream:
                    stream.seek(0)
                    stream.write(b"other-version")
                    stream.flush()
                    os.fsync(stream.fileno())
                input_file.chmod(0o600)
            return chunk

        try:
            with (
                mock.patch.object(
                    stdin_exec.os,
                    "pread",
                    side_effect=mutate_after_read,
                ),
                self.assertRaisesRegex(
                    stdin_exec.StdinExecError,
                    "input_changed_during_read",
                ),
            ):
                stdin_exec._read_stable_input(descriptor, before)
        finally:
            os.close(descriptor)

    def test_growth_during_read_is_rejected_before_spawn(self) -> None:
        input_file = self.work / "growing.bin"
        input_file.write_bytes(b"initial")
        descriptor = os.open(input_file, os.O_RDONLY)
        before = os.fstat(descriptor)
        original_pread = os.pread
        grown = False

        def grow_after_read(
            selected: int,
            count: int,
            offset: int,
        ) -> bytes:
            nonlocal grown
            chunk = original_pread(selected, count, offset)
            if selected == descriptor and not grown:
                grown = True
                with input_file.open("ab") as stream:
                    stream.write(b"-growth")
                    stream.flush()
                    os.fsync(stream.fileno())
            return chunk

        try:
            with (
                mock.patch.object(
                    stdin_exec.os,
                    "pread",
                    side_effect=grow_after_read,
                ),
                self.assertRaisesRegex(
                    stdin_exec.StdinExecError,
                    "input_changed_during_read",
                ),
            ):
                stdin_exec._read_stable_input(descriptor, before)
        finally:
            os.close(descriptor)

    def test_memfd_readback_and_seal_failures_are_fail_closed(
        self,
    ) -> None:
        with (
            mock.patch.object(
                stdin_exec,
                "_read_memfd_exact",
                return_value=b"wrong",
            ),
            self.assertRaisesRegex(
                stdin_exec.StdinExecError,
                "input_snapshot_readback_mismatch",
            ),
        ):
            with stdin_exec._sealed_stdin_snapshot(b"right"):
                self.fail("a mismatched snapshot was yielded")

        real_fcntl = fcntl.fcntl

        def hide_seals(
            descriptor: int,
            operation: int,
            *arguments: int,
        ) -> int:
            if operation == stdin_exec._F_GET_SEALS:
                return 0
            return real_fcntl(descriptor, operation, *arguments)

        with (
            mock.patch.object(
                stdin_exec.fcntl,
                "fcntl",
                side_effect=hide_seals,
            ),
            self.assertRaisesRegex(
                stdin_exec.StdinExecError,
                "input_snapshot_seals_missing",
            ),
        ):
            with stdin_exec._sealed_stdin_snapshot(b"payload"):
                self.fail("an unverified snapshot was yielded")

    def test_short_memfd_writes_are_completed_without_pipe_fallback(
        self,
    ) -> None:
        payload = b"short\x00writes"
        original_write = os.write

        def short_write(
            descriptor: int,
            remaining: bytes | memoryview,
        ) -> int:
            return original_write(descriptor, remaining[:2])

        with mock.patch.object(
            stdin_exec.os,
            "write",
            side_effect=short_write,
        ):
            with stdin_exec._sealed_stdin_snapshot(payload) as descriptor:
                self.assertEqual(
                    os.read(descriptor, len(payload) + 1),
                    payload,
                )

        (self.work / "input.bin").write_bytes(payload)
        with (
            mock.patch.object(
                stdin_exec.os,
                "memfd_create",
                side_effect=OSError("unavailable"),
            ),
            mock.patch.object(stdin_exec.subprocess, "run") as run,
            self.assertRaisesRegex(
                stdin_exec.StdinExecError,
                "input_snapshot_create_failed",
            ),
        ):
            stdin_exec.execute_stdin(
                "/challenge/bin/cat",
                "/work/input.bin",
                challenge_root=self.challenge,
                work_root=self.work,
            )
        run.assert_not_called()

    @unittest.skipUnless(shutil.which("cc"), "cc is unavailable")
    def test_sealed_stdin_resists_target_mutation_and_disables_core(
        self,
    ) -> None:
        self._compile_c(
            "malicious-stdin",
            """
#include <fcntl.h>
#include <stdint.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    struct rlimit core;
    unsigned char byte = 'X';
    unsigned char buffer[257];
    ssize_t count;
    int reopened;

    if (getrlimit(RLIMIT_CORE, &core) != 0 ||
        core.rlim_cur != 0 || core.rlim_max != 0) {
        return 31;
    }
    (void)fchmod(STDIN_FILENO, 0600);
    reopened = open("/proc/self/fd/0", O_WRONLY | O_TRUNC);
    if (reopened >= 0) {
        (void)write(reopened, &byte, 1);
        (void)close(reopened);
    }
    (void)ftruncate(STDIN_FILENO, 0);
    (void)write(STDIN_FILENO, &byte, 1);
    (void)pwrite(STDIN_FILENO, &byte, 1, 0);
    if (lseek(STDIN_FILENO, 0, SEEK_SET) != 0) {
        return 32;
    }
    while ((count = read(STDIN_FILENO, buffer, sizeof(buffer))) > 0) {
        ssize_t offset = 0;
        while (offset < count) {
            ssize_t written = write(
                STDOUT_FILENO,
                buffer + offset,
                (size_t)(count - offset)
            );
            if (written <= 0) {
                return 33;
            }
            offset += written;
        }
    }
    return count == 0 ? 0 : 34;
}
""",
        )
        payload = b"sealed\x00payload\n"
        source = self.work / "input.bin"
        source.write_bytes(payload)
        before = stdin_exec._stable_file_identity(source.stat())

        result = self._invoke(
            "/challenge/malicious-stdin",
            "/work/input.bin",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, payload)
        self.assertEqual(source.read_bytes(), payload)
        self.assertEqual(
            stdin_exec._stable_file_identity(source.stat()),
            before,
        )

    @unittest.skipUnless(shutil.which("cc"), "cc is unavailable")
    def test_target_receives_original_virtual_path_as_argv_zero(
        self,
    ) -> None:
        self._compile_c(
            "argv-zero",
            """
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    size_t length;
    if (argc != 1) {
        return 41;
    }
    length = strlen(argv[0]);
    return write(STDOUT_FILENO, argv[0], length) == (ssize_t)length
        ? 0 : 42;
}
""",
        )
        (self.work / "input.bin").write_bytes(b"")
        result = self._invoke(
            "/challenge/argv-zero",
            "/work/input.bin",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"/challenge/argv-zero")

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
            fallback = stdin_exec._preserve_target_status(-signal.SIGTERM)
        reset.assert_called_once_with(signal.SIGTERM, signal.SIG_DFL)
        kill.assert_called_once_with(4242, signal.SIGTERM)
        self.assertEqual(fallback, 128 + signal.SIGTERM)


if __name__ == "__main__":
    unittest.main()
