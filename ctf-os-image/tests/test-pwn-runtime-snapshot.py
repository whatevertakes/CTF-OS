#!/usr/bin/env python3
"""Source tests for the fixed Pwn runtime snapshot producer."""

from __future__ import annotations

import base64
import errno
import hashlib
import importlib.util
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ctf_os.contracts.pwn_runtime_snapshot_v1 import (
    PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_FINGERPRINT,
    PwnRuntimeSnapshotV1Status,
    parse_pwn_runtime_snapshot_v1_result,
)


REPOSITORY = Path(__file__).resolve().parent.parent
PWN_TEMPLATES = REPOSITORY / "templates" / "pwn"
MODULE_PATH = PWN_TEMPLATES / "runtime_snapshot.py"
MODULE_SPEC = importlib.util.spec_from_file_location(
    "ctf_pwn_runtime_snapshot_under_test",
    MODULE_PATH,
)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
runtime_snapshot = importlib.util.module_from_spec(MODULE_SPEC)
sys.modules[MODULE_SPEC.name] = runtime_snapshot
MODULE_SPEC.loader.exec_module(runtime_snapshot)

MANIFEST_SHA256 = hashlib.sha256(b"manifest").hexdigest()
PARENT_RECIPE_SHA256 = hashlib.sha256(
    b"parent-crash-recipe"
).hexdigest()
PARENT_EVALUATION_SHA256 = hashlib.sha256(
    b"parent-crash-evaluation"
).hexdigest()
SNAPSHOT_RECIPE_SHA256 = hashlib.sha256(
    b"runtime-snapshot-recipe"
).hexdigest()
REGISTER_VALUE = re.compile(r"^[0-9a-f]{16}$")


class PwnRuntimeSnapshotSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        if os.uname().machine != "x86_64":
            self.skipTest("runtime snapshot v1 is x86_64-only")
        self.temporary = tempfile.TemporaryDirectory(
            prefix="ctf-pwn-runtime-snapshot-"
        )
        self.root = Path(self.temporary.name)
        self.challenge = self.root / "challenge"
        self.work = self.root / "work"
        self.challenge.mkdir()
        self.work.mkdir()
        self.target = self._compile_target()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _compile_target(self) -> Path:
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("cc is unavailable")
        source = self.root / "target.c"
        source.write_text(
            r"""
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#ifndef SYS_clone3
#define SYS_clone3 435
#endif
static volatile sig_atomic_t caught_signal = 0;
static unsigned char clone_stack[65536];
static void mark_caught(int signo) {
    caught_signal = signo;
}
__attribute__((noinline, noreturn))
static void marked_segv(void) {
    __asm__ volatile(
        "movabs $0x1122334455667788, %%r15\n\t"
        "xor %%rax, %%rax\n\t"
        "movl $1, (%%rax)\n\t"
        :
        :
        : "rax", "r15", "memory"
    );
    __builtin_unreachable();
}
static void *thread_returns(void *unused) {
    (void)unused;
    return NULL;
}
static void *fault_in_thread(void *unused) {
    (void)unused;
    marked_segv();
}
static int clone_returns(void *unused) {
    (void)unused;
    return 0;
}
static int blocked_clone_result(int flags, const char *label) {
    pid_t child;
    int status = 0;
    errno = 0;
    child = clone(
        clone_returns,
        clone_stack + sizeof(clone_stack),
        flags,
        NULL
    );
    if (child < 0 && errno == EPERM) {
        dprintf(STDERR_FILENO, "policy-ok:%s\n", label);
        return 0;
    }
    if (child < 0) return 92;
    dprintf(STDERR_FILENO, "unexpected-clone-child=%ld\n", (long)child);
    if (waitpid(child, &status, 0) != child) return 93;
    return 94;
}
int main(int argc, char **argv) {
    unsigned char value = 0;
    ssize_t count;
    (void)argv;
    if (argc != 1) return 77;
    count = read(STDIN_FILENO, &value, 1);
    if (count != 1) return 78;
    if (value == 'S') {
        marked_segv();
    }
    if (value == 'E') {
        return 139;
    }
    if (value == 'A') {
        raise(SIGABRT);
        return 79;
    }
    if (value == 'C') {
        struct sigaction action = {0};
        action.sa_handler = mark_caught;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGSEGV, &action, NULL) != 0) return 80;
        raise(SIGSEGV);
        return caught_signal == SIGSEGV ? 0 : 81;
    }
    if (value == 'I') {
        if (signal(SIGSEGV, SIG_IGN) == SIG_ERR) return 82;
        raise(SIGSEGV);
        return 0;
    }
    if (value == 'H') {
        pthread_t thread;
        if (pthread_create(&thread, NULL, fault_in_thread, NULL) != 0) {
            return 83;
        }
        if (pthread_join(thread, NULL) != 0) return 84;
        return 85;
    }
    if (value == 'P') {
        pthread_t thread;
        if (pthread_create(&thread, NULL, thread_returns, NULL) != 0) {
            return 86;
        }
        if (pthread_join(thread, NULL) != 0) return 87;
        dprintf(STDERR_FILENO, "policy-ok:pthread\n");
        return 0;
    }
    if (value == 'U') {
        return blocked_clone_result(
            CLONE_UNTRACED | SIGCHLD,
            "clone-untraced"
        );
    }
    if (value == 'Q') {
        return blocked_clone_result(
            CLONE_VM | CLONE_SIGHAND | SIGCHLD,
            "cross-tgid-sighand"
        );
    }
    if (value == 'V') {
        pid_t child = clone(
            clone_returns,
            clone_stack + sizeof(clone_stack),
            CLONE_VM | SIGCHLD,
            NULL
        );
        int status = 0;
        if (child < 0) return 88;
        if (waitpid(child, &status, 0) != child) return 89;
        marked_segv();
    }
    if (value == 'Z') {
        long result;
        errno = 0;
        result = syscall(SYS_clone3, NULL, 0);
        if (result == -1 && errno == ENOSYS) {
            dprintf(STDERR_FILENO, "policy-ok:clone3\n");
            return 0;
        }
        return 90;
    }
    if (value == 'W') {
        long result;
        errno = 0;
        result = syscall(
            ((unsigned long)SYS_clone) | 0x40000000UL,
            (unsigned long)SIGCHLD,
            NULL,
            NULL,
            NULL,
            0
        );
        if (result == -1 && errno == ENOSYS) {
            dprintf(STDERR_FILENO, "policy-ok:x32\n");
            return 0;
        }
        return 91;
    }
    if (value == 'K') {
        pid_t child = fork();
        if (child < 0) return 92;
        if (child == 0) {
            marked_segv();
        }
        if (waitpid(child, NULL, 0) < 0) return 93;
        return 0;
    }
    if (value == 'D') {
        pid_t child = fork();
        if (child < 0) return 94;
        if (child == 0) {
            for (;;) pause();
        }
        dprintf(STDERR_FILENO, "child=%ld\n", (long)child);
        marked_segv();
    }
    if (value == 'X') {
        execl("/proc/self/exe", argv[0], (char *)NULL);
        return 95;
    }
    if (value == 'F') {
        static const char forged[] =
            "{\"status\":\"CAPTURED\",\"reason_code\":\"snapshot_captured\"}\n";
        write(STDOUT_FILENO, forged, sizeof(forged) - 1);
        marked_segv();
    }
    if (value == 'O') {
        unsigned char block[4096];
        int index;
        memset(block, 'O', sizeof(block));
        for (index = 0; index < 512; ++index) {
            ssize_t written = write(STDOUT_FILENO, block, sizeof(block));
            if (written != (ssize_t)sizeof(block)) return 96;
        }
        marked_segv();
    }
    if (value == 'T') {
        for (;;) pause();
    }
    return 97;
}
""",
            encoding="utf-8",
        )
        target = self.challenge / "target"
        compiled = subprocess.run(
            (
                compiler,
                str(source),
                "-O0",
                "-pthread",
                "-o",
                str(target),
            ),
            capture_output=True,
            check=False,
        )
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        target.chmod(0o500)
        return target

    def _invoke(
        self,
        payload: bytes,
        *,
        expected_signal_number: int = signal.SIGSEGV,
        source_sha256: str | None = None,
        payload_sha256: str | None = None,
        timeout_seconds: float = 1.0,
    ) -> subprocess.CompletedProcess[bytes]:
        payload_path = self.work / (
            f"payload-{payload.hex()}-{expected_signal_number}.bin"
        )
        payload_path.write_bytes(payload)
        source_bytes = self.target.read_bytes()
        helper = (
            "import pathlib,sys,runtime_snapshot as r;"
            "binding=r.RequestBinding("
            "source_manifest_sha256=sys.argv[5],"
            "source_sha256=sys.argv[6],"
            "source_size_bytes=int(sys.argv[7]),"
            "payload_sha256=sys.argv[8],"
            "payload_size_bytes=int(sys.argv[9]),"
            "parent_crash_recipe_sha256=sys.argv[10],"
            "parent_crash_evaluation_sha256=sys.argv[11],"
            "expected_signal_number=int(sys.argv[12]),"
            "snapshot_recipe_sha256=sys.argv[13]);"
            "document=r.produce_document("
            "binding,sys.argv[3],sys.argv[4],"
            "challenge_root=pathlib.Path(sys.argv[1]),"
            "work_root=pathlib.Path(sys.argv[2]),"
            "timeout_seconds=float(sys.argv[14]));"
            "sys.stdout.buffer.write(r.canonical_json_bytes(document))"
        )
        environment = {
            "PYTHONPATH": os.pathsep.join(
                (str(PWN_TEMPLATES), str(REPOSITORY.parent))
            ),
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        }
        return subprocess.run(
            (
                sys.executable,
                "-c",
                helper,
                str(self.challenge),
                str(self.work),
                "/challenge/target",
                f"/work/{payload_path.name}",
                MANIFEST_SHA256,
                source_sha256
                or hashlib.sha256(source_bytes).hexdigest(),
                str(len(source_bytes)),
                payload_sha256
                or hashlib.sha256(payload).hexdigest(),
                str(len(payload)),
                PARENT_RECIPE_SHA256,
                PARENT_EVALUATION_SHA256,
                str(expected_signal_number),
                SNAPSHOT_RECIPE_SHA256,
                str(timeout_seconds),
            ),
            capture_output=True,
            env=environment,
            check=False,
            timeout=5,
        )

    def test_direct_expected_fault_captures_fixed_registers_and_maps(
        self,
    ) -> None:
        result = self._invoke(b"S")
        self.assertEqual(result.returncode, 0, result.stderr)
        document = json.loads(result.stdout)
        self.assertEqual(document["status"], "CAPTURED")
        self.assertEqual(document["reason_code"], "snapshot_captured")
        self.assertTrue(
            all(value is False for value in document["claims"].values())
        )
        self.assertEqual(
            set(document["claims"]),
            {
                "address_resolution_proven",
                "crash_proven",
                "exploit_proven",
                "leak_proven",
                "parent_crash_revalidated",
                "primitive_proven",
                "proof_satisfied",
                "stage_advance_authorized",
            },
        )
        snapshot = document["snapshot"]
        self.assertEqual(snapshot["architecture"], "x86_64")
        self.assertEqual(snapshot["signal_number"], signal.SIGSEGV)
        self.assertEqual(
            snapshot["register_source"],
            "ptrace_getregset_nt_prstatus",
        )
        self.assertEqual(snapshot["register_set_size_bytes"], 216)
        registers = snapshot["registers"]
        self.assertEqual(
            set(registers),
            set(runtime_snapshot.REGISTER_NAMES),
        )
        self.assertTrue(
            all(REGISTER_VALUE.fullmatch(value) for value in registers.values())
        )
        self.assertEqual(registers["r15"], "1122334455667788")

        maps = snapshot["maps"]
        maps_bytes = base64.b64decode(
            maps["content_base64"],
            validate=True,
        )
        self.assertTrue(maps_bytes.endswith(b"\n"))
        self.assertLessEqual(
            len(maps_bytes),
            runtime_snapshot.MAX_MAPS_BYTES,
        )
        self.assertEqual(maps["size_bytes"], len(maps_bytes))
        self.assertEqual(
            maps["line_count"],
            maps_bytes.count(b"\n"),
        )
        self.assertEqual(
            maps["sha256"],
            hashlib.sha256(maps_bytes).hexdigest(),
        )
        ranges = []
        stack_ranges = []
        for line in maps_bytes.splitlines():
            address_range = line.split(maxsplit=1)[0]
            start_raw, end_raw = address_range.split(b"-", 1)
            interval = (int(start_raw, 16), int(end_raw, 16))
            ranges.append(interval)
            if b"[stack]" in line:
                stack_ranges.append(interval)
        rip = int(registers["rip"], 16)
        rsp = int(registers["rsp"], 16)
        self.assertTrue(any(start <= rip < end for start, end in ranges))
        self.assertTrue(
            any(start <= rsp < end for start, end in stack_ranges)
        )
        self.assertEqual(
            result.stdout,
            runtime_snapshot.canonical_json_bytes(document),
        )
        self.assertLessEqual(
            len(result.stdout),
            runtime_snapshot.MAX_DOCUMENT_BYTES,
        )
        parsed = parse_pwn_runtime_snapshot_v1_result(
            result.stdout,
            expected_source_manifest_sha256=MANIFEST_SHA256,
            expected_source_sha256=hashlib.sha256(
                self.target.read_bytes()
            ).hexdigest(),
            expected_source_size_bytes=self.target.stat().st_size,
            expected_payload_sha256=hashlib.sha256(b"S").hexdigest(),
            expected_payload_size_bytes=1,
            expected_parent_crash_recipe_sha256=(
                PARENT_RECIPE_SHA256
            ),
            expected_parent_crash_evaluation_sha256=(
                PARENT_EVALUATION_SHA256
            ),
            expected_signal_number=int(signal.SIGSEGV),
            expected_snapshot_recipe_sha256=SNAPSHOT_RECIPE_SHA256,
        )
        self.assertIs(parsed.status, PwnRuntimeSnapshotV1Status.CAPTURED)

    def test_emitted_contract_fingerprint_matches_frozen_host_v1(
        self,
    ) -> None:
        self.assertEqual(
            runtime_snapshot.CONTRACT_FINGERPRINT,
            PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_FINGERPRINT,
        )

    def test_binding_echoes_every_fixed_request_identity(self) -> None:
        result = self._invoke(b"S")
        self.assertEqual(result.returncode, 0, result.stderr)
        binding = json.loads(result.stdout)["binding"]
        source_bytes = self.target.read_bytes()
        self.assertEqual(
            binding,
            {
                "expected_signal_number": signal.SIGSEGV,
                "parent_crash_evaluation_sha256": (
                    PARENT_EVALUATION_SHA256
                ),
                "parent_crash_recipe_sha256": PARENT_RECIPE_SHA256,
                "payload_sha256": hashlib.sha256(b"S").hexdigest(),
                "payload_size_bytes": 1,
                "snapshot_recipe_sha256": SNAPSHOT_RECIPE_SHA256,
                "source_manifest_sha256": MANIFEST_SHA256,
                "source_sha256": hashlib.sha256(
                    source_bytes
                ).hexdigest(),
                "source_size_bytes": len(source_bytes),
            },
        )

    def test_clean_replay_nonreproduction_is_inconclusive(self) -> None:
        cases = (
            (b"E", signal.SIGSEGV, "target_exited_before_expected_signal"),
            (b"A", signal.SIGSEGV, "unexpected_core_signal_observed"),
            (b"T", signal.SIGSEGV, "target_timeout"),
        )
        for payload, expected, reason in cases:
            with self.subTest(payload=payload, reason=reason):
                result = self._invoke(
                    payload,
                    expected_signal_number=expected,
                    timeout_seconds=0.05 if payload == b"T" else 1.0,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                document = json.loads(result.stdout)
                self.assertEqual(document["status"], "INCONCLUSIVE")
                self.assertEqual(document["reason_code"], reason)
                self.assertIsNone(document["snapshot"])

    def test_caught_and_ignored_core_signals_are_errors(self) -> None:
        for payload in (b"C", b"I"):
            with self.subTest(payload=payload):
                result = self._invoke(payload)
                self.assertEqual(result.returncode, 0, result.stderr)
                document = json.loads(result.stdout)
                self.assertEqual(document["status"], "ERROR")
                self.assertEqual(
                    document["reason_code"],
                    "caught_or_ignored_core_signal_unsupported",
                )
                self.assertIsNone(document["snapshot"])

    def test_any_thread_child_or_shared_mm_clone_fails_closed(
        self,
    ) -> None:
        for payload in (b"H", b"P", b"K", b"D", b"V"):
            with self.subTest(payload=payload):
                result = self._invoke(payload)
                self.assertEqual(result.returncode, 0, result.stderr)
                document = json.loads(result.stdout)
                self.assertEqual(document["status"], "ERROR")
                self.assertEqual(
                    document["reason_code"],
                    "additional_tracee_snapshot_unsupported",
                )
                self.assertIsNone(document["snapshot"])
                for line in result.stderr.decode().splitlines():
                    if line.startswith("child="):
                        child_pid = int(line.split("=", 1)[1])
                        self.assertFalse(
                            Path(f"/proc/{child_pid}").exists()
                        )

    def test_later_exec_is_not_attributed_to_bound_source(self) -> None:
        result = self._invoke(b"X")
        self.assertEqual(result.returncode, 0, result.stderr)
        document = json.loads(result.stdout)
        self.assertEqual(document["status"], "ERROR")
        self.assertEqual(
            document["reason_code"],
            "target_reexec_unsupported",
        )
        self.assertIsNone(document["snapshot"])

    def test_seccomp_blocks_clone_bypasses_without_signal_actions(
        self,
    ) -> None:
        cases = (
            (b"U", b"policy-ok:clone-untraced"),
            (b"Q", b"policy-ok:cross-tgid-sighand"),
            (b"Z", b"policy-ok:clone3"),
            (b"W", b"policy-ok:x32"),
        )
        for payload, marker in cases:
            with self.subTest(payload=payload):
                result = self._invoke(payload)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(marker, result.stderr)
                self.assertNotIn(
                    b"unexpected-clone-child=",
                    result.stderr,
                )
                document = json.loads(result.stdout)
                self.assertEqual(document["status"], "INCONCLUSIVE")
                self.assertEqual(
                    document["reason_code"],
                    "target_exited_before_expected_signal",
                )

        instructions = runtime_snapshot._clone_seccomp_instructions()
        self.assertEqual(len(instructions), 14)
        enosys = runtime_snapshot._SECCOMP_RET_ERRNO | errno.ENOSYS
        self.assertEqual(instructions[2].k, enosys)
        self.assertEqual(instructions[4].k, 0x40000000)
        self.assertEqual(
            instructions[4 + 1 + instructions[4].jt].k,
            enosys,
        )
        self.assertEqual(
            instructions[5 + 1 + instructions[5].jt].k,
            enosys,
        )
        self.assertNotIn(
            0x80000000,
            tuple(instruction.k for instruction in instructions),
        )

    def test_target_output_is_stderr_only_and_strictly_bounded(
        self,
    ) -> None:
        forged = self._invoke(b"F")
        self.assertEqual(forged.returncode, 0, forged.stderr)
        document = json.loads(forged.stdout)
        self.assertEqual(document["status"], "CAPTURED")
        self.assertIn(b'"status":"CAPTURED"', forged.stderr)
        self.assertNotIn(b'{"status":"CAPTURED"', forged.stdout)

        flooded = self._invoke(b"O", timeout_seconds=2.0)
        self.assertEqual(flooded.returncode, 0, flooded.stderr[-1024:])
        self.assertEqual(
            json.loads(flooded.stdout)["status"],
            "CAPTURED",
        )
        self.assertLessEqual(
            len(flooded.stderr),
            runtime_snapshot.MAX_TARGET_OUTPUT_BYTES,
        )
        self.assertTrue(
            flooded.stderr.endswith(
                runtime_snapshot.TARGET_OUTPUT_TRUNCATION_MARKER
            ),
            flooded.stderr[-128:],
        )

    def test_source_payload_mismatch_and_maps_bound_are_errors(
        self,
    ) -> None:
        wrong_source = self._invoke(
            b"S",
            source_sha256="f" * 64,
        )
        wrong_payload = self._invoke(
            b"S",
            payload_sha256="e" * 64,
        )
        for result, reason in (
            (wrong_source, "source_hash_mismatch"),
            (wrong_payload, "payload_hash_mismatch"),
        ):
            with self.subTest(reason=reason):
                self.assertEqual(result.returncode, 0, result.stderr)
                document = json.loads(result.stdout)
                self.assertEqual(document["status"], "ERROR")
                self.assertEqual(document["reason_code"], reason)
                self.assertIsNone(document["snapshot"])

        fake_descriptor = 99
        chunks = [
            b"M" * runtime_snapshot.READ_CHUNK_BYTES,
            b"M" * runtime_snapshot.READ_CHUNK_BYTES,
            b"X",
        ]
        with mock.patch.object(
            runtime_snapshot.os,
            "open",
            return_value=fake_descriptor,
        ), mock.patch.object(
            runtime_snapshot.os,
            "read",
            side_effect=chunks,
        ), mock.patch.object(
            runtime_snapshot.os,
            "close",
        ):
            with self.assertRaisesRegex(
                runtime_snapshot.RuntimeSnapshotError,
                "maps_size_limit_exceeded",
            ):
                runtime_snapshot._read_proc_maps(123)

    def test_getregset_size_and_architecture_fail_closed(self) -> None:
        def short_getregset(
            request: int,
            pid: int,
            address: int = 0,
            data: int = 0,
        ) -> tuple[int, int]:
            del pid, address
            self.assertEqual(
                request,
                runtime_snapshot._PTRACE_GETREGSET,
            )
            vector = runtime_snapshot._Iovec.from_address(data)
            vector.iov_len = runtime_snapshot.REGISTER_SET_BYTES - 8
            return 0, 0

        with mock.patch.object(
            runtime_snapshot,
            "_raw_ptrace",
            side_effect=short_getregset,
        ):
            with self.assertRaisesRegex(
                runtime_snapshot.RuntimeSnapshotError,
                "register_set_size_mismatch",
            ):
                runtime_snapshot._read_registers(123)

        fake_uname = type(
            "FakeUname",
            (),
            {"machine": "aarch64"},
        )()
        with mock.patch.object(
            runtime_snapshot.os,
            "uname",
            return_value=fake_uname,
        ):
            with self.assertRaisesRegex(
                runtime_snapshot.RuntimeSnapshotError,
                "unsupported_architecture",
            ):
                runtime_snapshot._require_x86_64()

    def test_unobserved_core_termination_is_never_snapshot_success(
        self,
    ) -> None:
        self.assertEqual(
            runtime_snapshot._terminal_signal_error(signal.SIGSEGV),
            "unobserved_core_signal_termination",
        )
        self.assertEqual(
            runtime_snapshot._terminal_signal_error(signal.SIGTERM),
            "unexpected_signal_termination",
        )

    def test_fixed_cli_rejects_missing_duplicate_and_unknown_args(
        self,
    ) -> None:
        missing = subprocess.run(
            (sys.executable, str(MODULE_PATH)),
            capture_output=True,
            check=False,
            timeout=2,
        )
        duplicate = subprocess.run(
            (
                sys.executable,
                str(MODULE_PATH),
                "--binary",
                "/challenge/target",
                "--binary",
                "/challenge/target",
            ),
            capture_output=True,
            check=False,
            timeout=2,
        )
        unknown = subprocess.run(
            (
                sys.executable,
                str(MODULE_PATH),
                "--unknown",
                "value",
            ),
            capture_output=True,
            check=False,
            timeout=2,
        )
        for result in (missing, duplicate, unknown):
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, b"")
            self.assertIn(b"invalid_cli", result.stderr)
            self.assertLessEqual(len(result.stderr), 1024)


if __name__ == "__main__":
    unittest.main()
