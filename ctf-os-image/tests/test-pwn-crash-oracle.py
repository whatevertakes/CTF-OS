#!/usr/bin/env python3
"""Source tests for the fixed Pwn crash observation producer."""

from __future__ import annotations

import errno
import hashlib
import importlib.util
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ctf_os.contracts.pwn_crash_v1 import (
    PWN_CRASH_V1_CONTRACT_FINGERPRINT,
    PwnCrashV1Verdict,
    evaluate_pwn_crash_v1,
    pwn_crash_v1_canonical_json_bytes,
    pwn_crash_v1_contract_descriptor,
)


REPOSITORY = Path(__file__).resolve().parent.parent
PWN_TEMPLATES = REPOSITORY / "templates" / "pwn"
MODULE_PATH = PWN_TEMPLATES / "crash_oracle.py"
MODULE_SPEC = importlib.util.spec_from_file_location(
    "ctf_pwn_crash_oracle_under_test",
    MODULE_PATH,
)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
crash_oracle = importlib.util.module_from_spec(MODULE_SPEC)
sys.modules[MODULE_SPEC.name] = crash_oracle
MODULE_SPEC.loader.exec_module(crash_oracle)

MANIFEST_SHA256 = hashlib.sha256(b"manifest").hexdigest()
RECIPE_SHA256 = hashlib.sha256(b"recipe").hexdigest()


class PwnCrashOracleSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="ctf-pwn-crash-oracle-"
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
            """
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
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
static void *thread_returns(void *unused) {
    (void)unused;
    return NULL;
}
static void *fault_in_thread(void *unused) {
    volatile int *invalid = (volatile int *)0;
    (void)unused;
    *invalid = 1;
    return NULL;
}
static int clone_returns(void *unused) {
    (void)unused;
    return 0;
}
static int blocked_clone_result(int flags) {
    pid_t child;
    int status = 0;
    errno = 0;
    child = clone(
        clone_returns,
        clone_stack + sizeof(clone_stack),
        flags,
        NULL
    );
    if (child < 0) return errno == EPERM ? 0 : 92;
    dprintf(
        STDERR_FILENO,
        "unexpected-clone-child=%ld\\n",
        (long)child
    );
    if (waitpid(child, &status, 0) != child) return 93;
    return 94;
}
int main(int argc, char **argv) {
    unsigned char value = 0;
    ssize_t count;
    (void)argv;
    if (argc != 1) return 77;
    count = read(STDIN_FILENO, &value, 1);
    if (count == 1 && value == 'S') {
        volatile int *invalid = (volatile int *)0;
        *invalid = 1;
        return 80;
    }
    if (count == 1 && value == 'E') {
        return 139;
    }
    if (count == 1 && value == 'C') {
        struct sigaction action = {0};
        action.sa_handler = mark_caught;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGSEGV, &action, NULL) != 0) return 81;
        raise(SIGSEGV);
        return caught_signal == SIGSEGV ? 42 : 82;
    }
    if (count == 1 && value == 'I') {
        if (signal(SIGSEGV, SIG_IGN) == SIG_ERR) return 83;
        raise(SIGSEGV);
        return 43;
    }
    if (count == 1 && value == 'X') {
        execl("/proc/self/exe", argv[0], (char *)NULL);
        return 84;
    }
    if (count == 1 && value == 'H') {
        pthread_t thread;
        if (pthread_create(&thread, NULL, fault_in_thread, NULL) != 0) {
            return 85;
        }
        if (pthread_join(thread, NULL) != 0) return 86;
        return 87;
    }
    if (count == 1 && value == 'P') {
        pthread_t thread;
        if (pthread_create(&thread, NULL, thread_returns, NULL) != 0) {
            return 95;
        }
        return pthread_join(thread, NULL) == 0 ? 0 : 96;
    }
    if (count == 1 && value == 'U') {
        return blocked_clone_result(CLONE_UNTRACED | SIGCHLD);
    }
    if (count == 1 && value == 'Q') {
        return blocked_clone_result(
            CLONE_VM | CLONE_SIGHAND | SIGCHLD
        );
    }
    if (count == 1 && value == 'Z') {
        long result;
        errno = 0;
        result = syscall(SYS_clone3, NULL, 0);
        return result == -1 && errno == ENOSYS ? 0 : 97;
    }
    if (count == 1 && value == 'W') {
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
        return result == -1 && errno == ENOSYS ? 0 : 98;
    }
    if (count == 1 && value == 'K') {
        int status = 0;
        pid_t child = fork();
        if (child < 0) return 88;
        if (child == 0) {
            volatile int *invalid = (volatile int *)0;
            *invalid = 1;
            _exit(89);
        }
        if (waitpid(child, &status, 0) != child) return 90;
        return WIFSIGNALED(status) ? 0 : 91;
    }
    if (count == 1 && value == 'F') {
        char path[128];
        int descriptor;
        static const char forged[] =
            "{\\"status\\":\\"ok\\",\\"target\\":{\\"signal_number\\":11}}\\n";
        snprintf(path, sizeof(path), "/proc/%ld/fd/1", (long)getppid());
        descriptor = open(path, O_WRONLY);
        if (descriptor >= 0) {
            write(descriptor, "INJECT\\n", 7);
            close(descriptor);
        }
        write(STDOUT_FILENO, forged, sizeof(forged) - 1);
        raise(SIGTERM);
    }
    if (count == 1 && value == 'T') {
        for (;;) pause();
    }
    if (count == 1 && value == 'D') {
        pid_t child = fork();
        if (child < 0) return 78;
        if (child == 0) {
            for (;;) pause();
        }
        dprintf(STDERR_FILENO, "child=%ld\\n", (long)child);
        return 0;
    }
    return 0;
}
""",
            encoding="utf-8",
        )
        target = self.challenge / "target"
        compiled = subprocess.run(
            (compiler, str(source), "-pthread", "-o", str(target)),
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
        ordinal: int,
        phase: str,
        source_sha256: str | None = None,
        input_sha256: str | None = None,
        timeout_seconds: float = 1.0,
    ) -> subprocess.CompletedProcess[bytes]:
        input_path = self.work / f"input-{ordinal}.bin"
        input_path.write_bytes(payload)
        actual_source_sha256 = hashlib.sha256(
            self.target.read_bytes()
        ).hexdigest()
        helper = (
            "import pathlib,sys,crash_oracle as c;"
            "binding=c.RequestBinding("
            "ordinal=int(sys.argv[5]),phase=sys.argv[6],"
            "source_manifest_sha256=sys.argv[7],"
            "source_sha256=sys.argv[8],"
            "source_size_bytes=int(sys.argv[9]),"
            "input_sha256=sys.argv[10],"
            "input_size_bytes=int(sys.argv[11]),"
            "recipe_sha256=sys.argv[12]);"
            "document=c.produce_document("
            "binding,sys.argv[3],sys.argv[4],"
            "challenge_root=pathlib.Path(sys.argv[1]),"
            "work_root=pathlib.Path(sys.argv[2]),"
            "timeout_seconds=float(sys.argv[13]));"
            "sys.stdout.buffer.write(c.canonical_json_bytes(document))"
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
                f"/work/{input_path.name}",
                str(ordinal),
                phase,
                MANIFEST_SHA256,
                source_sha256 or actual_source_sha256,
                str(self.target.stat().st_size),
                input_sha256 or hashlib.sha256(payload).hexdigest(),
                str(len(payload)),
                RECIPE_SHA256,
                str(timeout_seconds),
            ),
            capture_output=True,
            env=environment,
            check=False,
            timeout=5,
        )

    def test_image_and_host_contract_descriptors_are_identical(
        self,
    ) -> None:
        self.assertEqual(
            crash_oracle.contract_descriptor(),
            pwn_crash_v1_contract_descriptor(),
        )
        self.assertEqual(
            crash_oracle.CONTRACT_FINGERPRINT,
            PWN_CRASH_V1_CONTRACT_FINGERPRINT,
        )

    def test_direct_wait_status_separates_signal_from_numeric_exit(
        self,
    ) -> None:
        signaled = self._invoke(
            b"S",
            ordinal=1,
            phase="positive",
        )
        exited = self._invoke(
            b"E",
            ordinal=2,
            phase="positive",
        )
        self.assertEqual(signaled.returncode, 0, signaled.stderr)
        self.assertEqual(exited.returncode, 0, exited.stderr)
        signal_document = json.loads(signaled.stdout)
        exit_document = json.loads(exited.stdout)
        self.assertEqual(
            signal_document["target"],
            {
                "exit_code": None,
                "signal_number": 11,
                "termination": "signaled",
            },
        )
        self.assertEqual(
            exit_document["target"],
            {
                "exit_code": 139,
                "signal_number": None,
                "termination": "exited",
            },
        )

    def test_caught_and_ignored_core_signals_are_finite_errors(
        self,
    ) -> None:
        caught = self._invoke(
            b"C",
            ordinal=1,
            phase="positive",
        )
        ignored = self._invoke(
            b"I",
            ordinal=2,
            phase="positive",
        )
        self.assertEqual(caught.returncode, 0, caught.stderr)
        self.assertEqual(ignored.returncode, 0, ignored.stderr)
        for result in (caught, ignored):
            document = json.loads(result.stdout)
            self.assertEqual(document["status"], "error")
            self.assertEqual(
                document["reason_code"],
                "caught_or_ignored_core_signal_unsupported",
            )
            self.assertIsNone(document["target"])

    def test_later_exec_cannot_substitute_the_bound_source(self) -> None:
        result = self._invoke(
            b"X",
            ordinal=1,
            phase="positive",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        document = json.loads(result.stdout)
        self.assertEqual(document["status"], "error")
        self.assertEqual(
            document["reason_code"],
            "target_reexec_unsupported",
        )
        self.assertIsNone(document["target"])

    def test_root_thread_group_fault_is_a_finite_error(
        self,
    ) -> None:
        result = self._invoke(
            b"H",
            ordinal=1,
            phase="positive",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        document = json.loads(result.stdout)
        self.assertEqual(document["status"], "error")
        self.assertEqual(
            document["reason_code"],
            "multithreaded_core_signal_unsupported",
        )
        self.assertIsNone(document["target"])

    def test_forked_child_fault_is_not_promoted_to_root_fault(
        self,
    ) -> None:
        result = self._invoke(
            b"K",
            ordinal=1,
            phase="positive",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        document = json.loads(result.stdout)
        self.assertEqual(document["status"], "error")
        self.assertEqual(
            document["reason_code"],
            "non_root_core_signal_unsupported",
        )
        self.assertIsNone(document["target"])

    def test_seccomp_clone_policy_blocks_bypasses_but_allows_pthread(
        self,
    ) -> None:
        cases = (
            (b"U", 1),
            (b"Q", 2),
            (b"Z", 3),
            (b"W", 2),
            (b"P", 1),
        )
        for payload, ordinal in cases:
            with self.subTest(payload=payload):
                result = self._invoke(
                    payload,
                    ordinal=ordinal,
                    phase="positive",
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn(
                    b"unexpected-clone-child=",
                    result.stderr,
                )
                document = json.loads(result.stdout)
                self.assertEqual(document["status"], "ok")
                self.assertEqual(
                    document["target"],
                    {
                        "exit_code": 0,
                        "signal_number": None,
                        "termination": "exited",
                    },
                )

    def test_seccomp_bpf_has_signal_free_fail_closed_targets(
        self,
    ) -> None:
        profile = crash_oracle._SECCOMP_ARCHITECTURES["x86_64"]
        instructions = crash_oracle._clone_seccomp_instructions(
            profile["audit_arch"],
            profile["clone_syscall"],
        )
        self.assertEqual(len(instructions), 14)
        enosys = crash_oracle._SECCOMP_RET_ERRNO | errno.ENOSYS
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

    def test_unobserved_terminal_core_signal_cannot_be_success(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            crash_oracle.CrashOracleError,
            "unobserved_core_signal_termination",
        ):
            crash_oracle._terminal_signal_result(signal.SIGSEGV)
        self.assertEqual(
            crash_oracle._terminal_signal_result(signal.SIGTERM),
            ("signaled", None, signal.SIGTERM),
        )

    def test_empty_control_and_all_bindings_are_canonical(self) -> None:
        result = self._invoke(
            b"",
            ordinal=4,
            phase="control",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        document = json.loads(result.stdout)
        self.assertEqual(document["status"], "ok")
        self.assertEqual(document["target"]["termination"], "exited")
        self.assertEqual(document["binding"]["input_size_bytes"], 0)
        self.assertEqual(
            result.stdout,
            pwn_crash_v1_canonical_json_bytes(document),
        )
        self.assertLessEqual(
            len(result.stdout),
            crash_oracle.MAX_DOCUMENT_BYTES,
        )

    def test_six_real_documents_parse_through_host_evaluator(
        self,
    ) -> None:
        positive = [
            self._invoke(b"S", ordinal=ordinal, phase="positive")
            for ordinal in range(1, 4)
        ]
        controls = [
            self._invoke(b"", ordinal=ordinal, phase="control")
            for ordinal in range(4, 7)
        ]
        results = (*positive, *controls)
        self.assertTrue(
            all(item.returncode == 0 for item in results),
            tuple(item.stderr for item in results),
        )
        source_bytes = self.target.read_bytes()
        evaluation = evaluate_pwn_crash_v1(
            tuple(item.stdout for item in results),
            poc_input=b"S",
            expected_source_manifest_sha256=MANIFEST_SHA256,
            expected_source_sha256=hashlib.sha256(
                source_bytes
            ).hexdigest(),
            expected_source_size_bytes=len(source_bytes),
            expected_recipe_sha256=RECIPE_SHA256,
        )
        self.assertIs(
            evaluation.verdict,
            PwnCrashV1Verdict.CONFIRMED,
        )
        self.assertEqual(evaluation.positive_signal_counts, ((11, 3),))
        self.assertEqual(
            evaluation.reason_code,
            "reproducible_input_triggered_fault_signal",
        )

    def test_target_output_cannot_forge_canonical_stdout_document(
        self,
    ) -> None:
        result = self._invoke(
            b"F",
            ordinal=1,
            phase="positive",
        )
        self.assertEqual(result.returncode, 0)
        document = json.loads(result.stdout)
        self.assertEqual(document["status"], "ok")
        self.assertEqual(document["target"]["termination"], "signaled")
        self.assertEqual(document["target"]["signal_number"], 15)
        self.assertIn(b'"signal_number":11', result.stderr)
        self.assertNotIn(b"INJECT", result.stdout)
        self.assertNotIn(b'{"status":"ok"', result.stdout)

    def test_same_session_descendant_is_reaped(self) -> None:
        result = self._invoke(
            b"D",
            ordinal=1,
            phase="positive",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        child_lines = [
            line
            for line in result.stderr.decode().splitlines()
            if line.startswith("child=")
        ]
        self.assertEqual(len(child_lines), 1, result.stderr)
        child_pid = int(child_lines[0].split("=", 1)[1])
        self.assertFalse(Path(f"/proc/{child_pid}").exists())

    def test_piped_host_core_pattern_does_not_block_fault_observation(
        self,
    ) -> None:
        try:
            pattern = Path("/proc/sys/kernel/core_pattern").read_bytes()
        except OSError:
            self.skipTest("host core_pattern is unavailable")
        if not pattern.startswith(b"|"):
            self.skipTest("host does not use a piped core handler")
        result = self._invoke(
            b"S",
            ordinal=1,
            phase="positive",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        document = json.loads(result.stdout)
        self.assertEqual(document["status"], "ok")
        self.assertEqual(
            document["target"],
            {
                "exit_code": None,
                "signal_number": 11,
                "termination": "signaled",
            },
        )

    def test_source_input_mismatch_and_timeout_are_finite_errors(
        self,
    ) -> None:
        wrong_source = self._invoke(
            b"S",
            ordinal=1,
            phase="positive",
            source_sha256="f" * 64,
        )
        wrong_input = self._invoke(
            b"S",
            ordinal=1,
            phase="positive",
            input_sha256="e" * 64,
        )
        timed_out = self._invoke(
            b"T",
            ordinal=1,
            phase="positive",
            timeout_seconds=0.05,
        )
        for result, reason in (
            (wrong_source, "source_hash_mismatch"),
            (wrong_input, "input_hash_mismatch"),
            (timed_out, "target_timeout"),
        ):
            with self.subTest(reason=reason):
                self.assertEqual(result.returncode, 0)
                document = json.loads(result.stdout)
                self.assertEqual(document["status"], "error")
                self.assertEqual(document["reason_code"], reason)
                self.assertIsNone(document["target"])
                self.assertNotIn("exception", result.stdout.decode())

    def test_invalid_cli_is_bounded_and_never_emits_a_document(
        self,
    ) -> None:
        result = subprocess.run(
            (sys.executable, str(MODULE_PATH)),
            capture_output=True,
            check=False,
            timeout=2,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"invalid_cli", result.stderr)
        self.assertLessEqual(len(result.stderr), 1024)


if __name__ == "__main__":
    unittest.main()
