#!/usr/bin/env python3
"""Source tests for the fixed Pwn crash observation producer."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
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
#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int main(int argc, char **argv) {
    unsigned char value = 0;
    ssize_t count;
    (void)argv;
    if (argc != 1) return 77;
    count = read(STDIN_FILENO, &value, 1);
    if (count == 1 && value == 'S') {
        raise(SIGTERM);
    }
    if (count == 1 && value == 'E') {
        return 143;
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
            (compiler, str(source), "-o", str(target)),
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
        core_pattern_path = self.root / "safe-core-pattern"
        core_pattern_path.write_bytes(b"core\n")
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
            "timeout_seconds=float(sys.argv[13]),"
            "core_pattern_path=pathlib.Path(sys.argv[14]));"
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
                str(core_pattern_path),
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
                "signal_number": 15,
                "termination": "signaled",
            },
        )
        self.assertEqual(
            exit_document["target"],
            {
                "exit_code": 143,
                "signal_number": None,
                "termination": "exited",
            },
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
            PwnCrashV1Verdict.INCONCLUSIVE,
        )
        self.assertEqual(evaluation.positive_signal_counts, ())
        self.assertEqual(
            evaluation.reason_code,
            "no_positive_fault_observed",
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

    def test_piped_core_handler_fails_closed_before_execution(
        self,
    ) -> None:
        pipe_pattern = self.root / "pipe-core-pattern"
        pipe_pattern.write_bytes(b"|/outside/collector %p\n")
        input_path = self.work / "pipe-check.bin"
        input_path.write_bytes(b"")
        source = self.target.read_bytes()
        binding = crash_oracle.RequestBinding(
            ordinal=4,
            phase="control",
            source_manifest_sha256=MANIFEST_SHA256,
            source_sha256=hashlib.sha256(source).hexdigest(),
            source_size_bytes=len(source),
            input_sha256=hashlib.sha256(b"").hexdigest(),
            input_size_bytes=0,
            recipe_sha256=RECIPE_SHA256,
        )

        document = crash_oracle.produce_document(
            binding,
            "/challenge/target",
            "/work/pipe-check.bin",
            challenge_root=self.challenge,
            work_root=self.work,
            core_pattern_path=pipe_pattern,
        )

        self.assertEqual(document["status"], "error")
        self.assertEqual(
            document["reason_code"],
            "piped_core_handler_forbidden",
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
