from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ctf_os.codex import (
    BatchInvocation,
    BatchRunner,
    BuiltCommand,
    LiveSession,
    ProcessOutcome,
    Role,
    SubprocessExecutor,
)
from ctf_os.credential_safety import (
    CredentialSafetyError,
    validate_metadata_credentials,
)
from ctf_os.sandbox.docker import DockerSandboxBackend
from ctf_os.sandbox.output_redaction import (
    OutputCredentialError,
    audit_run_output_credentials,
)
from ctf_os.sandbox.types import (
    ChallengeScope,
    CommandSpec,
    JobRef,
    JobState,
    SandboxError,
)


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def _provider_output_path(command: BuiltCommand) -> Path:
    index = command.argv.index("--output-last-message")
    return Path(command.argv[index + 1])


def _valid_recon_output(*, summary: str = "bounded result") -> dict[str, object]:
    return {
        "schema_version": 1,
        "role": "recon",
        "status": "ok",
        "summary": summary,
        "observations": [
            {
                "id": "obs-1",
                "claim": "The executable returned a marker.",
                "evidence": ["runs/tool-output.txt:1"],
                "provenance": "executed",
            }
        ],
        "hypotheses": [],
        "hypothesis_updates": [],
        "evaluations": [],
        "actions": [],
        "artifacts": [],
        "progress_markers": [],
        "flag_candidates": [],
        "decision": None,
        "goal_update": None,
        "refusal": None,
    }


class CommandCredentialBoundaryTests(unittest.TestCase):
    def test_sensitive_environment_is_rejected_before_serialization(
        self,
    ) -> None:
        credential = "must-never-enter-an-rpc-file"
        with self.assertRaises(CredentialSafetyError) as raised:
            CommandSpec(
                ("true",),
                environment={"OPENAI_API_KEY": credential},
            )
        self.assertNotIn(credential, str(raised.exception))

    def test_exact_host_and_provider_credentials_are_rejected_in_argv(
        self,
    ) -> None:
        host_credential = "host-provider-credential-value"
        with mock.patch.dict(
            os.environ,
            {"ANTHROPIC_API_KEY": host_credential},
        ):
            with self.assertRaisesRegex(
                CredentialSafetyError,
                "protected host credential",
            ):
                CommandSpec(("printf", host_credential))

        with self.assertRaisesRegex(
            CredentialSafetyError,
            "credential-bearing text",
        ):
            CommandSpec(
                ("printf", "sk-proj-ABCDEFGHIJKLMNOPQRSTUV")
            )

    def test_flag_candidates_and_flag_regex_environment_remain_allowed(
        self,
    ) -> None:
        candidate = "KCTF{candidate-token-is-challenge-data}"
        spec = CommandSpec(
            ("printf", candidate),
            environment={
                "CTF_WRAP_FLAG_PATTERNS_JSON": r'["KCTF\\{[^}]+\\}"]',
            },
        )
        self.assertEqual(spec.argv[-1], candidate)

    def test_engine_owned_web_role_and_callback_options_remain_allowed(
        self,
    ) -> None:
        callback_nonce = "0" * 32
        spec = CommandSpec(
            (
                "ctf-web-helper",
                "--session",
                "attacker",
                "--callback-token",
                callback_nonce,
            )
        )
        self.assertEqual(spec.argv[-1], callback_nonce)

    def test_metadata_rejects_host_and_provider_credentials(self) -> None:
        host_credential = "host-metadata-credential-value"
        with (
            mock.patch.dict(
                os.environ,
                {"OPENAI_API_KEY": host_credential},
            ),
            self.assertRaisesRegex(
                CredentialSafetyError,
                "protected host credential",
            ) as raised,
        ):
            validate_metadata_credentials(host_credential)
        self.assertNotIn(host_credential, str(raised.exception))

        with self.assertRaisesRegex(
            CredentialSafetyError,
            "credential-bearing text",
        ):
            validate_metadata_credentials(
                "sk-proj-ABCDEFGHIJKLMNOPQRSTUV"
            )
        validate_metadata_credentials("memory-scan-KCTF-candidate")

    def test_synthetic_challenge_credentials_remain_usable(self) -> None:
        samples = (
            "Authorization: Bearer challenge-oracle-token",
            "Cookie: session=challenge-session-value",
            "https://challenge.test/?access_token=oracle-token",
            "password=known-challenge-input",
        )
        for sample in samples:
            with self.subTest(sample=sample):
                spec = CommandSpec(("printf", sample))
                self.assertEqual(spec.argv[-1], sample)
                validate_metadata_credentials(sample)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prompt = "\n".join(samples)
            batch = BatchInvocation(
                "synthetic-credential-prompt",
                Role.RECON,
                prompt,
                root,
                root / "run",
            )
            live = LiveSession("synthetic-credential-live", root, prompt)
        self.assertEqual(batch.prompt, prompt)
        self.assertEqual(live.prompt, prompt)

    def test_model_prompts_reject_exact_host_credentials(self) -> None:
        credential = "host-prompt-secret-value"
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.dict(
                os.environ,
                {"OPENAI_API_KEY": credential},
            ),
        ):
            root = Path(temporary)
            with self.assertRaises(CredentialSafetyError):
                BatchInvocation(
                    "prompt-boundary",
                    Role.RECON,
                    credential,
                    root,
                    root / "run",
                )
            with self.assertRaises(CredentialSafetyError):
                LiveSession("live-boundary", root, credential)
            with self.assertRaises(CredentialSafetyError):
                BuiltCommand(("true",), credential)

    def test_trusted_model_argv_uses_provenance_aware_credential_checks(
        self,
    ) -> None:
        command = BuiltCommand(
            (
                "codex",
                "-c",
                "agents.max_concurrent_threads_per_session=3",
            ),
            "inspect",
        )
        self.assertEqual(
            command.argv[-1],
            "agents.max_concurrent_threads_per_session=3",
        )

        host_credential = "host-model-argv-secret-value"
        with mock.patch.dict(
            os.environ,
            {"OPENAI_API_KEY": host_credential},
        ):
            with self.assertRaises(CredentialSafetyError):
                BuiltCommand(("codex", host_credential), "inspect")
        with self.assertRaises(CredentialSafetyError):
            BuiltCommand(
                ("codex", "sk-proj-ABCDEFGHIJKLMNOPQRSTUV"),
                "inspect",
            )


class ModelProcessCredentialBoundaryTests(unittest.TestCase):
    def test_none_environment_uses_minimal_model_cli_allowlist(self) -> None:
        script = (
            "import os;"
            "keys=['OPENAI'+'_API_KEY','AWS'+'_SECRET_ACCESS_KEY',"
            "'SAFE'+'_SETTING','HOME','PATH'];"
            "print('|'.join(key for key in keys if key in os.environ))"
        )
        stdout: list[bytes | str] = []
        environment = {
            "OPENAI_API_KEY": "host-provider-secret-value",
            "AWS_SECRET_ACCESS_KEY": "unrelated-cloud-secret-value",
            "SAFE_SETTING": "must-not-be-inherited",
            "HOME": "/tmp",
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        }
        with mock.patch.dict(os.environ, environment, clear=True):
            outcome = SubprocessExecutor().run(
                BuiltCommand((sys.executable, "-c", script), ""),
                cwd=Path.cwd(),
                timeout=5,
                on_stdout_line=stdout.append,
            )

        self.assertEqual(outcome.returncode, 0)
        inherited = b"".join(
            item.encode("utf-8") if isinstance(item, str) else item
            for item in stdout
        ).decode("utf-8")
        self.assertIn("OPENAI_API_KEY", inherited)
        self.assertIn("HOME", inherited)
        self.assertIn("PATH", inherited)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", inherited)
        self.assertNotIn("SAFE_SETTING", inherited)

    def test_split_stdout_credential_is_rejected_before_raw_or_events(self) -> None:
        credential = "host-split-stdout-secret-value"

        class SplitStdoutExecutor:
            def run(self, command, *, cwd, timeout, on_stdout_line):
                del command, cwd, timeout
                split = len(credential) // 2
                on_stdout_line(
                    b'{"type":"message","text":"safe-prefix '
                    + credential[:split].encode("utf-8")
                )
                on_stdout_line(
                    credential[split:].encode("utf-8") + b'"}\n'
                )
                raise AssertionError("credential callback did not reject")

        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.dict(
                os.environ,
                {"OPENAI_API_KEY": credential},
            ),
        ):
            root = Path(temporary)
            result = BatchRunner(
                process_executor=SplitStdoutExecutor(),
                max_schema_retries=0,
            ).run(
                BatchInvocation(
                    "stdout-credential",
                    Role.RECON,
                    "inspect",
                    root,
                    root / "run",
                )
            )
            durable = [
                path.read_bytes()
                for path in (root / "run").rglob("*")
                if path.is_file()
            ]

        self.assertIsNone(result.output)
        self.assertFalse(result.validation.valid)
        self.assertIn(
            "credential_output_rejected",
            {failure.kind for failure in result.failures},
        )
        self.assertEqual(result.events, ())
        self.assertTrue(durable)
        for payload in durable:
            self.assertNotIn(credential.encode("utf-8"), payload)

    def test_injected_stderr_credential_is_scrubbed_and_rejected(self) -> None:
        credential = "host-injected-stderr-secret-value"

        class StderrExecutor:
            def run(self, command, *, cwd, timeout, on_stdout_line):
                del cwd, timeout, on_stdout_line
                _provider_output_path(command).write_text(
                    json.dumps(_valid_recon_output()),
                    encoding="utf-8",
                )
                payload = b"safe-prefix:" + credential.encode("utf-8")
                return ProcessOutcome(
                    0,
                    payload.decode("utf-8"),
                    0.0,
                    stderr_raw=payload,
                )

        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.dict(
                os.environ,
                {"OPENAI_API_KEY": credential},
            ),
        ):
            root = Path(temporary)
            result = BatchRunner(
                process_executor=StderrExecutor(),
                max_schema_retries=0,
            ).run(
                BatchInvocation(
                    "stderr-credential",
                    Role.RECON,
                    "inspect",
                    root,
                    root / "run",
                )
            )
            stderr = result.attempts[0].stderr_path.read_bytes()

        self.assertIsNone(result.output)
        self.assertNotIn(credential.encode("utf-8"), stderr)
        self.assertIn(b"safe-prefix:", stderr)
        self.assertIn(
            "credential_output_rejected",
            {failure.kind for failure in result.failures},
        )

    def test_final_provider_credential_is_redacted_before_promotion(self) -> None:
        credential = "sk-proj-ABCDEFGHIJKLMNOPQRSTUV"

        class FinalOutputExecutor:
            def run(self, command, *, cwd, timeout, on_stdout_line):
                del cwd, timeout, on_stdout_line
                _provider_output_path(command).write_text(
                    json.dumps(
                        _valid_recon_output(summary=credential)
                    ),
                    encoding="utf-8",
                )
                return ProcessOutcome(0, "", 0.0)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = BatchRunner(
                process_executor=FinalOutputExecutor(),
                max_schema_retries=0,
            ).run(
                BatchInvocation(
                    "final-credential",
                    Role.RECON,
                    "inspect",
                    root,
                    root / "run",
                )
            )
            output = result.attempts[0].output_path.read_bytes()

        self.assertIsNone(result.output)
        self.assertFalse(result.validation.valid)
        self.assertNotIn(credential.encode("utf-8"), output)
        self.assertIn(b"*" * len(credential), output)
        self.assertIn(
            "credential_output_rejected",
            {failure.kind for failure in result.failures},
        )


class RunOutputCredentialAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.work = self.root / "work"
        self.run_id = "run-00000001"
        self.work.mkdir(mode=0o700)
        ctf_root = self.work / ".ctf"
        runs_root = ctf_root / "runs"
        for directory in (ctf_root, runs_root):
            directory.mkdir(mode=0o700)
        self.run_root = runs_root / self.run_id
        self.run_root.mkdir(mode=0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, name: str, payload: bytes) -> Path:
        path = self.run_root / name
        path.write_bytes(payload)
        path.chmod(0o600)
        return path

    def test_binary_raw_control_and_base64_tail_are_scrubbed_but_flag_stays(
        self,
    ) -> None:
        host_credential = "host-provider-secret-value"
        provider_credential = "sk-proj-ABCDEFGHIJKLMNOPQRSTUV"
        candidate = "KCTF{keep-this-candidate}"
        stdout = (
            b"\x00binary-prefix\n"
            + host_credential.encode()
            + b"\n"
            + provider_credential.encode()
            + b"\n"
            + candidate.encode()
            + b"\n\xffbinary-suffix"
        )
        self.write("stdout.log", stdout)
        self.write("stderr.log", candidate.encode() + b"\n")
        self.write(
            "result.json",
            _canonical_json(
                {
                    "stdout_summary": (
                        host_credential
                        + " "
                        + provider_credential
                        + " "
                        + candidate
                    )
                }
            ),
        )
        self.write(
            "meta.json",
            _canonical_json({"command": ["safe-tool"]}),
        )
        self.write(
            "flag-candidates.jsonl",
            _canonical_json({"value": candidate}),
        )
        self.write(
            "stream-capture.json",
            _canonical_json(
                {
                    "schema_version": 1,
                    "streams": {
                        "stderr": {
                            "tail_base64": base64.b64encode(
                                stdout
                            ).decode("ascii")
                        },
                        "stdout": {
                            "tail_base64": base64.b64encode(stdout).decode(
                                "ascii"
                            )
                        },
                    },
                }
            ),
        )

        audit = audit_run_output_credentials(
            self.work,
            self.run_id,
            credentials=(host_credential,),
        )

        self.assertTrue(audit.contaminated)
        self.assertGreaterEqual(audit.redaction_count, 4)
        self.assertIn("stdout.log", audit.redacted_files)
        self.assertIn("result.json", audit.redacted_files)
        self.assertIn("stream-capture.json", audit.redacted_files)
        for path in self.run_root.iterdir():
            payload = path.read_bytes()
            self.assertNotIn(host_credential.encode(), payload)
            self.assertNotIn(provider_credential.encode(), payload)
        redacted_stdout = (self.run_root / "stdout.log").read_bytes()
        self.assertIn(b"\x00binary-prefix", redacted_stdout)
        self.assertIn(b"\xffbinary-suffix", redacted_stdout)
        self.assertIn(candidate.encode(), redacted_stdout)
        self.assertIn(
            candidate.encode(),
            (self.run_root / "flag-candidates.jsonl").read_bytes(),
        )
        capture = json.loads(
            (self.run_root / "stream-capture.json").read_bytes()
        )
        decoded_tail = base64.b64decode(
            capture["streams"]["stdout"]["tail_base64"],
            validate=True,
        )
        self.assertNotIn(host_credential.encode(), decoded_tail)
        self.assertNotIn(provider_credential.encode(), decoded_tail)
        self.assertIn(candidate.encode(), decoded_tail)

    def test_safe_long_binary_output_is_unchanged(self) -> None:
        payload = (
            b"\x00\xff"
            + b"x" * 256_000
            + b"\nKCTF{bounded-binary-candidate}\n"
        )
        path = self.write("stdout.log", payload)

        audit = audit_run_output_credentials(
            self.work,
            self.run_id,
            credentials=("unrelated-host-secret-value",),
        )

        self.assertFalse(audit.contaminated)
        self.assertEqual(path.read_bytes(), payload)

    def test_special_run_file_fails_closed(self) -> None:
        outside = self.root / "outside"
        outside.write_bytes(b"safe")
        (self.run_root / "stdout.log").symlink_to(outside)

        with self.assertRaisesRegex(
            OutputCredentialError,
            "cannot be opened",
        ):
            audit_run_output_credentials(
                self.work,
                self.run_id,
                credentials=("host-secret-value",),
            )

    def test_symlinked_run_ancestors_never_scrub_outside_files(self) -> None:
        credential = b"host-provider-secret-value"
        for component in (".ctf", "runs", "run"):
            with self.subTest(component=component):
                work = self.root / f"work-{component.replace('.', 'dot')}"
                work.mkdir(mode=0o700)
                outside = self.root / f"outside-{component.replace('.', 'dot')}"
                outside.mkdir(mode=0o700)
                if component == ".ctf":
                    target = outside / "ctf-target"
                    target.mkdir(mode=0o700)
                    runs = target / "runs"
                    runs.mkdir(mode=0o700)
                    outside_run = runs / self.run_id
                    outside_run.mkdir(mode=0o700)
                    (work / ".ctf").symlink_to(
                        target,
                        target_is_directory=True,
                    )
                elif component == "runs":
                    ctf_root = work / ".ctf"
                    ctf_root.mkdir(mode=0o700)
                    target = outside / "runs-target"
                    target.mkdir(mode=0o700)
                    outside_run = target / self.run_id
                    outside_run.mkdir(mode=0o700)
                    (ctf_root / "runs").symlink_to(
                        target,
                        target_is_directory=True,
                    )
                else:
                    ctf_root = work / ".ctf"
                    runs = ctf_root / "runs"
                    ctf_root.mkdir(mode=0o700)
                    runs.mkdir(mode=0o700)
                    outside_run = outside / "run-target"
                    outside_run.mkdir(mode=0o700)
                    (runs / self.run_id).symlink_to(
                        outside_run,
                        target_is_directory=True,
                    )
                outside_stdout = outside_run / "stdout.log"
                outside_stdout.write_bytes(credential)
                outside_stdout.chmod(0o600)

                with self.assertRaisesRegex(
                    OutputCredentialError,
                    "without following links",
                ):
                    audit_run_output_credentials(
                        work,
                        self.run_id,
                        credentials=(credential.decode(),),
                    )

                self.assertEqual(outside_stdout.read_bytes(), credential)

    def test_writable_ancestor_fails_before_run_file_write(self) -> None:
        credential = b"host-provider-secret-value"
        stdout = self.write("stdout.log", credential)
        (self.work / ".ctf" / "runs").chmod(0o733)

        with self.assertRaisesRegex(
            OutputCredentialError,
            "owned non-writable same-device",
        ):
            audit_run_output_credentials(
                self.work,
                self.run_id,
                credentials=(credential.decode(),),
            )

        self.assertEqual(stdout.read_bytes(), credential)

    def test_run_directory_rename_race_is_descriptor_bound(self) -> None:
        credential = b"host-provider-secret-value"
        stdout = self.write("stdout.log", credential)
        runs_root = self.run_root.parent
        moved_run = runs_root / "run-moved"
        outside_run = self.root / "outside-race"
        outside_run.mkdir(mode=0o700)
        outside_stdout = outside_run / "stdout.log"
        outside_stdout.write_bytes(credential)
        outside_stdout.chmod(0o600)
        real_pwrite = os.pwrite
        raced = False

        def racing_pwrite(descriptor, payload, offset):
            nonlocal raced
            if not raced:
                raced = True
                os.rename(self.run_root, moved_run)
                self.run_root.symlink_to(
                    outside_run,
                    target_is_directory=True,
                )
            return real_pwrite(descriptor, payload, offset)

        with (
            mock.patch(
                "ctf_os.sandbox.output_redaction.os.pwrite",
                side_effect=racing_pwrite,
            ),
            self.assertRaisesRegex(
                OutputCredentialError,
                "lineage changed",
            ),
        ):
            audit_run_output_credentials(
                self.work,
                self.run_id,
                credentials=(credential.decode(),),
            )

        self.assertTrue(raced)
        self.assertNotIn(credential, (moved_run / stdout.name).read_bytes())
        self.assertEqual(outside_stdout.read_bytes(), credential)


class DockerRunCredentialAuditTests(unittest.TestCase):
    def test_control_result_is_rejected_when_raw_run_was_removed(
        self,
    ) -> None:
        host_credential = "host-control-result-secret"
        candidate = "KCTF{ordinary-challenge-candidate}"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            challenge = root / "challenge"
            work = root / "work"
            challenge.mkdir()
            scope = ChallengeScope(
                "challenge",
                challenge,
                work,
                contest_id="contest",
                category="pwn",
            )

            def fake_runner(command, **_kwargs):
                result = {
                    "schema_version": 1,
                    "kind": "run_result",
                    "run_id": "run-00000001",
                    "status": "completed",
                    "exit_code": 0,
                    "timed_out": False,
                    "duration_ms": 1,
                    "stdout_summary": (
                        host_credential + "\n" + candidate
                    ),
                    "stderr_summary": "",
                    "stdout_bytes": len(host_credential) + len(candidate) + 1,
                    "stderr_bytes": 0,
                    "stdout_path": (
                        "/work/.ctf/runs/run-00000001/stdout.log"
                    ),
                    "stderr_path": (
                        "/work/.ctf/runs/run-00000001/stderr.log"
                    ),
                }
                return subprocess.CompletedProcess(
                    command,
                    0,
                    json.dumps(result),
                    "",
                )

            backend = DockerSandboxBackend(scope, runner=fake_runner)
            with (
                mock.patch.dict(
                    os.environ,
                    {"OPENAI_API_KEY": host_credential},
                ),
                self.assertRaisesRegex(
                    SandboxError,
                    "protected credential",
                ) as raised,
            ):
                backend.run(CommandSpec(("true",)))

            self.assertNotIn(host_credential, str(raised.exception))
            self.assertFalse((work / ".ctf").exists())

    def test_contaminated_raw_run_is_redacted_and_result_rejected(
        self,
    ) -> None:
        host_credential = "host-provider-secret-value"
        candidate = "KCTF{operator-visible-candidate}"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            challenge = root / "challenge"
            work = root / "work"
            challenge.mkdir()
            scope = ChallengeScope(
                "challenge",
                challenge,
                work,
                contest_id="contest",
                category="pwn",
            )
            calls: list[list[str]] = []

            def fake_runner(command, **_kwargs):
                calls.append(command)
                self.assertNotIn(
                    host_credential,
                    "\0".join(command),
                )
                run_root = work / ".ctf" / "runs" / "run-00000001"
                run_root.mkdir(parents=True, mode=0o700)
                for directory in (
                    work / ".ctf",
                    work / ".ctf" / "runs",
                    run_root,
                ):
                    directory.chmod(0o700)
                stdout = (
                    host_credential + "\n" + candidate + "\n"
                ).encode()
                for name, payload in (
                    ("stdout.log", stdout),
                    ("stderr.log", b""),
                    (
                        "result.json",
                        _canonical_json(
                            {"stdout_summary": host_credential}
                        ),
                    ),
                ):
                    path = run_root / name
                    path.write_bytes(payload)
                    path.chmod(0o600)
                result = {
                    "schema_version": 1,
                    "kind": "run_result",
                    "run_id": "run-00000001",
                    "status": "completed",
                    "exit_code": 0,
                    "timed_out": False,
                    "duration_ms": 1,
                    "stdout_summary": host_credential,
                    "stderr_summary": "",
                    "stdout_bytes": len(stdout),
                    "stderr_bytes": 0,
                    "stdout_path": (
                        "/work/.ctf/runs/run-00000001/stdout.log"
                    ),
                    "stderr_path": (
                        "/work/.ctf/runs/run-00000001/stderr.log"
                    ),
                }
                return subprocess.CompletedProcess(
                    command,
                    0,
                    json.dumps(result),
                    "",
                )

            backend = DockerSandboxBackend(scope, runner=fake_runner)
            with (
                mock.patch.dict(
                    os.environ,
                    {"OPENAI_API_KEY": host_credential},
                ),
                self.assertRaisesRegex(
                    SandboxError,
                    "protected credential",
                ),
            ):
                backend.run(CommandSpec(("true",)))

            self.assertEqual(len(calls), 1)
            stdout_path = (
                work
                / ".ctf"
                / "runs"
                / "run-00000001"
                / "stdout.log"
            )
            redacted = stdout_path.read_bytes()
            self.assertNotIn(host_credential.encode(), redacted)
            self.assertIn(candidate.encode(), redacted)


class BackgroundJobLogCredentialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.challenge = self.root / "challenge"
        self.work = self.root / "work"
        self.challenge.mkdir()
        self.work.mkdir()
        self.scope = ChallengeScope(
            "challenge",
            self.challenge,
            self.work,
            contest_id="contest",
            category="forensic",
        )
        self.backend = DockerSandboxBackend(self.scope)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_supervised_log_rejects_host_credential_and_preserves_flag(
        self,
    ) -> None:
        host_credential = "host-background-log-secret"
        candidate = "KCTF{background-log-candidate}"
        job_root = self.work / ".ctf" / "jobs" / "job-00000001"
        job_root.mkdir(parents=True)
        stdout = job_root / "stdout.log"
        stderr = job_root / "stderr.log"
        stdout.write_text(host_credential, encoding="utf-8")
        stderr.write_text("", encoding="utf-8")
        ref = JobRef(
            "job-00000001",
            self.scope.fingerprint,
            supervisor_id="bg-" + "1" * 32,
        )

        with (
            mock.patch.dict(
                os.environ,
                {"OPENAI_API_KEY": host_credential},
            ),
            self.assertRaisesRegex(
                SandboxError,
                "job log contained a protected credential",
            ) as raised,
        ):
            self.backend.job_log(ref)

        self.assertNotIn(host_credential, str(raised.exception))
        stdout.write_text(candidate, encoding="utf-8")
        with mock.patch.dict(
            os.environ,
            {"OPENAI_API_KEY": host_credential},
        ):
            log = self.backend.job_log(ref)
        self.assertEqual(log.stdout, candidate)

    def test_legacy_log_rejects_provider_credential_and_preserves_flag(
        self,
    ) -> None:
        provider_credential = "sk-proj-ABCDEFGHIJKLMNOPQRSTUV"
        candidate = "KCTF{legacy-log-candidate}"
        ref = JobRef("job-00000001", self.scope.fingerprint)

        def value(stdout: str) -> dict[str, object]:
            return {
                "kind": "job_log",
                "streams": {
                    "stdout": {
                        "tail": stdout,
                        "bytes": len(stdout),
                        "tail_truncated": False,
                    },
                    "stderr": {
                        "tail": "",
                        "bytes": 0,
                        "tail_truncated": False,
                    },
                },
            }

        with (
            mock.patch.object(
                self.backend,
                "_container_for_ref",
                return_value="ctfos-test",
            ),
            mock.patch.object(
                self.backend,
                "_exec_json",
                return_value=value(provider_credential),
            ),
            self.assertRaisesRegex(
                SandboxError,
                "job log contained a protected credential",
            ) as raised,
        ):
            self.backend.job_log(ref)

        self.assertNotIn(provider_credential, str(raised.exception))
        with (
            mock.patch.object(
                self.backend,
                "_container_for_ref",
                return_value="ctfos-test",
            ),
            mock.patch.object(
                self.backend,
                "_exec_json",
                return_value=value(candidate),
            ),
        ):
            log = self.backend.job_log(ref)
        self.assertEqual(log.stdout, candidate)

    def test_supervised_output_limit_metadata_survives_runtime_removal(
        self,
    ) -> None:
        job_root = self.work / ".ctf" / "jobs" / "job-00000001"
        job_root.mkdir(parents=True)
        (job_root / "stdout.log").write_bytes(b"ABCD")
        (job_root / "stderr.log").write_bytes(b"")
        limit = self.backend.limits.stream_capture_max_bytes
        (job_root / "stream-capture.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "reason_code": "output_limit_exceeded",
                    "streams": {
                        "stdout": {
                            "bytes": 65536,
                            "stored_bytes": 4,
                            "limit_bytes": limit,
                            "truncated": True,
                            "complete": True,
                        },
                        "stderr": {
                            "bytes": 0,
                            "stored_bytes": 0,
                            "limit_bytes": limit,
                            "truncated": False,
                            "complete": True,
                        },
                    },
                }
            ),
            encoding="utf-8",
        )
        (job_root / "status.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "job_id": "job-00000001",
                    "status": "failed",
                    "exit_code": 125,
                    "timed_out": False,
                    "cancelled": False,
                    "started_at": "2026-07-31T00:00:00+00:00",
                    "finished_at": "2026-07-31T00:00:01+00:00",
                    "reason_code": "output_limit_exceeded",
                }
            ),
            encoding="utf-8",
        )
        ref = JobRef(
            "job-00000001",
            self.scope.fingerprint,
            supervisor_id="bg-" + "1" * 32,
        )

        log = self.backend.job_log(ref, tail_bytes=4)
        self.assertEqual(log.stdout, "ABCD")
        self.assertEqual(log.stdout_bytes, 65536)
        self.assertTrue(log.stdout_truncated)
        with mock.patch.object(
            self.backend,
            "_supervised_container_for_ref",
            return_value=None,
        ):
            status = self.backend.job_status(ref)
        self.assertIs(status.status, JobState.FAILED)
        self.assertEqual(status.exit_code, 125)
        self.assertEqual(status.reason_code, "output_limit_exceeded")


if __name__ == "__main__":
    unittest.main()
