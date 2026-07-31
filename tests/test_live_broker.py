from __future__ import annotations

import errno
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import ctf_os.live_broker as live_broker_module
from ctf_os import cli
from ctf_os.engine.challenge import (
    ChallengeEngine,
    EngineError,
    SessionAlreadyRunning,
)
from ctf_os.knowledge import (
    MAX_KNOWLEDGE_READ_BYTES,
    MAX_KNOWLEDGE_SEARCH_RESULTS,
    KnowledgeStore,
)
from ctf_os.live_broker import (
    LIVE_BROKER_DIRECTORY_ENV,
    LIVE_SCOPE_CAPABILITY_ENV,
    LIVE_SESSION_ENV,
    MAX_INSPECT_PAGE_ITEMS,
    MAX_INSPECT_RESULT_BYTES,
    LiveBrokerClient,
    LiveBrokerError,
    LiveBrokerServer,
    LiveBrokerService,
    allocated_live_broker_directory,
)
from ctf_os.models import (
    ArtifactReference,
    CandidateStatus,
    ChallengeIdentity,
    ChallengeStatus,
    ExperimentStatus,
    HypothesisStatus,
    ProgressMarker,
    Provenance,
)
from ctf_os.sandbox import (
    ArtifactRef,
    JobRef,
    JobState,
    JobStatus,
    SandboxResult,
)
from ctf_os.sandbox.daemon import CapabilityAuthority
from ctf_os.store import ChallengeLock


class FakeLiveSandbox:
    scope_fingerprint = "a" * 64

    def __init__(self, work: Path) -> None:
        self.work = work
        self.run_count = 0
        self.initialized = False

    def initialize_workspace(
        self,
        *,
        deadline_monotonic_seconds: float | None = None,
    ) -> None:
        del deadline_monotonic_seconds
        self.work.mkdir(parents=True, exist_ok=True)
        self.initialized = True

    def run(self, spec) -> SandboxResult:
        self.run_count += 1
        run_id = f"run-{self.run_count:08d}"
        run_root = self.work / ".ctf" / "runs" / run_id
        run_root.mkdir(parents=True, exist_ok=True)
        stdout = run_root / "stdout.log"
        stderr = run_root / "stderr.log"
        stdout.write_text(
            f"{' '.join(spec.argv)} KCTF{{broker_tool_flag}}\n",
            encoding="utf-8",
        )
        stderr.write_text("", encoding="utf-8")
        return SandboxResult(
            run_id=run_id,
            status="completed",
            exit_code=0,
            timed_out=False,
            duration_ms=1,
            stdout_summary=stdout.read_text(encoding="utf-8"),
            stderr_summary="",
            stdout_bytes=stdout.stat().st_size,
            stderr_bytes=0,
            stdout_path=f"/work/.ctf/runs/{run_id}/stdout.log",
            stderr_path=f"/work/.ctf/runs/{run_id}/stderr.log",
        )

    def register_artifact(
        self,
        locator: str,
        *,
        maximum_bytes: int = 16 * 1024 * 1024 * 1024,
    ) -> ArtifactRef:
        path = self.work / locator
        data = path.read_bytes()
        if len(data) > maximum_bytes:
            raise ValueError("oversized test artifact")
        return ArtifactRef(
            locator=locator,
            sha256=hashlib.sha256(data).hexdigest(),
            size_bytes=len(data),
            scope_fingerprint=self.scope_fingerprint,
        )


class LiveBrokerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name).resolve()
        self.identity = ChallengeIdentity("국내 CTF", "misc", "Live Broker")
        self.clients: dict[Path, FakeLiveSandbox] = {}

        def sandbox_factory(state, work, policy):
            del state, policy
            return self.clients.setdefault(work, FakeLiveSandbox(work))

        self.engine = ChallengeEngine(
            self.root,
            sandbox_factory=sandbox_factory,
        )
        self.engine.add_challenge(self.identity, prompt="broker 경로를 검증하라")

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _service(self) -> tuple[LiveBrokerService, str]:
        prepared = self.engine.prepare_live_session(self.identity)
        authority = CapabilityAuthority.from_file(
            self.engine.config.state_root / "runtime" / "capability-secret"
        )
        token = str(prepared.environment[LIVE_SCOPE_CAPABILITY_ENV])
        return (
            LiveBrokerService(
                self.engine,
                self.identity,
                authority,
                token,
            ),
            token,
        )

    def test_client_timeout_requires_a_finite_positive_bounded_number(
        self,
    ) -> None:
        client = LiveBrokerClient(self.root, "bounded-token")
        for timeout in (
            True,
            0,
            -1,
            float("nan"),
            float("inf"),
            float("-inf"),
            "1",
        ):
            with (
                self.subTest(timeout=timeout),
                self.assertRaisesRegex(LiveBrokerError, "timeout"),
            ):
                client.call(
                    "inspect",
                    self.identity,
                    timeout=timeout,  # type: ignore[arg-type]
                )

    def test_background_quota_reason_is_visible_in_list_and_status(
        self,
    ) -> None:
        service, token = self._service()
        state = self.engine.store.load(self.identity)
        ref = JobRef(
            "job-00000001",
            "a" * 64,
            supervisor_id="bg-" + "b" * 32,
        )
        status = JobStatus(
            ref,
            JobState.FAILED,
            reason_code="work_tree_quota_exceeded",
        )

        def dispatch(params: dict[str, object]) -> object:
            return service.dispatch(
                {
                    "schema_version": 1,
                    "token": token,
                    "identity": self.identity.to_dict(),
                    "operation": "jobs",
                    "params": params,
                }
            )

        with patch.object(
            self.engine,
            "list_background_jobs",
            return_value=(state, (status,)),
        ):
            listed = dispatch({"action": "list"})
        self.assertEqual(
            listed["jobs"][0]["reason_code"],  # type: ignore[index]
            "work_tree_quota_exceeded",
        )

        with patch.object(
            self.engine,
            "background_job_status",
            return_value=(state, status),
        ):
            observed = dispatch(
                {
                    "action": "status",
                    "job_id": ref.job_id,
                    "runtime_id": ref.runtime_id,
                    "supervisor_id": ref.supervisor_id,
                }
            )
        self.assertEqual(
            observed["reason_code"],  # type: ignore[index]
            "work_tree_quota_exceeded",
        )

    def test_broker_reserves_operator_fact_and_abandoned_for_operator_paths(
        self,
    ) -> None:
        service, token = self._service()

        def dispatch(operation: str, params: dict[str, object]) -> object:
            return service.dispatch(
                {
                    "schema_version": 1,
                    "token": token,
                    "identity": self.identity.to_dict(),
                    "operation": operation,
                    "params": params,
                }
            )

        initial = self.engine.store.load(self.identity)
        for provenance in (
            Provenance.EXECUTED,
            Provenance.TOOL_INFERRED,
            Provenance.EXTERNAL_DOC,
            Provenance.OPERATOR,
        ):
            with (
                self.subTest(provenance=provenance.value),
                self.assertRaisesRegex(LiveBrokerError, "model_claimed"),
            ):
                dispatch(
                    "agent.fact",
                    {
                        "statement": (
                            f"model-controlled {provenance.value} assertion"
                        ),
                        "provenance": provenance.value,
                    },
                )
        with self.assertRaisesRegex(LiveBrokerError, "operator-owned"):
            dispatch("agent.transition", {"target": "ABANDONED"})
        with self.assertRaisesRegex(
            LiveBrokerError,
            "not an allowed Live transition target",
        ):
            dispatch("agent.transition", {"target": "PROVING"})
        with self.assertRaisesRegex(
            LiveBrokerError,
            "agent.evaluate",
        ):
            dispatch(
                "agent.hypothesis",
                {
                    "action": "update",
                    "hypothesis_id": "H-model-controlled",
                    "status": "confirmed",
                },
            )
        workspace = self.engine._workspace(initial)
        workspace.mkdir(parents=True, exist_ok=True)
        (workspace / "solver.py").write_text(
            "print('bounded')\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            LiveBrokerError,
            "unexpected agent.artifact params",
        ):
            dispatch(
                "agent.artifact",
                {
                    "locator": "solver.py",
                    "source_run_id": "model-chosen-run",
                },
            )

        unchanged = self.engine.store.load(self.identity)
        self.assertEqual(unchanged.revision, initial.revision)
        self.assertEqual(unchanged.status, initial.status)
        self.assertFalse(
            any(
                fact.statement.startswith("model-controlled")
                for fact in unchanged.facts
            )
        )

        fact_result = dispatch(
            "agent.fact",
            {
                "statement": "bounded model assertion",
                "provenance": "model_claimed",
            },
        )
        self.assertIn("fact_id", fact_result)
        artifact_result = dispatch(
            "agent.artifact",
            {"locator": "solver.py"},
        )
        self.assertIn("artifact_id", artifact_result)
        active = dispatch("agent.transition", {"target": "ACTIVE"})
        self.assertEqual(active["status"], ChallengeStatus.ACTIVE.value)
        state = self.engine.store.load(self.identity)
        self.assertIs(state.facts[-1].provenance, Provenance.MODEL_CLAIMED)
        artifact = next(
            item
            for item in state.artifacts
            if item.id == artifact_result["artifact_id"]
        )
        self.assertIsNone(artifact.source_run_id)
        self.assertIs(state.status, ChallengeStatus.ACTIVE)

    def test_live_transition_cannot_bypass_exact_paused_resume_target(
        self,
    ) -> None:
        service, token = self._service()
        self.engine.record_candidate(
            self.identity,
            "KCTF{paused_ready}",
            print_immediately=False,
        )

        def mark_ready(state) -> None:
            state.candidates[0].status = CandidateStatus.READY_TO_SUBMIT
            state.status = ChallengeStatus.READY_TO_SUBMIT

        ready = self.engine.store.update(self.identity, mark_ready)
        paused = self.engine.pause(self.identity)
        self.assertIs(paused.status, ChallengeStatus.PAUSED)
        self.assertIs(
            paused.resume_status,
            ChallengeStatus.READY_TO_SUBMIT,
        )
        with self.assertRaisesRegex(
            EngineError,
            "Live mutation is not allowed|must use resume",
        ):
            service.dispatch(
                {
                    "schema_version": 1,
                    "token": token,
                    "identity": self.identity.to_dict(),
                    "operation": "agent.transition",
                    "params": {"target": "ACTIVE"},
                }
            )
        unchanged = self.engine.store.load(self.identity)
        self.assertEqual(unchanged.revision, paused.revision)
        self.assertIs(unchanged.status, ChallengeStatus.PAUSED)
        self.assertIs(
            unchanged.resume_status,
            ChallengeStatus.READY_TO_SUBMIT,
        )
        resumed = self.engine.resume(self.identity)
        self.assertEqual(resumed.revision, ready.revision + 2)
        self.assertIs(resumed.status, ChallengeStatus.READY_TO_SUBMIT)
        self.assertIsNone(resumed.resume_status)

    def test_blocked_states_allow_only_live_reads_and_flag_capture(
        self,
    ) -> None:
        service, token = self._service()

        def dispatch(operation: str, params: dict[str, object]) -> object:
            return service.dispatch(
                {
                    "schema_version": 1,
                    "token": token,
                    "identity": self.identity.to_dict(),
                    "operation": operation,
                    "params": params,
                }
            )

        blocked_operations = (
            (
                "agent.fact",
                {
                    "statement": "must not be committed",
                    "provenance": "model_claimed",
                },
            ),
            (
                "agent.goal",
                {
                    "action": "create",
                    "description": "must not replace the active goal",
                    "activate": True,
                },
            ),
            (
                "agent.hypothesis",
                {
                    "action": "create",
                    "statement": "must not be committed",
                    "falsifier": "must not be committed",
                    "status": "open",
                },
            ),
            (
                "agent.experiment",
                {
                    "command": ["true"],
                    "expected_observation": "zero",
                    "keep_if": "zero",
                    "drop_if": "nonzero",
                    "resource_class": "light",
                    "needs_kvm": False,
                },
            ),
            ("agent.evaluate", {}),
            ("agent.artifact", {}),
            (
                "agent.progress",
                {"statement": "must not be committed"},
            ),
            (
                "agent.transition",
                {"target": "ACTIVE"},
            ),
            (
                "tool.run",
                {
                    "command": ["true"],
                    "expected_observation": "zero",
                    "keep_if": "zero",
                    "drop_if": "nonzero",
                    "resource_class": "light",
                    "needs_kvm": False,
                },
            ),
        )

        sandbox = next(iter(self.clients.values()))
        for status in (
            ChallengeStatus.PAUSED,
            ChallengeStatus.READY_TO_SUBMIT,
            ChallengeStatus.SOLVED,
            ChallengeStatus.ABANDONED,
        ):
            with self.subTest(status=status.value):
                def set_status(state) -> None:
                    state.status = status
                    state.resume_status = (
                        ChallengeStatus.ACTIVE
                        if status is ChallengeStatus.PAUSED
                        else None
                    )

                blocked = self.engine.store.update(
                    self.identity,
                    set_status,
                )
                run_count = sandbox.run_count
                for operation, params in blocked_operations:
                    with self.assertRaisesRegex(
                        EngineError,
                        "Live mutation is not allowed",
                    ):
                        dispatch(operation, params)
                unchanged = self.engine.store.load(self.identity)
                self.assertEqual(unchanged.revision, blocked.revision)
                self.assertIs(unchanged.status, status)
                self.assertEqual(sandbox.run_count, run_count)

                inspected = dispatch(
                    "inspect",
                    {"section": "facts"},
                )
                self.assertIsInstance(inspected, list)
                searched = dispatch(
                    "knowledge.search",
                    {"query": "nothing indexed", "limit": 1},
                )
                self.assertEqual(searched["results"], [])
                jobs = dispatch("jobs", {"action": "list"})
                self.assertEqual(jobs["jobs"], [])
                self.assertEqual(
                    self.engine.store.read_snapshot(
                        self.identity
                    ).revision,
                    blocked.revision,
                )
                flag = f"KCTF{{blocked_{status.value.lower()}}}"
                captured = dispatch(
                    "agent.flag",
                    {
                        "value": flag,
                        "source": "blocked-state regression",
                    },
                )
                self.assertIn("candidate_id", captured)
                after_flag = self.engine.store.load(self.identity)
                self.assertIs(after_flag.status, status)
                self.assertTrue(
                    any(
                        candidate.value == flag
                        for candidate in after_flag.candidates
                    )
                )

    @staticmethod
    def _publish_mailbox_file(
        directory: Path,
        name: str,
        payload: bytes,
    ) -> None:
        draft = directory / f".test-{uuid.uuid4().hex}.tmp"
        descriptor = os.open(
            draft,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        try:
            os.write(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(draft, directory / name)

    @staticmethod
    def _wait_for(path: Path, *, timeout: float = 2.0) -> None:
        deadline = time.monotonic() + timeout
        while not path.exists():
            if time.monotonic() >= deadline:
                raise AssertionError(f"timed out waiting for {path}")
            time.sleep(0.01)

    @staticmethod
    def _run_cli(arguments: list[str], *, root: Path) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = cli.main(arguments, root=root)
        return status, stdout.getvalue(), stderr.getvalue()

    def test_launch_routes_live_commands_without_local_engine_or_lock_reentry(
        self,
    ) -> None:
        observed_command: list[str] = []
        observed_broker_directories: list[Path] = []
        candidate_output: list[str] = []

        def runner(command, *, cwd, env, check):
            del check
            observed_command.extend(command)
            self.assertEqual(Path(cwd), self.engine._workspace(
                self.engine.store.load(self.identity)
            ))
            self.assertEqual(env[LIVE_SESSION_ENV], "1")
            self.assertIn(LIVE_SCOPE_CAPABILITY_ENV, env)
            self.assertNotIn("CTFOS_SCOPE_TOKEN", env)
            broker_directory = Path(env[LIVE_BROKER_DIRECTORY_ENV])
            observed_broker_directories.append(broker_directory)
            self.assertTrue(broker_directory.is_dir())
            self.assertEqual(
                broker_directory.stat().st_mode & 0o777,
                0o700,
            )

            # The child path must not construct an engine or read local config.
            # This models Codex workspace-write, where the canonical root is
            # outside the child's writable filesystem.
            unavailable_root = Path("/ctfos-live-child-cannot-access-state")
            with (
                patch.dict(os.environ, env, clear=True),
                patch(
                    "ctf_os.cli.load_config",
                    side_effect=AssertionError("Live child read local config"),
                ),
            ):
                status, output, errors = self._run_cli(
                    ["agent", "flag", "KCTF{broker_candidate}"],
                    root=unavailable_root,
                )
                self.assertEqual(status, 0, errors)
                self.assertIn("candidate 기록", output)
                candidate_output.append(errors)

                status, output, errors = self._run_cli(
                    [
                        "agent",
                        "fact",
                        "broker가 정본 상태를 갱신했다",
                        "--provenance",
                        "model_claimed",
                    ],
                    root=unavailable_root,
                )
                self.assertEqual(status, 0, errors)
                self.assertIn("fact 기록", output)

                status, output, errors = self._run_cli(
                    [
                        "agent",
                        "experiment",
                        "--expected",
                        "zero",
                        "--keep-if",
                        "zero",
                        "--drop-if",
                        "nonzero",
                        "--",
                        "true",
                    ],
                    root=unavailable_root,
                )
                self.assertEqual(status, 0, errors)
                self.assertIn("experiment 사전 등록", output)

                artifact_path = Path(cwd) / "solver.py"
                artifact_path.write_text("print('solver')\n", encoding="utf-8")
                status, output, errors = self._run_cli(
                    ["agent", "artifact", "solver.py"],
                    root=unavailable_root,
                )
                self.assertEqual(status, 0, errors)
                self.assertIn("artifact 등록", output)

                status, output, errors = self._run_cli(
                    ["agent", "progress", "solver artifact registered"],
                    root=unavailable_root,
                )
                self.assertEqual(status, 0, errors)
                self.assertIn("progress 기록", output)

                status, output, errors = self._run_cli(
                    ["agent", "transition", "ACTIVE"],
                    root=unavailable_root,
                )
                self.assertEqual(status, 0, errors)
                self.assertIn("transition: ACTIVE", output)

                # launch_live still owns session.lock here. Success proves that
                # the parent-owned broker path does not reacquire that lock.
                status, output, errors = self._run_cli(
                    ["tool", "run", "--", "printf", "tool"],
                    root=unavailable_root,
                )
                self.assertEqual(status, 0, errors)
                self.assertIn('"status": "awaiting_evaluation"', output)
                candidate_output.append(errors)

                status, output, errors = self._run_cli(
                    [
                        "jobs",
                        self.identity.contest_id,
                        self.identity.category,
                        self.identity.challenge_id,
                    ],
                    root=unavailable_root,
                )
                self.assertEqual(status, 0, errors)
                self.assertIn("experiment_id", output)

                status, output, errors = self._run_cli(
                    [
                        "inspect",
                        self.identity.contest_id,
                        self.identity.category,
                        self.identity.challenge_id,
                        "candidates",
                    ],
                    root=unavailable_root,
                )
                self.assertEqual(status, 0, errors)
                self.assertIn("KCTF{broker_candidate}", output)

                status, _, errors = self._run_cli(
                    [
                        "budget-reset",
                        self.identity.contest_id,
                        self.identity.category,
                        self.identity.challenge_id,
                    ],
                    root=unavailable_root,
                )
                self.assertNotEqual(status, 0)
                self.assertIn("사람의 별도 터미널", errors)

            return subprocess.CompletedProcess(command, 0)

        status = self.engine.launch_live(self.identity, runner=runner)
        self.assertEqual(status, 0)
        self.assertIn("KCTF{broker_candidate}", "".join(candidate_output))
        self.assertIn("KCTF{broker_tool_flag}", "".join(candidate_output))
        self.assertIn(
            "sandbox_workspace_write.network_access=false",
            observed_command,
        )
        self.assertFalse(
            any(
                value.startswith("features.network_proxy.")
                for value in observed_command
            )
        )
        self.assertNotIn("--add-dir", observed_command)
        self.assertEqual(len(observed_broker_directories), 1)
        self.assertNotIn(
            str(observed_broker_directories[0]),
            observed_command,
        )
        self.assertIn(
            "mcp_servers.ctfos_live.required=true",
            observed_command,
        )
        state = self.engine.store.load(self.identity)
        self.assertEqual(state.status, ChallengeStatus.ACTIVE)
        self.assertTrue(any(item.value == "KCTF{broker_candidate}" for item in state.candidates))
        self.assertTrue(any(item.value == "KCTF{broker_tool_flag}" for item in state.candidates))
        self.assertTrue(
            any(
                item.command == "printf tool"
                and item.status is ExperimentStatus.AWAITING_EVALUATION
                for item in state.experiments
            )
        )

    def test_isolated_mcp_process_records_candidate_through_broker(
        self,
    ) -> None:
        service, token = self._service()
        runtime_directory = self.engine.store.challenge_paths(
            self.identity
        ).runtime
        requests = "\n".join(
            json.dumps(value, separators=(",", ":"))
            for value in (
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18"},
                },
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                },
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "agent.flag",
                        "arguments": {
                            "value": "KCTF{mcp_bridge_candidate}",
                            "source": "MCP integration test",
                        },
                    },
                },
            )
        ) + "\n"

        with allocated_live_broker_directory(
            runtime_directory
        ) as broker_directory_owner:
            broker_directory = broker_directory_owner.allocate()
            environment = {
                **os.environ,
                LIVE_SESSION_ENV: "1",
                LIVE_BROKER_DIRECTORY_ENV: str(broker_directory),
                LIVE_SCOPE_CAPABILITY_ENV: token,
                "CTFOS_CONTEST": self.identity.contest_id,
                "CTFOS_CATEGORY": self.identity.category,
                "CTFOS_CHALLENGE": self.identity.challenge_id,
            }
            with LiveBrokerServer(
                broker_directory,
                service,
            ) as server:
                server.start()
                result = subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        "-m",
                        "ctf_os.live_mcp",
                    ],
                    input=requests,
                    text=True,
                    capture_output=True,
                    env=environment,
                    check=False,
                    timeout=10,
                )

        self.assertEqual(result.returncode, 0, result.stderr)
        responses = [
            json.loads(line) for line in result.stdout.splitlines()
        ]
        self.assertEqual([item["id"] for item in responses], [1, 2])
        self.assertFalse(responses[1]["result"]["isError"])
        self.assertIn(
            "candidate_id",
            responses[1]["result"]["structuredContent"]["result"],
        )
        state = self.engine.store.load(self.identity)
        self.assertTrue(
            any(
                item.value == "KCTF{mcp_bridge_candidate}"
                for item in state.candidates
            )
        )

    def test_live_closed_loop_refutes_only_after_executed_evidence(
        self,
    ) -> None:
        service, token = self._service()

        def dispatch(operation: str, params: dict[str, object]) -> object:
            return service.dispatch(
                {
                    "schema_version": 1,
                    "token": token,
                    "identity": self.identity.to_dict(),
                    "operation": operation,
                    "params": params,
                }
            )

        hypothesis_result = dispatch(
            "agent.hypothesis",
            {
                "action": "create",
                "hypothesis_id": "H-live-existing",
                "statement": "the probe will match the prediction",
                "falsifier": "a successful counterexample refutes it",
                "status": "open",
                "evidence_fact_ids": [],
                "evidence_artifact_ids": [],
                "evidence_run_ids": [],
                "confidence": 0.5,
            },
        )
        self.assertEqual(
            hypothesis_result["hypothesis_id"], "H-live-existing"
        )
        experiment_result = dispatch(
            "agent.experiment",
            {
                "command": ["true"],
                "expected_observation": "counterexample output",
                "keep_if": "operator explicitly keeps the result",
                "drop_if": "operator explicitly drops the hypothesis",
                "hypothesis_ids": ["H-live-existing"],
                "timeout_seconds": 30,
                "resource_class": "light",
                "needs_kvm": False,
            },
        )
        experiment_id = str(experiment_result["experiment_id"])
        executed = self.engine.execute_registered_experiments(
            self.identity,
            experiment_ids=(experiment_id,),
        )
        experiment = next(
            item
            for item in executed.experiments
            if item.id == experiment_id
        )
        self.assertIs(
            experiment.status,
            ExperimentStatus.AWAITING_EVALUATION,
        )
        fact_id = str(experiment.result["fact_id"])

        evaluation = dispatch(
            "agent.evaluate",
            {
                "experiment_id": experiment_id,
                "status": "dropped",
                "reason": "the executed counterexample contradicted it",
                "evidence_fact_ids": [fact_id],
                "evidence_artifact_ids": [],
                "evidence_run_ids": [],
                "support_hypothesis_ids": [],
                "refute_hypothesis_ids": ["H-live-existing"],
            },
        )
        self.assertEqual(evaluation["status"], "dropped")
        state = self.engine.store.load(self.identity)
        hypothesis = next(
            item
            for item in state.hypotheses
            if item.id == "H-live-existing"
        )
        self.assertIs(hypothesis.status, HypothesisStatus.REFUTED)
        self.assertEqual(hypothesis.refuted_by, experiment_id)
        with self.assertRaisesRegex(EngineError, "cannot reopen"):
            dispatch(
                "agent.hypothesis",
                {
                    "action": "update",
                    "hypothesis_id": "H-live-existing",
                    "statement": None,
                    "falsifier": None,
                    "status": "open",
                    "evidence_fact_ids": [],
                    "evidence_artifact_ids": [],
                    "evidence_run_ids": [],
                    "confidence": 0.5,
                    "refuted_by": None,
                },
            )
        unchanged = next(
            item
            for item in self.engine.store.load(
                self.identity
            ).hypotheses
            if item.id == "H-live-existing"
        )
        self.assertIs(unchanged.status, HypothesisStatus.REFUTED)
        self.assertEqual(unchanged.refuted_by, experiment_id)

    def test_inspect_list_pagination_is_deterministic_and_compatible(
        self,
    ) -> None:
        service, token = self._service()
        state = self.engine.store.load(self.identity)
        state.progress_markers.extend(
            ProgressMarker(
                id=f"PM-{index:04d}",
                statement=f"marker {index}",
            )
            for index in range(7)
        )
        self.engine.store.save(state)

        def inspect(params: dict[str, object]) -> object:
            return service.dispatch(
                {
                    "schema_version": 1,
                    "token": token,
                    "identity": self.identity.to_dict(),
                    "operation": "inspect",
                    "params": params,
                }
            )

        unpaginated = inspect({"section": "progress_markers"})
        self.assertIsInstance(unpaginated, list)
        self.assertEqual(len(unpaginated), 7)

        first = inspect(
            {
                "section": "progress_markers",
                "offset": 2,
                "limit": 3,
            }
        )
        self.assertEqual(first["offset"], 2)
        self.assertEqual(first["limit"], 3)
        self.assertEqual(first["returned"], 3)
        self.assertEqual(first["total"], 7)
        self.assertEqual(first["next_offset"], 5)
        self.assertEqual(
            [item["id"] for item in first["items"]],
            ["PM-0002", "PM-0003", "PM-0004"],
        )

        final = inspect(
            {
                "section": "progress_markers",
                "offset": first["next_offset"],
                "limit": 3,
            }
        )
        self.assertEqual(final["returned"], 2)
        self.assertIsNone(final["next_offset"])
        self.assertEqual(
            [item["id"] for item in final["items"]],
            ["PM-0005", "PM-0006"],
        )

    def test_inspect_never_exposes_engine_private_artifacts(self) -> None:
        service, token = self._service()
        state = self.engine.store.load(self.identity)
        paths = self.engine.store.challenge_paths(self.identity)
        paths.artifacts.mkdir(parents=True, exist_ok=True)
        visible_path = paths.artifacts / "visible.bin"
        private_path = paths.artifacts / "variant-answer.bin"
        visible_path.write_bytes(b"visible")
        private_path.write_bytes(b"engine-private-answer")
        state.artifacts.extend(
            (
                ArtifactReference(
                    id="A-visible-live",
                    path=visible_path.relative_to(paths.root).as_posix(),
                    sha256=hashlib.sha256(b"visible").hexdigest(),
                    size=len(b"visible"),
                ),
                ArtifactReference(
                    id="A-private-live",
                    path=private_path.relative_to(paths.root).as_posix(),
                    sha256=hashlib.sha256(
                        b"engine-private-answer"
                    ).hexdigest(),
                    size=len(b"engine-private-answer"),
                    extra={
                        "context_visibility": "engine_private",
                        "source_locator": "variant.out",
                    },
                ),
            )
        )
        self.engine.store.save(state)

        def inspect(section: str, **params: object) -> object:
            return service.dispatch(
                {
                    "schema_version": 1,
                    "token": token,
                    "identity": self.identity.to_dict(),
                    "operation": "inspect",
                    "params": {"section": section, **params},
                }
            )

        artifact_view = inspect("artifacts")
        full_state = inspect("state")
        paged = inspect("artifacts", offset=0, limit=20)
        encoded = json.dumps(
            (artifact_view, full_state, paged),
            sort_keys=True,
        )
        self.assertIn("A-visible-live", encoded)
        self.assertNotIn("A-private-live", encoded)
        self.assertNotIn("variant-answer.bin", encoded)
        self.assertNotIn("variant.out", encoded)

    def test_knowledge_search_and_read_are_scoped_strict_and_read_only(
        self,
    ) -> None:
        source = self.root / "reviewed-notes.md"
        source.write_text(
            "Coppersmith lattice notes\n가나다 exploit constraints\n",
            encoding="utf-8",
        )
        record = KnowledgeStore(self.engine.store).add(
            self.identity,
            source,
            source_url="https://example.test/reviewed-notes",
            title="reviewed crypto notes",
        )
        service, token = self._service()
        revision = self.engine.store.load(self.identity).revision

        def dispatch(operation: str, params: dict[str, object]) -> object:
            return service.dispatch(
                {
                    "schema_version": 1,
                    "token": token,
                    "identity": self.identity.to_dict(),
                    "operation": operation,
                    "params": params,
                }
            )

        search = dispatch(
            "knowledge.search",
            {"query": "Coppersmith lattice", "limit": 1},
        )
        self.assertEqual(search["schema_version"], 1)
        self.assertEqual(search["returned"], 1)
        self.assertEqual(search["results"][0]["document"]["id"], record.id)
        self.assertEqual(
            search["results"][0]["document"]["sha256"],
            record.sha256,
        )
        chunk = dispatch(
            "knowledge.read",
            {
                "document_id": record.id,
                "offset_bytes": 0,
                "max_bytes": 12,
            },
        )
        self.assertEqual(chunk["offset_unit"], "utf8_bytes")
        self.assertLessEqual(chunk["returned_bytes"], 12)
        self.assertEqual(chunk["document"]["source_url"], record.source_url)
        for value in (search, chunk):
            self.assertLess(
                len(
                    json.dumps(
                        value,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ),
                1024 * 1024,
            )
        self.assertEqual(
            self.engine.store.load(self.identity).revision,
            revision,
        )

        for operation, params in (
            (
                "knowledge.search",
                {"query": "lattice", "unknown": True},
            ),
            (
                "knowledge.search",
                {
                    "query": "lattice",
                    "limit": MAX_KNOWLEDGE_SEARCH_RESULTS + 1,
                },
            ),
            (
                "knowledge.read",
                {
                    "document_id": record.id,
                    "max_bytes": MAX_KNOWLEDGE_READ_BYTES + 1,
                },
            ),
            (
                "knowledge.read",
                {"document_id": record.id, "offset_bytes": True},
            ),
        ):
            with (
                self.subTest(operation=operation, params=params),
                self.assertRaises(LiveBrokerError),
            ):
                dispatch(operation, params)

    def test_inspect_pagination_arguments_are_strictly_bounded(self) -> None:
        service, token = self._service()

        def request(params: dict[str, object]) -> dict[str, object]:
            return {
                "schema_version": 1,
                "token": token,
                "identity": self.identity.to_dict(),
                "operation": "inspect",
                "params": params,
            }

        invalid = (
            {"section": "runs", "offset": -1},
            {"section": "runs", "offset": True},
            {"section": "runs", "offset": 1.5},
            {"section": "runs", "offset": None},
            {"section": "runs", "limit": 0},
            {"section": "runs", "limit": True},
            {"section": "runs", "limit": 1.5},
            {"section": "runs", "limit": None},
            {
                "section": "runs",
                "limit": MAX_INSPECT_PAGE_ITEMS + 1,
            },
        )
        for params in invalid:
            with (
                self.subTest(params=params),
                self.assertRaisesRegex(LiveBrokerError, "must be an integer"),
            ):
                service.dispatch(request(params))
        with self.assertRaisesRegex(
            LiveBrokerError,
            "only for list sections",
        ):
            service.dispatch(
                request({"section": "summary", "offset": 0})
            )
        with self.assertRaisesRegex(
            LiveBrokerError,
            "unexpected inspect params",
        ):
            service.dispatch(
                request({"section": "runs", "unknown": 1})
            )

    def test_large_state_and_list_inspection_are_bounded_before_rpc(
        self,
    ) -> None:
        service, token = self._service()
        state = self.engine.store.load(self.identity)
        state.prompt = "P" * (MAX_INSPECT_RESULT_BYTES + 64 * 1024)
        state.progress_markers.extend(
            ProgressMarker(
                id=f"PM-{index:04d}",
                statement=f"marker {index}",
            )
            for index in range(101)
        )
        self.engine.store.save(state)

        def inspect(params: dict[str, object]) -> object:
            return service.dispatch(
                {
                    "schema_version": 1,
                    "token": token,
                    "identity": self.identity.to_dict(),
                    "operation": "inspect",
                    "params": params,
                }
            )

        state_view = inspect({"section": "state"})
        self.assertEqual(state_view["section"], "summary")
        self.assertTrue(state_view["full_state_omitted"])
        self.assertEqual(
            state_view["counts"]["progress_markers"],
            101,
        )
        page = inspect({"section": "progress_markers"})
        self.assertEqual(page["total"], 101)
        self.assertEqual(page["returned"], 100)
        self.assertEqual(page["next_offset"], 100)
        for value in (state_view, page):
            encoded = json.dumps(
                value,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            self.assertLessEqual(len(encoded), MAX_INSPECT_RESULT_BYTES)
        runtime_directory = self.engine.store.challenge_paths(
            self.identity
        ).runtime
        with allocated_live_broker_directory(
            runtime_directory
        ) as broker_directory_owner:
            broker_directory = broker_directory_owner.allocate()
            with LiveBrokerServer(
                broker_directory,
                service,
            ) as server:
                server.start()
                client = LiveBrokerClient(broker_directory, token)
                wire_state = client.call(
                    "inspect",
                    self.identity,
                    {"section": "state"},
                    timeout=2,
                )
                wire_page = client.call(
                    "inspect",
                    self.identity,
                    {"section": "progress_markers"},
                    timeout=2,
                )
        self.assertEqual(wire_state, state_view)
        self.assertEqual(wire_page, page)

    def test_single_oversized_inspect_record_returns_bounded_stub(
        self,
    ) -> None:
        service, token = self._service()
        state = self.engine.store.load(self.identity)
        state.progress_markers.append(
            ProgressMarker(
                id="PM-huge",
                statement="X" * (MAX_INSPECT_RESULT_BYTES + 64 * 1024),
            )
        )
        self.engine.store.save(state)
        page = service.dispatch(
            {
                "schema_version": 1,
                "token": token,
                "identity": self.identity.to_dict(),
                "operation": "inspect",
                "params": {
                    "section": "progress_markers",
                    "offset": 0,
                    "limit": 1,
                },
            }
        )

        self.assertEqual(page["returned"], 1)
        self.assertEqual(page["truncated_items"], 1)
        self.assertTrue(page["items"][0]["_truncated"])
        self.assertEqual(page["items"][0]["id"], "PM-huge")
        encoded = json.dumps(
            page,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        self.assertLessEqual(len(encoded), MAX_INSPECT_RESULT_BYTES)

    def test_inspect_byte_boundary_never_skips_the_next_record(self) -> None:
        service, token = self._service()
        state = self.engine.store.load(self.identity)
        state.progress_markers.extend(
            ProgressMarker(
                id=f"PM-wide-{index}",
                statement=chr(ord("A") + index) * (300 * 1024),
            )
            for index in range(3)
        )
        self.engine.store.save(state)

        def inspect(offset: int) -> dict[str, object]:
            value = service.dispatch(
                {
                    "schema_version": 1,
                    "token": token,
                    "identity": self.identity.to_dict(),
                    "operation": "inspect",
                    "params": {
                        "section": "progress_markers",
                        "offset": offset,
                        "limit": 3,
                    },
                }
            )
            self.assertIsInstance(value, dict)
            return value

        first = inspect(0)
        self.assertEqual(first["returned"], 2)
        self.assertEqual(first["next_offset"], 2)
        final = inspect(2)
        self.assertEqual(final["returned"], 1)
        self.assertIsNone(final["next_offset"])
        ids = [
            item["id"]
            for page in (first, final)
            for item in page["items"]
        ]
        self.assertEqual(
            ids,
            ["PM-wide-0", "PM-wide-1", "PM-wide-2"],
        )

    def test_invalid_capability_cross_scope_and_cross_identity_are_rejected(
        self,
    ) -> None:
        service, token = self._service()
        authority = service.authority
        runtime_directory = self.engine.store.challenge_paths(
            self.identity
        ).runtime
        with allocated_live_broker_directory(
            runtime_directory
        ) as broker_directory_owner:
            broker_directory = broker_directory_owner.allocate()
            with LiveBrokerServer(
                broker_directory,
                service,
            ) as server:
                server.start()
                invalid = LiveBrokerClient(broker_directory, "invalid")
                with self.assertRaisesRegex(
                    LiveBrokerError, "invalid Live session capability"
                ):
                    invalid.call("inspect", self.identity, {"section": "state"})

                cross_scope = LiveBrokerClient(
                    broker_directory,
                    authority.issue("b" * 64),
                )
                with self.assertRaisesRegex(
                    LiveBrokerError, "invalid Live session capability"
                ):
                    cross_scope.call(
                        "inspect", self.identity, {"section": "state"}
                    )

                valid = LiveBrokerClient(broker_directory, token)
                with self.assertRaisesRegex(
                    LiveBrokerError, "another challenge"
                ):
                    valid.call(
                        "inspect",
                        ChallengeIdentity("국내 CTF", "misc", "Other"),
                        {"section": "state"},
                    )

    def test_request_ids_are_at_most_once_for_mutating_operations(self) -> None:
        service, token = self._service()
        runtime_directory = self.engine.store.challenge_paths(
            self.identity
        ).runtime
        fixed_id = uuid.UUID("01234567-89ab-cdef-0123-456789abcdef")
        params = {
            "command": ["printf", "once"],
            "expected_observation": "one run",
            "keep_if": "the command ran once",
            "drop_if": "it did not run",
            "hypothesis_ids": [],
            "timeout_seconds": 30,
            "resource_class": "light",
            "network_target": None,
            "needs_kvm": False,
        }
        with allocated_live_broker_directory(
            runtime_directory
        ) as broker_directory_owner:
            broker_directory = broker_directory_owner.allocate()
            with LiveBrokerServer(
                broker_directory,
                service,
            ) as server:
                server.start()
                client = LiveBrokerClient(broker_directory, token)
                with patch(
                    "ctf_os.live_broker.uuid.uuid4",
                    return_value=fixed_id,
                ):
                    result = client.call(
                        "tool.run",
                        self.identity,
                        params,
                        timeout=5,
                    )
                    self.assertEqual(
                        result["status"],
                        ExperimentStatus.AWAITING_EVALUATION.value,
                    )
                    with self.assertRaisesRegex(
                        LiveBrokerError,
                        "already accepted",
                    ):
                        client.call(
                            "tool.run",
                            self.identity,
                            params,
                            timeout=5,
                        )
        sandbox = next(iter(self.clients.values()))
        self.assertEqual(sandbox.run_count, 1)

    def test_hostile_response_entry_does_not_kill_watcher(self) -> None:
        service, token = self._service()
        runtime_directory = self.engine.store.challenge_paths(
            self.identity
        ).runtime
        fixed_id = uuid.UUID("11111111-2222-3333-4444-555555555555")
        response_name = f"response-{fixed_id.hex}.json"
        with allocated_live_broker_directory(
            runtime_directory
        ) as broker_directory_owner:
            broker_directory = broker_directory_owner.allocate()
            with LiveBrokerServer(
                broker_directory,
                service,
            ) as server:
                server.start()
                (broker_directory / response_name).mkdir(mode=0o700)
                client = LiveBrokerClient(broker_directory, token)
                with (
                    patch(
                        "ctf_os.live_broker.uuid.uuid4",
                        return_value=fixed_id,
                    ),
                    self.assertRaises(LiveBrokerError),
                ):
                    client.call(
                        "inspect",
                        self.identity,
                        {"section": "state"},
                        timeout=1,
                    )
                deadline = time.monotonic() + 2
                request_name = (
                    broker_directory / f"request-{fixed_id.hex}.json"
                )
                while request_name.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                (broker_directory / response_name).rmdir()
                result = client.call(
                    "inspect",
                    self.identity,
                    {"section": "candidates"},
                    timeout=2,
                )
                self.assertEqual(result, [])

    def test_symlink_fifo_and_hardlink_requests_are_rejected_without_following(
        self,
    ) -> None:
        service, _token = self._service()
        runtime_directory = self.engine.store.challenge_paths(
            self.identity
        ).runtime
        sentinel = self.root / "outside-sentinel.json"
        sentinel.write_text('{"outside":"unchanged"}\n', encoding="utf-8")
        sentinel.chmod(0o600)
        original = sentinel.read_bytes()
        request_ids = (
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "cccccccccccccccccccccccccccccccc",
        )
        cleanup_at_response: list[tuple[int, tuple[str, ...]]] = []
        original_write_response = LiveBrokerServer._write_response

        def observe_response_cleanup(
            server,
            request_id: str,
            response: object,
        ) -> None:
            if request_id == request_ids[2]:
                processing = tuple(
                    sorted(
                        path.name
                        for path in broker_directory.iterdir()
                        if path.name.startswith(
                            f".processing-{request_id}-"
                        )
                    )
                )
                cleanup_at_response.append(
                    (sentinel.stat().st_nlink, processing)
                )
            original_write_response(server, request_id, response)

        with allocated_live_broker_directory(
            runtime_directory
        ) as broker_directory_owner:
            broker_directory = broker_directory_owner.allocate()
            with (
                patch.object(
                    LiveBrokerServer,
                    "_write_response",
                    new=observe_response_cleanup,
                ),
                LiveBrokerServer(
                    broker_directory,
                    service,
                ) as server,
            ):
                server.start()
                os.symlink(
                    sentinel,
                    broker_directory / f"request-{request_ids[0]}.json",
                )
                os.mkfifo(
                    broker_directory / f"request-{request_ids[1]}.json",
                    0o600,
                )
                os.link(
                    sentinel,
                    broker_directory / f"request-{request_ids[2]}.json",
                )
                for request_id in request_ids:
                    response_path = (
                        broker_directory / f"response-{request_id}.json"
                    )
                    self._wait_for(response_path)
                    response = json.loads(
                        response_path.read_text(encoding="utf-8")
                    )
                    self.assertFalse(response["ok"])
                    response_path.unlink()
                self.assertEqual(sentinel.read_bytes(), original)
                self.assertEqual(sentinel.stat().st_nlink, 1)
                self.assertEqual(cleanup_at_response, [(1, ())])

    def test_duplicate_nonfinite_and_oversized_requests_are_rejected(
        self,
    ) -> None:
        service, _token = self._service()
        runtime_directory = self.engine.store.challenge_paths(
            self.identity
        ).runtime
        invalid_payloads = (
            b'{"request_id":"dddddddddddddddddddddddddddddddd",'
            b'"request_id":"dddddddddddddddddddddddddddddddd"}',
            b'{"request_id":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",'
            b'"value":NaN}',
            b"x" * (1024 * 1024 + 1),
        )
        request_ids = (
            "dddddddddddddddddddddddddddddddd",
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "ffffffffffffffffffffffffffffffff",
        )
        with allocated_live_broker_directory(
            runtime_directory
        ) as broker_directory_owner:
            broker_directory = broker_directory_owner.allocate()
            with LiveBrokerServer(
                broker_directory,
                service,
            ) as server:
                server.start()
                for request_id, payload in zip(
                    request_ids,
                    invalid_payloads,
                    strict=True,
                ):
                    self._publish_mailbox_file(
                        broker_directory,
                        f"request-{request_id}.json",
                        payload,
                    )
                    response_path = (
                        broker_directory / f"response-{request_id}.json"
                    )
                    self._wait_for(response_path)
                    response = json.loads(
                        response_path.read_text(encoding="utf-8")
                    )
                    self.assertFalse(response["ok"])
                    response_path.unlink()

                client = LiveBrokerClient(
                    broker_directory,
                    service.expected_token,
                )
                self.assertEqual(
                    client.call(
                        "inspect",
                        self.identity,
                        {"section": "candidates"},
                        timeout=2,
                    ),
                    [],
                )

    def test_operation_timeout_and_argument_aggregate_are_bounded(self) -> None:
        service, token = self._service()

        def request(params: dict[str, object]) -> dict[str, object]:
            return {
                "schema_version": 1,
                "token": token,
                "identity": self.identity.to_dict(),
                "operation": "agent.experiment",
                "params": params,
            }

        base: dict[str, object] = {
            "command": ["true"],
            "expected_observation": "bounded",
            "keep_if": "success",
            "drop_if": "failure",
            "hypothesis_ids": [],
            "timeout_seconds": 30,
            "resource_class": "light",
            "network_target": None,
            "needs_kvm": False,
        }
        with self.assertRaisesRegex(LiveBrokerError, "bounded string array"):
            service.dispatch(
                request(
                    {
                        **base,
                        "command": ["a" * (300 * 1024), "b" * (300 * 1024)],
                    }
                )
            )
        with self.assertRaisesRegex(
            LiveBrokerError,
            "between 1 and 28800",
        ):
            service.dispatch(
                request(
                    {
                        **base,
                        "timeout_seconds": 8 * 60 * 60 + 1,
                    }
                )
            )

    def test_mailbox_scan_cap_is_terminal_instead_of_silent_starvation(
        self,
    ) -> None:
        service, _token = self._service()
        runtime_directory = self.engine.store.challenge_paths(
            self.identity
        ).runtime
        with allocated_live_broker_directory(
            runtime_directory
        ) as broker_directory_owner:
            broker_directory = broker_directory_owner.allocate()
            (broker_directory / "junk-one").write_text("1", encoding="utf-8")
            (broker_directory / "junk-two").write_text("2", encoding="utf-8")
            with (
                patch(
                    "ctf_os.live_broker.MAX_MAILBOX_SCAN_ENTRIES",
                    2,
                ),
                self.assertRaisesRegex(
                    LiveBrokerError,
                    "entry limit exceeded",
                ),
            ):
                with LiveBrokerServer(broker_directory, service) as server:
                    server.start()
                    self.assertTrue(server._stop.wait(2))

    def test_server_exit_waits_for_an_active_operation(self) -> None:
        service, token = self._service()
        sandbox = next(iter(self.clients.values()))
        original_run = sandbox.run
        entered = threading.Event()
        release = threading.Event()
        result: list[object] = []
        errors: list[BaseException] = []

        def slow_run(spec):
            entered.set()
            if not release.wait(2):
                raise AssertionError("test did not release the tool operation")
            return original_run(spec)

        def invoke(client: LiveBrokerClient) -> None:
            try:
                result.append(
                    client.call(
                        "tool.run",
                        self.identity,
                        {
                            "command": ["true"],
                            "expected_observation": "one run",
                            "keep_if": "success",
                            "drop_if": "failure",
                            "hypothesis_ids": [],
                            "timeout_seconds": 30,
                            "resource_class": "light",
                            "network_target": None,
                            "needs_kvm": False,
                        },
                        timeout=5,
                    )
                )
            except BaseException as error:
                errors.append(error)

        runtime_directory = self.engine.store.challenge_paths(
            self.identity
        ).runtime
        with patch.object(sandbox, "run", side_effect=slow_run):
            with allocated_live_broker_directory(
                runtime_directory
            ) as broker_directory_owner:
                broker_directory = broker_directory_owner.allocate()
                worker: threading.Thread
                with LiveBrokerServer(
                    broker_directory,
                    service,
                ) as server:
                    server.start()
                    client = LiveBrokerClient(broker_directory, token)
                    worker = threading.Thread(target=invoke, args=(client,))
                    worker.start()
                    self.assertTrue(entered.wait(2))
                    releaser = threading.Timer(0.15, release.set)
                    releaser.start()
                    started = time.monotonic()
                elapsed = time.monotonic() - started
                releaser.join()
                worker.join(2)
        self.assertGreaterEqual(elapsed, 0.12)
        self.assertFalse(worker.is_alive())
        self.assertFalse(errors, errors)
        self.assertEqual(len(result), 1)

    def test_server_start_interrupt_after_watcher_start_cleans_lifecycle(
        self,
    ) -> None:
        service, _token = self._service()
        runtime_directory = self.engine.store.challenge_paths(
            self.identity
        ).runtime
        for interruption in (
            KeyboardInterrupt("synthetic watcher start handoff interrupt"),
            SystemExit(41),
        ):
            with (
                self.subTest(interruption=type(interruption).__name__),
                allocated_live_broker_directory(
                    runtime_directory
                ) as broker_directory_owner,
            ):
                broker_directory = broker_directory_owner.allocate()
                server = LiveBrokerServer(
                    broker_directory,
                    service,
                )
                started_threads: list[threading.Thread] = []
                directory_fds: list[int] = []
                executors = []
                original_start = threading.Thread.start

                def start_then_interrupt(
                    thread: threading.Thread,
                ) -> None:
                    started_threads.append(thread)
                    assert server._directory_fd is not None
                    directory_fds.append(server._directory_fd)
                    assert server._operation_executor is not None
                    executors.append(server._operation_executor)
                    original_start(thread)
                    raise interruption

                with (
                    server,
                    patch.object(
                        threading.Thread,
                        "start",
                        new=start_then_interrupt,
                    ),
                    self.assertRaises(type(interruption)) as raised,
                ):
                    server.start()

                self.assertIs(raised.exception, interruption)
                self.assertEqual(len(started_threads), 1)
                self.assertFalse(started_threads[0].is_alive())
                self.assertIsNone(server._thread)
                self.assertIsNone(server._operation_executor)
                self.assertIsNone(server._directory_fd)
                with self.assertRaises(RuntimeError):
                    executors[0].submit(lambda: None)
                with self.assertRaises(OSError) as closed:
                    os.fstat(directory_fds[0])
                self.assertEqual(closed.exception.errno, errno.EBADF)

                # Cleanup is idempotent even after failed start, and a new
                # server can immediately own the same exact mailbox.
                server.__exit__(None, None, None)
                with LiveBrokerServer(
                    broker_directory,
                    service,
                ) as next_server:
                    next_server.start()
                    next_thread = next_server._thread
                    assert next_thread is not None
                    self.assertTrue(next_thread.is_alive())
                self.assertFalse(next_thread.is_alive())

    def test_server_start_interrupt_before_bootstrap_joins_delayed_watcher(
        self,
    ) -> None:
        service, _token = self._service()
        runtime_directory = self.engine.store.challenge_paths(
            self.identity
        ).runtime
        for interruption in (
            KeyboardInterrupt("synthetic delayed watcher bootstrap interrupt"),
            SystemExit(42),
        ):
            with (
                self.subTest(interruption=type(interruption).__name__),
                allocated_live_broker_directory(
                    runtime_directory
                ) as broker_directory_owner,
            ):
                broker_directory = broker_directory_owner.allocate()
                server = LiveBrokerServer(
                    broker_directory,
                    service,
                )
                original_start = threading.Thread.start
                delayed_threads: list[threading.Thread] = []
                observers: list[threading.Thread] = []
                directory_fds: list[int] = []
                executors = []
                native_identities: list[int] = []
                owner_retained: list[bool] = []
                descriptor_open: list[bool] = []
                observer_errors: list[BaseException] = []
                release_bootstrap = threading.Event()

                def start_native_then_interrupt(
                    thread: threading.Thread,
                ) -> None:
                    delayed_threads.append(thread)
                    assert server._directory_fd is not None
                    directory_fds.append(server._directory_fd)
                    assert server._operation_executor is not None
                    executors.append(server._operation_executor)
                    entered_native = threading.Event()
                    original_bootstrap = thread._bootstrap

                    def delayed_bootstrap() -> None:
                        entered_native.set()
                        release_bootstrap.wait()
                        original_bootstrap()

                    with threading._active_limbo_lock:
                        threading._limbo[thread] = thread
                    try:
                        threading._start_joinable_thread(
                            delayed_bootstrap,
                            handle=thread._handle,
                            daemon=thread.daemon,
                        )
                    except BaseException:
                        with threading._active_limbo_lock:
                            threading._limbo.pop(thread, None)
                        raise
                    self.assertTrue(entered_native.wait(2))
                    self.assertIsNone(thread.ident)
                    native_identities.append(thread._handle.ident)

                    def observe_cleanup_then_release() -> None:
                        try:
                            if not server._stop.wait(2):
                                raise AssertionError(
                                    "server cleanup did not publish stop"
                                )
                            owner_retained.append(server._thread is thread)
                            os.fstat(directory_fds[-1])
                            descriptor_open.append(True)
                        except BaseException as error:
                            observer_errors.append(error)
                        finally:
                            release_bootstrap.set()

                    observer = threading.Thread(
                        target=observe_cleanup_then_release,
                        daemon=True,
                    )
                    observers.append(observer)
                    original_start(observer)
                    raise interruption

                with (
                    server,
                    patch.object(
                        threading.Thread,
                        "start",
                        new=start_native_then_interrupt,
                    ),
                    self.assertRaises(type(interruption)) as raised,
                ):
                    server.start()

                self.assertIs(raised.exception, interruption)
                self.assertEqual(len(delayed_threads), 1)
                self.assertTrue(all(identity > 0 for identity in native_identities))
                self.assertEqual(owner_retained, [True])
                self.assertEqual(descriptor_open, [True])
                for observer in observers:
                    observer.join(2)
                    self.assertFalse(observer.is_alive())
                self.assertFalse(observer_errors, observer_errors)
                self.assertFalse(delayed_threads[0].is_alive())
                self.assertIsNotNone(delayed_threads[0].ident)
                self.assertIsNone(server._thread)
                self.assertIsNone(server._operation_executor)
                self.assertIsNone(server._directory_fd)
                with self.assertRaises(RuntimeError):
                    executors[0].submit(lambda: None)
                with self.assertRaises(OSError) as closed:
                    os.fstat(directory_fds[0])
                self.assertEqual(closed.exception.errno, errno.EBADF)

                # A retry on the same owner cannot revive the delayed watcher:
                # its exact native thread was joined before cleanup retired it.
                with server:
                    server.start()
                    restarted = server._thread
                    assert restarted is not None
                    self.assertTrue(restarted.is_alive())
                self.assertFalse(restarted.is_alive())

    def test_server_enter_return_is_resource_free(self) -> None:
        service, _token = self._service()
        runtime_directory = self.engine.store.challenge_paths(
            self.identity
        ).runtime
        for interruption in (
            KeyboardInterrupt("synthetic server enter return interrupt"),
            SystemExit("synthetic server enter return exit"),
        ):
            with (
                self.subTest(interruption=type(interruption).__name__),
                allocated_live_broker_directory(
                    runtime_directory
                ) as broker_directory_owner,
            ):
                broker_directory = broker_directory_owner.allocate()
                server = LiveBrokerServer(broker_directory, service)
                enter_code = LiveBrokerServer.__enter__.__code__

                def interrupt_return(frame, event, _argument):
                    if (
                        frame.f_code is enter_code
                        and event == "return"
                    ):
                        sys.settrace(None)
                        raise interruption
                    return interrupt_return

                previous_trace = sys.gettrace()
                try:
                    sys.settrace(interrupt_return)
                    with self.assertRaises(
                        type(interruption)
                    ) as raised:
                        with server:
                            self.fail("resource-free enter returned")
                finally:
                    sys.settrace(previous_trace)

                self.assertIs(raised.exception, interruption)
                self.assertIsNone(server._directory_fd)
                self.assertIsNone(server._operation_executor)
                self.assertIsNone(server._thread)
                with server:
                    server.start()
                    thread = server._thread
                    assert thread is not None
                    self.assertTrue(thread.is_alive())
                self.assertFalse(thread.is_alive())

    def test_server_start_return_interrupt_is_guarded_by_exit(self) -> None:
        service, _token = self._service()
        runtime_directory = self.engine.store.challenge_paths(
            self.identity
        ).runtime
        for interruption in (
            KeyboardInterrupt("synthetic server start return interrupt"),
            SystemExit("synthetic server start return exit"),
        ):
            with (
                self.subTest(interruption=type(interruption).__name__),
                allocated_live_broker_directory(
                    runtime_directory
                ) as broker_directory_owner,
            ):
                broker_directory = broker_directory_owner.allocate()
                server = LiveBrokerServer(broker_directory, service)
                start_code = LiveBrokerServer.start.__code__
                resources: list[
                    tuple[int, object, threading.Thread]
                ] = []

                def interrupt_return(frame, event, _argument):
                    if (
                        frame.f_code is start_code
                        and event == "return"
                    ):
                        assert server._directory_fd is not None
                        assert server._operation_executor is not None
                        assert server._thread is not None
                        resources.append(
                            (
                                server._directory_fd,
                                server._operation_executor,
                                server._thread,
                            )
                        )
                        sys.settrace(None)
                        raise interruption
                    return interrupt_return

                previous_trace = sys.gettrace()
                try:
                    sys.settrace(interrupt_return)
                    with self.assertRaises(
                        type(interruption)
                    ) as raised:
                        with server:
                            server.start()
                finally:
                    sys.settrace(previous_trace)

                self.assertIs(raised.exception, interruption)
                self.assertEqual(len(resources), 1)
                descriptor, executor, thread = resources[0]
                self.assertFalse(thread.is_alive())
                with self.assertRaises(RuntimeError):
                    executor.submit(lambda: None)
                with self.assertRaises(OSError) as closed:
                    os.fstat(descriptor)
                self.assertEqual(closed.exception.errno, errno.EBADF)
                self.assertIsNone(server._directory_fd)
                self.assertIsNone(server._operation_executor)
                self.assertIsNone(server._thread)

    def test_server_claim_return_interrupt_terminalizes_without_orphan(
        self,
    ) -> None:
        service, token = self._service()
        runtime_directory = self.engine.store.challenge_paths(
            self.identity
        ).runtime
        for index, interruption in enumerate(
            (
                KeyboardInterrupt("synthetic claim return interrupt"),
                SystemExit("synthetic claim return exit"),
            ),
            start=1,
        ):
            with (
                self.subTest(interruption=type(interruption).__name__),
                allocated_live_broker_directory(
                    runtime_directory
                ) as broker_directory_owner,
            ):
                broker_directory = broker_directory_owner.allocate()
                request_id = f"{index:032x}"
                request_name = f"request-{request_id}.json"
                original_rename = os.rename
                injected = False

                def rename_then_interrupt(*args, **kwargs):
                    nonlocal injected
                    result = original_rename(*args, **kwargs)
                    destination = os.fsdecode(args[1])
                    if (
                        destination.startswith(".processing-")
                        and not injected
                    ):
                        injected = True
                        raise interruption
                    return result

                with self.assertRaisesRegex(
                    LiveBrokerError,
                    "watcher was interrupted",
                ):
                    with LiveBrokerServer(
                        broker_directory,
                        service,
                    ) as server:
                        server.start()
                        thread = server._thread
                        assert thread is not None
                        payload = json.dumps(
                            {
                                "request_id": request_id,
                                "operation": "inspect",
                            }
                        ).encode("utf-8")
                        with patch(
                            "ctf_os.live_broker.os.rename",
                            side_effect=rename_then_interrupt,
                        ):
                            self._publish_mailbox_file(
                                broker_directory,
                                request_name,
                                payload,
                            )
                            self.assertTrue(server._stop.wait(2))
                        thread.join(2)
                        self.assertTrue(injected)
                        self.assertFalse(thread.is_alive())
                        self.assertFalse(
                            (broker_directory / request_name).exists()
                        )
                        self.assertEqual(
                            list(
                                broker_directory.glob(
                                    f".processing-{request_id}-*.json"
                                )
                            ),
                            [],
                        )
                        status = json.loads(
                            (
                                broker_directory / "server-status.json"
                            ).read_text(encoding="utf-8")
                        )
                        self.assertEqual(status["state"], "error")
                        self.assertIn(
                            type(interruption).__name__,
                            status["error"],
                        )

                        started = time.monotonic()
                        with self.assertRaisesRegex(
                            LiveBrokerError,
                            "not ready",
                        ):
                            LiveBrokerClient(
                                broker_directory,
                                token,
                            ).call(
                                "inspect",
                                self.identity,
                                {"section": "candidates"},
                                timeout=2,
                            )
                        self.assertLess(time.monotonic() - started, 0.5)

    def test_server_submit_return_interrupt_has_single_owner_and_terminalizes(
        self,
    ) -> None:
        service, token = self._service()
        runtime_directory = self.engine.store.challenge_paths(
            self.identity
        ).runtime
        for index, interruption in enumerate(
            (
                KeyboardInterrupt("synthetic submit return interrupt"),
                SystemExit("synthetic submit return exit"),
            ),
            start=17,
        ):
            with (
                self.subTest(interruption=type(interruption).__name__),
                allocated_live_broker_directory(
                    runtime_directory
                ) as broker_directory_owner,
            ):
                broker_directory = broker_directory_owner.allocate()
                request_id = f"{index:032x}"
                processing_pattern = (
                    f".processing-{request_id}-*.json"
                )
                response_path = (
                    broker_directory / f"response-{request_id}.json"
                )
                worker_started = threading.Event()
                release_worker = threading.Event()
                original_dispatch = service.dispatch

                def blocked_dispatch(request):
                    worker_started.set()
                    if not release_worker.wait(2):
                        raise AssertionError(
                            "submit handoff test did not release worker"
                        )
                    return original_dispatch(request)

                class InterruptAfterStartedSubmit:
                    def __init__(self, executor) -> None:
                        self._executor = executor
                        self.injected = False

                    def submit(self, *args, **kwargs):
                        future = self._executor.submit(*args, **kwargs)
                        if not self.injected:
                            self.injected = True
                            if not worker_started.wait(2):
                                raise AssertionError(
                                    "submitted worker did not start"
                                )
                            raise interruption
                        return future

                    def shutdown(self, *args, **kwargs):
                        return self._executor.shutdown(*args, **kwargs)

                with (
                    patch.object(
                        service,
                        "dispatch",
                        new=blocked_dispatch,
                    ),
                    self.assertRaisesRegex(
                        LiveBrokerError,
                        "watcher was interrupted",
                    ),
                ):
                    with LiveBrokerServer(
                        broker_directory,
                        service,
                    ) as server:
                        server.start()
                        executor = server._operation_executor
                        assert executor is not None
                        interrupting_executor = (
                            InterruptAfterStartedSubmit(executor)
                        )
                        server._operation_executor = interrupting_executor
                        request = {
                            "schema_version": 1,
                            "request_id": request_id,
                            "token": token,
                            "identity": self.identity.to_dict(),
                            # This test exercises the single mutation-lane
                            # ownership handoff. ``inspect`` moved to the
                            # bounded read lane, so use a real state mutation
                            # instead of asserting mutation-lane state for a
                            # read-only request.
                            "operation": "agent.progress",
                            "params": {
                                "statement": "submit handoff ownership",
                                "artifact_ids": [],
                            },
                        }
                        try:
                            self._publish_mailbox_file(
                                broker_directory,
                                f"request-{request_id}.json",
                                json.dumps(request).encode("utf-8"),
                            )
                            self.assertTrue(worker_started.wait(2))
                            self.assertTrue(server._stop.wait(2))
                            thread = server._thread
                            assert thread is not None
                            thread.join(2)
                            self.assertFalse(thread.is_alive())
                            self.assertTrue(
                                interrupting_executor.injected
                            )
                            # The worker, not the interrupted submitter, owns
                            # the exact claimed file until dispatch completes.
                            self.assertEqual(
                                len(
                                    list(
                                        broker_directory.glob(
                                            processing_pattern
                                        )
                                    )
                                ),
                                1,
                            )
                            self.assertFalse(
                                server._operation_idle.is_set()
                            )
                            status = json.loads(
                                (
                                    broker_directory
                                    / "server-status.json"
                                ).read_text(encoding="utf-8")
                            )
                            self.assertEqual(status["state"], "error")
                            self.assertIn(
                                type(interruption).__name__,
                                status["error"],
                            )

                            started = time.monotonic()
                            with self.assertRaisesRegex(
                                LiveBrokerError,
                                "not ready",
                            ):
                                LiveBrokerClient(
                                    broker_directory,
                                    token,
                                ).call(
                                    "inspect",
                                    self.identity,
                                    {"section": "candidates"},
                                    timeout=2,
                                )
                            self.assertLess(
                                time.monotonic() - started,
                                0.5,
                            )
                        finally:
                            release_worker.set()

                        self._wait_for(response_path)
                        self.assertEqual(
                            list(
                                broker_directory.glob(
                                    processing_pattern
                                )
                            ),
                            [],
                        )
                        self.assertTrue(
                            server._operation_idle.wait(2)
                        )

    def test_worker_ownership_transition_is_inside_lane_finalizer(
        self,
    ) -> None:
        interruption = KeyboardInterrupt(
            "synthetic worker ownership transition interrupt"
        )

        class DispatchServer:
            def __init__(self) -> None:
                self._operation_idle = threading.Event()
                self.dispatched = False
                self.removed: list[str] = []
                self.terminal_errors: list[BaseException] = []

            def _dispatch_claimed(self, *_args, **_kwargs) -> None:
                self.dispatched = True

            def _remove_claimed_request(self, processing: str) -> None:
                self.removed.append(processing)

            def _set_terminal_error(self, error: BaseException) -> None:
                self.terminal_errors.append(error)

        server = DispatchServer()
        dispatch = live_broker_module._BackgroundRequestDispatch(
            server,  # type: ignore[arg-type]
            ".processing-worker-transition.json",
            "3" * 32,
            {},
        )
        target_code = dispatch.__call__.__func__.__code__
        injected = False

        def interrupt_after_worker_ownership(
            frame,
            event,
            _argument,
        ):
            nonlocal injected
            if (
                frame.f_code is target_code
                and event == "line"
                and frame.f_locals.get("self") is dispatch
                and dispatch._state == "worker"
                and not injected
            ):
                injected = True
                sys.settrace(None)
                raise interruption
            return interrupt_after_worker_ownership

        previous_trace = sys.gettrace()
        try:
            sys.settrace(interrupt_after_worker_ownership)
            with self.assertRaises(KeyboardInterrupt) as raised:
                dispatch()
        finally:
            sys.settrace(previous_trace)

        self.assertTrue(injected)
        self.assertIs(raised.exception, interruption)
        self.assertFalse(server.dispatched)
        self.assertEqual(
            server.removed,
            [".processing-worker-transition.json"],
        )
        self.assertEqual(len(server.terminal_errors), 1)
        self.assertTrue(server._operation_idle.is_set())

    def test_submit_cancel_return_interrupt_reclaims_lane_and_claim(
        self,
    ) -> None:
        service, _token = self._service()
        broker_directory = self.root / "submit-cancel-return"
        broker_directory.mkdir(mode=0o700)
        server = LiveBrokerServer(broker_directory, service)
        server._directory_fd = os.open(
            broker_directory,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY,
        )

        class FailingExecutor:
            @staticmethod
            def submit(_dispatch) -> None:
                raise OSError("synthetic pre-worker submit failure")

        server._operation_executor = FailingExecutor()  # type: ignore[assignment]
        request_id = "4" * 32
        request_name = f"request-{request_id}.json"
        live_broker_module._atomic_mailbox_write(
            server._directory_fd,
            request_name,
            json.dumps(
                {
                    "request_id": request_id,
                    "operation": "inspect",
                }
            ).encode("utf-8"),
        )
        target_code = (
            live_broker_module
            ._BackgroundRequestDispatch
            .cancel_before_worker_start
            .__code__
        )
        interruption = KeyboardInterrupt(
            "synthetic submit cancellation return interrupt"
        )
        injected = False

        def interrupt_cancel_return(frame, event, _argument):
            nonlocal injected
            if (
                frame.f_code is target_code
                and event == "return"
                and not injected
            ):
                injected = True
                sys.settrace(None)
                raise interruption
            return interrupt_cancel_return

        previous_trace = sys.gettrace()
        try:
            sys.settrace(interrupt_cancel_return)
            with self.assertRaises(KeyboardInterrupt) as raised:
                server._process(request_name)
        finally:
            sys.settrace(previous_trace)
            server._operation_executor = None
            close_error = server._close_directory_fd()
            if close_error is not None:
                raise close_error

        self.assertTrue(injected)
        self.assertIs(raised.exception, interruption)
        self.assertTrue(server._operation_idle.is_set())
        self.assertFalse((broker_directory / request_name).exists())
        self.assertEqual(
            list(broker_directory.glob(".processing-*.json")),
            [],
        )

    def test_cancelled_late_dispatch_cannot_release_a_newer_lane(
        self,
    ) -> None:
        class DispatchServer:
            def __init__(self) -> None:
                self._operation_idle = threading.Event()
                self._operation_idle.set()
                self.dispatched: list[str] = []

            def _dispatch_claimed(
                self,
                _processing: str,
                request_id: str,
                _request: object,
                *,
                background: bool,
            ) -> None:
                self.assert_background_false(background)
                self.dispatched.append(request_id)

            @staticmethod
            def assert_background_false(background: bool) -> None:
                if background:
                    raise AssertionError("dispatch unexpectedly ran in background")

            @staticmethod
            def _remove_claimed_request(_processing: str) -> None:
                raise AssertionError("successful dispatch removed its claim")

            @staticmethod
            def _set_terminal_error(_error: BaseException) -> None:
                raise AssertionError("successful dispatch became terminal")

        server = DispatchServer()
        cancelled = live_broker_module._BackgroundRequestDispatch(
            server,  # type: ignore[arg-type]
            ".processing-cancelled.json",
            "5" * 32,
            {},
        )
        newer = live_broker_module._BackgroundRequestDispatch(
            server,  # type: ignore[arg-type]
            ".processing-newer.json",
            "6" * 32,
            {},
        )

        self.assertTrue(cancelled.cancel_before_worker_start())
        server._operation_idle.set()
        server._operation_idle.clear()

        cancelled()
        self.assertFalse(server._operation_idle.is_set())
        self.assertEqual(server.dispatched, [])

        newer()
        self.assertTrue(server._operation_idle.is_set())
        self.assertEqual(server.dispatched, ["6" * 32])

        # A duplicate callback from an already-finished dispatch cannot release
        # a still newer lane either.
        server._operation_idle.clear()
        newer()
        self.assertFalse(server._operation_idle.is_set())
        self.assertEqual(server.dispatched, ["6" * 32])

    def test_directory_owner_enter_and_allocate_return_handoffs(
        self,
    ) -> None:
        runtime_directory = self.engine.store.challenge_paths(
            self.identity
        ).runtime
        for interruption in (
            KeyboardInterrupt("synthetic allocator handoff interrupt"),
            SystemExit("synthetic allocator handoff exit"),
        ):
            with self.subTest(interruption=type(interruption).__name__):
                owner = allocated_live_broker_directory(
                    runtime_directory
                )
                enter_code = type(owner).__enter__.__code__

                def interrupt_enter(frame, event, _argument):
                    if (
                        frame.f_code is enter_code
                        and event == "return"
                    ):
                        sys.settrace(None)
                        raise interruption
                    return interrupt_enter

                previous_trace = sys.gettrace()
                try:
                    sys.settrace(interrupt_enter)
                    with self.assertRaises(
                        type(interruption)
                    ) as enter_raised:
                        with owner:
                            self.fail("resource-free owner enter returned")
                finally:
                    sys.settrace(previous_trace)

                self.assertIs(enter_raised.exception, interruption)
                self.assertIsNone(owner._runtime_fd)
                self.assertIsNone(owner._mailboxes_fd)
                self.assertIsNone(owner._cleanup_fd)
                self.assertFalse(owner.directory.exists())

                descriptors: list[tuple[int, int, int]] = []
                allocate_code = type(owner).allocate.__code__

                def interrupt_allocate(frame, event, _argument):
                    if (
                        frame.f_code is allocate_code
                        and event == "return"
                    ):
                        assert owner._runtime_fd is not None
                        assert owner._mailboxes_fd is not None
                        assert owner._cleanup_fd is not None
                        descriptors.append(
                            (
                                owner._runtime_fd,
                                owner._mailboxes_fd,
                                owner._cleanup_fd,
                            )
                        )
                        sys.settrace(None)
                        raise interruption
                    return interrupt_allocate

                previous_trace = sys.gettrace()
                try:
                    sys.settrace(interrupt_allocate)
                    with self.assertRaises(
                        type(interruption)
                    ) as allocate_raised:
                        with owner:
                            owner.allocate()
                finally:
                    sys.settrace(previous_trace)

                self.assertIs(allocate_raised.exception, interruption)
                self.assertEqual(len(descriptors), 1)
                for descriptor in descriptors[0]:
                    with self.assertRaises(OSError) as closed:
                        os.fstat(descriptor)
                    self.assertEqual(
                        closed.exception.errno,
                        errno.EBADF,
                    )
                self.assertIsNone(owner._runtime_fd)
                self.assertIsNone(owner._mailboxes_fd)
                self.assertIsNone(owner._cleanup_fd)
                self.assertFalse(owner.directory.exists())

    def test_directory_owner_close_never_recloses_a_reused_fd(
        self,
    ) -> None:
        runtime_directory = self.engine.store.challenge_paths(
            self.identity
        ).runtime
        real_close = os.close
        flags = os.O_RDONLY | os.O_CLOEXEC

        for interruption in (
            KeyboardInterrupt("synthetic directory fd close interrupt"),
            SystemExit("synthetic directory fd close exit"),
        ):
            with self.subTest(interruption=type(interruption).__name__):
                owner = allocated_live_broker_directory(
                    runtime_directory
                )
                descriptor = os.open(
                    runtime_directory,
                    flags | os.O_DIRECTORY,
                )
                opened = os.fstat(descriptor)
                identity = (opened.st_dev, opened.st_ino)
                owner._runtime_fd = descriptor
                close_calls: list[int] = []
                peer_descriptor: int | None = None

                def close_then_reuse(value: int) -> None:
                    nonlocal peer_descriptor
                    close_calls.append(value)
                    if len(close_calls) == 1:
                        real_close(value)
                        replacement = os.open(
                            runtime_directory,
                            flags | os.O_DIRECTORY,
                        )
                        if replacement != value:
                            self.assertEqual(
                                os.dup2(
                                    replacement,
                                    value,
                                    inheritable=False,
                                ),
                                value,
                            )
                            real_close(replacement)
                        peer_descriptor = value
                        reopened = os.fstat(value)
                        self.assertEqual(
                            (reopened.st_dev, reopened.st_ino),
                            identity,
                        )
                        raise interruption
                    real_close(value)

                try:
                    with patch(
                        "ctf_os.live_broker.os.close",
                        side_effect=close_then_reuse,
                    ):
                        close_error = owner._close_owned_fd(
                            owner,
                            "_runtime_fd",
                        )

                    self.assertIs(close_error, interruption)
                    self.assertEqual(close_calls, [descriptor])
                    self.assertIsNone(owner._runtime_fd)
                    self.assertEqual(peer_descriptor, descriptor)
                    self.assertEqual(
                        (
                            os.fstat(descriptor).st_dev,
                            os.fstat(descriptor).st_ino,
                        ),
                        identity,
                    )
                    self.assertIsNone(
                        owner._close_owned_fd(owner, "_runtime_fd")
                    )
                finally:
                    try:
                        real_close(descriptor)
                    except OSError as error:
                        if error.errno != errno.EBADF:
                            raise

                with allocated_live_broker_directory(
                    runtime_directory
                ) as next_owner:
                    next_directory = next_owner.allocate()
                    self.assertTrue(next_directory.is_dir())
                self.assertFalse(next_directory.exists())

    def test_server_directory_close_never_recloses_same_inode_peer(
        self,
    ) -> None:
        service, _token = self._service()
        runtime_directory = self.engine.store.challenge_paths(
            self.identity
        ).runtime
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
        real_close = os.close

        for interruption in (
            KeyboardInterrupt("synthetic server directory close interrupt"),
            SystemExit("synthetic server directory close exit"),
        ):
            with self.subTest(interruption=type(interruption).__name__):
                with allocated_live_broker_directory(
                    runtime_directory
                ) as owner:
                    broker_directory = owner.allocate()
                    server = LiveBrokerServer(broker_directory, service)
                    descriptor = os.open(broker_directory, flags)
                    server._directory_fd = descriptor
                    opened = os.fstat(descriptor)
                    identity = (opened.st_dev, opened.st_ino)
                    peer_descriptor: int | None = None
                    close_calls: list[int] = []

                    def close_then_reopen_same_inode(value: int) -> None:
                        nonlocal peer_descriptor
                        close_calls.append(value)
                        if peer_descriptor is None:
                            real_close(value)
                            replacement = os.open(
                                broker_directory,
                                flags,
                            )
                            if replacement != value:
                                os.dup2(
                                    replacement,
                                    value,
                                    inheritable=False,
                                )
                                real_close(replacement)
                            peer_descriptor = value
                            reopened = os.fstat(value)
                            self.assertEqual(
                                (reopened.st_dev, reopened.st_ino),
                                identity,
                            )
                            raise interruption
                        real_close(value)

                    try:
                        with patch(
                            "ctf_os.live_broker.os.close",
                            side_effect=close_then_reopen_same_inode,
                        ):
                            close_error = server._close_directory_fd()

                        self.assertIs(close_error, interruption)
                        self.assertIsNone(server._directory_fd)
                        self.assertEqual(close_calls, [descriptor])
                        self.assertEqual(peer_descriptor, descriptor)
                        peer = os.fstat(descriptor)
                        self.assertEqual(
                            (peer.st_dev, peer.st_ino),
                            identity,
                        )
                        self.assertIsNone(server._close_directory_fd())
                        os.fstat(descriptor)
                    finally:
                        try:
                            real_close(descriptor)
                        except OSError as error:
                            if error.errno != errno.EBADF:
                                raise

    def test_private_directory_rejection_never_recloses_same_inode_peer(
        self,
    ) -> None:
        runtime_directory = self.engine.store.challenge_paths(
            self.identity
        ).runtime
        unsafe_directory = runtime_directory / "unsafe-live-mailbox"
        unsafe_directory.mkdir(mode=0o755)
        unsafe_directory.chmod(0o755)
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
        real_close = os.close

        try:
            for interruption in (
                KeyboardInterrupt(
                    "synthetic private directory close interrupt"
                ),
                SystemExit("synthetic private directory close exit"),
            ):
                with self.subTest(
                    interruption=type(interruption).__name__
                ):
                    close_calls: list[int] = []
                    peer_descriptor: int | None = None
                    identity: tuple[int, int] | None = None

                    def close_then_reopen_same_inode(value: int) -> None:
                        nonlocal peer_descriptor, identity
                        close_calls.append(value)
                        if peer_descriptor is None:
                            opened = os.fstat(value)
                            identity = (opened.st_dev, opened.st_ino)
                            real_close(value)
                            replacement = os.open(
                                unsafe_directory,
                                flags,
                            )
                            if replacement != value:
                                os.dup2(
                                    replacement,
                                    value,
                                    inheritable=False,
                                )
                                real_close(replacement)
                            peer_descriptor = value
                            reopened = os.fstat(value)
                            self.assertEqual(
                                (reopened.st_dev, reopened.st_ino),
                                identity,
                            )
                            raise interruption
                        real_close(value)

                    try:
                        with (
                            patch(
                                "ctf_os.live_broker.os.close",
                                side_effect=close_then_reopen_same_inode,
                            ),
                            self.assertRaises(
                                type(interruption)
                            ) as raised,
                        ):
                            live_broker_module._open_private_directory(
                                unsafe_directory
                            )

                        self.assertIs(raised.exception, interruption)
                        assert peer_descriptor is not None
                        assert identity is not None
                        self.assertEqual(
                            close_calls,
                            [peer_descriptor],
                        )
                        peer = os.fstat(peer_descriptor)
                        self.assertEqual(
                            (peer.st_dev, peer.st_ino),
                            identity,
                        )
                    finally:
                        if peer_descriptor is not None:
                            try:
                                real_close(peer_descriptor)
                            except OSError:
                                pass
        finally:
            unsafe_directory.rmdir()

    def test_client_directory_return_interrupt_closes_handoff_fd(
        self,
    ) -> None:
        broker_directory = self.root / "client-directory-handoff"
        broker_directory.mkdir(mode=0o700)
        client = LiveBrokerClient(broker_directory, "test-token")
        target_code = (
            live_broker_module._open_private_directory.__code__
        )
        interruption = KeyboardInterrupt(
            "synthetic client directory return interrupt"
        )
        captured_descriptors: list[int] = []

        def interrupt_directory_return(frame, event, argument):
            if frame.f_code is target_code and event == "return":
                captured_descriptors.append(int(argument))
                sys.settrace(None)
                raise interruption
            return interrupt_directory_return

        previous_trace = sys.gettrace()
        try:
            sys.settrace(interrupt_directory_return)
            with self.assertRaises(KeyboardInterrupt) as raised:
                client.call(
                    "inspect",
                    self.identity,
                    {"section": "summary"},
                    timeout=1,
                )
        finally:
            sys.settrace(previous_trace)

        self.assertIs(raised.exception, interruption)
        self.assertEqual(len(captured_descriptors), 1)
        with self.assertRaises(OSError) as closed:
            os.fstat(captured_descriptors[0])
        self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_directory_owner_normal_close_return_interrupt_is_safe(
        self,
    ) -> None:
        runtime_directory = self.engine.store.challenge_paths(
            self.identity
        ).runtime
        foreign_path = runtime_directory / "foreign-normal-close-owner"
        foreign_path.write_bytes(b"foreign")
        real_close = os.close
        flags = os.O_RDONLY | os.O_CLOEXEC

        for interruption in (
            KeyboardInterrupt("synthetic owner normal close interrupt"),
            SystemExit(49),
        ):
            with self.subTest(interruption=type(interruption).__name__):
                owner = allocated_live_broker_directory(runtime_directory)
                descriptor = os.open(
                    runtime_directory,
                    flags | os.O_DIRECTORY,
                )
                owner._runtime_fd = descriptor
                foreign_source = os.open(foreign_path, flags)
                self.assertNotEqual(foreign_source, descriptor)
                injected = False
                close_code = type(owner)._close_owned_fd.__code__

                def interrupt_after_normal_close(
                    frame,
                    event,
                    _argument,
                ):
                    nonlocal injected
                    if (
                        frame.f_code is close_code
                        and event == "line"
                        and owner._runtime_fd is None
                        and not injected
                    ):
                        try:
                            os.fstat(descriptor)
                        except OSError as error:
                            if error.errno == errno.EBADF:
                                injected = True
                                sys.settrace(None)
                                raise interruption
                    return interrupt_after_normal_close

                previous_trace = sys.gettrace()
                try:
                    sys.settrace(interrupt_after_normal_close)
                    with self.assertRaises(
                        type(interruption)
                    ) as raised:
                        owner._close_owned_fd(owner, "_runtime_fd")
                finally:
                    sys.settrace(previous_trace)

                self.assertTrue(injected)
                self.assertIs(raised.exception, interruption)
                self.assertIsNone(owner._runtime_fd)
                self.assertEqual(
                    os.dup2(
                        foreign_source,
                        descriptor,
                        inheritable=False,
                    ),
                    descriptor,
                )
                try:
                    self.assertIsNone(
                        owner._close_owned_fd(owner, "_runtime_fd")
                    )
                    self.assertEqual(
                        os.fstat(descriptor).st_ino,
                        os.fstat(foreign_source).st_ino,
                    )
                finally:
                    for value in (descriptor, foreign_source):
                        try:
                            real_close(value)
                        except OSError:
                            pass

                with allocated_live_broker_directory(
                    runtime_directory
                ) as next_owner:
                    next_directory = next_owner.allocate()
                    self.assertTrue(next_directory.is_dir())
                self.assertFalse(next_directory.exists())

    def test_atomic_mailbox_never_recloses_same_inode_peer_descriptor(
        self,
    ) -> None:
        runtime_directory = self.engine.store.challenge_paths(
            self.identity
        ).runtime
        flags = os.O_RDONLY | os.O_CLOEXEC
        directory_fd = os.open(
            runtime_directory,
            flags | os.O_DIRECTORY,
        )
        real_close = os.close
        try:
            for index, interruption in enumerate(
                (
                    KeyboardInterrupt(
                        "synthetic mailbox normal close interrupt"
                    ),
                    SystemExit(51),
                ),
                start=1,
            ):
                with self.subTest(
                    interruption=type(interruption).__name__
                ):
                    close_calls: list[int] = []
                    peer_descriptor: int | None = None
                    peer_identity: tuple[int, int] | None = None

                    def close_then_reopen_same_inode(
                        descriptor: int,
                    ) -> None:
                        nonlocal peer_descriptor, peer_identity
                        close_calls.append(descriptor)
                        if peer_descriptor is None:
                            opened = os.fstat(descriptor)
                            peer_identity = (
                                opened.st_dev,
                                opened.st_ino,
                            )
                            descriptor_path = Path(
                                os.readlink(f"/proc/self/fd/{descriptor}")
                            )
                            real_close(descriptor)
                            replacement = os.open(
                                descriptor_path,
                                flags,
                            )
                            if replacement != descriptor:
                                os.dup2(
                                    replacement,
                                    descriptor,
                                    inheritable=False,
                                )
                                real_close(replacement)
                            peer_descriptor = descriptor
                            reopened = os.fstat(descriptor)
                            self.assertEqual(
                                (reopened.st_dev, reopened.st_ino),
                                peer_identity,
                            )
                            raise interruption
                        real_close(descriptor)

                    try:
                        with (
                            patch(
                                "ctf_os.live_broker.os.close",
                                side_effect=close_then_reopen_same_inode,
                            ),
                            self.assertRaises(
                                type(interruption)
                            ) as raised,
                        ):
                            live_broker_module._atomic_mailbox_write(
                                directory_fd,
                                f"interrupted-{index}.json",
                                b"payload",
                            )
                        self.assertIs(raised.exception, interruption)
                        self.assertIsNotNone(peer_descriptor)
                        assert peer_descriptor is not None
                        assert peer_identity is not None
                        self.assertEqual(
                            close_calls,
                            [peer_descriptor],
                        )
                        peer = os.fstat(peer_descriptor)
                        self.assertEqual(
                            (peer.st_dev, peer.st_ino),
                            peer_identity,
                        )
                    finally:
                        if peer_descriptor is not None:
                            try:
                                real_close(peer_descriptor)
                            except OSError:
                                pass

                    self.assertEqual(
                        list(runtime_directory.glob(".mailbox-*.tmp")),
                        [],
                    )

                    next_name = f"next-{index}.json"
                    live_broker_module._atomic_mailbox_write(
                        directory_fd,
                        next_name,
                        b"next",
                    )
                    self.assertEqual(
                        (runtime_directory / next_name).read_bytes(),
                        b"next",
                    )
                    (runtime_directory / next_name).unlink()
        finally:
            real_close(directory_fd)

    def test_server_exit_interrupt_still_closes_every_owned_resource(
        self,
    ) -> None:
        service, _token = self._service()
        runtime_directory = self.engine.store.challenge_paths(
            self.identity
        ).runtime
        interruption = KeyboardInterrupt(
            "synthetic watcher join interrupt"
        )
        with allocated_live_broker_directory(
            runtime_directory
        ) as broker_directory_owner:
            broker_directory = broker_directory_owner.allocate()
            server = LiveBrokerServer(broker_directory, service)
            server.start()
            directory_fd = server._directory_fd
            assert directory_fd is not None
            thread = server._thread
            assert thread is not None
            executor = server._operation_executor
            assert executor is not None
            original_join = thread.join
            interrupted = False

            def interrupt_first_join(*args, **kwargs) -> None:
                nonlocal interrupted
                if not interrupted:
                    interrupted = True
                    raise interruption
                original_join(*args, **kwargs)

            thread.join = interrupt_first_join
            with self.assertRaises(KeyboardInterrupt) as raised:
                server.__exit__(None, None, None)

            self.assertIs(raised.exception, interruption)
            self.assertFalse(thread.is_alive())
            self.assertIsNone(server._thread)
            self.assertIsNone(server._operation_executor)
            self.assertIsNone(server._directory_fd)
            with self.assertRaises(RuntimeError):
                executor.submit(lambda: None)
            with self.assertRaises(OSError) as closed:
                os.fstat(directory_fd)
            self.assertEqual(closed.exception.errno, errno.EBADF)
            server.__exit__(None, None, None)

    def test_lifecycle_retry_and_aggregation_prioritize_control(
        self,
    ) -> None:
        later_control = KeyboardInterrupt(
            "synthetic later lifecycle control"
        )
        calls = 0

        def fail_ordinary_then_control() -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("synthetic ordinary lifecycle failure")
            raise later_control

        retry_error, completed = (
            LiveBrokerServer._retry_lifecycle_step(
                "synthetic lifecycle step",
                fail_ordinary_then_control,
            )
        )
        self.assertIs(retry_error, later_control)
        self.assertFalse(completed)

        service, _token = self._service()
        server = LiveBrokerServer(
            self.root / "lifecycle-error-priority",
            service,
        )
        ordinary = OSError("synthetic earlier aggregate error")
        aggregate_control = SystemExit(
            "synthetic aggregate cleanup control"
        )
        with (
            patch.object(
                server,
                "_cleanup_lifecycle",
                return_value=[
                    ("ordinary step", ordinary),
                    ("control step", aggregate_control),
                ],
            ),
            self.assertRaises(SystemExit) as raised,
        ):
            server.__exit__(None, None, None)

        self.assertIs(raised.exception, aggregate_control)
        self.assertTrue(
            any(
                "ordinary step" in note
                for note in aggregate_control.__notes__
            )
        )

        active_ordinary = OSError("synthetic active ordinary error")
        active_cleanup_control = KeyboardInterrupt(
            "synthetic active cleanup control"
        )
        with (
            patch.object(
                server,
                "_cleanup_lifecycle",
                return_value=[
                    ("active cleanup control", active_cleanup_control),
                ],
            ),
            self.assertRaises(KeyboardInterrupt) as active_raised,
        ):
            server.__exit__(
                OSError,
                active_ordinary,
                active_ordinary.__traceback__,
            )

        self.assertIs(active_raised.exception, active_cleanup_control)
        self.assertTrue(
            any(
                "active OSError" in note
                for note in active_cleanup_control.__notes__
            )
        )

    def test_start_and_directory_cleanup_prioritize_control(
        self,
    ) -> None:
        service, _token = self._service()
        start_error = OSError("synthetic server start failure")
        start_cleanup_control = KeyboardInterrupt(
            "synthetic server start cleanup control"
        )
        server = LiveBrokerServer(
            self.root / "start-cleanup-control",
            service,
        )
        with (
            patch(
                "ctf_os.live_broker._open_private_directory",
                side_effect=start_error,
            ),
            patch.object(
                server,
                "_cleanup_lifecycle",
                return_value=[
                    ("start cleanup", start_cleanup_control),
                ],
            ),
            self.assertRaises(KeyboardInterrupt) as start_raised,
        ):
            server.start()

        self.assertIs(start_raised.exception, start_cleanup_control)
        self.assertTrue(
            any(
                "server start failure" in note
                for note in start_cleanup_control.__notes__
            )
        )

        active_start_control = SystemExit(
            "synthetic active server start control"
        )
        server_with_active_control = LiveBrokerServer(
            self.root / "active-start-control",
            service,
        )
        with (
            patch(
                "ctf_os.live_broker._open_private_directory",
                side_effect=active_start_control,
            ),
            patch.object(
                server_with_active_control,
                "_cleanup_lifecycle",
                side_effect=OSError(
                    "synthetic ordinary start cleanup failure"
                ),
            ),
            self.assertRaises(SystemExit) as active_start_raised,
        ):
            server_with_active_control.start()

        self.assertIs(
            active_start_raised.exception,
            active_start_control,
        )

        runtime_directory = self.engine.store.challenge_paths(
            self.identity
        ).runtime
        allocating_owner = allocated_live_broker_directory(
            runtime_directory
        )
        allocation_error = OSError(
            "synthetic directory allocation failure"
        )
        allocation_cleanup_control = KeyboardInterrupt(
            "synthetic directory allocation cleanup control"
        )
        with (
            patch.object(
                allocating_owner,
                "_open_owned_directory",
                side_effect=allocation_error,
            ),
            patch.object(
                allocating_owner,
                "close",
                side_effect=allocation_cleanup_control,
            ),
            self.assertRaises(KeyboardInterrupt) as allocation_raised,
        ):
            allocating_owner.allocate()

        self.assertIs(
            allocation_raised.exception,
            allocation_cleanup_control,
        )

        closing_owner = allocated_live_broker_directory(runtime_directory)
        closing_owner._cleanup_fd = 101
        closing_owner._mailboxes_fd = 102
        closing_owner._runtime_fd = 103
        earlier_close_error = OSError(
            "synthetic earlier directory close failure"
        )
        later_close_control = SystemExit(
            "synthetic later directory close control"
        )
        close_results = iter(
            (earlier_close_error, later_close_control, None)
        )

        def synthetic_owned_close(
            actual_owner,
            attribute: str,
        ) -> BaseException | None:
            self.assertIs(actual_owner, closing_owner)
            setattr(actual_owner, attribute, None)
            return next(close_results)

        with (
            patch.object(
                live_broker_module.os,
                "scandir",
                side_effect=OSError("synthetic ignored scan failure"),
            ),
            patch.object(
                live_broker_module.os,
                "rmdir",
                side_effect=OSError("synthetic ignored rmdir failure"),
            ),
            patch.object(
                type(closing_owner),
                "_close_owned_fd",
                side_effect=synthetic_owned_close,
            ),
            self.assertRaises(SystemExit) as close_raised,
        ):
            closing_owner.close()

        self.assertIs(close_raised.exception, later_close_control)
        self.assertTrue(
            any(
                "earlier directory close failure" in note
                for note in later_close_control.__notes__
            )
        )
        self.assertIsNone(closing_owner._cleanup_fd)
        self.assertIsNone(closing_owner._mailboxes_fd)
        self.assertIsNone(closing_owner._runtime_fd)

        exiting_owner = allocated_live_broker_directory(runtime_directory)
        active_exit_error = OSError(
            "synthetic active directory owner failure"
        )
        exit_cleanup_control = KeyboardInterrupt(
            "synthetic directory owner exit cleanup control"
        )
        with (
            patch.object(
                exiting_owner,
                "close",
                side_effect=exit_cleanup_control,
            ),
            self.assertRaises(KeyboardInterrupt) as exit_raised,
        ):
            exiting_owner.__exit__(
                OSError,
                active_exit_error,
                active_exit_error.__traceback__,
            )

        self.assertIs(exit_raised.exception, exit_cleanup_control)

        active_exit_control = SystemExit(
            "synthetic active directory owner control"
        )
        ordinary_exit_cleanup = OSError(
            "synthetic ordinary owner exit cleanup failure"
        )
        with patch.object(
            exiting_owner,
            "close",
            side_effect=ordinary_exit_cleanup,
        ):
            exiting_owner.__exit__(
                SystemExit,
                active_exit_control,
                active_exit_control.__traceback__,
            )

        self.assertTrue(
            any(
                "ordinary owner exit cleanup failure" in note
                for note in active_exit_control.__notes__
            )
        )

    def test_server_exit_drains_worker_missing_from_executor_registry(
        self,
    ) -> None:
        service, _token = self._service()
        runtime_directory = self.engine.store.challenge_paths(
            self.identity
        ).runtime
        with allocated_live_broker_directory(
            runtime_directory
        ) as broker_directory_owner:
            broker_directory = broker_directory_owner.allocate()
            server = LiveBrokerServer(broker_directory, service)
            server.start()
            directory_fd = server._directory_fd
            assert directory_fd is not None
            executor = server._operation_executor
            assert executor is not None

            worker_entered = threading.Event()
            release_worker = threading.Event()
            worker_finished = threading.Event()
            exit_finished = threading.Event()
            exit_errors: list[BaseException] = []

            def hidden_worker() -> None:
                worker_entered.set()
                try:
                    if not release_worker.wait(2):
                        raise AssertionError(
                            "hidden Live operation was not released"
                        )
                finally:
                    server._operation_idle.set()
                    worker_finished.set()

            server._operation_idle.clear()
            future = executor.submit(hidden_worker)
            self.assertTrue(worker_entered.wait(2))
            hidden_threads = tuple(executor._threads)
            self.assertTrue(hidden_threads)
            # Model CPython 3.13's Thread.start() -> executor registry STORE
            # interruption window: shutdown cannot see this already-running
            # callback, so the lane event must remain the cleanup authority.
            executor._threads.clear()

            def exit_server() -> None:
                try:
                    server.__exit__(None, None, None)
                except BaseException as error:
                    exit_errors.append(error)
                finally:
                    exit_finished.set()

            closer = threading.Thread(
                target=exit_server,
                name="ctfos-test-hidden-live-worker-cleanup",
            )
            closer.start()
            try:
                self.assertFalse(exit_finished.wait(0.1))
                self.assertFalse(server._operation_idle.is_set())
                self.assertIsNotNone(server._directory_fd)
                os.fstat(directory_fd)
            finally:
                release_worker.set()
                closer.join(2)
                for thread in hidden_threads:
                    thread.join(2)

            self.assertFalse(closer.is_alive())
            self.assertTrue(exit_finished.is_set())
            self.assertTrue(worker_finished.is_set())
            self.assertTrue(future.done())
            self.assertFalse(exit_errors, exit_errors)
            self.assertTrue(server._operation_idle.is_set())
            self.assertIsNone(server._operation_executor)
            self.assertIsNone(server._directory_fd)
            with self.assertRaises(OSError) as closed:
                os.fstat(directory_fd)
            self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_client_retries_response_published_after_initial_enoent(
        self,
    ) -> None:
        from ctf_os import live_broker as broker_module

        service, token = self._service()
        runtime_directory = self.engine.store.challenge_paths(
            self.identity
        ).runtime
        original_read = broker_module._read_mailbox_file
        injected = False

        def publish_between_lookups(directory_fd: int, name: str) -> bytes:
            nonlocal injected
            try:
                return original_read(directory_fd, name)
            except LiveBrokerError as error:
                if (
                    not injected
                    and name.startswith("response-")
                    and isinstance(error.__cause__, FileNotFoundError)
                ):
                    deadline = time.monotonic() + 2
                    while True:
                        try:
                            os.stat(
                                name,
                                dir_fd=directory_fd,
                                follow_symlinks=False,
                            )
                            break
                        except FileNotFoundError:
                            if time.monotonic() >= deadline:
                                raise AssertionError(
                                    "response was not published"
                                ) from error
                            time.sleep(0.005)
                    injected = True
                raise

        with allocated_live_broker_directory(
            runtime_directory
        ) as broker_directory_owner:
            broker_directory = broker_directory_owner.allocate()
            with LiveBrokerServer(
                broker_directory,
                service,
            ) as server:
                server.start()
                client = LiveBrokerClient(broker_directory, token)
                with patch.object(
                    broker_module,
                    "_read_mailbox_file",
                    side_effect=publish_between_lookups,
                ):
                    result = client.call(
                        "inspect",
                        self.identity,
                        {"section": "candidates"},
                        timeout=2,
                    )

        self.assertTrue(injected)
        self.assertEqual(result, [])

    def test_claimed_request_cleanup_failure_is_terminal_and_releases_lane(
        self,
    ) -> None:
        service, token = self._service()
        runtime_directory = self.engine.store.challenge_paths(
            self.identity
        ).runtime
        original_unlink = os.unlink
        injected = False

        def fail_processing_cleanup(path, *args, **kwargs):
            nonlocal injected
            name = os.fsdecode(path)
            if name.startswith(".processing-") and not injected:
                injected = True
                raise PermissionError("injected processing cleanup failure")
            return original_unlink(path, *args, **kwargs)

        with allocated_live_broker_directory(
            runtime_directory
        ) as broker_directory_owner:
            broker_directory = broker_directory_owner.allocate()
            with (
                patch(
                    "ctf_os.live_broker.os.unlink",
                    side_effect=fail_processing_cleanup,
                ),
                self.assertRaisesRegex(
                    LiveBrokerError,
                    "could not remove a claimed request",
                ),
            ):
                with LiveBrokerServer(broker_directory, service) as server:
                    server.start()
                    client = LiveBrokerClient(broker_directory, token)
                    self.assertEqual(
                        client.call(
                            "inspect",
                            self.identity,
                            {"section": "candidates"},
                            timeout=2,
                        ),
                        [],
                    )
                    self.assertTrue(server._stop.wait(2))
                    self.assertTrue(server._operation_idle.is_set())
                    status = json.loads(
                        (broker_directory / "server-status.json").read_text(
                            encoding="utf-8"
                        )
                    )
                    self.assertEqual(status["state"], "error")

    def test_flag_commit_bypasses_an_active_tool_operation(self) -> None:
        service, token = self._service()
        sandbox = next(iter(self.clients.values()))
        original_run = sandbox.run
        entered = threading.Event()
        release = threading.Event()
        tool_errors: list[BaseException] = []

        def slow_run(spec):
            entered.set()
            if not release.wait(3):
                raise AssertionError("test did not release the tool operation")
            return original_run(spec)

        def invoke_tool(client: LiveBrokerClient) -> None:
            try:
                client.call(
                    "tool.run",
                    self.identity,
                    {
                        "command": ["true"],
                        "expected_observation": "one run",
                        "keep_if": "success",
                        "drop_if": "failure",
                        "hypothesis_ids": [],
                        "timeout_seconds": 30,
                        "resource_class": "light",
                        "network_target": None,
                        "needs_kvm": False,
                    },
                    timeout=5,
                )
            except BaseException as error:
                tool_errors.append(error)

        runtime_directory = self.engine.store.challenge_paths(
            self.identity
        ).runtime
        with patch.object(sandbox, "run", side_effect=slow_run):
            with allocated_live_broker_directory(
                runtime_directory
            ) as broker_directory_owner:
                broker_directory = broker_directory_owner.allocate()
                with LiveBrokerServer(
                    broker_directory,
                    service,
                ) as server:
                    server.start()
                    tool_client = LiveBrokerClient(broker_directory, token)
                    tool_worker = threading.Thread(
                        target=invoke_tool,
                        args=(tool_client,),
                    )
                    tool_worker.start()
                    self.assertTrue(entered.wait(2))

                    flag_client = LiveBrokerClient(broker_directory, token)
                    started = time.monotonic()
                    result = flag_client.call(
                        "agent.flag",
                        self.identity,
                        {
                            "value": "FLAG{broker_fast_path}",
                            "source": "live-test",
                        },
                        timeout=1,
                    )
                    elapsed = time.monotonic() - started

                    self.assertLess(elapsed, 0.75)
                    self.assertFalse(release.is_set())
                    self.assertIn("candidate_id", result)
                    self.assertTrue(
                        any(
                            candidate.value == "FLAG{broker_fast_path}"
                            for candidate in self.engine.store.load(
                                self.identity
                            ).candidates
                        )
                    )
                    release.set()
                    tool_worker.join(3)
        self.assertFalse(tool_worker.is_alive())
        self.assertFalse(tool_errors, tool_errors)

    def test_local_tool_lock_failure_does_not_orphan_registered_experiment(
        self,
    ) -> None:
        before = self.engine.store.load(self.identity)
        lock_path = (
            self.engine.store.challenge_paths(self.identity).runtime
            / "session.lock"
        )
        with ChallengeLock(lock_path, timeout=0) as session_lock:
            session_lock.acquire()
            with self.assertRaises(SessionAlreadyRunning):
                self.engine.run_tool_command(self.identity, ("true",))
        after = self.engine.store.load(self.identity)
        self.assertEqual(len(after.experiments), len(before.experiments))


if __name__ == "__main__":
    unittest.main()
