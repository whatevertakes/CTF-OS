from __future__ import annotations

import hashlib
import io
import json
import shutil
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

from ctf_os import cli
from ctf_os.engine import challenge as challenge_module
from ctf_os.analysis_leases import AnalysisLease
from ctf_os.director.leases import Lease
from ctf_os.engine.challenge import (
    ChallengeEngine,
    EngineError,
    SessionAlreadyRunning,
)
from ctf_os.flag_formats import resolve_flag_format
from ctf_os.live_broker import LiveBrokerService
from ctf_os.models import (
    ChallengeIdentity,
    ExperimentStatus,
    ReceiptOutcome,
    RunStatus,
    SessionMode,
    SessionStatus,
    SolveSession,
    utc_now,
)
from ctf_os.sandbox import (
    AnalysisLeaseRef,
    ArtifactRef,
    ChallengeScope,
    CommandSpec,
    SandboxError,
    SandboxResult,
)
from ctf_os.sandbox.docker import DockerSandboxBackend
from ctf_os.schema import STATE_SCHEMA_VERSION
from ctf_os.store.atomic import atomic_write_json


class _AnalysisController:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.release = threading.Event()
        self.overlapped = threading.Event()
        self.block = False
        self.active = 0
        self.max_active = 0
        self.run_count = 0
        self.run_calls = 0
        self.writer_calls = 0
        self.cleanup_calls: list[str] = []
        self.private_work_dirs: list[Path] = []
        self.copied_inputs: list[tuple[str, ...]] = []
        self.run_error: BaseException | None = None
        self.cleanup_error: BaseException | None = None
        self.timed_out = False
        self.result_status: str | None = None
        self.exit_code: int | None = None
        self.effective_timeout_seconds: int | None = None
        self.wrapper_started_at: str | None = None
        self.wrapper_finished_at: str | None = None
        self.pre_result_delay_seconds = 0.0
        self.stdout_payload: bytes | None = None
        self.sidecar_mutator = None

    def allocate_run_id(self) -> str:
        with self.lock:
            self.run_count += 1
            return f"run-{self.run_count:08d}"

    def enter(self) -> None:
        with self.lock:
            self.run_calls += 1
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            if self.active >= 2:
                self.overlapped.set()

    def leave(self) -> None:
        with self.lock:
            self.active -= 1


class _IsolatedSandbox:
    def __init__(
        self,
        *,
        scope: ChallengeScope,
        challenge_root: Path,
        controller: _AnalysisController,
    ) -> None:
        self.scope = scope
        self.scope_fingerprint = scope.fingerprint
        self.challenge_root = challenge_root
        self.controller = controller

    def initialize_workspace(self, *, deadline_monotonic_seconds=None) -> None:
        del deadline_monotonic_seconds

    def isolated_analysis_runtime_id(
        self,
        lease: AnalysisLeaseRef,
    ) -> str:
        return (
            f"ctfos-analysis-{lease.scope_fingerprint[:12]}-"
            f"{lease.analysis_id.removeprefix('analysis-')[:20]}-run"
        )

    def run_isolated_analysis(
        self,
        lease: AnalysisLeaseRef,
        spec,
        *,
        input_locators=(),
    ) -> SandboxResult:
        issued_timeout_seconds = spec.timeout_seconds
        work = (
            self.challenge_root
            / "runtime"
            / "analysis"
            / lease.analysis_id
            / "work"
        )
        self.controller.private_work_dirs.append(work)
        copied: list[str] = []
        for locator in input_locators:
            source = self.scope.work_dir / locator
            destination = work / locator
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            copied.append(locator)
        self.controller.copied_inputs.append(tuple(copied))
        self.controller.enter()
        try:
            if self.controller.block:
                if not self.controller.release.wait(timeout=15):
                    raise AssertionError("test analysis release was not signalled")
            if self.controller.run_error is not None:
                raise self.controller.run_error
            if self.controller.pre_result_delay_seconds:
                time.sleep(self.controller.pre_result_delay_seconds)

            run_id = self.controller.allocate_run_id()
            run_root = work / ".ctf" / "runs" / run_id
            run_root.mkdir(parents=True)
            stdout_payload = self.controller.stdout_payload or (
                f"analysis {run_id}\n".encode("utf-8")
            )
            stderr_payload = b""
            (run_root / "stdout.log").write_bytes(stdout_payload)
            (run_root / "stderr.log").write_bytes(stderr_payload)
            timed_out = self.controller.timed_out
            exit_code = (
                self.controller.exit_code
                if self.controller.exit_code is not None
                else 124
                if timed_out
                else 0
            )
            status = (
                self.controller.result_status
                if self.controller.result_status is not None
                else "timed_out"
                if timed_out
                else "completed"
                if exit_code == 0
                else "failed"
            )
            wrapper_started = (
                self.controller.wrapper_started_at
                or datetime.now(UTC).isoformat()
            )
            wrapper_finished = (
                self.controller.wrapper_finished_at
                or (
                    datetime.fromisoformat(wrapper_started)
                    + timedelta(milliseconds=5)
                ).isoformat()
            )
            effective_timeout_seconds = (
                self.controller.effective_timeout_seconds
                if self.controller.effective_timeout_seconds is not None
                else issued_timeout_seconds
            )
            result = SandboxResult(
                run_id=run_id,
                status=status,
                exit_code=exit_code,
                timed_out=timed_out,
                duration_ms=5,
                stdout_summary=stdout_payload.decode("utf-8").rstrip(),
                stderr_summary="",
                stdout_bytes=len(stdout_payload),
                stderr_bytes=0,
                stdout_path=f"/work/.ctf/runs/{run_id}/stdout.log",
                stderr_path=f"/work/.ctf/runs/{run_id}/stderr.log",
                stdout_stored_bytes=len(stdout_payload),
                stderr_stored_bytes=0,
                stdout_limit_bytes=16 * 1024 * 1024,
                stderr_limit_bytes=16 * 1024 * 1024,
                stdout_truncated=False,
                stderr_truncated=False,
                stdout_truncation_known=True,
                stderr_truncation_known=True,
                stdout_capture_complete=True,
                stderr_capture_complete=True,
                stdout_summary_truncated=False,
                stderr_summary_truncated=False,
                stdout_error=None,
                stderr_error=None,
                stream_capture_error=None,
                orchestration_error=None,
                timeout_seconds=effective_timeout_seconds,
                started_at=wrapper_started,
                finished_at=wrapper_finished,
            )
            sidecar = asdict(result)
            sidecar.pop("proof_outputs")
            sidecar.update(
                {
                    "schema_version": 1,
                    "kind": "run_result",
                    "timeout_seconds": effective_timeout_seconds,
                    "started_at": wrapper_started,
                    "finished_at": wrapper_finished,
                }
            )
            if self.controller.sidecar_mutator is not None:
                self.controller.sidecar_mutator(sidecar)
            (run_root / "result.json").write_text(
                json.dumps(
                    sidecar,
                    allow_nan=False,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n",
                encoding="ascii",
            )
            return result
        finally:
            self.controller.leave()

    def cleanup_isolated_analysis(self, lease: AnalysisLeaseRef) -> None:
        self.controller.cleanup_calls.append(lease.analysis_id)
        if self.controller.cleanup_error is not None:
            raise self.controller.cleanup_error

    def run(self, spec) -> SandboxResult:
        del spec
        self.controller.writer_calls += 1
        raw = self.scope.work_dir / "raw"
        raw.mkdir(exist_ok=True)
        stdout = raw / "stdout.log"
        stderr = raw / "stderr.log"
        stdout.write_text("ordinary writer\n", encoding="utf-8")
        stderr.write_bytes(b"")
        return SandboxResult(
            run_id="run-00000001",
            status="completed",
            exit_code=0,
            timed_out=False,
            duration_ms=1,
            stdout_summary="ordinary writer",
            stderr_summary="",
            stdout_bytes=stdout.stat().st_size,
            stderr_bytes=0,
            stdout_path="/work/raw/stdout.log",
            stderr_path="/work/raw/stderr.log",
        )

    def register_artifact(
        self,
        locator: str,
        *,
        maximum_bytes: int = 16 * 1024 * 1024 * 1024,
    ) -> ArtifactRef:
        payload = (self.scope.work_dir / locator).read_bytes()
        if len(payload) > maximum_bytes:
            raise ValueError("oversized test artifact")
        return ArtifactRef(
            locator=locator,
            sha256=hashlib.sha256(payload).hexdigest(),
            size_bytes=len(payload),
            scope_fingerprint=self.scope_fingerprint,
        )


class ReadOnlyAnalysisTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name).resolve()
        self.identity = ChallengeIdentity(
            "국내 CTF",
            "misc",
            "parallel analysis",
        )
        self.controller = _AnalysisController()

        def sandbox_factory(state, work, policy):
            del policy
            scope = ChallengeScope.create(
                contest_id=state.contest_id,
                category=state.category,
                challenge_id=state.challenge_id,
                challenge_dir=(
                    self.root
                    / "incoming"
                    / state.contest_id
                    / state.category
                    / state.challenge_id
                ),
                work_dir=work,
            )
            challenge_root = (
                self.root
                / ".ctfos"
                / "contests"
                / state.contest_id
                / "challenges"
                / state.category
                / state.challenge_id
            )
            return _IsolatedSandbox(
                scope=scope,
                challenge_root=challenge_root,
                controller=self.controller,
            )

        self.engine = ChallengeEngine(
            self.root,
            sandbox_factory=sandbox_factory,
        )
        self.engine.add_challenge(
            self.identity,
            prompt="analyze explicitly selected artifacts",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        self.paths = self.engine.store.challenge_paths(self.identity)

    def tearDown(self) -> None:
        self.controller.release.set()
        self.temporary_directory.cleanup()

    def initialize_workspace(self) -> Path:
        workspace = self.paths.artifacts / "workspace"
        workspace.mkdir(parents=True, exist_ok=True)
        (workspace / "input.bin").write_bytes(b"immutable canonical input")
        return workspace

    @staticmethod
    def workspace_snapshot(workspace: Path) -> dict[str, bytes | None]:
        return {
            path.relative_to(workspace).as_posix(): (
                path.read_bytes() if path.is_file() else None
            )
            for path in sorted(workspace.rglob("*"))
        }

    def analysis_experiments(self):
        return [
            item
            for item in self.engine.store.load(self.identity).experiments
            if item.extra.get("isolated_read_only") is True
        ]

    def assert_host_resources_released(self) -> None:
        status = self.engine.lease_broker.status()
        self.assertEqual(status.leases, ())
        self.assertTrue(status.used.is_empty())

    def test_two_readers_overlap_and_exclude_the_default_writer(self) -> None:
        workspace = self.initialize_workspace()
        before = self.workspace_snapshot(workspace)
        self.controller.block = True
        errors: list[BaseException] = []

        def analyze() -> None:
            try:
                self.engine.run_tool_command(
                    self.identity,
                    ("file", "input.bin"),
                    read_only=True,
                    input_locators=("input.bin",),
                    timeout_seconds=30,
                )
            except BaseException as error:
                errors.append(error)

        threads = [threading.Thread(target=analyze) for _ in range(2)]
        for thread in threads:
            thread.start()
        try:
            self.assertTrue(self.controller.overlapped.wait(timeout=20))
            self.assertEqual(self.controller.max_active, 2)
            self.assertEqual(self.workspace_snapshot(workspace), before)
            self.assertEqual(
                sorted(self.controller.copied_inputs),
                [("input.bin",), ("input.bin",)],
            )
            self.assertEqual(len(set(self.controller.private_work_dirs)), 2)
            for private_work in self.controller.private_work_dirs:
                self.assertEqual(
                    (private_work / "input.bin").read_bytes(),
                    b"immutable canonical input",
                )
            with self.assertRaises(SessionAlreadyRunning):
                self.engine.run_tool_command(self.identity, ("true",))
        finally:
            self.controller.release.set()
            for thread in threads:
                thread.join(timeout=15)
                self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])

        state = self.engine.store.load(self.identity)
        experiments = [
            item
            for item in state.experiments
            if item.extra.get("isolated_read_only") is True
        ]
        self.assertEqual(len(experiments), 2)
        self.assertTrue(
            all(item.status is ExperimentStatus.COMPLETED for item in experiments)
        )
        analysis_runs = [
            run
            for run in state.runs
            if run.extra.get("isolated_read_only") is True
        ]
        self.assertEqual(len(analysis_runs), 2)
        self.assertEqual(
            len(
                [
                    artifact
                    for artifact in state.artifacts
                    if artifact.extra.get("isolated_read_only") is True
                ]
            ),
            6,
        )
        records = state.extra["analysis_leases"]
        self.assertEqual(len(records), 2)
        self.assertTrue(
            all(
                record["status"] == "completed"
                and record["storage_reservation_bytes"] == 0
                for record in records
            )
        )
        self.assertFalse(any((self.paths.runtime / "analysis").iterdir()))

    def test_timeout_is_committed_and_private_tree_is_finalized(self) -> None:
        self.initialize_workspace()
        self.controller.timed_out = True
        state = self.engine.run_tool_command(
            self.identity,
            ("sleep", "30"),
            read_only=True,
            timeout_seconds=30,
        )
        experiment = next(
            item
            for item in state.experiments
            if item.extra.get("isolated_read_only") is True
        )
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        self.assertIs(state.receipts[-1].outcome, ReceiptOutcome.TIMED_OUT)
        record = state.extra["analysis_leases"][-1]
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["reason_code"], "analysis_timed_out")
        self.assertEqual(record["storage_reservation_bytes"], 0)
        self.assertFalse(any((self.paths.runtime / "analysis").iterdir()))
        self.assert_host_resources_released()

    def test_sandbox_error_terminalizes_and_cleans_the_lease(self) -> None:
        self.initialize_workspace()
        self.controller.run_error = SandboxError("synthetic sandbox failure")
        state = self.engine.run_tool_command(
            self.identity,
            ("false",),
            read_only=True,
        )
        experiment = self.analysis_experiments()[-1]
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        self.assertIn("synthetic sandbox failure", experiment.result["error"])
        record = state.extra["analysis_leases"][-1]
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["storage_reservation_bytes"], 0)
        self.assertFalse(any((self.paths.runtime / "analysis").iterdir()))
        self.assert_host_resources_released()

    def test_base_exception_terminalizes_and_preserves_original_exception(
        self,
    ) -> None:
        self.initialize_workspace()
        interruption = KeyboardInterrupt("operator interrupt")
        self.controller.run_error = interruption
        with self.assertRaises(KeyboardInterrupt) as raised:
            self.engine.run_tool_command(
                self.identity,
                ("long-analysis",),
                read_only=True,
            )
        self.assertIs(raised.exception, interruption)
        experiment = self.analysis_experiments()[-1]
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        state = self.engine.store.load(self.identity)
        record = state.extra["analysis_leases"][-1]
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["storage_reservation_bytes"], 0)
        self.assertFalse(any((self.paths.runtime / "analysis").iterdir()))
        self.assert_host_resources_released()

    def test_promotion_body_control_precedes_artifact_cleanup_control(
        self,
    ) -> None:
        self.initialize_workspace()
        body_interruption = KeyboardInterrupt("promotion interrupted first")
        cleanup_interruption = SystemExit(93)
        original_copy = challenge_module.copy_bounded_regular
        copy_calls = 0

        def interrupt_first_copy(*args, **kwargs):
            nonlocal copy_calls
            copy_calls += 1
            if copy_calls == 1:
                raise body_interruption
            return original_copy(*args, **kwargs)

        with (
            patch(
                "ctf_os.engine.challenge.copy_bounded_regular",
                side_effect=interrupt_first_copy,
            ),
            patch.object(
                self.engine,
                "_cleanup_uncommitted_artifacts",
                side_effect=cleanup_interruption,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            self.engine.run_tool_command(
                self.identity,
                ("true",),
                read_only=True,
            )
        self.assertIs(raised.exception, body_interruption)
        self.assertIn(
            "SystemExit",
            "\n".join(getattr(body_interruption, "__notes__", ())),
        )
        self.assertIs(
            self.analysis_experiments()[-1].status,
            ExperimentStatus.FAILED,
        )
        self.assert_host_resources_released()

    def test_registration_return_interrupt_has_no_registered_orphan(
        self,
    ) -> None:
        self.initialize_workspace()
        interruption = KeyboardInterrupt("registration return interrupted")
        original_update = self.engine.store.update
        injected = False

        def update_then_interrupt(*args, **kwargs):
            nonlocal injected
            committed = original_update(*args, **kwargs)
            mutator = args[1]
            if (
                not injected
                and "register_experiment.<locals>.apply"
                in getattr(mutator, "__qualname__", "")
            ):
                injected = True
                raise interruption
            return committed

        with patch.object(
            self.engine.store,
            "update",
            side_effect=update_then_interrupt,
        ):
            with self.assertRaises(KeyboardInterrupt) as raised:
                self.engine.run_tool_command(
                    self.identity,
                    ("true",),
                    read_only=True,
                )
        self.assertIs(raised.exception, interruption)
        state = self.engine.store.load(self.identity)
        self.assertTrue(injected)
        operator_experiments = [
            experiment
            for experiment in state.experiments
            if experiment.command == "true"
        ]
        self.assertEqual(len(operator_experiments), 1)
        self.assertIs(
            operator_experiments[0].status,
            ExperimentStatus.FAILED,
        )
        self.assertEqual(state.runs, [])
        self.assertFalse(any(self.paths.runs.iterdir()))
        record = state.extra["analysis_leases"][-1]
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["storage_reservation_bytes"], 0)
        self.assert_host_resources_released()

    def test_create_run_return_interrupt_records_the_durable_run(
        self,
    ) -> None:
        self.initialize_workspace()
        interruption = KeyboardInterrupt("create_run return interrupted")
        original_create_run = self.engine.store.create_run
        injected = False

        def create_then_interrupt(*args, **kwargs):
            nonlocal injected
            run_paths = original_create_run(*args, **kwargs)
            if not injected:
                injected = True
                raise interruption
            return run_paths

        with patch.object(
            self.engine.store,
            "create_run",
            side_effect=create_then_interrupt,
        ):
            with self.assertRaises(KeyboardInterrupt) as raised:
                self.engine.run_tool_command(
                    self.identity,
                    ("true",),
                    read_only=True,
                )
        self.assertIs(raised.exception, interruption)
        state = self.engine.store.load(self.identity)
        self.assertTrue(injected)
        experiments = self.analysis_experiments()
        self.assertEqual(len(experiments), 1)
        self.assertIs(experiments[0].status, ExperimentStatus.FAILED)
        self.assertEqual(len(state.runs), 1)
        run = state.runs[0]
        self.assertIs(run.status, RunStatus.FAILED)
        run_paths = self.engine.store.run_paths(
            self.identity,
            run_id=run.id,
        )
        self.assertTrue(run_paths.request.is_file())
        self.assertTrue(run_paths.result.is_file())
        self.assertTrue(run_paths.validation.is_file())
        self.assertEqual(
            {path.name for path in self.paths.runs.iterdir()},
            {run.id},
        )
        self.assertEqual(len(state.receipts), 1)
        self.assertIs(state.receipts[0].outcome, ReceiptOutcome.FAILED)
        self.assert_host_resources_released()

    def test_final_commit_return_interrupt_preserves_canonical_evidence(
        self,
    ) -> None:
        self.initialize_workspace()
        interruption = KeyboardInterrupt("finish return interrupted")
        original_update = self.engine.store.update
        injected = False

        def update_then_interrupt(*args, **kwargs):
            nonlocal injected
            committed = original_update(*args, **kwargs)
            mutator = args[1]
            if (
                not injected
                and "_run_read_only_tool_command.<locals>.finish"
                in getattr(mutator, "__qualname__", "")
            ):
                injected = True
                raise interruption
            return committed

        with patch.object(
            self.engine.store,
            "update",
            side_effect=update_then_interrupt,
        ):
            with self.assertRaises(KeyboardInterrupt) as raised:
                self.engine.run_tool_command(
                    self.identity,
                    ("true",),
                    read_only=True,
                )
        self.assertIs(raised.exception, interruption)
        state = self.engine.store.load(self.identity)
        self.assertTrue(injected)
        experiments = self.analysis_experiments()
        self.assertEqual(len(experiments), 1)
        self.assertIs(
            experiments[0].status,
            ExperimentStatus.COMPLETED,
        )
        self.assertEqual(len(state.runs), 1)
        self.assertIs(state.runs[0].status, RunStatus.COMPLETED)
        self.assertEqual(len(state.receipts), 1)
        self.assertIs(state.receipts[0].outcome, ReceiptOutcome.SUCCEEDED)
        self.assertEqual(len(state.artifacts), 3)
        for artifact in state.artifacts:
            artifact_path = self.paths.root / artifact.path
            self.assertTrue(artifact_path.is_file())
            self.assertEqual(
                hashlib.sha256(artifact_path.read_bytes()).hexdigest(),
                artifact.sha256,
            )
        record = state.extra["analysis_leases"][-1]
        self.assertEqual(record["status"], "completed")
        self.assertEqual(record["storage_reservation_bytes"], 0)
        self.assertFalse(any((self.paths.runtime / "analysis").iterdir()))
        self.assert_host_resources_released()

    def assert_final_commit_document_tamper_is_detected(
        self,
        document_name: str,
    ) -> None:
        self.initialize_workspace()
        interruption = KeyboardInterrupt(
            f"{document_name} tampered after finish"
        )
        original_update = self.engine.store.update
        injected = False

        def update_tamper_then_interrupt(*args, **kwargs):
            nonlocal injected
            committed = original_update(*args, **kwargs)
            mutator = args[1]
            if (
                not injected
                and "_run_read_only_tool_command.<locals>.finish"
                in getattr(mutator, "__qualname__", "")
            ):
                run_paths = self.engine.store.run_paths(
                    self.identity,
                    run_id=committed.runs[-1].id,
                )
                document_path = getattr(run_paths, document_name)
                document = json.loads(
                    document_path.read_text(encoding="utf-8")
                )
                if document_name == "request":
                    document["argv"] = ["tampered"]
                elif document_name == "result":
                    document["artifact_ids"] = []
                else:
                    document["ok"] = False
                atomic_write_json(document_path, document)
                injected = True
                raise interruption
            return committed

        with patch.object(
            self.engine.store,
            "update",
            side_effect=update_tamper_then_interrupt,
        ):
            with self.assertRaises(KeyboardInterrupt) as raised:
                self.engine.run_tool_command(
                    self.identity,
                    ("true",),
                    read_only=True,
                )
        self.assertIs(raised.exception, interruption)
        self.assertTrue(injected)
        notes = "\n".join(getattr(interruption, "__notes__", ()))
        self.assertIn("durable commit inspection failed", notes)
        self.assertIn("physical run documents", notes)
        state = self.engine.store.load(self.identity)
        self.assertIs(state.runs[-1].status, RunStatus.COMPLETED)
        self.assertEqual(len(state.artifacts), 3)
        for artifact in state.artifacts:
            self.assertTrue((self.paths.root / artifact.path).is_file())
        self.assert_host_resources_released()

    def test_final_commit_request_tamper_is_detected(self) -> None:
        self.assert_final_commit_document_tamper_is_detected("request")

    def test_final_commit_result_tamper_is_detected(self) -> None:
        self.assert_final_commit_document_tamper_is_detected("result")

    def test_final_commit_validation_tamper_is_detected(self) -> None:
        self.assert_final_commit_document_tamper_is_detected("validation")

    def test_precommit_run_document_tamper_fails_closed(self) -> None:
        self.initialize_workspace()
        original_write_validation = self.engine.store.write_run_validation

        def write_validation_then_tamper(*args, **kwargs):
            path = original_write_validation(*args, **kwargs)
            run_id = args[1]
            run_paths = self.engine.store.run_paths(
                self.identity,
                run_id=run_id,
            )
            document = json.loads(
                run_paths.result.read_text(encoding="utf-8")
            )
            document["artifact_ids"] = []
            atomic_write_json(run_paths.result, document)
            return path

        with patch.object(
            self.engine.store,
            "write_run_validation",
            side_effect=write_validation_then_tamper,
        ):
            with self.assertRaisesRegex(
                EngineError,
                "physical run documents",
            ):
                self.engine.run_tool_command(
                    self.identity,
                    ("true",),
                    read_only=True,
                )
        state = self.engine.store.load(self.identity)
        self.assertIs(
            self.analysis_experiments()[-1].status,
            ExperimentStatus.FAILED,
        )
        self.assertFalse(
            any(
                artifact.extra.get("isolated_read_only") is True
                for artifact in state.artifacts
            )
        )
        self.assert_host_resources_released()

    def test_body_control_exception_precedes_cleanup_control_exception(
        self,
    ) -> None:
        self.initialize_workspace()
        body_interruption = KeyboardInterrupt("body interrupted first")
        cleanup_interruption = SystemExit(73)
        self.controller.run_error = body_interruption
        self.controller.cleanup_error = cleanup_interruption
        with self.assertRaises(KeyboardInterrupt) as raised:
            self.engine.run_tool_command(
                self.identity,
                ("long-analysis",),
                read_only=True,
            )
        self.assertIs(raised.exception, body_interruption)
        self.assertIn(
            "SystemExit",
            "\n".join(getattr(body_interruption, "__notes__", ())),
        )
        state = self.engine.store.load(self.identity)
        self.assertIs(state.experiments[-1].status, ExperimentStatus.FAILED)
        record = state.extra["analysis_leases"][-1]
        self.assertEqual(record["status"], "cleanup_pending")
        self.assertGreater(record["storage_reservation_bytes"], 0)
        self.assert_host_resources_released()

    def test_cleanup_failure_keeps_cleanup_pending_reservation(self) -> None:
        self.initialize_workspace()
        self.controller.cleanup_error = SandboxError(
            "runtime absence is uncertain"
        )
        with self.assertRaisesRegex(EngineError, "cleanup failed"):
            self.engine.run_tool_command(
                self.identity,
                ("true",),
                read_only=True,
            )
        state = self.engine.store.load(self.identity)
        record = state.extra["analysis_leases"][-1]
        experiment = self.analysis_experiments()[-1]
        self.assertIs(experiment.status, ExperimentStatus.COMPLETED)
        self.assertEqual(
            len(
                [
                    run
                    for run in state.runs
                    if run.extra.get("isolated_read_only") is True
                ]
            ),
            1,
        )
        self.assertEqual(
            len(
                [
                    artifact
                    for artifact in state.artifacts
                    if artifact.extra.get("isolated_read_only") is True
                ]
            ),
            3,
        )
        self.assertIs(state.receipts[-1].outcome, ReceiptOutcome.SUCCEEDED)
        self.assertEqual(record["status"], "cleanup_pending")
        self.assertGreater(record["storage_reservation_bytes"], 0)
        self.assertTrue(
            (self.paths.runtime / "analysis" / record["analysis_id"]).is_dir()
        )
        self.assert_host_resources_released()

    def test_cleanup_control_exception_is_not_wrapped_or_lost(self) -> None:
        self.initialize_workspace()
        interruption = SystemExit(71)
        self.controller.cleanup_error = interruption
        with self.assertRaises(SystemExit) as raised:
            self.engine.run_tool_command(
                self.identity,
                ("true",),
                read_only=True,
            )
        self.assertIs(raised.exception, interruption)
        state = self.engine.store.load(self.identity)
        self.assertIs(
            self.analysis_experiments()[-1].status,
            ExperimentStatus.COMPLETED,
        )
        record = state.extra["analysis_leases"][-1]
        self.assertEqual(record["status"], "cleanup_pending")
        self.assertGreater(record["storage_reservation_bytes"], 0)
        self.assert_host_resources_released()

    def test_finalize_control_exception_uses_cleanup_pending_fallback(
        self,
    ) -> None:
        self.initialize_workspace()
        interruption = KeyboardInterrupt("finalize interrupted")
        with patch.object(
            AnalysisLease,
            "finalize",
            side_effect=interruption,
        ):
            with self.assertRaises(KeyboardInterrupt) as raised:
                self.engine.run_tool_command(
                    self.identity,
                    ("true",),
                    read_only=True,
                )
        self.assertIs(raised.exception, interruption)
        state = self.engine.store.load(self.identity)
        record = state.extra["analysis_leases"][-1]
        self.assertEqual(record["status"], "cleanup_pending")
        self.assertEqual(record["reason_code"], "analysis_finalize_failed")
        self.assertGreater(record["storage_reservation_bytes"], 0)
        self.assert_host_resources_released()

    def test_resource_release_control_exception_preserves_identity(
        self,
    ) -> None:
        self.initialize_workspace()
        interruption = SystemExit(72)
        original_release = Lease.release

        def release_then_interrupt(lease) -> None:
            original_release(lease)
            raise interruption

        with patch.object(Lease, "release", release_then_interrupt):
            with self.assertRaises(SystemExit) as raised:
                self.engine.run_tool_command(
                    self.identity,
                    ("true",),
                    read_only=True,
                )
        self.assertIs(raised.exception, interruption)
        state = self.engine.store.load(self.identity)
        record = state.extra["analysis_leases"][-1]
        self.assertEqual(record["status"], "completed")
        self.assertEqual(record["storage_reservation_bytes"], 0)
        self.assertFalse(any((self.paths.runtime / "analysis").iterdir()))
        self.assert_host_resources_released()

    def test_omitted_sidecar_safety_field_is_rejected(self) -> None:
        self.initialize_workspace()

        def omit_capture_complete(sidecar) -> None:
            sidecar.pop("stdout_capture_complete")

        self.controller.sidecar_mutator = omit_capture_complete
        with self.assertRaisesRegex(EngineError, "unexpected schema"):
            self.engine.run_tool_command(
                self.identity,
                ("true",),
                read_only=True,
            )
        state = self.engine.store.load(self.identity)
        experiment = self.analysis_experiments()[-1]
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        self.assertFalse(
            any(
                artifact.extra.get("isolated_read_only") is True
                for artifact in state.artifacts
            )
        )
        self.assertFalse(any((self.paths.runtime / "analysis").iterdir()))

    def test_hostile_status_exit_timeout_combinations_are_rejected(
        self,
    ) -> None:
        self.initialize_workspace()
        cases = (
            ("failed", 0, False),
            ("completed", 1, False),
            ("timed_out", 124, False),
            ("completed", 124, True),
            ("failed", 124, True),
            ("timed_out", 0, True),
        )
        for status, exit_code, timed_out in cases:
            with self.subTest(
                status=status,
                exit_code=exit_code,
                timed_out=timed_out,
            ):
                self.controller.result_status = status
                self.controller.exit_code = exit_code
                self.controller.timed_out = timed_out
                with self.assertRaisesRegex(EngineError, "status contract"):
                    self.engine.run_tool_command(
                        self.identity,
                        ("hostile-result",),
                        read_only=True,
                    )
        state = self.engine.store.load(self.identity)
        self.assertTrue(
            all(
                experiment.status is ExperimentStatus.FAILED
                for experiment in self.analysis_experiments()
            )
        )
        self.assertEqual(len(self.analysis_experiments()), len(cases))
        self.assertFalse(
            any(
                artifact.extra.get("isolated_read_only") is True
                for artifact in state.artifacts
            )
        )
        self.assert_host_resources_released()

    def test_sidecar_only_timeout_and_timestamp_fields_are_bound(self) -> None:
        self.initialize_workspace()

        def wrong_timeout(sidecar) -> None:
            sidecar["timeout_seconds"] += 1

        def zero_timeout(sidecar) -> None:
            sidecar["timeout_seconds"] = 0

        def boolean_timeout(sidecar) -> None:
            sidecar["timeout_seconds"] = True

        def invalid_timestamp(sidecar) -> None:
            sidecar["started_at"] = "not-a-timestamp"

        def reversed_timestamps(sidecar) -> None:
            sidecar["started_at"] = "2026-07-31T00:00:01+00:00"

        def inconsistent_duration(sidecar) -> None:
            sidecar["finished_at"] = "2026-07-31T00:00:10+00:00"

        for mutator in (
            wrong_timeout,
            zero_timeout,
            boolean_timeout,
            invalid_timestamp,
            reversed_timestamps,
            inconsistent_duration,
        ):
            with self.subTest(mutator=mutator.__name__):
                self.controller.sidecar_mutator = mutator
                with self.assertRaisesRegex(EngineError, "sidecar"):
                    self.engine.run_tool_command(
                        self.identity,
                        ("hostile-sidecar",),
                        read_only=True,
                    )
        state = self.engine.store.load(self.identity)
        self.assertTrue(
            all(
                experiment.status is ExperimentStatus.FAILED
                for experiment in self.analysis_experiments()
            )
        )
        self.assertEqual(len(self.analysis_experiments()), 6)
        self.assertFalse(
            any(
                artifact.extra.get("isolated_read_only") is True
                for artifact in state.artifacts
            )
        )
        self.assert_host_resources_released()

    def test_backend_clamped_timeout_is_accepted_and_never_exceeds_issue(
        self,
    ) -> None:
        self.initialize_workspace()
        spec = CommandSpec.create(("true",), timeout_seconds=30)
        with patch(
            "ctf_os.sandbox.docker.time.monotonic",
            return_value=100.1,
        ):
            clamped = DockerSandboxBackend._effective_command_timeout(
                spec,
                129.9,
                operation="deterministic test",
            )
        self.assertEqual(clamped, 29)

        self.controller.effective_timeout_seconds = clamped
        state = self.engine.run_tool_command(
            self.identity,
            ("true",),
            read_only=True,
            timeout_seconds=30,
        )
        self.assertIs(
            self.analysis_experiments()[-1].status,
            ExperimentStatus.COMPLETED,
        )
        self.assertIs(state.runs[-1].status, RunStatus.COMPLETED)
        self.assert_host_resources_released()

    def test_matched_lower_timeout_with_shifted_clock_is_rejected(self) -> None:
        self.initialize_workspace()
        self.controller.effective_timeout_seconds = 1
        self.controller.wrapper_started_at = (
            "1900-01-01T00:00:00.000000+00:00"
        )
        self.controller.wrapper_finished_at = (
            "1900-01-01T00:00:00.005000+00:00"
        )
        with self.assertRaisesRegex(EngineError, "host-observed"):
            self.engine.run_tool_command(
                self.identity,
                ("hostile-clock",),
                read_only=True,
                timeout_seconds=30,
            )
        state = self.engine.store.load(self.identity)
        self.assertIs(
            self.analysis_experiments()[-1].status,
            ExperimentStatus.FAILED,
        )
        self.assertFalse(
            any(
                artifact.extra.get("isolated_read_only") is True
                for artifact in state.artifacts
            )
        )
        self.assert_host_resources_released()

    def test_matched_lower_timeout_with_current_clock_is_rejected(self) -> None:
        self.initialize_workspace()
        self.controller.effective_timeout_seconds = 1
        with self.assertRaisesRegex(EngineError, "plausible clamp range"):
            self.engine.run_tool_command(
                self.identity,
                ("hostile-timeout",),
                read_only=True,
                timeout_seconds=30,
            )
        self.assertIs(
            self.analysis_experiments()[-1].status,
            ExperimentStatus.FAILED,
        )
        self.assert_host_resources_released()

    def test_slow_initialization_clamp_to_one_second_is_accepted(self) -> None:
        self.initialize_workspace()
        self.controller.pre_result_delay_seconds = 1.1
        self.controller.effective_timeout_seconds = 1
        state = self.engine.run_tool_command(
            self.identity,
            ("true",),
            read_only=True,
            timeout_seconds=3,
        )
        self.assertIs(
            self.analysis_experiments()[-1].status,
            ExperimentStatus.COMPLETED,
        )
        self.assertIs(state.runs[-1].status, RunStatus.COMPLETED)
        self.assert_host_resources_released()

    def test_flag_candidate_is_deduplicated_and_intent_is_cleared(self) -> None:
        self.initialize_workspace()
        value = "KCTF{read_only_candidate}"
        self.controller.stdout_payload = (
            f"{value}\nsecond observation {value}\n".encode("utf-8")
        )
        with (
            redirect_stdout(io.StringIO()),
            patch.object(self.engine, "_on_tool_flag"),
        ):
            state = self.engine.run_tool_command(
                self.identity,
                ("strings",),
                read_only=True,
            )
        matches = [
            candidate
            for candidate in state.candidates
            if candidate.value == value
        ]
        self.assertEqual(len(matches), 1)
        policy = resolve_flag_format(
            state,
            self.engine.config.runtime.flag_patterns,
        )
        self.assertEqual(matches[0].tier, policy.tier_for(value))
        self.assertEqual(
            self.engine.store.load_candidate_intents(self.identity),
            (),
        )

    def test_candidate_intent_clear_interrupt_keeps_success_and_retry_journal(
        self,
    ) -> None:
        self.initialize_workspace()
        value = "KCTF{intent_cleanup_retry}"
        self.controller.stdout_payload = f"{value}\n".encode("utf-8")
        interruption = KeyboardInterrupt("intent clear interrupted")
        with (
            redirect_stdout(io.StringIO()),
            patch.object(self.engine, "_on_tool_flag"),
            patch.object(
                self.engine.store,
                "clear_candidate_intents",
                side_effect=interruption,
            ),
        ):
            with self.assertRaises(KeyboardInterrupt) as raised:
                self.engine.run_tool_command(
                    self.identity,
                    ("strings",),
                    read_only=True,
                )
        self.assertIs(raised.exception, interruption)
        state = self.engine.store.load(self.identity)
        self.assertIs(state.experiments[-1].status, ExperimentStatus.COMPLETED)
        self.assertIs(state.runs[-1].status, RunStatus.COMPLETED)
        self.assertIs(state.receipts[-1].outcome, ReceiptOutcome.SUCCEEDED)
        self.assertEqual(
            [candidate.value for candidate in state.candidates],
            [value],
        )
        intents = self.engine.store.load_candidate_intents(self.identity)
        self.assertEqual([intent["value"] for intent in intents], [value])
        record = state.extra["analysis_leases"][-1]
        self.assertEqual(record["status"], "completed")
        self.assertEqual(record["storage_reservation_bytes"], 0)
        self.assertEqual(len(state.artifacts), 3)
        self.assert_host_resources_released()

    def test_missing_workspace_fails_without_creating_canonical_work(self) -> None:
        workspace = self.paths.artifacts / "workspace"
        self.assertFalse(workspace.exists())
        with self.assertRaisesRegex(EngineError, "existing canonical workspace"):
            self.engine.run_tool_command(
                self.identity,
                ("true",),
                read_only=True,
            )
        self.assertFalse(workspace.exists())
        self.assertEqual(self.controller.run_calls, 0)

    def test_legacy_schema_is_rejected_before_any_analysis_side_effect(self) -> None:
        legacy_identity = ChallengeIdentity(
            "국내 CTF",
            "misc",
            "legacy read only",
        )
        self.engine.add_challenge(
            legacy_identity,
            prompt="legacy state",
            state_schema_version=1,
        )
        legacy_paths = self.engine.store.challenge_paths(legacy_identity)
        workspace = legacy_paths.artifacts / "workspace"
        workspace.mkdir(parents=True, exist_ok=True)
        (workspace / "input.bin").write_bytes(b"legacy")
        before = self.engine.store.load(legacy_identity).to_dict()
        with self.assertRaisesRegex(
            EngineError,
            "read_only_analysis_requires_current_state_schema",
        ):
            self.engine.run_tool_command(
                legacy_identity,
                ("file", "input.bin"),
                read_only=True,
                input_locators=("input.bin",),
            )
        after = self.engine.store.load(legacy_identity)
        self.assertEqual(after.to_dict(), before)
        self.assertEqual(after.runs, [])
        self.assertFalse((legacy_paths.runtime / "analysis").exists())
        self.assertEqual(self.controller.run_calls, 0)
        self.assert_host_resources_released()

    def test_inputs_are_explicit_validated_and_require_read_only(self) -> None:
        workspace = self.initialize_workspace()
        (workspace / "directory").mkdir()
        (workspace / "link").symlink_to("input.bin")
        with self.assertRaisesRegex(EngineError, "require read_only"):
            self.engine.run_tool_command(
                self.identity,
                ("true",),
                input_locators=("input.bin",),
            )
        for locators in (
            ("../input.bin",),
            ("directory",),
            ("link",),
            ("input.bin", "input.bin"),
        ):
            with (
                self.subTest(locators=locators),
                self.assertRaises(EngineError),
            ):
                self.engine.run_tool_command(
                    self.identity,
                    ("true",),
                    read_only=True,
                    input_locators=locators,
                )
        self.assertEqual(self.controller.run_calls, 0)

    def test_active_background_job_rejects_analysis_before_launch(self) -> None:
        self.initialize_workspace()

        def add_background(state) -> None:
            state.extra["background_jobs"] = [
                {
                    "schema_version": 1,
                    "supervisor_id": "bg-" + "1" * 32,
                    "status": "running",
                }
            ]

        self.engine.store.update(self.identity, add_background)
        with self.assertRaises((SessionAlreadyRunning, EngineError)):
            self.engine.run_tool_command(
                self.identity,
                ("true",),
                read_only=True,
            )
        self.assertEqual(self.controller.run_calls, 0)
        self.assert_host_resources_released()

    def test_active_managed_session_rejects_before_launch(self) -> None:
        self.initialize_workspace()

        def add_managed(state) -> None:
            session_id = "S-read-only-analysis-block"
            state.sessions.append(
                SolveSession(
                    id=session_id,
                    mode=SessionMode.MANAGED,
                    status=SessionStatus.RUNNING,
                    configuration_epoch=state.configuration_epoch,
                    start_revision=state.revision,
                    started_at=utc_now(),
                )
            )
            state.active_managed_session_id = session_id

        self.engine.store.update(self.identity, add_managed)
        with self.assertRaises((SessionAlreadyRunning, EngineError)):
            self.engine.run_tool_command(
                self.identity,
                ("true",),
                read_only=True,
            )
        self.assertEqual(self.controller.run_calls, 0)
        self.assert_host_resources_released()

    def test_default_writer_uses_only_the_legacy_sandbox_run_path(self) -> None:
        self.initialize_workspace()
        state = self.engine.run_tool_command(
            self.identity,
            ("true",),
            read_only=False,
        )
        self.assertEqual(self.controller.writer_calls, 1)
        self.assertEqual(self.controller.run_calls, 0)
        self.assertEqual(self.controller.cleanup_calls, [])
        self.assertFalse(
            any(
                item.extra.get("isolated_read_only") is True
                for item in state.experiments
            )
        )
        self.assert_host_resources_released()

    def test_live_session_read_only_semantics_are_stably_rejected(self) -> None:
        with self.assertRaisesRegex(
            EngineError,
            "read_only_analysis_unavailable_in_live_session",
        ):
            self.engine.run_tool_command(
                self.identity,
                ("true",),
                read_only=True,
                input_locators=("input.bin",),
                _session_owned=True,
                _live_only=True,
            )

        service = LiveBrokerService.__new__(LiveBrokerService)
        service.engine = Mock()
        service.identity = self.identity
        service.engine.run_tool_command.side_effect = EngineError(
            "read_only_analysis_unavailable_in_live_session"
        )
        params = {
            "command": ["true"],
            "expected_observation": "bounded",
            "keep_if": "useful",
            "drop_if": "not useful",
            "hypothesis_ids": [],
            "timeout_seconds": 30,
            "resource_class": "light",
            "network_target": None,
            "needs_kvm": False,
            "read_only": True,
            "input_locators": ["input.bin"],
        }
        with self.assertRaisesRegex(
            EngineError,
            "read_only_analysis_unavailable_in_live_session",
        ):
            service._dispatch_authorized("tool.run", params)
        kwargs = service.engine.run_tool_command.call_args.kwargs
        self.assertIs(kwargs["read_only"], True)
        self.assertEqual(kwargs["input_locators"], ("input.bin",))
        self.assertIs(kwargs["_session_owned"], True)
        self.assertIs(kwargs["_live_only"], True)

    def test_cli_parser_exposes_repeatable_explicit_inputs(self) -> None:
        args = cli.build_parser().parse_args(
            [
                "tool",
                "run",
                "--contest",
                self.identity.contest_id,
                "--category",
                self.identity.category,
                "--challenge",
                self.identity.challenge_id,
                "--read-only",
                "--input",
                "one.bin",
                "--input",
                "nested/two.bin",
                "--",
                "file",
                "one.bin",
            ]
        )
        self.assertTrue(args.read_only)
        self.assertEqual(args.input, ["one.bin", "nested/two.bin"])
        self.assertEqual(args.tool_argv, ["--", "file", "one.bin"])


if __name__ == "__main__":
    unittest.main()
