from __future__ import annotations

import copy
import hashlib
import io
import inspect
import json
import os
import shlex
import stat
import struct
import sys
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager, redirect_stderr
from dataclasses import replace
from pathlib import Path
from unittest import mock

import ctf_os.engine.challenge as challenge_module
import ctf_os.models as models_module
import ctf_os.store.files as store_files
from ctf_os.adapters import get_adapter
from ctf_os.budget import deadline_epoch
from ctf_os.benchmark import THIN_SCAFFOLD
from ctf_os.codex import (
    BatchRunner,
    BuiltCommand,
    FifoModelCallLimiter,
    FlagNotificationError,
    ProcessOutcome,
    Role,
)
from ctf_os.config import load_config
from ctf_os.contracts.rev_inventory_v1 import (
    REV_INVENTORY_V1_CONTRACT_FINGERPRINT,
    REV_INVENTORY_V1_CONTRACT_ID,
    REV_INVENTORY_V1_CONTRACT_VERSION,
    REV_INVENTORY_V1_MAX_SOURCE_BYTES,
    REV_INVENTORY_V1_SCHEMA_VERSION,
    build_rev_inventory_v1_seed_extra,
    build_rev_inventory_v1_source_binding,
    build_rev_inventory_v1_source_snapshot,
    rev_inventory_v1_seed_command,
)
from ctf_os.engine.challenge import (
    WAVE_ROLES,
    ChallengeEngine,
    EngineError,
    SessionAlreadyRunning,
    WaveOutcome,
)
from ctf_os.engine.context_pack import build_context_pack
from ctf_os.engine.flags import (
    FLAG_CANDIDATE_SIDECAR,
    FLAG_PATTERNS_ENV,
    PROOF_LIVE_DIRECTORY,
    DetectedFlag,
    FlagDetector,
)
from ctf_os.contracts.rev_inventory_v2 import (
    REV_INVENTORY_V2_CONTRACT_FINGERPRINT,
    REV_INVENTORY_V2_CONTRACT_ID,
    REV_INVENTORY_V2_CONTRACT_VERSION,
    REV_INVENTORY_V2_DOCUMENT_TRANSPORT,
    REV_INVENTORY_V2_MAX_BYTES,
    REV_INVENTORY_V2_SCHEMA_VERSION,
)
from ctf_os.engine.receipt_summary import ReceiptSummaryError
from ctf_os.governor import (
    GOVERNOR_METADATA_KEY,
    RecoveryAction,
    StallSignal,
)
from ctf_os.models import (
    ArtifactReference,
    CandidateStatus,
    ChallengeIdentity,
    ChallengeState,
    ChallengeStatus,
    Experiment,
    ExperimentKind,
    ExperimentStatus,
    Fact,
    GoalStatus,
    HypothesisStatus,
    MAX_EXPERIMENT_TIMEOUT_SECONDS,
    ModelValidationError,
    Provenance,
    RunReference,
    RunStatus,
)
from ctf_os.sandbox import (
    ArtifactRef,
    LocalChallengeSandboxClient,
    SandboxError,
    SandboxResult,
)
from ctf_os.schema import STATE_SCHEMA_VERSION
from ctf_os.scaffold_binding import (
    SCAFFOLD_LAUNCH_METADATA_KEY,
    parse_scaffold_launch_record,
)
from ctf_os.store import (
    ArtifactValidationError,
    ChallengeLock,
    RevisionConflict,
    WorkerResultValidationError,
    sha256_file,
)


def _output_path(command: BuiltCommand) -> Path:
    index = command.argv.index("--output-last-message")
    return Path(command.argv[index + 1])


def _rev_inventory_payload(
    source: bytes,
    *,
    arch: str | None = "x86",
    bits: int | None = 64,
    bintype: str = "elf",
    endian: str = "little",
    havecode: bool = True,
) -> bytes:
    return (
        json.dumps(
            {
                "binary": {
                    "arch": arch,
                    "bits": bits,
                    "bintype": bintype,
                    "endian": endian,
                    "havecode": havecode,
                },
                "contract": {
                    "fingerprint": (
                        REV_INVENTORY_V2_CONTRACT_FINGERPRINT
                    ),
                    "id": REV_INVENTORY_V2_CONTRACT_ID,
                    "version": REV_INVENTORY_V2_CONTRACT_VERSION,
                },
                "schema_version": REV_INVENTORY_V2_SCHEMA_VERSION,
                "source": {
                    "sha256": hashlib.sha256(source).hexdigest(),
                    "size_bytes": len(source),
                },
                "status": "ok",
            },
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


@contextmanager
def _interrupt_on_source_line(
    target,
    source_line: str,
    interruption: BaseException,
):
    """Raise one exact interruption before a named source line executes."""

    lines, first_line = inspect.getsourcelines(target)
    matches = [
        first_line + offset
        for offset, line in enumerate(lines)
        if line.strip() == source_line
    ]
    if len(matches) != 1:
        raise AssertionError(
            f"expected one {source_line!r} line in {target.__qualname__}, "
            f"found {matches}"
        )
    target_line = matches[0]
    target_code = target.__code__
    previous_trace = sys.gettrace()

    def interrupt_at_line(frame, event, arg):
        del arg
        if (
            frame.f_code is target_code
            and event == "line"
            and frame.f_lineno == target_line
        ):
            raise interruption
        return interrupt_at_line

    sys.settrace(interrupt_at_line)
    try:
        yield
    finally:
        sys.settrace(previous_trace)


IMAGE_DIGEST = "sha256:" + "a" * 64


def _role_for(command: BuiltCommand) -> Role:
    schema_index = command.argv.index("--output-schema")
    schema = json.loads(Path(command.argv[schema_index + 1]).read_text())
    title = str(schema["title"])
    role_name = title.removeprefix("CTF-OS ").removesuffix(" result")
    return Role(role_name)


def _payload(role: Role, *, flag: str | None = None) -> dict[str, object]:
    return {
        "schema_version": 1,
        "role": role.value,
        "status": "ok",
        "summary": "one bounded result",
        "observations": [
            {
                "id": "obs-1",
                "claim": f"{role.value} proposes one observation",
                "evidence": ["model output only"],
                "provenance": "executed",
            }
        ],
        "hypotheses": [
            {
                "id": "hyp-1",
                "statement": f"{role.value} hypothesis",
                "observation_refs": ["obs-1"],
                "falsifier": "change one input and rerun",
                "keep_if": "behavior changes",
                "drop_if": "behavior is unchanged",
            }
        ],
        "hypothesis_updates": [],
        "evaluations": [],
        "actions": [
            {
                "kind": "command",
                "description": "run a bounded probe",
                "command": "/bin/true",
                "artifact_path": None,
            }
        ],
        "artifacts": [],
        "progress_markers": [
            {"name": "probe_ready", "evidence": "proposal only"}
        ],
        "flag_candidates": (
            [
                {
                    "value": flag,
                    "source": "tool_output",
                    "evidence": "stdout",
                }
            ]
            if flag
            else []
        ),
        "decision": (
            {"next_stage": "attack", "reason": "triage complete"}
            if role is Role.CAPTAIN
            else None
        ),
        "goal_update": None,
        "refusal": None,
    }


def _elf64_image(
    elf_type: int,
    *,
    program_types: tuple[int, ...] = (),
) -> bytes:
    identity = bytearray(16)
    identity[:4] = b"\x7fELF"
    identity[4] = 2
    identity[5] = 1
    identity[6] = 1
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        bytes(identity),
        elf_type,
        62,
        1,
        0,
        64,
        0,
        0,
        64,
        56,
        len(program_types),
        0,
        0,
        0,
    )
    program_headers = b"".join(
        struct.pack("<IIQQQQQQ", program_type, 0, 0, 0, 0, 0, 0, 0)
        for program_type in program_types
    )
    return header + program_headers


class RoleExecutor:
    def __init__(
        self,
        flag_role: Role | None = None,
        *,
        observation_ref: str | None = None,
        refusal_role: Role | None = None,
    ) -> None:
        self.flag_role = flag_role
        self.observation_ref = observation_ref
        self.refusal_role = refusal_role
        self.lock = threading.Lock()
        self.active = 0
        self.max_active = 0
        self.roles: list[Role] = []
        self.working_directories: dict[Role, Path] = {}
        self.reasoning_efforts: dict[Role, str] = {}

    def run(self, command, *, cwd, timeout, on_stdout_line):
        del timeout
        role = _role_for(command)
        with self.lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            self.roles.append(role)
            self.working_directories[role] = Path(cwd)
            self.reasoning_efforts[role] = next(
                value.removeprefix("model_reasoning_effort=").strip('"')
                for value in command.argv
                if value.startswith("model_reasoning_effort=")
            )
        try:
            flag = "KCTF{stream_now}" if role is self.flag_role else None
            if flag:
                on_stdout_line(
                    json.dumps(
                        {
                            "type": "item.completed",
                            "text": f"candidate {flag}",
                        }
                    )
                    + "\n"
                )
            time.sleep(0.01)
            payload = _payload(role, flag=flag)
            if self.observation_ref is not None:
                payload["hypotheses"][0]["observation_refs"] = [
                    self.observation_ref
                ]
            if role is self.refusal_role:
                payload.update(
                    {
                        "status": "refused",
                        "summary": "provider refused this role",
                        "observations": [],
                        "hypotheses": [],
                        "actions": [],
                        "artifacts": [],
                        "progress_markers": [],
                        "flag_candidates": [],
                        "decision": None,
                        "refusal": {
                            "kind": "policy",
                            "message": "synthetic refusal",
                            "retryable": False,
                        },
                    }
                )
            _output_path(command).write_text(
                json.dumps(payload), encoding="utf-8"
            )
            return ProcessOutcome(0, "", 0.01)
        finally:
            with self.lock:
                self.active -= 1


class MixedOutcomeExecutor:
    """One success, one timeout, and one invalid artifact in one wave."""

    def run(self, command, *, cwd, timeout, on_stdout_line):
        del cwd, timeout
        role = _role_for(command)
        if role is Role.SPECIALIST:
            on_stdout_line(
                json.dumps(
                    {
                        "type": "item.completed",
                        "text": "candidate KCTF{partial_timeout}",
                    }
                )
                + "\n"
            )
            return ProcessOutcome(-15, "timed out", 0.01, timed_out=True)
        payload = _payload(role)
        if role is Role.EXTRACTOR:
            payload["artifacts"] = [
                {
                    "path": "missing.bin",
                    "sha256": None,
                    "purpose": "synthetic missing artifact",
                }
            ]
        _output_path(command).write_text(json.dumps(payload), encoding="utf-8")
        return ProcessOutcome(0, "", 0.01)


class FakeSandbox:
    scope_fingerprint = "a" * 64

    def __init__(self, work: Path) -> None:
        self.work = work
        self.proof_calls = 0
        self.proof_input_calls = []
        self.proof_specs = []
        self.specs = []
        self.initializations = 0

    def initialize_workspace(self, *, deadline_monotonic_seconds=None):
        self.initialization_deadline = deadline_monotonic_seconds
        self.initializations += 1

    def run(self, spec):
        self.specs.append(spec)
        raw = self.work / "raw"
        raw.mkdir(exist_ok=True)
        stdout = raw / "stdout.log"
        stderr = raw / "stderr.log"
        stdout.write_text("answer KCTF{tool_flag}\n", encoding="utf-8")
        stderr.write_text("", encoding="utf-8")
        return SandboxResult(
            "tool-1",
            "completed",
            0,
            False,
            5,
            "answer KCTF{tool_flag}",
            "",
            stdout.stat().st_size,
            0,
            "/work/raw/stdout.log",
            "/work/raw/stderr.log",
        )

    def register_artifact(self, locator, *, maximum_bytes=1 << 34):
        del maximum_bytes
        path = self.work / locator
        import hashlib

        return ArtifactRef(
            locator,
            hashlib.sha256(path.read_bytes()).hexdigest(),
            path.stat().st_size,
            self.scope_fingerprint,
        )

    def start_job(self, *args, **kwargs):
        raise AssertionError("not used")

    def job_status(self, *args, **kwargs):
        raise AssertionError("not used")

    def job_log(self, *args, **kwargs):
        raise AssertionError("not used")

    def cancel_job(self, *args, **kwargs):
        raise AssertionError("not used")

    def run_clean_proof(
        self,
        spec,
        *,
        input_locators=(),
        proof_inputs=(),
    ):
        del input_locators
        self.proof_specs.append(spec)
        captured_inputs = []
        for item in proof_inputs:
            source = self.work / item.source_locator
            payload = source.read_bytes()
            import hashlib

            if hashlib.sha256(payload).hexdigest() != item.sha256:
                raise OSError("proof input hash mismatch")
            if len(payload) != item.size_bytes:
                raise OSError("proof input size mismatch")
            captured_inputs.append((item.destination_locator, payload))
        self.proof_input_calls.append(tuple(captured_inputs))
        self.proof_calls += 1
        relative = Path("proof") / f"clean-{self.proof_calls}"
        directory = self.work / relative
        directory.mkdir(parents=True)
        stdout = directory / "stdout.log"
        stderr = directory / "stderr.log"
        stdout.write_text("KCTF{proof_flag}\n", encoding="utf-8")
        stderr.write_text("", encoding="utf-8")
        return SandboxResult(
            f"proof-{self.proof_calls}",
            "completed",
            0,
            False,
            5,
            "KCTF{proof_flag}",
            "",
            stdout.stat().st_size,
            0,
            f"/work/{relative.as_posix()}/stdout.log",
            f"/work/{relative.as_posix()}/stderr.log",
        )


class RevInventorySandbox(FakeSandbox):
    def __init__(
        self,
        work: Path,
        payload: bytes,
        *,
        complete_capture: bool = True,
        status: str = "completed",
        exit_code: int = 0,
        timed_out: bool = False,
        orchestration_error: str | None = None,
        on_run=None,
    ) -> None:
        super().__init__(work)
        self.payload = payload
        self.complete_capture = complete_capture
        self.status = status
        self.exit_code = exit_code
        self.timed_out = timed_out
        self.orchestration_error = orchestration_error
        self.on_run = on_run

    def run(self, spec):
        self.specs.append(spec)
        raw = self.work / "raw"
        raw.mkdir(exist_ok=True)
        stdout = raw / "stdout.log"
        stderr = raw / "stderr.log"
        stdout.write_bytes(self.payload)
        stderr.write_bytes(b"")
        if self.on_run is not None:
            self.on_run()
        stdout_size = stdout.stat().st_size
        return SandboxResult(
            "rev-inventory-tool",
            self.status,
            self.exit_code,
            self.timed_out,
            5,
            self.payload.decode("utf-8", errors="replace"),
            "",
            stdout_size,
            0,
            "/work/raw/stdout.log",
            "/work/raw/stderr.log",
            stdout_stored_bytes=stdout_size,
            stderr_stored_bytes=0,
            stdout_limit_bytes=16 * 1024 * 1024,
            stderr_limit_bytes=16 * 1024 * 1024,
            stdout_truncated=False,
            stderr_truncated=False,
            stdout_truncation_known=True,
            stderr_truncation_known=True,
            stdout_capture_complete=self.complete_capture,
            stderr_capture_complete=True,
            stdout_error=None,
            stderr_error=None,
            stream_capture_error=None,
            orchestration_error=self.orchestration_error,
        )


class EngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.identity = ChallengeIdentity("국내 CTF", "rev", "문제 1")

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def engine_with_executor(
        self, executor: RoleExecutor
    ) -> ChallengeEngine:
        runner = BatchRunner(
            process_executor=executor,
            limiter=FifoModelCallLimiter(1),
            limiter_wait_timeout=2,
            max_schema_retries=0,
        )
        return ChallengeEngine(
            self.root,
            batch_runner=runner,
            sandbox_factory=lambda state, work, policy: FakeSandbox(work),
        )

    def engine_with_rev_inventory(
        self,
        payload: bytes,
        *,
        complete_capture: bool = True,
        image_digest: str | None = "sha256:" + ("1" * 64),
        status: str = "completed",
        exit_code: int = 0,
        timed_out: bool = False,
        orchestration_error: str | None = None,
        on_run=None,
    ) -> ChallengeEngine:
        config = load_config(self.root)
        config = replace(
            config,
            runtime=replace(
                config.runtime,
                image_digest=image_digest,
            ),
        )
        runner = BatchRunner(
            process_executor=RoleExecutor(),
            limiter=FifoModelCallLimiter(1),
            limiter_wait_timeout=2,
            max_schema_retries=0,
        )
        return ChallengeEngine(
            self.root,
            config=config,
            batch_runner=runner,
            sandbox_factory=lambda state, work, policy: RevInventorySandbox(
                work,
                payload,
                complete_capture=complete_capture,
                status=status,
                exit_code=exit_code,
                timed_out=timed_out,
                orchestration_error=orchestration_error,
                on_run=on_run,
            ),
        )

    def install_legacy_v1_inventory(
        self,
        engine: ChallengeEngine,
        *,
        status: ExperimentStatus,
        result: dict[str, object] | None = None,
        source_size_bytes: int | None = None,
    ) -> tuple[ChallengeState, str]:
        """Replace only the active inventory seed with a frozen v1 seed."""

        state = engine.store.load(self.identity)
        primary = next(
            source
            for source in state.source_inventory
            if source.path
            == state.metadata.get("adapter_primary_source")
        )
        size = (
            primary.size
            if source_size_bytes is None
            else source_size_bytes
        )
        binding = build_rev_inventory_v1_source_binding(
            manifest_generation=(
                len(
                    state.metadata.get(
                        "source_manifest_history",
                        [],
                    )
                )
                + 1
            ),
            manifest_sha256=state.metadata["source_manifest_sha256"],
            path=primary.path,
            source_sha256=primary.sha256,
            source_size_bytes=size,
        )
        snapshot = build_rev_inventory_v1_source_snapshot(binding)
        extra = build_rev_inventory_v1_seed_extra(binding, snapshot)
        legacy_id = (
            "E-adapter-reversing-"
            + str(extra["adapter_spec_id"]).replace("@", "-")
        )

        def apply(current: ChallengeState) -> None:
            current_primary = next(
                source
                for source in current.source_inventory
                if source.path == primary.path
            )
            current_primary.size = size
            inventory = next(
                experiment
                for experiment in current.experiments
                if experiment.extra.get("adapter_spec_template_id")
                == "inventory_observation"
            )
            inventory.id = legacy_id
            inventory.command = rev_inventory_v1_seed_command(
                primary.path
            )
            inventory.status = status
            inventory.result = copy.deepcopy(result)
            inventory.extra = copy.deepcopy(extra)

        return (
            engine.store.update(
                self.identity,
                apply,
                validate_artifacts=False,
            ),
            legacy_id,
        )

    def test_add_ingests_human_folder_and_prepares_live_session(self) -> None:
        input_dir = (
            self.root
            / "incoming"
            / self.identity.contest_id
            / self.identity.category
            / self.identity.challenge_id
        )
        input_dir.mkdir(parents=True)
        (input_dir / "chall").write_bytes(b"\x7fELF")
        engine = self.engine_with_executor(RoleExecutor())
        state = engine.add_challenge(
            self.identity, prompt="이 바이너리를 풀어라", budget_seconds=28_800
        )
        self.assertEqual(state.source_inventory[0].path, "chall")
        self.assertEqual(state.budget.allocated_seconds, 28_800)
        live = engine.prepare_live_session(self.identity)
        self.assertTrue(live.session_context.exists())
        self.assertIn("SESSION.md", live.command[-1])
        self.assertEqual(len(WAVE_ROLES["discovery"]), 3)

    def test_thin_live_hot_path_has_one_model_and_no_roles(self) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(self.identity, prompt="solve")
        prepared = engine.prepare_live_session(
            self.identity,
            scaffold=THIN_SCAFFOLD,
        )
        self.assertEqual(prepared.scaffold, THIN_SCAFFOLD)
        self.assertIn("features.multi_agent=false", prepared.command)
        self.assertIn("agents.enabled=false", prepared.command)
        self.assertIn(
            "agents.max_concurrent_threads_per_session=1",
            prepared.command,
        )
        self.assertEqual(len(prepared.command_contract_sha256), 64)
        instructions = (
            prepared.working_directory / "AGENTS.md"
        ).read_text(encoding="utf-8")
        self.assertIn("thin one-model baseline", instructions)
        self.assertNotIn("Maintain three logical worker roles", instructions)

    def test_evaluation_scaffold_launch_is_exact_and_one_shot(self) -> None:
        image_digest = "sha256:" + hashlib.sha256(b"image").hexdigest()
        config = load_config(self.root)
        config = replace(
            config,
            runtime=replace(
                config.runtime,
                image_digest=image_digest,
            ),
        )
        engine = ChallengeEngine(
            self.root,
            config=config,
            sandbox_factory=lambda state, work, policy: FakeSandbox(work),
        )
        added = engine.add_challenge(
            self.identity,
            prompt="solve",
            state_schema_version=STATE_SCHEMA_VERSION,
        )

        def digest(value: bytes) -> str:
            return hashlib.sha256(value).hexdigest()

        def prepare(state: ChallengeState) -> None:
            state.metadata.update(
                {
                    "evaluation_prepared": True,
                    "evaluation_system": THIN_SCAFFOLD,
                    "evaluation_benchmark_id": "blind-release",
                    "evaluation_case_id": "case-one",
                    "evaluation_session_id": "case-one-thin-1",
                    "evaluation_manifest_sha256": digest(b"manifest"),
                    "evaluation_model": config.models.captain,
                    "evaluation_image_sha256": (
                        image_digest.removeprefix("sha256:")
                    ),
                    "evaluation_tool_manifest_sha256": digest(b"tools"),
                    "evaluation_model_config_sha256": digest(b"models"),
                    "evaluation_engine_source_sha256": digest(b"source"),
                }
            )

        engine.store.update(
            self.identity,
            prepare,
            expected_revision=added.revision,
        )
        contract_sha256 = digest(b"thin-contract")
        fingerprint = mock.Mock(
            tool_manifest_sha256=digest(b"tools"),
            image_sha256=image_digest.removeprefix("sha256:"),
            model_config_sha256=digest(b"models"),
            engine_source_sha256=digest(b"source"),
        )
        with mock.patch(
            "ctf_os.promotion_bundles.local_execution_fingerprint",
            return_value=fingerprint,
        ):
            launched = engine.record_evaluation_scaffold_launch(
                self.identity,
                arm=THIN_SCAFFOLD,
                command_contract_sha256=contract_sha256,
            )
        binding, _timestamp = parse_scaffold_launch_record(
            launched.metadata[SCAFFOLD_LAUNCH_METADATA_KEY]
        )
        self.assertEqual(binding.arm, THIN_SCAFFOLD)
        self.assertEqual(binding.command_contract_sha256, contract_sha256)
        self.assertEqual(
            binding.configuration_epoch,
            launched.configuration_epoch,
        )
        with (
            mock.patch(
                "ctf_os.promotion_bundles.local_execution_fingerprint",
                return_value=fingerprint,
            ),
            self.assertRaisesRegex(EngineError, "already launched"),
        ):
            engine.record_evaluation_scaffold_launch(
                self.identity,
                arm=THIN_SCAFFOLD,
                command_contract_sha256=contract_sha256,
            )

    def test_provider_start_rechecks_prepared_source_before_executor(
        self,
    ) -> None:
        image_digest = "sha256:" + hashlib.sha256(b"image").hexdigest()
        config = load_config(self.root)
        config = replace(
            config,
            runtime=replace(
                config.runtime,
                image_digest=image_digest,
            ),
        )
        executor = RoleExecutor()
        engine = ChallengeEngine(
            self.root,
            config=config,
            batch_runner=BatchRunner(
                process_executor=executor,
                limiter=FifoModelCallLimiter(1),
                limiter_wait_timeout=2,
                max_schema_retries=0,
            ),
            sandbox_factory=lambda state, work, policy: FakeSandbox(work),
        )
        added = engine.add_challenge(
            self.identity,
            prompt="solve",
            state_schema_version=STATE_SCHEMA_VERSION,
        )

        def digest(value: bytes) -> str:
            return hashlib.sha256(value).hexdigest()

        def prepare(state: ChallengeState) -> None:
            state.metadata.update(
                {
                    "evaluation_prepared": True,
                    "evaluation_system": THIN_SCAFFOLD,
                    "evaluation_benchmark_id": "blind-release",
                    "evaluation_case_id": "case-one",
                    "evaluation_session_id": "case-one-thin-1",
                    "evaluation_manifest_sha256": digest(b"manifest"),
                    "evaluation_model": config.models.captain,
                    "evaluation_image_sha256": (
                        image_digest.removeprefix("sha256:")
                    ),
                    "evaluation_tool_manifest_sha256": digest(b"tools"),
                    "evaluation_model_config_sha256": digest(b"models"),
                    "evaluation_engine_source_sha256": digest(b"source"),
                }
            )

        engine.store.update(
            self.identity,
            prepare,
            expected_revision=added.revision,
        )
        frozen = mock.Mock(
            tool_manifest_sha256=digest(b"tools"),
            image_sha256=image_digest.removeprefix("sha256:"),
            model_config_sha256=digest(b"models"),
            engine_source_sha256=digest(b"source"),
        )
        with mock.patch(
            "ctf_os.promotion_bundles.local_execution_fingerprint",
            return_value=frozen,
        ):
            launched = engine.record_evaluation_scaffold_launch(
                self.identity,
                arm=THIN_SCAFFOLD,
                command_contract_sha256=digest(b"contract"),
            )

        deadline_monotonic, deadline_epoch = (
            engine._budget_deadline_pair(launched, 60)
        )
        invocation = engine._make_invocation(
            launched,
            Role.RECON,
            prefix="source-recheck",
            instruction="must not reach the provider",
            deadline_monotonic_seconds=deadline_monotonic,
            deadline_epoch_seconds=deadline_epoch,
        )
        changed = mock.Mock(
            tool_manifest_sha256=digest(b"tools"),
            image_sha256=image_digest.removeprefix("sha256:"),
            model_config_sha256=digest(b"models"),
            engine_source_sha256=digest(b"changed-source"),
        )
        with mock.patch(
            "ctf_os.promotion_bundles.local_execution_fingerprint",
            return_value=changed,
        ):
            result = engine.batch_runner.run(
                invocation,
                before_provider_start=lambda: (
                    engine._before_provider_start(self.identity)
                ),
            )

        self.assertFalse(result.success)
        self.assertEqual(executor.roles, [])
        self.assertIn(
            "model_call_cancelled",
            {failure.kind for failure in result.failures},
        )

    def test_prepared_full_arm_rejects_assisted_live_before_setup(self) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        added = engine.add_challenge(self.identity, prompt="solve")

        def prepare(state: ChallengeState) -> None:
            state.metadata["evaluation_prepared"] = True
            state.metadata["evaluation_system"] = "ctf_os"

        engine.store.update(
            self.identity,
            prepare,
            expected_revision=added.revision,
        )
        with self.assertRaisesRegex(EngineError, "managed mode"):
            engine.launch_live(
                self.identity,
                runner=lambda *args, **kwargs: None,
            )

    def test_prepared_thin_headless_run_attests_exact_model_usage(self) -> None:
        class ThinUsageExecutor:
            def __init__(inner_self) -> None:
                inner_self.commands: list[BuiltCommand] = []

            def run(
                inner_self,
                command,
                *,
                cwd,
                timeout,
                on_stdout_line,
            ):
                del cwd, timeout
                inner_self.commands.append(command)
                self.assertEqual(command.argv[:3], ("codex", "exec", "--json"))
                self.assertIn("features.multi_agent=false", command.argv)
                self.assertIsNotNone(command.environment)
                assert command.environment is not None
                self.assertIn(
                    "CTFOS_SCOPE_CAPABILITY",
                    command.environment,
                )
                self.assertIn("CTFOS_LIVE_SESSION", command.environment)
                on_stdout_line(
                    json.dumps(
                        {
                            "type": "thread.started",
                            "thread_id": "thin-thread-1",
                        }
                    )
                    + "\n"
                )
                on_stdout_line(
                    json.dumps(
                        {
                            "type": "turn.completed",
                            "usage": {
                                "input_tokens": 101,
                                "cached_input_tokens": 41,
                                "output_tokens": 29,
                                "reasoning_output_tokens": 17,
                            },
                        }
                    )
                    + "\n"
                )
                _output_path(command).write_text(
                    json.dumps(_payload(Role.CAPTAIN)),
                    encoding="utf-8",
                )
                return ProcessOutcome(0, "", 0.01)

        image_digest = "sha256:" + hashlib.sha256(b"image").hexdigest()
        config = load_config(self.root)
        config = replace(
            config,
            runtime=replace(
                config.runtime,
                image_digest=image_digest,
            ),
        )
        executor = ThinUsageExecutor()
        batch_runner = BatchRunner(
            process_executor=executor,
            limiter=FifoModelCallLimiter(1),
            limiter_wait_timeout=2,
            max_schema_retries=0,
        )
        engine = ChallengeEngine(
            self.root,
            config=config,
            batch_runner=batch_runner,
            sandbox_factory=lambda state, work, policy: FakeSandbox(work),
        )
        added = engine.add_challenge(
            self.identity,
            prompt="solve",
            state_schema_version=STATE_SCHEMA_VERSION,
        )

        def digest(value: bytes) -> str:
            return hashlib.sha256(value).hexdigest()

        def prepare(state: ChallengeState) -> None:
            state.metadata.update(
                {
                    "evaluation_prepared": True,
                    "evaluation_system": THIN_SCAFFOLD,
                    "evaluation_benchmark_id": "blind-release",
                    "evaluation_case_id": "case-one",
                    "evaluation_session_id": "case-one-thin-1",
                    "evaluation_manifest_sha256": digest(b"manifest"),
                    "evaluation_model": config.models.captain,
                    "evaluation_image_sha256": (
                        image_digest.removeprefix("sha256:")
                    ),
                    "evaluation_tool_manifest_sha256": digest(b"tools"),
                    "evaluation_model_config_sha256": digest(b"models"),
                    "evaluation_engine_source_sha256": digest(b"source"),
                }
            )

        engine.store.update(
            self.identity,
            prepare,
            expected_revision=added.revision,
        )
        announced = []
        fingerprint = mock.Mock(
            tool_manifest_sha256=digest(b"tools"),
            image_sha256=image_digest.removeprefix("sha256:"),
            model_config_sha256=digest(b"models"),
            engine_source_sha256=digest(b"source"),
        )
        with mock.patch(
            "ctf_os.promotion_bundles.local_execution_fingerprint",
            return_value=fingerprint,
        ):
            status = engine.launch_live(
                self.identity,
                scaffold=THIN_SCAFFOLD,
                on_prepared=announced.append,
            )
        self.assertEqual(status, 0)
        self.assertEqual(len(announced), 1)
        self.assertEqual(len(executor.commands), 1)
        state = engine.store.load(self.identity)
        model_runs = [
            run for run in state.runs if run.model is not None
        ]
        self.assertEqual(len(model_runs), 1)
        run = model_runs[0]
        self.assertIs(run.status, RunStatus.COMPLETED)
        self.assertIs(run.origin, models_module.RunOrigin.ASSISTED_MODEL)
        self.assertEqual(run.extra["evaluation_scaffold"], THIN_SCAFFOLD)
        self.assertEqual(run.extra["execution_transport"], "headless_jsonl")
        self.assertEqual(
            run.extra["usage"],
            {
                "input_tokens": 101,
                "cached_input_tokens": 41,
                "output_tokens": 29,
                "reasoning_output_tokens": 17,
            },
        )
        self.assertNotIn("thread_id", run.extra)
        self.assertEqual(
            run.extra["produced_thread_id_sha256"],
            hashlib.sha256(b"thin-thread-1").hexdigest(),
        )
        challenge_root = engine.store.challenge_paths(
            self.identity
        ).root
        for pointer_field, digest_field in (
            ("request_path", "request_sha256"),
            ("result_path", "result_sha256"),
            ("validation_path", "validation_sha256"),
        ):
            pointer = getattr(run, pointer_field)
            self.assertIsNotNone(pointer)
            assert pointer is not None
            self.assertEqual(
                run.extra[digest_field],
                sha256_file(challenge_root / pointer),
            )
        self.assertEqual(run.extra["attempt_count"], 1)
        self.assertEqual(state.candidates, [])
        self.assertEqual(state.submissions, [])
        self.assertIn(SCAFFOLD_LAUNCH_METADATA_KEY, state.metadata)

    def test_adapter_initial_plan_is_registered_once_and_never_auto_runs(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        input_dir = engine.challenge_input(self.identity)
        input_dir.mkdir(parents=True)
        (input_dir / "chall").write_bytes(_elf64_image(2))
        state = engine.add_challenge(self.identity, prompt="solve")
        seeded = [
            experiment
            for experiment in state.experiments
            if experiment.extra.get("adapter_seed")
        ]
        self.assertTrue(seeded)
        self.assertTrue(
            all(
                experiment.status is ExperimentStatus.REGISTERED
                for experiment in seeded
            )
        )
        self.assertEqual(state.metadata["adapter_name"], "reversing")
        self.assertTrue(state.metadata["failure_labels"])

        state = engine.add_challenge(self.identity, prompt="solve again")
        self.assertEqual(
            len(
                [
                    experiment
                    for experiment in state.experiments
                    if experiment.extra.get("adapter_seed")
                ]
            ),
            len(seeded),
        )
        state = engine.execute_registered_experiments(
            self.identity, maximum=len(seeded)
        )
        self.assertTrue(
            all(
                experiment.status is ExperimentStatus.REGISTERED
                for experiment in state.experiments
                if experiment.extra.get("adapter_seed")
            )
        )

        state = engine.execute_registered_experiments(
            self.identity,
            experiment_ids=(seeded[0].id,),
        )
        selected = next(
            experiment
            for experiment in state.experiments
            if experiment.id == seeded[0].id
        )
        self.assertIs(
            selected.status,
            ExperimentStatus.AWAITING_EVALUATION,
        )

    def test_rev_seed_refreshes_after_an_empty_session_gains_input(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        state = engine.add_challenge(self.identity, prompt="solve")

        self.assertFalse(
            any(
                experiment.extra.get("adapter_seed") is True
                for experiment in state.experiments
            )
        )
        self.assertNotIn("adapter_primary_source", state.metadata)

        input_dir = engine.challenge_input(self.identity)
        (input_dir / "chall").write_bytes(_elf64_image(2))
        state = engine.refresh_ingest(self.identity)
        seeded = [
            experiment
            for experiment in state.experiments
            if experiment.extra.get("adapter_seed") is True
            and experiment.status is ExperimentStatus.REGISTERED
        ]

        self.assertEqual(
            [
                experiment.extra["adapter_spec_template_id"]
                for experiment in seeded
            ],
            [
                "inventory_observation",
                "assembly_observation",
                "dynamic_observation",
            ],
        )
        self.assertNotIn(
            "ghidra-decompile",
            "\n".join(experiment.command for experiment in seeded),
        )
        self.assertIn(
            "decompiler_observation",
            {
                spec.id
                for spec in get_adapter(
                    self.identity.category
                ).initial_observations()
            },
        )
        self.assertTrue(
            all(
                experiment.extra["source_binding"]
                == {
                    "manifest_generation": (
                        len(
                            state.metadata.get(
                                "source_manifest_history",
                                [],
                            )
                        )
                        + 1
                    ),
                    "manifest_sha256": (
                        state.metadata["source_manifest_sha256"]
                    ),
                    "path": "chall",
                    "sha256": state.source_inventory[0].sha256,
                    "size_bytes": state.source_inventory[0].size,
                }
                for experiment in seeded
            )
        )
        inventory_oracle = seeded[0].extra["partial_oracle"]
        self.assertEqual(
            inventory_oracle,
            {
                "oracle_id": REV_INVENTORY_V2_CONTRACT_ID,
                "oracle_version": REV_INVENTORY_V2_CONTRACT_VERSION,
                "contract_fingerprint": (
                    REV_INVENTORY_V2_CONTRACT_FINGERPRINT
                ),
                "document_transport": (
                    REV_INVENTORY_V2_DOCUMENT_TRANSPORT
                ),
            },
        )
        self.assertTrue(
            all(
                experiment.extra["adapter_spec_id"].startswith(
                    experiment.extra["adapter_spec_template_id"] + "@"
                )
                for experiment in seeded
            )
        )
        self.assertEqual(
            len(
                {
                    experiment.extra["adapter_spec_id"]
                    for experiment in seeded
                }
            ),
            3,
        )

    def test_rev_seed_refresh_is_idempotent_for_the_same_manifest(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        input_dir = engine.challenge_input(self.identity)
        input_dir.mkdir(parents=True)
        (input_dir / "chall").write_bytes(_elf64_image(2))
        state = engine.add_challenge(self.identity, prompt="solve")
        original_ids = [
            experiment.id
            for experiment in state.experiments
            if experiment.extra.get("adapter_seed") is True
        ]
        original_revision = state.revision

        first = engine.refresh_ingest(self.identity)
        second = engine.refresh_ingest(self.identity)

        self.assertEqual(first.revision, original_revision)
        self.assertEqual(second.revision, original_revision)
        self.assertEqual(
            [
                experiment.id
                for experiment in second.experiments
                if experiment.extra.get("adapter_seed") is True
            ],
            original_ids,
        )
        self.assertFalse(
            any(
                experiment.status is ExperimentStatus.CANCELLED
                for experiment in second.experiments
                if experiment.extra.get("adapter_seed") is True
            )
        )

    def test_legacy_v1_registered_seed_is_cancelled_before_v2_sync(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        input_dir = engine.challenge_input(self.identity)
        input_dir.mkdir(parents=True)
        (input_dir / "chall").write_bytes(_elf64_image(2))
        engine.add_challenge(self.identity, prompt="solve")
        _legacy, legacy_id = self.install_legacy_v1_inventory(
            engine,
            status=ExperimentStatus.REGISTERED,
        )

        state = engine.refresh_ingest(self.identity)

        legacy = next(
            item for item in state.experiments if item.id == legacy_id
        )
        self.assertIs(legacy.status, ExperimentStatus.CANCELLED)
        self.assertEqual(
            legacy.extra["cancelled_reason"],
            "legacy_contract_replaced",
        )
        current = [
            item
            for item in state.experiments
            if item.status is ExperimentStatus.REGISTERED
            and item.extra.get("adapter_spec_template_id")
            == "inventory_observation"
        ]
        self.assertEqual(len(current), 1)
        self.assertEqual(
            current[0].extra["partial_oracle"]["oracle_version"],
            REV_INVENTORY_V2_CONTRACT_VERSION,
        )
        self.assertNotIn("inventory_v2.py", legacy.command)

    def test_legacy_v1_running_seed_fails_then_v2_is_registered(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        input_dir = engine.challenge_input(self.identity)
        input_dir.mkdir(parents=True)
        (input_dir / "chall").write_bytes(_elf64_image(2))
        engine.add_challenge(self.identity, prompt="solve")
        _legacy, legacy_id = self.install_legacy_v1_inventory(
            engine,
            status=ExperimentStatus.RUNNING,
        )

        state = engine._recover_session_boundary(self.identity)

        legacy = next(
            item for item in state.experiments if item.id == legacy_id
        )
        self.assertIs(legacy.status, ExperimentStatus.FAILED)
        self.assertIn("orphaned tool execution", legacy.result["error"])
        self.assertNotEqual(
            legacy.extra.get("orphan_recovery"),
            "retryable_without_canonical_outcome",
        )
        current = next(
            item
            for item in state.experiments
            if item.status is ExperimentStatus.REGISTERED
            and item.extra.get("adapter_spec_template_id")
            == "inventory_observation"
        )
        self.assertEqual(
            current.extra["partial_oracle"]["oracle_version"],
            REV_INVENTORY_V2_CONTRACT_VERSION,
        )

    def test_legacy_v1_terminal_history_is_byte_stable_during_sync(
        self,
    ) -> None:
        original_identity = self.identity
        try:
            for name, status, result in (
                (
                    "success",
                    ExperimentStatus.COMPLETED,
                    {"exit_code": 0, "timed_out": False},
                ),
                (
                    "failed",
                    ExperimentStatus.FAILED,
                    {"exit_code": 7, "timed_out": False},
                ),
                (
                    "timeout",
                    ExperimentStatus.FAILED,
                    {"exit_code": 124, "timed_out": True},
                ),
            ):
                with self.subTest(name=name):
                    identity = ChallengeIdentity(
                        "legacy-v1-terminal",
                        "rev",
                        name,
                    )
                    self.identity = identity
                    engine = self.engine_with_executor(RoleExecutor())
                    input_dir = engine.challenge_input(identity)
                    input_dir.mkdir(parents=True)
                    (input_dir / "chall").write_bytes(_elf64_image(2))
                    engine.add_challenge(identity, prompt="solve")
                    state, legacy_id = (
                        self.install_legacy_v1_inventory(
                            engine,
                            status=status,
                            result=result,
                        )
                    )
                    before = copy.deepcopy(
                        next(
                            item
                            for item in state.experiments
                            if item.id == legacy_id
                        ).to_dict(v2=True)
                    )

                    synced = engine.refresh_ingest(identity)
                    after = next(
                        item
                        for item in synced.experiments
                        if item.id == legacy_id
                    ).to_dict(v2=True)

                    self.assertEqual(after, before)
                    self.assertTrue(
                        any(
                            item.status
                            is ExperimentStatus.REGISTERED
                            and item.extra.get(
                                "adapter_spec_template_id"
                            )
                            == "inventory_observation"
                            and item.extra["partial_oracle"][
                                "oracle_version"
                            ]
                            == REV_INVENTORY_V2_CONTRACT_VERSION
                            for item in synced.experiments
                        )
                    )
        finally:
            self.identity = original_identity

    def test_legacy_v1_oversize_seed_loads_but_never_runs(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        input_dir = engine.challenge_input(self.identity)
        input_dir.mkdir(parents=True)
        (input_dir / "chall").write_bytes(_elf64_image(2))
        engine.add_challenge(self.identity, prompt="solve")
        _legacy, legacy_id = self.install_legacy_v1_inventory(
            engine,
            status=ExperimentStatus.REGISTERED,
            source_size_bytes=REV_INVENTORY_V1_MAX_SOURCE_BYTES + 1,
        )

        state = engine.refresh_ingest(self.identity)

        legacy = next(
            item for item in state.experiments if item.id == legacy_id
        )
        self.assertIs(legacy.status, ExperimentStatus.CANCELLED)
        self.assertFalse(
            any(
                item.status is ExperimentStatus.REGISTERED
                and item.extra.get("adapter_spec_template_id")
                == "inventory_observation"
                for item in state.experiments
            )
        )

    def test_rev_execute_all_synchronizes_input_added_after_empty_init(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        state = engine.add_challenge(self.identity, prompt="solve")
        self.assertFalse(
            any(
                experiment.extra.get("adapter_seed") is True
                for experiment in state.experiments
            )
        )
        input_dir = engine.challenge_input(self.identity)
        (input_dir / "chall").write_bytes(_elf64_image(2))

        state = engine.execute_registered_experiments(self.identity)

        seeded = [
            experiment
            for experiment in state.experiments
            if experiment.extra.get("adapter_seed") is True
        ]
        self.assertEqual(len(seeded), 3)
        self.assertTrue(
            all(
                experiment.status is ExperimentStatus.REGISTERED
                for experiment in seeded
            )
        )
        self.assertEqual(state.runs, [])

    def test_rev_bound_spec_id_covers_seed_execution_semantics(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        input_dir = engine.challenge_input(self.identity)
        input_dir.mkdir(parents=True)
        (input_dir / "chall").write_bytes(_elf64_image(2))
        state = engine.add_challenge(self.identity, prompt="solve")
        adapter = get_adapter(self.identity.category)
        _primary, baseline = engine._rev_adapter_seed_plan(
            state,
            adapter,
        )
        specs = list(adapter.initial_observations())
        inventory_index = next(
            index
            for index, spec in enumerate(specs)
            if spec.id == "inventory_observation"
        )
        drifted_inventory_specs = list(specs)
        drifted_inventory_specs[inventory_index] = replace(
            specs[inventory_index],
            purpose=f"{specs[inventory_index].purpose} drifted",
        )
        drifted_inventory_adapter = mock.Mock()
        drifted_inventory_adapter.name = adapter.name
        drifted_inventory_adapter.initial_observations.return_value = tuple(
            drifted_inventory_specs
        )
        with self.assertRaisesRegex(
            EngineError,
            "drifted from the immutable v2 contract",
        ):
            engine._rev_adapter_seed_plan(
                state,
                drifted_inventory_adapter,
            )

        assembly_index = next(
            index
            for index, spec in enumerate(specs)
            if spec.id == "assembly_observation"
        )
        changed_specs = list(specs)
        changed_specs[assembly_index] = replace(
            specs[assembly_index],
            timeout_s=specs[assembly_index].timeout_s + 1,
        )
        changed_adapter = mock.Mock()
        changed_adapter.name = adapter.name
        changed_adapter.initial_observations.return_value = tuple(
            changed_specs
        )
        _primary, changed = engine._rev_adapter_seed_plan(
            state,
            changed_adapter,
        )
        baseline_ids = {
            item[0].id: item[1]
            for item in baseline
        }
        changed_ids = {
            item[0].id: item[1]
            for item in changed
        }
        self.assertEqual(
            baseline_ids["inventory_observation"],
            changed_ids["inventory_observation"],
        )
        self.assertNotEqual(
            baseline_ids["assembly_observation"],
            changed_ids["assembly_observation"],
        )
        self.assertEqual(
            [item[3]["adapter_seed_order"] for item in baseline],
            [0, 1, 2],
        )

    def test_rev_manifest_recurrence_gets_fresh_bound_seed_records(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        input_dir = engine.challenge_input(self.identity)
        input_dir.mkdir(parents=True)
        primary = input_dir / "chall"
        source_a = _elf64_image(2) + b"A"
        source_b = _elf64_image(2) + b"B"
        primary.write_bytes(source_a)
        first = engine.add_challenge(self.identity, prompt="solve")
        first_ids = {
            experiment.id
            for experiment in first.experiments
            if experiment.extra.get("adapter_seed") is True
        }
        first_generation = next(
            experiment
            for experiment in first.experiments
            if experiment.id in first_ids
        ).extra["source_binding"]["manifest_generation"]

        primary.write_bytes(source_b)
        second = engine.refresh_ingest(self.identity)
        second_ids = {
            experiment.id
            for experiment in second.experiments
            if experiment.extra.get("adapter_seed") is True
            and experiment.id not in first_ids
        }
        primary.write_bytes(source_a)
        third = engine.refresh_ingest(self.identity)
        third_ids = {
            experiment.id
            for experiment in third.experiments
            if experiment.extra.get("adapter_seed") is True
            and experiment.id not in first_ids | second_ids
        }

        self.assertEqual(len(first_ids), 3)
        self.assertEqual(len(second_ids), 3)
        self.assertEqual(len(third_ids), 3)
        self.assertTrue(first_ids.isdisjoint(second_ids))
        self.assertTrue(first_ids.isdisjoint(third_ids))
        self.assertTrue(second_ids.isdisjoint(third_ids))
        self.assertTrue(
            all(
                experiment.status is ExperimentStatus.CANCELLED
                for experiment in third.experiments
                if experiment.id in first_ids | second_ids
            )
        )
        current = [
            experiment
            for experiment in third.experiments
            if experiment.id in third_ids
        ]
        self.assertTrue(
            all(
                experiment.status is ExperimentStatus.REGISTERED
                for experiment in current
            )
        )
        self.assertEqual(
            {
                experiment.extra["source_binding"][
                    "manifest_generation"
                ]
                for experiment in current
            },
            {first_generation + 2},
        )
        stable_revision = third.revision
        repeated = engine.refresh_ingest(self.identity)
        self.assertEqual(repeated.revision, stable_revision)
        self.assertEqual(
            {
                experiment.id
                for experiment in repeated.experiments
                if experiment.extra.get("adapter_seed") is True
                and experiment.status is ExperimentStatus.REGISTERED
            },
            third_ids,
        )

    def test_rev_seed_execution_refresh_cancels_a_stale_primary_binding(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        input_dir = engine.challenge_input(self.identity)
        input_dir.mkdir(parents=True)
        original = input_dir / "old-chall"
        original.write_bytes(_elf64_image(2))
        state = engine.add_challenge(self.identity, prompt="solve")
        old_seed_ids = [
            experiment.id
            for experiment in state.experiments
            if experiment.extra.get("adapter_seed") is True
        ]
        old_inventory_id = old_seed_ids[0]

        original.unlink()
        (input_dir / "new-chall").write_bytes(
            _elf64_image(2) + b"replacement"
        )
        state = engine.execute_registered_experiments(
            self.identity,
            experiment_ids=(old_inventory_id,),
        )

        old_seeds = [
            experiment
            for experiment in state.experiments
            if experiment.id in old_seed_ids
        ]
        self.assertTrue(
            all(
                experiment.status is ExperimentStatus.CANCELLED
                for experiment in old_seeds
            )
        )
        self.assertFalse(
            any(
                run.extra.get("experiment_id") == old_inventory_id
                for run in state.runs
            )
        )
        new_seeds = [
            experiment
            for experiment in state.experiments
            if experiment.extra.get("adapter_seed") is True
            and experiment.id not in old_seed_ids
        ]
        self.assertEqual(len(new_seeds), 3)
        self.assertTrue(
            all(
                "/challenge/new-chall" in experiment.command
                for experiment in new_seeds
            )
        )
        self.assertTrue(
            all(
                experiment.extra["source_binding"]["path"] == "new-chall"
                for experiment in new_seeds
            )
        )

    def test_rev_execute_all_refreshes_a_same_path_binding_change(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        input_dir = engine.challenge_input(self.identity)
        input_dir.mkdir(parents=True)
        primary = input_dir / "chall"
        primary.write_bytes(_elf64_image(2))
        state = engine.add_challenge(self.identity, prompt="solve")
        old_seed_ids = {
            experiment.id
            for experiment in state.experiments
            if experiment.extra.get("adapter_seed") is True
        }
        old_sha256 = state.source_inventory[0].sha256

        primary.write_bytes(_elf64_image(2) + b"same-path-replacement")
        state = engine.execute_registered_experiments(self.identity)

        self.assertTrue(
            all(
                experiment.status is ExperimentStatus.CANCELLED
                for experiment in state.experiments
                if experiment.id in old_seed_ids
            )
        )
        self.assertFalse(
            any(
                run.extra.get("experiment_id") in old_seed_ids
                for run in state.runs
            )
        )
        new_seeds = [
            experiment
            for experiment in state.experiments
            if experiment.extra.get("adapter_seed") is True
            and experiment.id not in old_seed_ids
        ]
        self.assertEqual(len(new_seeds), 3)
        self.assertTrue(
            all(
                experiment.status is ExperimentStatus.REGISTERED
                and experiment.extra["source_binding"]["path"] == "chall"
                and experiment.extra["source_binding"]["sha256"]
                != old_sha256
                for experiment in new_seeds
            )
        )

    def test_rev_seed_refresh_preserves_terminal_history_and_pins_run(
        self,
    ) -> None:
        source_bytes = _elf64_image(2)
        engine = self.engine_with_rev_inventory(
            _rev_inventory_payload(source_bytes)
        )
        input_dir = engine.challenge_input(self.identity)
        input_dir.mkdir(parents=True)
        original = input_dir / "chall"
        original.write_bytes(source_bytes)
        state = engine.add_challenge(
            self.identity,
            prompt="solve",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        old_manifest = state.metadata["source_manifest_sha256"]
        old_seed_ids = [
            experiment.id
            for experiment in state.experiments
            if experiment.extra.get("adapter_seed") is True
        ]
        inventory = next(
            experiment
            for experiment in state.experiments
            if experiment.id == old_seed_ids[0]
        )
        expected_binding = copy.deepcopy(
            inventory.extra["source_binding"]
        )
        expected_oracle = copy.deepcopy(
            inventory.extra["partial_oracle"]
        )

        state = engine.execute_registered_experiments(
            self.identity,
            experiment_ids=(inventory.id,),
        )
        completed = next(
            experiment
            for experiment in state.experiments
            if experiment.id == inventory.id
        )
        self.assertIs(completed.status, ExperimentStatus.COMPLETED)
        run = next(
            run
            for run in state.runs
            if run.extra.get("experiment_id") == inventory.id
        )
        request_path = (
            engine.store.challenge_paths(self.identity).root
            / run.request_path
        )
        request = json.loads(request_path.read_text(encoding="utf-8"))
        self.assertEqual(request["source_binding"], expected_binding)
        self.assertEqual(request["partial_oracle"], expected_oracle)
        self.assertEqual(run.extra["source_binding"], expected_binding)
        self.assertEqual(run.extra["partial_oracle"], expected_oracle)

        original.unlink()
        (input_dir / "replacement").write_bytes(
            _elf64_image(2) + b"new"
        )
        state = engine.refresh_ingest(self.identity)

        historical = next(
            experiment
            for experiment in state.experiments
            if experiment.id == inventory.id
        )
        self.assertIs(historical.status, ExperimentStatus.COMPLETED)
        self.assertTrue(
            all(
                next(
                    experiment
                    for experiment in state.experiments
                    if experiment.id == experiment_id
                ).status
                is ExperimentStatus.CANCELLED
                for experiment_id in old_seed_ids[1:]
            )
        )
        self.assertIn(
            old_manifest,
            {
                item["sha256"]
                for item in state.metadata["source_manifest_history"]
            },
        )
        self.assertEqual(
            len(
                [
                    experiment
                    for experiment in state.experiments
                    if experiment.extra.get("adapter_seed") is True
                    and experiment.id not in old_seed_ids
                    and experiment.status is ExperimentStatus.REGISTERED
                ]
            ),
            3,
        )

    def test_rev_inventory_active_seed_rejects_single_field_tamper(
        self,
    ) -> None:
        source_bytes = _elf64_image(2) + b"active-seed-contract"
        engine = self.engine_with_rev_inventory(
            _rev_inventory_payload(source_bytes)
        )
        input_dir = engine.challenge_input(self.identity)
        input_dir.mkdir(parents=True)
        (input_dir / "chall").write_bytes(source_bytes)
        state = engine.add_challenge(
            self.identity,
            prompt="solve",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        inventory_id = next(
            item.id
            for item in state.experiments
            if item.extra.get("adapter_spec_template_id")
            == "inventory_observation"
        )
        canonical = state.to_dict()

        for mutation in (
            "source-path",
            "source-hash",
            "source-manifest",
            "snapshot-hash",
            "snapshot-locator",
            "snapshot-binding",
            "adapter-spec-id",
            "adapter-spec-hash",
            "command",
            "resource-class",
            "explicit-execution",
            "timeout",
            "incomplete-recovery-metadata",
        ):
            with self.subTest(mutation=mutation):
                data = copy.deepcopy(canonical)
                experiment = next(
                    item
                    for item in data["experiments"]
                    if item["id"] == inventory_id
                )
                if mutation == "source-path":
                    experiment["source_binding"]["path"] = "other"
                elif mutation == "source-hash":
                    experiment["source_binding"]["sha256"] = "0" * 64
                elif mutation == "source-manifest":
                    experiment["source_binding"][
                        "manifest_sha256"
                    ] = "0" * 64
                elif mutation == "snapshot-hash":
                    experiment["source_snapshot"]["sha256"] = "0" * 64
                elif mutation == "snapshot-locator":
                    experiment["source_snapshot"][
                        "source_locator"
                    ] = "other"
                elif mutation == "snapshot-binding":
                    experiment["source_snapshot"][
                        "binding_sha256"
                    ] = "0" * 64
                elif mutation == "adapter-spec-id":
                    experiment["adapter_spec_id"] = (
                        "inventory_observation@" + ("0" * 64)
                    )
                elif mutation == "adapter-spec-hash":
                    experiment["adapter_spec_sha256"] = "0" * 64
                elif mutation == "command":
                    experiment["command"] = "/bin/true"
                elif mutation == "resource-class":
                    experiment["resource_class"] = "heavy"
                elif mutation == "explicit-execution":
                    experiment["requires_explicit_execution"] = False
                elif mutation == "timeout":
                    experiment["timeout_seconds"] = 61
                elif mutation == "incomplete-recovery-metadata":
                    experiment["orphan_recovery"] = (
                        "retryable_without_canonical_outcome"
                    )

                with self.assertRaisesRegex(
                    ModelValidationError,
                    "Rev inventory",
                ):
                    ChallengeState.from_dict(data).validate()

    def test_refresh_ingest_repairs_registered_rev_seed_plan_fields(
        self,
    ) -> None:
        source_bytes = _elf64_image(2) + b"active-seed-repair"
        engine = self.engine_with_rev_inventory(
            _rev_inventory_payload(source_bytes)
        )
        input_dir = engine.challenge_input(self.identity)
        input_dir.mkdir(parents=True)
        (input_dir / "chall").write_bytes(source_bytes)
        state = engine.add_challenge(
            self.identity,
            prompt="solve",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        tampered = ChallengeState.from_dict(
            copy.deepcopy(state.to_dict())
        )
        inventory = next(
            item
            for item in tampered.experiments
            if item.extra.get("adapter_spec_template_id")
            == "inventory_observation"
        )
        inventory.extra["orphan_recovered_at"] = (
            "2026-07-30T00:00:00+00:00"
        )
        inventory.extra["orphan_recovery"] = (
            "retryable_without_canonical_outcome"
        )
        inventory.command = "/bin/true"
        inventory.resource_class = "heavy"
        inventory.extra["adapter_spec_sha256"] = "0" * 64
        inventory.extra["source_binding"]["sha256"] = "0" * 64
        adapter = get_adapter(tampered.category)
        primary, plan = engine._rev_adapter_seed_plan(
            tampered,
            adapter,
        )
        self.assertIsNotNone(primary)
        self.assertTrue(
            engine._rev_adapter_seed_plan_needs_sync(
                tampered,
                adapter,
                primary,
                plan,
            )
        )
        update_calls = 0

        def apply_in_memory(identity, mutator, **kwargs):
            nonlocal update_calls
            del kwargs
            self.assertEqual(identity, self.identity)
            update_calls += 1
            mutator(tampered)
            tampered.validate()
            return tampered

        with (
            mock.patch.object(
                engine.store,
                "load",
                return_value=tampered,
            ),
            mock.patch.object(
                engine.store,
                "update",
                side_effect=apply_in_memory,
            ),
        ):
            repaired = engine.refresh_ingest(self.identity)

        expected = next(
            item
            for item in plan
            if item[1] == inventory.id
        )
        repaired_inventory = next(
            item
            for item in repaired.experiments
            if item.id == inventory.id
        )
        self.assertEqual(update_calls, 1)
        self.assertEqual(
            repaired_inventory.command,
            shlex.join(expected[2]),
        )
        self.assertEqual(
            repaired_inventory.resource_class,
            expected[0].resource_class,
        )
        for key, value in expected[3].items():
            self.assertEqual(repaired_inventory.extra[key], value)
        self.assertEqual(
            repaired_inventory.extra["orphan_recovery"],
            "retryable_without_canonical_outcome",
        )
        self.assertEqual(
            repaired_inventory.extra["orphan_recovered_at"],
            "2026-07-30T00:00:00+00:00",
        )

    def test_rev_inventory_oracle_confirms_and_commits_atomically(
        self,
    ) -> None:
        source_bytes = _elf64_image(2) + b"oracle-confirmed"
        payload = _rev_inventory_payload(source_bytes)
        engine = self.engine_with_rev_inventory(payload)
        input_dir = engine.challenge_input(self.identity)
        input_dir.mkdir(parents=True)
        (input_dir / "chall").write_bytes(source_bytes)
        before = engine.add_challenge(
            self.identity,
            prompt="solve",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        inventory = next(
            item
            for item in before.experiments
            if item.extra.get("adapter_spec_template_id")
            == "inventory_observation"
        )
        stdout_copies: list[tuple[str | None, int | None]] = []
        original_copy = challenge_module.copy_bounded_regular

        def observing_copy(*args, **kwargs):
            copied = original_copy(*args, **kwargs)
            destination = Path(args[2])
            if destination.name == "stdout.bin":
                stdout_copies.append(
                    (
                        kwargs.get("expected_sha256"),
                        kwargs.get("expected_size"),
                    )
                )
            return copied

        with (
            mock.patch.object(
                challenge_module,
                "copy_bounded_regular",
                side_effect=observing_copy,
            ),
            mock.patch.object(
                challenge_module,
                "inventory_challenge",
                wraps=challenge_module.inventory_challenge,
            ) as live_inventory,
        ):
            state = engine.execute_registered_experiments(
                self.identity,
                experiment_ids=(inventory.id,),
            )

        completed = next(
            item for item in state.experiments if item.id == inventory.id
        )
        run = next(
            item
            for item in state.runs
            if item.extra.get("experiment_id") == inventory.id
        )
        receipt = next(
            item for item in state.receipts if item.run_id == run.id
        )
        fact = next(
            item
            for item in state.facts
            if item.id == f"F-{run.id}-rev-inventory"
        )
        semantic = completed.result["partial_oracle"]

        self.assertIs(completed.status, ExperimentStatus.COMPLETED)
        self.assertIs(run.status, RunStatus.COMPLETED)
        self.assertEqual(receipt.outcome.value, "succeeded")
        self.assertTrue(semantic["transport_succeeded"])
        self.assertEqual(semantic["evaluation_status"], "evaluated")
        self.assertEqual(semantic["result"]["verdict"], "CONFIRMED")
        binding = semantic["execution_binding"]
        self.assertEqual(binding["argv"], list(inventory.command.split()))
        self.assertEqual(
            binding["configuration_epoch"],
            state.configuration_epoch,
        )
        self.assertEqual(
            binding["experiment"]["adapter_spec_id"],
            inventory.extra["adapter_spec_id"],
        )
        self.assertEqual(
            binding["oracle"],
            inventory.extra["partial_oracle"],
        )
        self.assertEqual(
            binding["source_binding"],
            inventory.extra["source_binding"],
        )
        self.assertEqual(
            binding["source_snapshot"],
            inventory.extra["source_snapshot"],
        )
        self.assertEqual(
            binding["network"],
            {
                "target": None,
                "target_generation": None,
                "target_id": None,
            },
        )
        self.assertEqual(
            binding["image"]["reference"],
            "sha256:" + ("1" * 64),
        )
        self.assertEqual(
            binding["stdout_artifact"],
            {
                "id": receipt.stdout_artifact_id,
                "path": fact.locator,
                "sha256": next(
                    artifact.sha256
                    for artifact in state.artifacts
                    if artifact.id == fact.artifact_id
                ),
                "size": next(
                    artifact.size
                    for artifact in state.artifacts
                    if artifact.id == fact.artifact_id
                ),
            },
        )
        self.assertEqual(
            binding["request"]["sha256"],
            semantic["request_sha256"],
        )
        self.assertEqual(
            completed.evidence_fact_ids,
            [fact.id],
        )
        self.assertEqual(completed.evidence_run_ids, [run.id])
        self.assertEqual(
            completed.evidence_receipt_ids,
            [receipt.id],
        )
        self.assertEqual(fact.source_run_id, run.id)
        self.assertEqual(fact.artifact_id, receipt.stdout_artifact_id)
        self.assertEqual(
            run.extra["partial_oracle_result"],
            semantic,
        )
        self.assertEqual(
            receipt.extra["partial_oracle_result"],
            semantic,
        )
        self.assertEqual(
            fact.extra["partial_oracle_result"],
            semantic,
        )
        root = engine.store.challenge_paths(self.identity).root
        persisted_result = json.loads(
            (root / run.result_path).read_text(encoding="utf-8")
        )
        persisted_validation = json.loads(
            (root / run.validation_path).read_text(encoding="utf-8")
        )
        self.assertEqual(persisted_result["partial_oracle"], semantic)
        self.assertEqual(
            persisted_validation["partial_oracle"],
            semantic,
        )
        self.assertEqual(len(stdout_copies), 2)
        # Public execution refreshes ingest once before the run; the oracle
        # adds exactly one full inventory at commit, not one per phase.
        self.assertEqual(live_inventory.call_count, 2)
        self.assertTrue(
            all(
                sha256 == fact.extra["partial_oracle_result"][
                    "result"
                ]["source_sha256"]
                or sha256
                == next(
                    artifact.sha256
                    for artifact in state.artifacts
                    if artifact.id == fact.artifact_id
                )
                for sha256, _size in stdout_copies
            )
        )
        stdout_artifact = next(
            artifact
            for artifact in state.artifacts
            if artifact.id == fact.artifact_id
        )
        self.assertEqual(
            stdout_copies,
            [
                (stdout_artifact.sha256, stdout_artifact.size),
                (stdout_artifact.sha256, stdout_artifact.size),
            ],
        )
        self.assertEqual(state.candidates, [])
        self.assertEqual(state.submissions, [])
        self.assertEqual(state.status, before.status)

    def test_rev_inventory_oracle_state_rejects_round_trip_tamper(
        self,
    ) -> None:
        source_bytes = _elf64_image(2) + b"oracle-state-tamper"
        engine = self.engine_with_rev_inventory(
            _rev_inventory_payload(source_bytes)
        )
        input_dir = engine.challenge_input(self.identity)
        input_dir.mkdir(parents=True)
        (input_dir / "chall").write_bytes(source_bytes)
        state = engine.add_challenge(
            self.identity,
            prompt="solve",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        inventory = next(
            item
            for item in state.experiments
            if item.extra.get("adapter_spec_template_id")
            == "inventory_observation"
        )
        state = engine.execute_registered_experiments(
            self.identity,
            experiment_ids=(inventory.id,),
        )
        canonical = state.to_dict()
        ChallengeState.from_dict(copy.deepcopy(canonical)).validate()

        for mutation in (
            "unknown-outcome-field",
            "run-copy-diverges",
            "stdout-pin-diverges",
            "image-pin-removed",
            "semantic-source-diverges",
            "verdict-status-diverges",
            "nested-evaluation-status",
            "nested-verdict",
            "nested-snapshot-mode",
            "descriptor-removed",
            "adapter-seed-disabled",
            "run-experiment-id-diverges",
            "resource-all-copies-diverge",
            "semantic-contract-diverges",
            "all-contract-markers-downgraded",
        ):
            with self.subTest(mutation=mutation):
                data = copy.deepcopy(canonical)
                experiment = next(
                    item
                    for item in data["experiments"]
                    if item["id"] == inventory.id
                )
                run_id = experiment["result"]["run_id"]
                run = next(
                    item for item in data["runs"] if item["id"] == run_id
                )
                receipt = next(
                    item
                    for item in data["receipts"]
                    if item["run_id"] == run_id
                )
                fact = next(
                    item
                    for item in data["facts"]
                    if item["id"] == f"F-{run_id}-rev-inventory"
                )
                outcomes = (
                    experiment["result"]["partial_oracle"],
                    run["partial_oracle_result"],
                    receipt["partial_oracle_result"],
                    fact["partial_oracle_result"],
                )

                if mutation == "unknown-outcome-field":
                    outcomes[0]["model_confidence"] = 1
                elif mutation == "run-copy-diverges":
                    outcomes[1]["rejection_code"] = "tampered"
                elif mutation == "stdout-pin-diverges":
                    for outcome in outcomes:
                        outcome["execution_binding"][
                            "stdout_artifact"
                        ]["sha256"] = "0" * 64
                elif mutation == "image-pin-removed":
                    for outcome in outcomes:
                        outcome["image_reference"] = None
                        outcome["execution_binding"]["image"].update(
                            {
                                "digest": None,
                                "reference": "ctf-os:core",
                            }
                        )
                elif mutation == "semantic-source-diverges":
                    for outcome in outcomes:
                        outcome["result"]["source_sha256"] = "0" * 64
                elif mutation == "verdict-status-diverges":
                    experiment["status"] = "failed"
                elif mutation == "nested-evaluation-status":
                    outcomes[0]["evaluation_status"] = []
                elif mutation == "nested-verdict":
                    outcomes[0]["result"]["verdict"] = {}
                elif mutation == "nested-snapshot-mode":
                    outcomes[0]["execution_binding"][
                        "source_snapshot_execution_binding"
                    ]["mode"] = []
                elif mutation == "descriptor-removed":
                    experiment["partial_oracle"] = None
                elif mutation == "adapter-seed-disabled":
                    experiment["adapter_seed"] = False
                elif mutation == "run-experiment-id-diverges":
                    run["experiment_id"] = "E-unrelated"
                elif mutation == "resource-all-copies-diverge":
                    for outcome in outcomes:
                        outcome["execution_binding"]["resource_request"][
                            "cpu"
                        ] = 2
                elif mutation == "semantic-contract-diverges":
                    for outcome in outcomes:
                        outcome["result"]["verdict"] = "NOT_APPLICABLE"
                elif mutation == "all-contract-markers-downgraded":
                    legacy_oracle = {
                        "contract_fingerprint": (
                            REV_INVENTORY_V1_CONTRACT_FINGERPRINT
                        ),
                        "document_transport": (
                            "atomic-work-file-plus-exact-stdout-once-v1"
                        ),
                        "oracle_id": REV_INVENTORY_V1_CONTRACT_ID,
                        "oracle_version": (
                            REV_INVENTORY_V1_CONTRACT_VERSION
                        ),
                    }
                    experiment["partial_oracle"] = copy.deepcopy(
                        legacy_oracle
                    )
                    for outcome in outcomes:
                        outcome["execution_binding"]["oracle"] = (
                            copy.deepcopy(legacy_oracle)
                        )
                        outcome["result"]["contract_fingerprint"] = (
                            REV_INVENTORY_V1_CONTRACT_FINGERPRINT
                        )
                        outcome["result"]["oracle_version"] = (
                            REV_INVENTORY_V1_CONTRACT_VERSION
                        )

                with self.assertRaisesRegex(
                    ModelValidationError,
                    "Rev inventory",
                ):
                    ChallengeState.from_dict(data).validate()

    def test_rev_inventory_oracle_neutral_result_is_inconclusive_fact(
        self,
    ) -> None:
        source_bytes = _elf64_image(2) + b"oracle-neutral"
        engine = self.engine_with_rev_inventory(
            _rev_inventory_payload(source_bytes, arch=None)
        )
        input_dir = engine.challenge_input(self.identity)
        input_dir.mkdir(parents=True)
        (input_dir / "chall").write_bytes(source_bytes)
        state = engine.add_challenge(
            self.identity,
            prompt="solve",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        inventory = next(
            item
            for item in state.experiments
            if item.extra.get("adapter_spec_template_id")
            == "inventory_observation"
        )

        state = engine.execute_registered_experiments(
            self.identity,
            experiment_ids=(inventory.id,),
        )

        evaluated = next(
            item for item in state.experiments if item.id == inventory.id
        )
        self.assertIs(
            evaluated.status,
            ExperimentStatus.INCONCLUSIVE,
        )
        self.assertIn("INCONCLUSIVE", evaluated.evaluation_reason)
        self.assertIsNotNone(evaluated.evaluated_at)
        self.assertEqual(len(evaluated.evidence_fact_ids), 1)
        fact = next(
            item
            for item in state.facts
            if item.id == evaluated.evidence_fact_ids[0]
        )
        self.assertIn("incomplete_binary_profile", fact.statement)
        self.assertEqual(state.candidates, [])
        self.assertEqual(state.submissions, [])

    def test_rev_inventory_oracle_errors_do_not_create_facts(
        self,
    ) -> None:
        source_bytes = _elf64_image(2) + b"oracle-errors"
        valid = _rev_inventory_payload(source_bytes)
        duplicate = valid.replace(
            b'"status":"ok"}',
            b'"status":"ok","status":"ok"}',
        )
        wrong_source = _rev_inventory_payload(
            source_bytes + b"different"
        )
        legacy_document = json.loads(valid)
        legacy_document["contract"] = {
            "fingerprint": REV_INVENTORY_V1_CONTRACT_FINGERPRINT,
            "id": REV_INVENTORY_V1_CONTRACT_ID,
            "version": REV_INVENTORY_V1_CONTRACT_VERSION,
        }
        legacy_document["schema_version"] = (
            REV_INVENTORY_V1_SCHEMA_VERSION
        )
        legacy_payload = (
            json.dumps(
                legacy_document,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
        cases = (
            ("malformed", valid[:-2], "invalid_json"),
            ("duplicate", duplicate, "duplicate_json_key"),
            ("source-mismatch", wrong_source, "source_hash_mismatch"),
            ("legacy-v1-image", legacy_payload, "invalid_schema"),
            (
                "noncanonical",
                json.dumps(
                    json.loads(valid),
                    indent=2,
                ).encode("ascii"),
                "noncanonical_json",
            ),
        )
        for name, payload, reason_code in cases:
            with self.subTest(name=name):
                identity = ChallengeIdentity(
                    "rev oracle errors",
                    "rev",
                    name,
                )
                engine = self.engine_with_rev_inventory(payload)
                input_dir = engine.challenge_input(identity)
                input_dir.mkdir(parents=True)
                (input_dir / "chall").write_bytes(source_bytes)
                state = engine.add_challenge(
                    identity,
                    prompt="solve",
                    state_schema_version=STATE_SCHEMA_VERSION,
                )
                inventory = next(
                    item
                    for item in state.experiments
                    if item.extra.get("adapter_spec_template_id")
                    == "inventory_observation"
                )

                state = engine.execute_registered_experiments(
                    identity,
                    experiment_ids=(inventory.id,),
                )

                failed = next(
                    item
                    for item in state.experiments
                    if item.id == inventory.id
                )
                run = next(
                    item
                    for item in state.runs
                    if item.extra.get("experiment_id") == inventory.id
                )
                receipt = next(
                    item
                    for item in state.receipts
                    if item.run_id == run.id
                )
                semantic = failed.result["partial_oracle"]
                self.assertIs(failed.status, ExperimentStatus.FAILED)
                self.assertIs(run.status, RunStatus.COMPLETED)
                self.assertEqual(receipt.outcome.value, "succeeded")
                self.assertEqual(
                    semantic["evaluation_status"],
                    "evaluated",
                )
                self.assertEqual(
                    semantic["result"]["verdict"],
                    "ERROR",
                )
                self.assertEqual(
                    semantic["result"]["reason_code"],
                    reason_code,
                )
                self.assertEqual(
                    failed.evaluation_reason,
                    f"rev_inventory:evaluated:ERROR/{reason_code}",
                )
                self.assertIsNotNone(failed.evaluated_at)
                self.assertEqual(failed.evidence_fact_ids, [])
                self.assertFalse(
                    any(fact.source_run_id == run.id for fact in state.facts)
                )
                self.assertEqual(state.candidates, [])
                self.assertEqual(state.submissions, [])
                rerun = engine.execute_registered_experiments(
                    identity,
                    experiment_ids=(inventory.id,),
                )
                self.assertEqual(len(rerun.runs), len(state.runs))
                self.assertEqual(len(rerun.receipts), len(state.receipts))

    def test_rev_inventory_oversized_complete_stdout_skips_byte_copy(
        self,
    ) -> None:
        source_bytes = _elf64_image(2) + b"oracle-oversized"
        payload = b"x" * (REV_INVENTORY_V2_MAX_BYTES + 1)
        engine = self.engine_with_rev_inventory(payload)
        input_dir = engine.challenge_input(self.identity)
        input_dir.mkdir(parents=True)
        (input_dir / "chall").write_bytes(source_bytes)
        state = engine.add_challenge(
            self.identity,
            prompt="solve",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        inventory = next(
            item
            for item in state.experiments
            if item.extra.get("adapter_spec_template_id")
            == "inventory_observation"
        )
        stdout_copy_count = 0
        original_copy = challenge_module.copy_bounded_regular

        def observing_copy(*args, **kwargs):
            nonlocal stdout_copy_count
            destination = Path(args[2])
            if destination.name == "stdout.bin":
                stdout_copy_count += 1
            return original_copy(*args, **kwargs)

        with mock.patch.object(
            challenge_module,
            "copy_bounded_regular",
            side_effect=observing_copy,
        ):
            state = engine.execute_registered_experiments(
                self.identity,
                experiment_ids=(inventory.id,),
            )

        failed = next(
            item for item in state.experiments if item.id == inventory.id
        )
        run = next(
            item
            for item in state.runs
            if item.extra.get("experiment_id") == inventory.id
        )
        receipt = next(
            item for item in state.receipts if item.run_id == run.id
        )
        outcome = failed.result["partial_oracle"]
        self.assertEqual(stdout_copy_count, 0)
        self.assertIs(failed.status, ExperimentStatus.FAILED)
        self.assertIs(run.status, RunStatus.COMPLETED)
        self.assertEqual(receipt.outcome.value, "succeeded")
        self.assertEqual(outcome["evaluation_status"], "evaluated")
        self.assertEqual(
            outcome["result"]["reason_code"],
            "artifact_too_large",
        )
        self.assertEqual(failed.evidence_fact_ids, [])
        stdout_artifact = next(
            item
            for item in state.artifacts
            if item.id == receipt.stdout_artifact_id
        )
        self.assertEqual(stdout_artifact.size, len(payload))

    def test_rev_inventory_error_link_validation_scans_collections_once(
        self,
    ) -> None:
        source_bytes = _elf64_image(2) + b"oracle-linear-error"
        malformed = _rev_inventory_payload(source_bytes)[:-2]
        engine = self.engine_with_rev_inventory(malformed)
        input_dir = engine.challenge_input(self.identity)
        input_dir.mkdir(parents=True)
        (input_dir / "chall").write_bytes(source_bytes)
        state = engine.add_challenge(
            self.identity,
            prompt="solve",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        inventory = next(
            item
            for item in state.experiments
            if item.extra.get("adapter_spec_template_id")
            == "inventory_observation"
        )
        state = engine.execute_registered_experiments(
            self.identity,
            experiment_ids=(inventory.id,),
        )
        state.experiments.extend(
            Experiment(
                id=f"E-linear-{index}",
                hypothesis_ids=[],
                command="true",
                expected_observation="bounded output",
                keep_if="output exists",
                drop_if="output is absent",
                timeout_seconds=1,
                kind=ExperimentKind.PROBE,
                status=ExperimentStatus.REGISTERED,
            )
            for index in range(256)
        )

        class CountingList(list):
            def __init__(self, values=()):
                super().__init__(values)
                self.iterations = 0

            def __iter__(self):
                self.iterations += 1
                return super().__iter__()

        raw_runs = list(state.runs)
        raw_receipts = list(state.receipts)
        raw_facts = list(state.facts)
        state.runs = CountingList(raw_runs)
        state.receipts = CountingList(raw_receipts)
        state.facts = CountingList(raw_facts)

        errors = models_module._rev_inventory_state_errors(
            state,
            runs={item.id: item for item in raw_runs},
            receipts={item.id: item for item in raw_receipts},
            artifacts={item.id: item for item in state.artifacts},
            facts={item.id: item for item in raw_facts},
        )

        self.assertEqual(errors, [])
        self.assertEqual(state.runs.iterations, 1)
        self.assertEqual(state.receipts.iterations, 1)
        self.assertEqual(state.facts.iterations, 1)

    def test_rev_inventory_oracle_rejects_unpinned_or_incomplete_run(
        self,
    ) -> None:
        source_bytes = _elf64_image(2) + b"oracle-rejections"
        payload = _rev_inventory_payload(source_bytes)
        cases = (
            ("unpinned-image", None, True, "request_binding_mismatch"),
            (
                "incomplete-stdout",
                "sha256:" + ("2" * 64),
                False,
                "stdout_capture_incomplete",
            ),
        )
        for name, digest, complete_capture, rejection in cases:
            with self.subTest(name=name):
                identity = ChallengeIdentity(
                    "rev oracle rejections",
                    "rev",
                    name,
                )
                engine = self.engine_with_rev_inventory(
                    payload,
                    image_digest=digest,
                    complete_capture=complete_capture,
                )
                input_dir = engine.challenge_input(identity)
                input_dir.mkdir(parents=True)
                (input_dir / "chall").write_bytes(source_bytes)
                state = engine.add_challenge(
                    identity,
                    prompt="solve",
                    state_schema_version=STATE_SCHEMA_VERSION,
                )
                inventory = next(
                    item
                    for item in state.experiments
                    if item.extra.get("adapter_spec_template_id")
                    == "inventory_observation"
                )

                state = engine.execute_registered_experiments(
                    identity,
                    experiment_ids=(inventory.id,),
                )

                failed = next(
                    item
                    for item in state.experiments
                    if item.id == inventory.id
                )
                run = next(
                    item
                    for item in state.runs
                    if item.extra.get("experiment_id") == inventory.id
                )
                receipt = next(
                    item
                    for item in state.receipts
                    if item.run_id == run.id
                )
                semantic = failed.result["partial_oracle"]
                self.assertIs(failed.status, ExperimentStatus.FAILED)
                self.assertIs(run.status, RunStatus.COMPLETED)
                self.assertEqual(receipt.outcome.value, "succeeded")
                self.assertEqual(
                    semantic["evaluation_status"],
                    "rejected",
                )
                self.assertEqual(
                    semantic["rejection_code"],
                    rejection,
                )
                self.assertEqual(
                    failed.evaluation_reason,
                    f"rev_inventory:rejected:{rejection}",
                )
                self.assertIsNotNone(failed.evaluated_at)
                self.assertEqual(failed.evidence_fact_ids, [])
                resume_context = build_context_pack(
                    state,
                    get_adapter(state.category),
                    state_path=(
                        engine.store.challenge_paths(identity).state
                    ),
                )
                self.assertIn(
                    f'"evaluation_reason":"{failed.evaluation_reason}"',
                    resume_context.text,
                )

    def test_rev_inventory_oracle_rejects_request_and_snapshot_tamper(
        self,
    ) -> None:
        source_bytes = _elf64_image(2) + b"oracle-binding-tamper"
        payload = _rev_inventory_payload(source_bytes)
        for mutation, expected_rejection in (
            ("request", "request_binding_mismatch"),
            (
                "snapshot",
                "source_snapshot_reverification_failed",
            ),
        ):
            with self.subTest(mutation=mutation):
                identity = ChallengeIdentity(
                    "rev oracle tamper",
                    "rev",
                    mutation,
                )
                holder: dict[str, object] = {}

                def tamper() -> None:
                    engine = holder["engine"]
                    assert isinstance(engine, ChallengeEngine)
                    paths = engine.store.challenge_paths(identity)
                    if mutation == "request":
                        requests = list(paths.runs.glob("*/request.json"))
                        self.assertEqual(len(requests), 1)
                        request = json.loads(
                            requests[0].read_text(encoding="utf-8")
                        )
                        request["argv"] = ["/bin/false"]
                        requests[0].write_text(
                            json.dumps(
                                request,
                                ensure_ascii=True,
                                separators=(",", ":"),
                                sort_keys=True,
                            )
                            + "\n",
                            encoding="ascii",
                        )
                    else:
                        snapshot_file = holder["snapshot_file"]
                        assert isinstance(snapshot_file, Path)
                        original = snapshot_file.read_bytes()
                        snapshot_file.chmod(0o700)
                        snapshot_file.write_bytes(
                            bytes([original[0] ^ 0xFF]) + original[1:]
                        )
                        snapshot_file.chmod(0o500)

                engine = self.engine_with_rev_inventory(
                    payload,
                    on_run=tamper,
                )
                holder["engine"] = engine
                input_dir = engine.challenge_input(identity)
                input_dir.mkdir(parents=True)
                (input_dir / "chall").write_bytes(source_bytes)
                state = engine.add_challenge(
                    identity,
                    prompt="solve",
                    state_schema_version=STATE_SCHEMA_VERSION,
                )
                inventory = next(
                    item
                    for item in state.experiments
                    if item.extra.get("adapter_spec_template_id")
                    == "inventory_observation"
                )
                holder["snapshot_file"] = (
                    engine.store.challenge_paths(identity).root
                    / inventory.extra["source_snapshot"]["challenge_dir"]
                    / "chall"
                )

                state = engine.execute_registered_experiments(
                    identity,
                    experiment_ids=(inventory.id,),
                )

                failed = next(
                    item
                    for item in state.experiments
                    if item.id == inventory.id
                )
                run = next(
                    item
                    for item in state.runs
                    if item.extra.get("experiment_id") == inventory.id
                )
                receipt = next(
                    item
                    for item in state.receipts
                    if item.run_id == run.id
                )
                semantic = failed.result["partial_oracle"]
                self.assertIs(failed.status, ExperimentStatus.FAILED)
                self.assertIs(run.status, RunStatus.COMPLETED)
                self.assertEqual(receipt.outcome.value, "succeeded")
                self.assertEqual(
                    semantic["rejection_code"],
                    expected_rejection,
                )
                self.assertEqual(
                    failed.evaluation_reason,
                    (
                        "rev_inventory:rejected:"
                        f"{expected_rejection}"
                    ),
                )
                self.assertEqual(failed.evidence_fact_ids, [])
                self.assertFalse(
                    any(fact.source_run_id == run.id for fact in state.facts)
                )

    def test_rev_inventory_oracle_rejects_stdout_evidence_tamper(
        self,
    ) -> None:
        source_bytes = _elf64_image(2) + b"oracle-stdout-tamper"
        engine = self.engine_with_rev_inventory(
            _rev_inventory_payload(source_bytes)
        )
        input_dir = engine.challenge_input(self.identity)
        input_dir.mkdir(parents=True)
        (input_dir / "chall").write_bytes(source_bytes)
        state = engine.add_challenge(
            self.identity,
            prompt="solve",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        inventory = next(
            item
            for item in state.experiments
            if item.extra.get("adapter_spec_template_id")
            == "inventory_observation"
        )
        original_summary = challenge_module.summarize_stream_snapshot

        def tampered_summary(*args, **kwargs):
            evidence = original_summary(*args, **kwargs)
            if kwargs.get("stream") == "stdout":
                evidence["sha256"] = "0" * 64
            return evidence

        with mock.patch.object(
            challenge_module,
            "summarize_stream_snapshot",
            side_effect=tampered_summary,
        ):
            with self.assertRaisesRegex(
                Exception,
                "stdout evidence SHA-256 does not match its artifact",
            ):
                engine.execute_registered_experiments(
                    self.identity,
                    experiment_ids=(inventory.id,),
                )
        state = engine.store.load(self.identity)

        failed = next(
            item for item in state.experiments if item.id == inventory.id
        )
        run = next(
            item
            for item in state.runs
            if item.extra.get("experiment_id") == inventory.id
        )
        receipt = next(
            item for item in state.receipts if item.run_id == run.id
        )
        self.assertIs(failed.status, ExperimentStatus.FAILED)
        self.assertIs(run.status, RunStatus.FAILED)
        self.assertEqual(receipt.outcome.value, "failed")
        self.assertIn("tool result commit failed", failed.result["error"])
        self.assertEqual(failed.evidence_fact_ids, [])
        self.assertFalse(
            any(fact.source_run_id == run.id for fact in state.facts)
        )

    def test_rev_inventory_oracle_rechecks_live_source_before_commit(
        self,
    ) -> None:
        source_bytes = _elf64_image(2) + b"oracle-live-source"
        payload = _rev_inventory_payload(source_bytes)
        engine = self.engine_with_rev_inventory(payload)
        input_dir = engine.challenge_input(self.identity)
        input_dir.mkdir(parents=True)
        source = input_dir / "chall"
        source.write_bytes(source_bytes)
        state = engine.add_challenge(
            self.identity,
            prompt="solve",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        inventory = next(
            item
            for item in state.experiments
            if item.extra.get("adapter_spec_template_id")
            == "inventory_observation"
        )
        original_evaluate = engine._evaluate_rev_inventory_run
        calls = 0

        def mutate_after_first_evaluation(*args, **kwargs):
            nonlocal calls
            outcome = original_evaluate(*args, **kwargs)
            calls += 1
            if calls == 1:
                self.assertIsNotNone(outcome)
                assert outcome is not None
                self.assertEqual(outcome.evaluation_status, "evaluated")
                source.write_bytes(source_bytes + b"changed")
            return outcome

        with mock.patch.object(
            engine,
            "_evaluate_rev_inventory_run",
            side_effect=mutate_after_first_evaluation,
        ):
            state = engine.execute_registered_experiments(
                self.identity,
                experiment_ids=(inventory.id,),
            )

        failed = next(
            item for item in state.experiments if item.id == inventory.id
        )
        run = next(
            item
            for item in state.runs
            if item.extra.get("experiment_id") == inventory.id
        )
        receipt = next(
            item for item in state.receipts if item.run_id == run.id
        )
        semantic = failed.result["partial_oracle"]
        self.assertEqual(calls, 2)
        self.assertIs(failed.status, ExperimentStatus.FAILED)
        self.assertIs(run.status, RunStatus.COMPLETED)
        self.assertEqual(receipt.outcome.value, "succeeded")
        self.assertEqual(
            semantic["rejection_code"],
            "live_source_binding_mismatch",
        )
        self.assertEqual(
            failed.evaluation_reason,
            (
                "rev_inventory:rejected:"
                "live_source_binding_mismatch"
            ),
        )
        self.assertIsNotNone(failed.evaluated_at)
        self.assertEqual(failed.evidence_fact_ids, [])
        self.assertFalse(
            any(fact.source_run_id == run.id for fact in state.facts)
        )
        root = engine.store.challenge_paths(self.identity).root
        persisted_result = json.loads(
            (root / run.result_path).read_text(encoding="utf-8")
        )
        persisted_validation = json.loads(
            (root / run.validation_path).read_text(encoding="utf-8")
        )
        self.assertEqual(persisted_result["partial_oracle"], semantic)
        self.assertEqual(
            persisted_validation["partial_oracle"],
            semantic,
        )

    def test_rev_inventory_oracle_rechecks_full_live_manifest(
        self,
    ) -> None:
        source_bytes = _elf64_image(2) + b"oracle-live-manifest"
        engine = self.engine_with_rev_inventory(
            _rev_inventory_payload(source_bytes)
        )
        input_dir = engine.challenge_input(self.identity)
        input_dir.mkdir(parents=True)
        (input_dir / "chall").write_bytes(source_bytes)
        secondary = input_dir / "notes.txt"
        secondary.write_bytes(b"original secondary bytes")
        state = engine.add_challenge(
            self.identity,
            prompt="solve",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        inventory = next(
            item
            for item in state.experiments
            if item.extra.get("adapter_spec_template_id")
            == "inventory_observation"
        )
        original_evaluate = engine._evaluate_rev_inventory_run
        calls = 0

        def mutate_secondary_after_first(*args, **kwargs):
            nonlocal calls
            outcome = original_evaluate(*args, **kwargs)
            calls += 1
            if calls == 1:
                self.assertIsNotNone(outcome)
                assert outcome is not None
                self.assertEqual(outcome.evaluation_status, "evaluated")
                secondary.write_bytes(b"changed! secondary bytes")
            return outcome

        with mock.patch.object(
            engine,
            "_evaluate_rev_inventory_run",
            side_effect=mutate_secondary_after_first,
        ):
            state = engine.execute_registered_experiments(
                self.identity,
                experiment_ids=(inventory.id,),
            )

        failed = next(
            item for item in state.experiments if item.id == inventory.id
        )
        run = next(
            item
            for item in state.runs
            if item.extra.get("experiment_id") == inventory.id
        )
        receipt = next(
            item for item in state.receipts if item.run_id == run.id
        )
        semantic = failed.result["partial_oracle"]
        self.assertEqual(calls, 2)
        self.assertIs(failed.status, ExperimentStatus.FAILED)
        self.assertIs(run.status, RunStatus.COMPLETED)
        self.assertEqual(receipt.outcome.value, "succeeded")
        self.assertEqual(
            semantic["rejection_code"],
            "live_source_manifest_mismatch",
        )
        self.assertEqual(
            failed.evaluation_reason,
            (
                "rev_inventory:rejected:"
                "live_source_manifest_mismatch"
            ),
        )
        self.assertEqual(failed.evidence_fact_ids, [])
        self.assertFalse(
            any(fact.source_run_id == run.id for fact in state.facts)
        )

    def test_rev_inventory_oracle_transport_matches_run_receipt(
        self,
    ) -> None:
        source_bytes = _elf64_image(2) + b"oracle-transport"
        engine = self.engine_with_rev_inventory(
            _rev_inventory_payload(source_bytes),
            status="failed",
            orchestration_error="synthetic transport failure",
        )
        input_dir = engine.challenge_input(self.identity)
        input_dir.mkdir(parents=True)
        (input_dir / "chall").write_bytes(source_bytes)
        state = engine.add_challenge(
            self.identity,
            prompt="solve",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        inventory = next(
            item
            for item in state.experiments
            if item.extra.get("adapter_spec_template_id")
            == "inventory_observation"
        )

        state = engine.execute_registered_experiments(
            self.identity,
            experiment_ids=(inventory.id,),
        )

        failed = next(
            item for item in state.experiments if item.id == inventory.id
        )
        run = next(
            item
            for item in state.runs
            if item.extra.get("experiment_id") == inventory.id
        )
        receipt = next(
            item for item in state.receipts if item.run_id == run.id
        )
        semantic = failed.result["partial_oracle"]
        self.assertIs(failed.status, ExperimentStatus.FAILED)
        self.assertIs(run.status, RunStatus.FAILED)
        self.assertEqual(receipt.outcome.value, "failed")
        self.assertFalse(semantic["transport_succeeded"])
        self.assertEqual(
            semantic["evaluation_status"],
            "not_evaluated",
        )
        self.assertEqual(
            failed.evaluation_reason,
            "rev_inventory:not_evaluated:transport_failed",
        )
        self.assertIsNotNone(failed.evaluated_at)
        self.assertEqual(failed.evidence_fact_ids, [])

    def test_rev_inventory_oracle_timeout_matches_run_receipt(
        self,
    ) -> None:
        source_bytes = _elf64_image(2) + b"oracle-timeout"
        engine = self.engine_with_rev_inventory(
            _rev_inventory_payload(source_bytes),
            status="timed_out",
            exit_code=124,
            timed_out=True,
        )
        input_dir = engine.challenge_input(self.identity)
        input_dir.mkdir(parents=True)
        (input_dir / "chall").write_bytes(source_bytes)
        state = engine.add_challenge(
            self.identity,
            prompt="solve",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        inventory = next(
            item
            for item in state.experiments
            if item.extra.get("adapter_spec_template_id")
            == "inventory_observation"
        )

        state = engine.execute_registered_experiments(
            self.identity,
            experiment_ids=(inventory.id,),
        )

        failed = next(
            item for item in state.experiments if item.id == inventory.id
        )
        run = next(
            item
            for item in state.runs
            if item.extra.get("experiment_id") == inventory.id
        )
        receipt = next(
            item for item in state.receipts if item.run_id == run.id
        )
        self.assertIs(failed.status, ExperimentStatus.FAILED)
        self.assertIs(run.status, RunStatus.TIMED_OUT)
        self.assertEqual(receipt.outcome.value, "timed_out")
        self.assertEqual(
            failed.evaluation_reason,
            "rev_inventory:not_evaluated:transport_failed",
        )
        self.assertEqual(failed.evidence_fact_ids, [])

    def test_rev_inventory_oracle_deadline_after_commit_revalidation(
        self,
    ) -> None:
        source_bytes = _elf64_image(2) + b"oracle-deadline"
        engine = self.engine_with_rev_inventory(
            _rev_inventory_payload(source_bytes)
        )
        input_dir = engine.challenge_input(self.identity)
        input_dir.mkdir(parents=True)
        (input_dir / "chall").write_bytes(source_bytes)
        state = engine.add_challenge(
            self.identity,
            prompt="solve",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        inventory = next(
            item
            for item in state.experiments
            if item.extra.get("adapter_spec_template_id")
            == "inventory_observation"
        )
        original_gate = engine._require_before_hard_deadline
        observed_operations: list[str] = []

        def expire_after_revalidation(deadline, operation):
            observed_operations.append(operation)
            if operation == (
                "Rev inventory commit revalidation completed"
            ):
                raise challenge_module._HardDeadlineExpired(
                    "synthetic post-revalidation expiry"
                )
            return original_gate(deadline, operation)

        with mock.patch.object(
            engine,
            "_require_before_hard_deadline",
            side_effect=expire_after_revalidation,
        ):
            state = engine.execute_registered_experiments(
                self.identity,
                experiment_ids=(inventory.id,),
            )

        failed = next(
            item for item in state.experiments if item.id == inventory.id
        )
        run = next(
            item
            for item in state.runs
            if item.extra.get("experiment_id") == inventory.id
        )
        self.assertIn(
            "Rev inventory commit revalidation completed",
            observed_operations,
        )
        self.assertIs(failed.status, ExperimentStatus.FAILED)
        self.assertIs(run.status, RunStatus.FAILED)
        self.assertEqual(failed.evidence_fact_ids, [])
        self.assertFalse(
            any(fact.source_run_id == run.id for fact in state.facts)
        )

    def test_rev_inventory_oracle_deadline_guard_runs_after_artifact_validation(
        self,
    ) -> None:
        source_bytes = _elf64_image(2) + b"oracle-store-deadline"
        engine = self.engine_with_rev_inventory(
            _rev_inventory_payload(source_bytes)
        )
        input_dir = engine.challenge_input(self.identity)
        input_dir.mkdir(parents=True)
        (input_dir / "chall").write_bytes(source_bytes)
        state = engine.add_challenge(
            self.identity,
            prompt="solve",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        inventory = next(
            item
            for item in state.experiments
            if item.extra.get("adapter_spec_template_id")
            == "inventory_observation"
        )
        original_gate = engine._require_before_hard_deadline
        real_validate_artifact = store_files.validate_artifact
        operations: list[str] = []

        def observe_validation(*args, **kwargs):
            operations.append("artifact_validation")
            return real_validate_artifact(*args, **kwargs)

        def expire_at_canonical_commit(deadline, operation):
            if operation == "Rev inventory canonical state commit":
                operations.append("commit_guard")
                raise challenge_module._HardDeadlineExpired(
                    "synthetic post-artifact-validation expiry"
                )
            return original_gate(deadline, operation)

        with (
            mock.patch.object(
                store_files,
                "validate_artifact",
                side_effect=observe_validation,
            ),
            mock.patch.object(
                engine,
                "_require_before_hard_deadline",
                side_effect=expire_at_canonical_commit,
            ),
        ):
            state = engine.execute_registered_experiments(
                self.identity,
                experiment_ids=(inventory.id,),
            )

        failed = next(
            item for item in state.experiments if item.id == inventory.id
        )
        run = next(
            item
            for item in state.runs
            if item.extra.get("experiment_id") == inventory.id
        )
        self.assertIn("artifact_validation", operations)
        self.assertEqual(operations[-1], "commit_guard")
        self.assertLess(
            operations.index("artifact_validation"),
            operations.index("commit_guard"),
        )
        self.assertIs(failed.status, ExperimentStatus.FAILED)
        self.assertIs(run.status, RunStatus.FAILED)
        self.assertEqual(failed.evidence_fact_ids, [])
        self.assertFalse(
            any(fact.source_run_id == run.id for fact in state.facts)
        )

    def test_rev_inventory_orphan_without_canonical_outcome_is_retried(
        self,
    ) -> None:
        source_bytes = _elf64_image(2) + b"oracle-orphan-retry"
        engine = self.engine_with_rev_inventory(
            _rev_inventory_payload(source_bytes)
        )
        input_dir = engine.challenge_input(self.identity)
        input_dir.mkdir(parents=True)
        (input_dir / "chall").write_bytes(source_bytes)
        state = engine.add_challenge(
            self.identity,
            prompt="solve",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        inventory = next(
            item
            for item in state.experiments
            if item.extra.get("adapter_spec_template_id")
            == "inventory_observation"
        )

        def simulate_crash_after_reservation(current):
            orphan = next(
                item
                for item in current.experiments
                if item.id == inventory.id
            )
            orphan.status = ExperimentStatus.RUNNING

        crashed = engine.store.update(
            self.identity,
            simulate_crash_after_reservation,
        )
        self.assertEqual(crashed.runs, [])
        self.assertEqual(crashed.receipts, [])

        state = engine.execute_registered_experiments(
            self.identity,
            experiment_ids=(inventory.id,),
        )

        recovered = next(
            item for item in state.experiments if item.id == inventory.id
        )
        self.assertIs(recovered.status, ExperimentStatus.COMPLETED)
        self.assertEqual(
            recovered.extra["orphan_recovery"],
            "retryable_without_canonical_outcome",
        )
        self.assertIn("orphan_recovered_at", recovered.extra)
        self.assertEqual(len(recovered.evidence_run_ids), 1)
        self.assertEqual(len(recovered.evidence_receipt_ids), 1)
        self.assertEqual(len(recovered.evidence_fact_ids), 1)

    def test_successful_tool_deadline_guard_runs_after_artifact_validation(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(
            self.identity,
            prompt="solve",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        _state, experiment_id = engine.register_experiment(
            self.identity,
            command=("/bin/true",),
            expected_observation="exit zero",
            keep_if="zero",
            drop_if="nonzero",
        )
        original_gate = engine._require_before_hard_deadline
        real_validate_artifact = store_files.validate_artifact
        operations: list[str] = []

        def observe_validation(*args, **kwargs):
            operations.append("artifact_validation")
            return real_validate_artifact(*args, **kwargs)

        def expire_at_canonical_commit(deadline, operation):
            if operation == "tool canonical state commit":
                operations.append("commit_guard")
                raise challenge_module._HardDeadlineExpired(
                    "synthetic generic tool commit expiry"
                )
            return original_gate(deadline, operation)

        with (
            mock.patch.object(
                store_files,
                "validate_artifact",
                side_effect=observe_validation,
            ),
            mock.patch.object(
                engine,
                "_require_before_hard_deadline",
                side_effect=expire_at_canonical_commit,
            ),
        ):
            state = engine.execute_registered_experiments(
                self.identity,
                experiment_ids=(experiment_id,),
            )

        failed = next(
            item for item in state.experiments if item.id == experiment_id
        )
        run = next(
            item
            for item in state.runs
            if item.extra.get("experiment_id") == experiment_id
        )
        self.assertIn("artifact_validation", operations)
        self.assertEqual(operations[-1], "commit_guard")
        self.assertIs(failed.status, ExperimentStatus.FAILED)
        self.assertIs(run.status, RunStatus.FAILED)
        self.assertFalse(
            any(fact.source_run_id == run.id for fact in state.facts)
        )

    def test_rev_seed_executes_from_verified_read_only_snapshot(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        input_dir = engine.challenge_input(self.identity)
        nested = input_dir / "nested"
        nested.mkdir(parents=True)
        primary = nested / "chall"
        original_bytes = _elf64_image(2) + b"snapshot-original"
        replacement_bytes = _elf64_image(2) + b"incoming-replaced"
        primary.write_bytes(original_bytes)
        state = engine.add_challenge(
            self.identity,
            prompt="solve",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        inventory = next(
            experiment
            for experiment in state.experiments
            if experiment.extra.get("adapter_spec_template_id")
            == "inventory_observation"
        )
        observed_overrides: list[Path] = []

        class SnapshotReadingSandbox(FakeSandbox):
            def __init__(self, work: Path, challenge_root: Path) -> None:
                super().__init__(work)
                self.challenge_root = challenge_root

            def run(self, spec):
                self_outer.assertEqual(
                    spec.argv[-1],
                    "/challenge/nested/chall",
                )
                self_outer.assertEqual(
                    (self.challenge_root / "nested" / "chall").read_bytes(),
                    original_bytes,
                )
                return super().run(spec)

        self_outer = self

        def sandbox(
            current,
            *,
            workspace_override=None,
            challenge_dir_override=None,
        ):
            del current
            self.assertIsNotNone(challenge_dir_override)
            assert challenge_dir_override is not None
            observed_overrides.append(challenge_dir_override)
            primary.write_bytes(replacement_bytes)
            return SnapshotReadingSandbox(
                Path(workspace_override),
                challenge_dir_override,
            )

        with mock.patch.object(engine, "sandbox", side_effect=sandbox):
            state = engine.execute_registered_experiments(
                self.identity,
                experiment_ids=(inventory.id,),
            )

        self.assertEqual(len(observed_overrides), 1)
        snapshot_root = observed_overrides[0]
        snapshot_file = snapshot_root / "nested" / "chall"
        self.assertEqual(snapshot_file.read_bytes(), original_bytes)
        self.assertEqual(
            stat.S_IMODE(snapshot_file.stat().st_mode),
            0o500,
        )
        self.assertEqual(snapshot_file.stat().st_nlink, 1)
        run = next(
            run
            for run in state.runs
            if run.extra.get("experiment_id") == inventory.id
        )
        expected_snapshot = inventory.extra["source_snapshot"]
        self.assertEqual(
            {
                key: expected_snapshot[key]
                for key in (
                    "tree_contract",
                    "file_mode",
                    "directory_mode",
                    "publish",
                )
            },
            {
                "tree_contract": "exact-single-primary-v2",
                "file_mode": 0o500,
                "directory_mode": 0o500,
                "publish": "staged-atomic-no-repair-v2",
            },
        )
        request_path = (
            engine.store.challenge_paths(self.identity).root
            / run.request_path
        )
        request = json.loads(request_path.read_text(encoding="utf-8"))
        self.assertEqual(request["source_snapshot"], expected_snapshot)
        self.assertEqual(run.extra["source_snapshot"], expected_snapshot)
        self.assertEqual(
            request["source_snapshot_execution_binding"],
            {
                "enforced": False,
                "mode": "trusted_injected_sandbox",
                "scope_fingerprint": "a" * 64,
                "snapshot_id": expected_snapshot["id"],
            },
        )
        self.assertEqual(
            run.extra["source_snapshot_execution_binding"],
            request["source_snapshot_execution_binding"],
        )
        self.assertEqual(
            snapshot_root,
            engine.store.challenge_paths(self.identity).root
            / expected_snapshot["challenge_dir"],
        )

    def test_rev_snapshot_reuse_rejects_non_exact_tree_variants(
        self,
    ) -> None:
        mutations = (
            "extra",
            "symlink",
            "hardlink",
            "partial",
            "tamper",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                identity = ChallengeIdentity(
                    "snapshot topology",
                    "rev",
                    mutation,
                )
                engine = self.engine_with_executor(RoleExecutor())
                input_dir = engine.challenge_input(identity)
                nested = input_dir / "nested"
                nested.mkdir(parents=True)
                source_bytes = _elf64_image(2) + mutation.encode("ascii")
                source = nested / "chall"
                source.write_bytes(source_bytes)
                state = engine.add_challenge(
                    identity,
                    prompt="solve",
                    state_schema_version=STATE_SCHEMA_VERSION,
                )
                inventory = next(
                    experiment
                    for experiment in state.experiments
                    if experiment.extra.get("adapter_spec_template_id")
                    == "inventory_observation"
                )
                snapshot = inventory.extra["source_snapshot"]
                challenge_root = (
                    engine.store.challenge_paths(identity).root
                    / snapshot["challenge_dir"]
                )
                snapshot_root = challenge_root.parent
                leaf = challenge_root / "nested" / "chall"

                if mutation == "partial":
                    (challenge_root / "nested").mkdir(parents=True)
                    for directory in (
                        challenge_root / "nested",
                        challenge_root,
                        snapshot_root,
                    ):
                        directory.chmod(0o500)
                else:
                    engine._prepare_rev_adapter_source_snapshot(
                        state,
                        inventory,
                    )
                    if mutation == "extra":
                        challenge_root.chmod(0o700)
                        extra = challenge_root / "injected.conf"
                        extra.write_text(
                            "behavior-changing-sidecar",
                            encoding="utf-8",
                        )
                        extra.chmod(0o500)
                        challenge_root.chmod(0o500)
                    elif mutation == "symlink":
                        leaf.parent.chmod(0o700)
                        leaf.unlink()
                        leaf.symlink_to(source)
                        leaf.parent.chmod(0o500)
                    elif mutation == "hardlink":
                        leaf.chmod(0o500)
                        os.link(
                            leaf,
                            snapshot_root.parent
                            / f"{snapshot_root.name}.outside-hardlink",
                        )
                    elif mutation == "tamper":
                        leaf.chmod(0o700)
                        leaf.write_bytes(b"X" * len(source_bytes))
                        leaf.chmod(0o500)

                with self.assertRaisesRegex(
                    EngineError,
                    "snapshot failed verification",
                ):
                    engine._prepare_rev_adapter_source_snapshot(
                        state,
                        inventory,
                    )

    def test_rev_snapshot_publish_failure_cleans_only_its_staging_tree(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        input_dir = engine.challenge_input(self.identity)
        input_dir.mkdir(parents=True)
        (input_dir / "chall").write_bytes(_elf64_image(2))
        state = engine.add_challenge(
            self.identity,
            prompt="solve",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        inventory = next(
            experiment
            for experiment in state.experiments
            if experiment.extra.get("adapter_spec_template_id")
            == "inventory_observation"
        )
        snapshot = inventory.extra["source_snapshot"]
        snapshot_parent = (
            engine.store.challenge_paths(self.identity).runtime
            / "source-snapshots"
        )
        snapshot_parent.mkdir(parents=True)
        sentinel = snapshot_parent / "unrelated-staging-sentinel"
        sentinel.mkdir()
        (sentinel / "keep").write_text("keep", encoding="utf-8")

        with (
            mock.patch.object(
                challenge_module.os,
                "rename",
                side_effect=OSError("synthetic publish failure"),
            ),
            self.assertRaisesRegex(
                EngineError,
                "snapshot could not be created",
            ),
        ):
            engine._prepare_rev_adapter_source_snapshot(
                state,
                inventory,
            )

        self.assertEqual(
            (sentinel / "keep").read_text(encoding="utf-8"),
            "keep",
        )
        self.assertFalse(
            (
                snapshot_parent
                / snapshot["id"]
            ).exists()
        )
        self.assertEqual(
            list(
                snapshot_parent.glob(
                    f".{snapshot['id']}.staging-*"
                )
            ),
            [],
        )

    def test_rev_snapshot_failure_terminalizes_before_durable_run(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        input_dir = engine.challenge_input(self.identity)
        input_dir.mkdir(parents=True)
        (input_dir / "chall").write_bytes(_elf64_image(2))
        state = engine.add_challenge(
            self.identity,
            prompt="solve",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        inventory = next(
            experiment
            for experiment in state.experiments
            if experiment.extra.get("adapter_spec_template_id")
            == "inventory_observation"
        )

        with mock.patch.object(
            engine,
            "_prepare_rev_adapter_source_snapshot",
            side_effect=EngineError("snapshot hash mismatch"),
        ):
            state = engine.execute_registered_experiments(
                self.identity,
                experiment_ids=(inventory.id,),
            )

        failed = next(
            experiment
            for experiment in state.experiments
            if experiment.id == inventory.id
        )
        self.assertIs(failed.status, ExperimentStatus.FAILED)
        self.assertFalse(
            any(
                run.extra.get("experiment_id") == inventory.id
                for run in state.runs
            )
        )

    def test_failed_rev_seed_run_preserves_durable_binding_pins(
        self,
    ) -> None:
        engine_holder: dict[str, ChallengeEngine] = {}

        class FailingSeedSandbox(FakeSandbox):
            def run(self, spec):
                del spec
                engine_holder["engine"].store.update(
                    self_outer.identity,
                    lambda current: current.metadata.__setitem__(
                        "synthetic_concurrent_state_bump",
                        True,
                    ),
                )
                raise SandboxError("synthetic sandbox failure")

        self_outer = self
        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                limiter=FifoModelCallLimiter(1),
                limiter_wait_timeout=2,
                max_schema_retries=0,
            ),
            sandbox_factory=(
                lambda state, work, policy: FailingSeedSandbox(work)
            ),
        )
        engine_holder["engine"] = engine
        input_dir = engine.challenge_input(self.identity)
        input_dir.mkdir(parents=True)
        (input_dir / "chall").write_bytes(_elf64_image(2))
        state = engine.add_challenge(
            self.identity,
            prompt="solve",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        inventory = next(
            experiment
            for experiment in state.experiments
            if experiment.extra.get("adapter_spec_template_id")
            == "inventory_observation"
        )

        state = engine.execute_registered_experiments(
            self.identity,
            experiment_ids=(inventory.id,),
        )

        failed = next(
            experiment
            for experiment in state.experiments
            if experiment.id == inventory.id
        )
        self.assertIs(failed.status, ExperimentStatus.FAILED)
        run = next(
            run
            for run in state.runs
            if run.extra.get("experiment_id") == inventory.id
        )
        self.assertIs(run.status, RunStatus.FAILED)
        root = engine.store.challenge_paths(self.identity).root
        request = json.loads(
            (root / run.request_path).read_text(encoding="utf-8")
        )
        result = json.loads(
            (root / run.result_path).read_text(encoding="utf-8")
        )
        validation = json.loads(
            (root / run.validation_path).read_text(encoding="utf-8")
        )
        self.assertEqual(run.base_revision, request["base_revision"])
        self.assertEqual(result["base_revision"], request["base_revision"])
        self.assertEqual(
            validation["base_revision"],
            request["base_revision"],
        )
        self.assertLess(run.base_revision, state.revision)
        for key in (
            "adapter_name",
            "adapter_seed",
            "adapter_seed_contract_version",
            "adapter_seed_order",
            "adapter_spec_id",
            "adapter_spec_sha256",
            "adapter_spec_template_id",
            "partial_oracle",
            "requires_explicit_execution",
            "source_binding",
            "source_snapshot",
        ):
            self.assertEqual(run.extra[key], inventory.extra[key])
        self.assertEqual(
            run.extra["source_snapshot_execution_binding"],
            {
                "enforced": False,
                "mode": "trusted_injected_sandbox",
                "scope_fingerprint": "a" * 64,
                "snapshot_id": inventory.extra["source_snapshot"]["id"],
            },
        )

    def test_adapter_seed_prefers_elf_executable_over_libc_and_archive(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        for category in ("pwn", "rev"):
            with self.subTest(category=category):
                identity = ChallengeIdentity(
                    "selector contest",
                    category,
                    "primary executable",
                )
                input_dir = engine.challenge_input(identity)
                input_dir.mkdir(parents=True)
                (input_dir / "00-bundle.zip").write_bytes(b"PK\x03\x04")
                library = input_dir / "01-libc.so.6"
                library.write_bytes(
                    _elf64_image(3, program_types=(1,))
                )
                library.chmod(0o755)
                challenge = input_dir / "zz-challenge"
                challenge.write_bytes(
                    _elf64_image(3, program_types=(3,))
                )
                # Selection is based on the ELF structure, not an executable
                # mode bit that shared libraries commonly also carry.
                challenge.chmod(0o644)

                state = engine.add_challenge(identity, prompt="solve")

                self.assertEqual(
                    state.metadata["adapter_primary_source"],
                    "zz-challenge",
                )
                seeded = [
                    experiment
                    for experiment in state.experiments
                    if experiment.extra.get("adapter_seed")
                ]
                self.assertTrue(seeded)
                self.assertTrue(
                    all(
                        "/challenge/zz-challenge" in experiment.command
                        for experiment in seeded
                    )
                )

    def test_crypto_adapter_seed_prefers_solver_source_deterministically(
        self,
    ) -> None:
        identity = ChallengeIdentity(
            "selector contest",
            "crypto",
            "primary source",
        )
        engine = self.engine_with_executor(RoleExecutor())
        input_dir = engine.challenge_input(identity)
        input_dir.mkdir(parents=True)
        (input_dir / "00-output.txt").write_text("ciphertext")
        (input_dir / "zz-task.py").write_text("N = 17\n")

        state = engine.add_challenge(identity, prompt="solve")

        self.assertEqual(
            state.metadata["adapter_primary_source"],
            "zz-task.py",
        )
        seeded = [
            experiment
            for experiment in state.experiments
            if experiment.extra.get("adapter_seed")
        ]
        self.assertEqual(len(seeded), 1)
        self.assertIn("/challenge/zz-task.py", seeded[0].command)

    def test_engine_budget_sets_deadline_and_clamps_tool_timeout(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        state = engine.add_challenge(
            self.identity,
            prompt="solve",
            budget_seconds=60,
        )
        self.assertIsNotNone(state.budget.deadline_utc)
        assert state.budget.deadline_utc is not None
        self.assertGreater(deadline_epoch(state.budget.deadline_utc), time.time())

        state, experiment_id = engine.register_experiment(
            self.identity,
            command=("true",),
            expected_observation="exit zero",
            keep_if="explicitly kept",
            drop_if="explicitly dropped",
            timeout_seconds=600,
        )
        experiment = next(
            item
            for item in state.experiments
            if item.id == experiment_id
        )
        self.assertLess(experiment.timeout_seconds, 600)
        old_deadline = state.budget.deadline_utc
        state = engine.reset_budget(self.identity, 120)
        self.assertNotEqual(state.budget.deadline_utc, old_deadline)
        self.assertEqual(state.budget.spent_seconds, 0)

        def expire(current):
            current.budget.deadline_utc = "2000-01-01T00:00:00Z"

        engine.store.update(self.identity, expire)
        with self.assertRaisesRegex(EngineError, "budget is exhausted"):
            engine.run_role(
                self.identity,
                Role.RECON,
                instruction="must not reach the model",
            )

    def test_registered_experiment_timeout_matches_canonical_bound(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(self.identity, prompt="solve")
        arguments = {
            "command": ("true",),
            "expected_observation": "exit zero",
            "keep_if": "the output appears",
            "drop_if": "the output does not appear",
        }
        for timeout in (
            True,
            0,
            -1,
            1.0,
            float("nan"),
            float("inf"),
            float("-inf"),
            "1",
            MAX_EXPERIMENT_TIMEOUT_SECONDS + 1,
            604_801,
        ):
            with (
                self.subTest(invalid_timeout=timeout),
                self.assertRaisesRegex(
                    EngineError,
                    "integer between 1 and",
                ),
            ):
                engine.register_experiment(
                    self.identity,
                    timeout_seconds=timeout,  # type: ignore[arg-type]
                    **arguments,
                )

        for timeout in (1, MAX_EXPERIMENT_TIMEOUT_SECONDS):
            with self.subTest(valid_timeout=timeout):
                state, experiment_id = engine.register_experiment(
                    self.identity,
                    timeout_seconds=timeout,
                    **arguments,
                )
                experiment = next(
                    item
                    for item in state.experiments
                    if item.id == experiment_id
                )
                self.assertEqual(experiment.timeout_seconds, timeout)

    def test_sandbox_deadline_anchors_monotonic_before_budget_clock(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        state = engine.add_challenge(self.identity, prompt="solve")
        samples: list[str] = []

        def monotonic() -> float:
            samples.append("monotonic")
            return 100.0

        def epoch() -> float:
            samples.append("epoch")
            return 1_000.0

        with (
            mock.patch(
                "ctf_os.engine.challenge.time.monotonic",
                side_effect=monotonic,
            ),
            mock.patch(
                "ctf_os.engine.challenge.time.time",
                side_effect=epoch,
            ),
            mock.patch.object(
                ChallengeEngine,
                "_remaining_budget_seconds",
                return_value=2.0,
            ),
        ):
            timeout, deadline = engine._budget_command_limits(
                state,
                30,
            )

        self.assertEqual(samples[:2], ["monotonic", "epoch"])
        self.assertEqual(timeout, 2)
        self.assertEqual(deadline, 102.0)

    def test_pinned_image_is_wired_to_default_sandbox(self) -> None:
        config = load_config(self.root)
        config = replace(
            config,
            runtime=replace(config.runtime, image_digest=IMAGE_DIGEST),
        )
        engine = ChallengeEngine(self.root, config=config)
        state = engine.add_challenge(self.identity, prompt="solve")
        client = engine.sandbox(state)
        self.assertIsInstance(client, LocalChallengeSandboxClient)
        self.assertEqual(client.backend.image, "ctf-os:core")
        self.assertEqual(client.backend.image_digest, IMAGE_DIGEST)
        self.assertEqual(client.backend.image_reference, IMAGE_DIGEST)
        self.assertEqual(
            client.backend.limits.work_tree_max_bytes,
            config.runtime.work_tree_max_bytes,
        )

    def test_live_workspace_is_initialized_before_session_files_are_written(
        self,
    ) -> None:
        events: list[str] = []

        class OrderedSandbox(FakeSandbox):
            def initialize_workspace(
                inner_self,
                *,
                deadline_monotonic_seconds=None,
            ):
                self.assertFalse((inner_self.work / "SESSION.md").exists())
                self.assertFalse((inner_self.work / "AGENTS.md").exists())
                events.append("initialized")
                super().initialize_workspace(
                    deadline_monotonic_seconds=deadline_monotonic_seconds
                )

        holder: dict[str, OrderedSandbox] = {}

        def sandbox_factory(state, work, policy):
            del state, policy
            holder.setdefault("client", OrderedSandbox(work))
            return holder["client"]

        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=sandbox_factory,
        )
        engine.add_challenge(self.identity, prompt="solve")
        prepared = engine.prepare_live_session(self.identity)
        self.assertEqual(events, ["initialized"])
        self.assertIsNotNone(holder["client"].initialization_deadline)
        self.assertGreater(
            holder["client"].initialization_deadline,
            time.monotonic(),
        )
        self.assertTrue(prepared.session_context.is_file())
        self.assertTrue(
            (prepared.working_directory / "AGENTS.md").is_file()
        )

    def test_live_prepare_requires_prompt_before_any_runtime_setup(
        self,
    ) -> None:
        holder: dict[str, FakeSandbox] = {}

        def sandbox_factory(state, work, policy):
            del state, policy
            holder.setdefault("client", FakeSandbox(work))
            return holder["client"]

        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=sandbox_factory,
        )
        state = engine.add_challenge(self.identity, prompt="")
        workspace = (
            engine.store.challenge_paths(state.identity).artifacts
            / "workspace"
        )

        with (
            mock.patch.object(engine.live_builder, "start") as start,
            mock.patch.object(engine.live_builder, "resume") as resume,
            mock.patch(
                "ctf_os.sandbox.daemon.CapabilityAuthority.issue"
            ) as issue,
            self.assertRaisesRegex(
                EngineError,
                "problem-solving prompt is required",
            ),
        ):
            engine.prepare_live_session(self.identity)

        self.assertEqual(holder, {})
        start.assert_not_called()
        resume.assert_not_called()
        issue.assert_not_called()
        self.assertFalse((workspace / "SESSION.md").exists())
        self.assertFalse((workspace / "AGENTS.md").exists())
        self.assertFalse(
            (workspace / ".ctfos-session.json").exists()
        )

    def test_live_workspace_init_rechecks_state_after_resource_wait(
        self,
    ) -> None:
        holder: dict[str, FakeSandbox] = {}
        lease_released = False

        class Lease:
            released = False

            def release(inner_self) -> None:
                nonlocal lease_released
                inner_self.released = True
                lease_released = True

        class PausingBroker:
            def acquire(inner_self, request, *, timeout, owner):
                del inner_self, request, timeout, owner
                engine.pause(self.identity)
                return Lease()

        def sandbox_factory(state, work, policy):
            del state, policy
            holder.setdefault("client", FakeSandbox(work))
            return holder["client"]

        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=sandbox_factory,
        )
        engine.add_challenge(self.identity, prompt="solve")
        engine.lease_broker = PausingBroker()  # type: ignore[assignment]

        with self.assertRaisesRegex(EngineError, "PAUSED"):
            engine.prepare_live_session(self.identity)

        self.assertTrue(lease_released)
        self.assertEqual(holder["client"].initializations, 0)
        self.assertFalse(
            (holder["client"].work / "SESSION.md").exists()
        )

    def test_live_workspace_init_rechecks_state_after_inflight_init(
        self,
    ) -> None:
        engine_holder: dict[str, ChallengeEngine] = {}
        holder: dict[str, FakeSandbox] = {}

        class PausingInitSandbox(FakeSandbox):
            def initialize_workspace(
                inner_self,
                *,
                deadline_monotonic_seconds=None,
            ):
                super().initialize_workspace(
                    deadline_monotonic_seconds=deadline_monotonic_seconds
                )
                engine_holder["engine"].pause(self.identity)

        def sandbox_factory(state, work, policy):
            del state, policy
            holder.setdefault("client", PausingInitSandbox(work))
            return holder["client"]

        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=sandbox_factory,
        )
        engine_holder["engine"] = engine
        engine.add_challenge(self.identity, prompt="solve")

        with self.assertRaisesRegex(EngineError, "PAUSED"):
            engine.prepare_live_session(self.identity)

        client = holder["client"]
        self.assertEqual(client.initializations, 1)
        self.assertIs(
            engine.store.load(self.identity).status,
            ChallengeStatus.PAUSED,
        )
        self.assertFalse((client.work / "SESSION.md").exists())
        self.assertFalse((client.work / "AGENTS.md").exists())
        self.assertFalse(
            (client.work / ".ctfos-session.json").exists()
        )
        self.assertTrue(engine.lease_broker.status().used.is_empty())

    def test_live_builder_state_change_blocks_capability_and_return(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        state = engine.add_challenge(self.identity, prompt="solve")
        delegate = engine.live_builder

        class PausingBuilder:
            def start(inner_self, session):
                del inner_self
                engine.pause(self.identity)
                return delegate.start(session)

            def resume(inner_self, session, thread_id):
                del inner_self
                engine.pause(self.identity)
                return delegate.resume(session, thread_id)

        engine.live_builder = PausingBuilder()  # type: ignore[assignment]
        with (
            mock.patch(
                "ctf_os.sandbox.daemon.CapabilityAuthority.issue"
            ) as issue,
            self.assertRaisesRegex(EngineError, "PAUSED"),
        ):
            engine.prepare_live_session(self.identity)

        paused = engine.store.load(self.identity)
        self.assertIs(paused.status, ChallengeStatus.PAUSED)
        issue.assert_not_called()
        workspace = (
            engine.store.challenge_paths(state.identity).artifacts
            / "workspace"
        )
        # Initialization/session context may be durable, but no runnable
        # PreparedLiveSession or scoped capability leaves this function.
        self.assertTrue((workspace / "SESSION.md").is_file())
        self.assertTrue((workspace / ".ctfos-session.json").is_file())

    def test_live_final_gate_blocks_state_change_during_capability_issue(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(self.identity, prompt="solve")

        def pause_on_issue(*args, **kwargs):
            del args, kwargs
            engine.pause(self.identity)
            return "test-capability-not-exposed"

        with (
            mock.patch(
                "ctf_os.sandbox.daemon.CapabilityAuthority.issue",
                side_effect=pause_on_issue,
            ) as issue,
            self.assertRaisesRegex(EngineError, "PAUSED"),
        ):
            engine.prepare_live_session(self.identity)

        issue.assert_called_once()
        self.assertIs(
            engine.store.load(self.identity).status,
            ChallengeStatus.PAUSED,
        )

    def test_live_prompt_gate_rechecks_state_inside_the_store_mutator(
        self,
    ) -> None:
        executor = RoleExecutor()
        engine = self.engine_with_executor(executor)
        original = engine.add_challenge(
            self.identity,
            prompt="original prompt",
        )
        real_update_prompt = engine.update_prompt
        paused_bytes: list[bytes] = []
        runner_calls = 0

        def pause_then_update(*args, **kwargs):
            engine.pause(self.identity)
            paused_bytes.append(
                engine.store.challenge_paths(self.identity).state.read_bytes()
            )
            return real_update_prompt(*args, **kwargs)

        def runner(*args, **kwargs):
            nonlocal runner_calls
            del args, kwargs
            runner_calls += 1
            raise AssertionError("Live runner must not start after PAUSED")

        with (
            mock.patch.object(
                engine,
                "update_prompt",
                side_effect=pause_then_update,
            ),
            self.assertRaisesRegex(EngineError, "PAUSED"),
        ):
            engine.launch_live(
                self.identity,
                prompt="racing replacement",
                runner=runner,
            )

        paused = engine.store.load(self.identity)
        self.assertIs(paused.status, ChallengeStatus.PAUSED)
        self.assertEqual(paused.prompt, original.prompt)
        self.assertEqual(
            engine.store.challenge_paths(self.identity).state.read_bytes(),
            paused_bytes[0],
        )
        self.assertEqual(runner_calls, 0)
        self.assertEqual(executor.roles, [])

    def test_live_launch_rechecks_state_after_prepared_callback(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(self.identity, prompt="solve")
        state = engine.record_candidate(
            self.identity,
            "KCTF{accepted_before_live_launch}",
            print_immediately=False,
        )
        candidate_id = state.candidates[0].id

        def mark_ready(current: ChallengeState) -> None:
            current.candidates[0].status = (
                CandidateStatus.READY_TO_SUBMIT
            )

        engine.store.update(self.identity, mark_ready)
        runner_calls = 0

        def solve_after_prepared(_prepared) -> None:
            engine.record_manual_submission(
                self.identity,
                candidate_id,
                outcome="accepted",
            )

        def runner(*args, **kwargs):
            nonlocal runner_calls
            del args, kwargs
            runner_calls += 1
            raise AssertionError("Live runner must not start after SOLVED")

        with self.assertRaisesRegex(EngineError, "SOLVED"):
            engine.launch_live(
                self.identity,
                runner=runner,
                on_prepared=solve_after_prepared,
            )

        self.assertEqual(runner_calls, 0)
        self.assertIs(
            engine.store.load(self.identity).status,
            ChallengeStatus.SOLVED,
        )

    def test_batch_model_cannot_mint_trusted_provenance_by_citing_run_id(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        state = engine.add_challenge(self.identity, prompt="solve")
        state.runs.append(
            RunReference(
                id="R-existing",
                base_revision=state.revision,
                status=RunStatus.COMPLETED,
            )
        )

        provenance = engine._provenance(
            Provenance.EXECUTED,
            ("R-existing was already canonical",),
            state,
        )

        self.assertIs(provenance, Provenance.MODEL_CLAIMED)

    def test_wave_integrates_all_roles_and_downgrades_unverified_claims(self) -> None:
        executor = RoleExecutor(flag_role=Role.EXTRACTOR)
        engine = self.engine_with_executor(executor)
        engine.add_challenge(self.identity, prompt="solve")
        terminal = io.StringIO()
        with redirect_stderr(terminal):
            outcome = engine.run_wave(self.identity, "discovery")
        state = engine.store.load(self.identity)
        self.assertCountEqual(
            executor.roles,
            [Role.RECON, Role.SPECIALIST, Role.EXTRACTOR],
        )
        self.assertEqual(executor.max_active, 1)
        self.assertEqual(len(outcome.results), 3)
        self.assertEqual(
            [result.invocation.role for result in outcome.results],
            [Role.RECON, Role.SPECIALIST, Role.EXTRACTOR],
        )
        self.assertEqual(len(state.runs), 3)
        self.assertEqual(len(state.hypotheses), 3)
        self.assertTrue(
            all(fact.provenance is Provenance.MODEL_CLAIMED for fact in state.facts)
        )
        self.assertIn("KCTF{stream_now}", terminal.getvalue())
        self.assertEqual(state.candidates[0].value, "KCTF{stream_now}")
        self.assertEqual(
            state.candidates[0].status,
            CandidateStatus.OBSERVED_CANDIDATE,
        )

    def test_queued_wave_yields_to_a_concurrent_operator_solution(
        self,
    ) -> None:
        class BlockingFirstExecutor:
            def __init__(inner_self) -> None:
                inner_self.lock = threading.Lock()
                inner_self.first_started = threading.Event()
                inner_self.release = threading.Event()
                inner_self.roles: list[Role] = []

            def run(
                inner_self,
                command,
                *,
                cwd,
                timeout,
                on_stdout_line,
            ):
                del cwd, timeout
                role = _role_for(command)
                with inner_self.lock:
                    inner_self.roles.append(role)
                    call_number = len(inner_self.roles)
                if call_number != 1:
                    raise AssertionError(
                        "provider work started after the challenge was solved"
                    )
                on_stdout_line(
                    json.dumps(
                        {
                            "type": "item.completed",
                            "text": (
                                "candidate KCTF{streamed_before_solution}"
                            ),
                        }
                    )
                    + "\n"
                )
                inner_self.first_started.set()
                if not inner_self.release.wait(timeout=2):
                    raise AssertionError(
                        "first provider call was not released"
                    )
                _output_path(command).write_text(
                    json.dumps(_payload(role)),
                    encoding="utf-8",
                )
                return ProcessOutcome(0, "", 0.01)

        executor = BlockingFirstExecutor()
        engine = self.engine_with_executor(executor)
        engine.add_challenge(self.identity, prompt="solve")
        state = engine.record_candidate(
            self.identity,
            "KCTF{operator_accepted}",
            print_immediately=False,
        )
        candidate_id = state.candidates[0].id

        def mark_ready(current: ChallengeState) -> None:
            current.candidates[0].status = (
                CandidateStatus.READY_TO_SUBMIT
            )

        engine.store.update(self.identity, mark_ready)
        outcomes: list[WaveOutcome] = []
        failures: list[BaseException] = []

        def run_wave() -> None:
            try:
                outcomes.append(
                    engine.run_wave(self.identity, "discovery")
                )
            except BaseException as error:
                failures.append(error)

        thread = threading.Thread(target=run_wave)
        thread.start()
        try:
            self.assertTrue(executor.first_started.wait(timeout=1))
            deadline = time.monotonic() + 1
            while (
                engine.batch_runner.limiter.snapshot().waiting < 2
                and time.monotonic() < deadline
            ):
                time.sleep(0.005)
            self.assertEqual(
                engine.batch_runner.limiter.snapshot().waiting,
                2,
            )
            solved = engine.record_manual_submission(
                self.identity,
                candidate_id,
                outcome="accepted",
            )
            self.assertIs(solved.status, ChallengeStatus.SOLVED)
            executor.release.set()
            thread.join(timeout=2)
        finally:
            executor.release.set()
            thread.join(timeout=2)

        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(len(outcomes), 1)
        outcome = outcomes[0]
        self.assertEqual(len(outcome.results), 3)
        self.assertEqual(
            [result.invocation.role for result in outcome.results],
            [Role.RECON, Role.SPECIALIST, Role.EXTRACTOR],
        )
        self.assertEqual(len(executor.roles), 1)
        self.assertEqual(
            sum(
                any(
                    failure.kind == "model_call_cancelled"
                    for failure in result.failures
                )
                for result in outcome.results
            ),
            2,
        )
        final = engine.store.load(self.identity)
        self.assertIs(final.status, ChallengeStatus.SOLVED)
        self.assertEqual(outcome.committed_revision, final.revision)
        self.assertEqual(final.runs, [])
        self.assertEqual(final.facts, [])
        self.assertEqual(final.artifacts, [])
        self.assertEqual(
            {candidate.value for candidate in final.candidates},
            {
                "KCTF{operator_accepted}",
                "KCTF{streamed_before_solution}",
            },
        )
        self.assertEqual(
            engine.store.load_candidate_intents(self.identity),
            (),
        )

    def test_batch_flag_intent_is_durable_before_print_and_cleared_after_commit(
        self,
    ) -> None:
        executor = RoleExecutor(flag_role=Role.EXTRACTOR)
        engine = self.engine_with_executor(executor)
        initial = engine.add_challenge(self.identity, prompt="solve")
        print_observations: list[tuple[int, tuple[str, ...]]] = []

        def observe_print(detected) -> None:
            current = engine.store.load(self.identity)
            intents = engine.store.load_candidate_intents(self.identity)
            self.assertFalse(
                any(
                    candidate.value == detected.value
                    for candidate in current.candidates
                )
            )
            print_observations.append(
                (
                    current.revision,
                    tuple(str(item["value"]) for item in intents),
                )
            )

        with mock.patch(
            "ctf_os.engine.challenge.print_flag_candidate",
            side_effect=observe_print,
        ):
            outcome = engine.run_wave(self.identity, "discovery")

        committed = engine.store.load(self.identity)
        self.assertEqual(
            print_observations,
            [(initial.revision, ("KCTF{stream_now}",))],
        )
        self.assertEqual(outcome.base_revision, initial.revision)
        self.assertEqual(
            outcome.committed_revision,
            outcome.base_revision + 1,
        )
        self.assertEqual(
            [candidate.value for candidate in committed.candidates],
            ["KCTF{stream_now}"],
        )
        self.assertEqual(
            engine.store.load_candidate_intents(self.identity),
            (),
        )

    def test_filtered_raw_brace_marker_does_not_abort_batch_commit(
        self,
    ) -> None:
        class NonFlagBraceExecutor:
            def run(
                inner_self,
                command,
                *,
                cwd,
                timeout,
                on_stdout_line,
            ):
                del inner_self, cwd, timeout
                role = _role_for(command)
                on_stdout_line(
                    json.dumps(
                        {
                            "type": "item.completed",
                            "text": (
                                "generated code contains "
                                "LIVE_T{trial} and FREED_T{trial}"
                            ),
                        }
                    )
                    + "\n"
                )
                _output_path(command).write_text(
                    json.dumps(_payload(role)),
                    encoding="utf-8",
                )
                return ProcessOutcome(0, "", 0.0)

        engine = self.engine_with_executor(NonFlagBraceExecutor())
        engine.add_challenge(
            self.identity,
            prompt="solve",
            challenge_flag_format={
                "alphabet": "printable",
                "kind": "prefix_brace",
                "max_inner": 512,
                "min_inner": 1,
                "prefix": "flag",
            },
        )

        with mock.patch(
            "ctf_os.engine.challenge.print_flag_candidate"
        ) as printed:
            outcome = engine.run_wave(self.identity, "discovery")

        committed = engine.store.load(self.identity)
        self.assertEqual(outcome.candidate_values, ())
        self.assertEqual(committed.candidates, [])
        self.assertEqual(
            engine.store.load_candidate_intents(self.identity),
            (),
        )
        printed.assert_not_called()

    def test_batch_intent_failure_aborts_wave_instead_of_losing_flag(
        self,
    ) -> None:
        engine = self.engine_with_executor(
            RoleExecutor(flag_role=Role.EXTRACTOR)
        )
        initial = engine.add_challenge(self.identity, prompt="solve")

        with (
            mock.patch.object(
                engine.store,
                "record_candidate_intent",
                side_effect=OSError("candidate intent unavailable"),
            ),
            self.assertRaisesRegex(
                FlagNotificationError,
                "candidate intent unavailable",
            ),
        ):
            engine.run_wave(self.identity, "discovery")

        unchanged = engine.store.load(self.identity)
        self.assertEqual(unchanged.revision, initial.revision)
        self.assertEqual(unchanged.candidates, [])
        self.assertEqual(
            engine.store.load_candidate_intents(self.identity),
            (),
        )

    def test_structured_only_batch_candidate_is_printed_and_committed(
        self,
    ) -> None:
        candidate = "KCTF{" + "z" * 513 + "}"

        class StructuredOnlyExecutor:
            def run(
                inner_self,
                command,
                *,
                cwd,
                timeout,
                on_stdout_line,
            ):
                del inner_self, cwd, timeout, on_stdout_line
                role = _role_for(command)
                _output_path(command).write_text(
                    json.dumps(
                        _payload(
                            role,
                            flag=(
                                candidate
                                if role is Role.RECON
                                else None
                            ),
                        )
                    ),
                    encoding="utf-8",
                )
                return ProcessOutcome(0, "", 0.0)

        engine = self.engine_with_executor(StructuredOnlyExecutor())
        engine.add_challenge(self.identity, prompt="solve")

        with mock.patch(
            "ctf_os.engine.challenge.print_flag_candidate"
        ) as printed:
            outcome = engine.run_wave(self.identity, "discovery")

        committed = engine.store.load(self.identity)
        self.assertEqual(outcome.candidate_values, (candidate,))
        self.assertEqual(printed.call_count, 1)
        self.assertEqual(
            [item.value for item in committed.candidates],
            [candidate],
        )
        self.assertEqual(
            engine.store.load_candidate_intents(self.identity),
            (),
        )

    def test_batch_commit_failure_leaves_intent_for_next_session_recovery(
        self,
    ) -> None:
        engine = self.engine_with_executor(
            RoleExecutor(flag_role=Role.EXTRACTOR)
        )
        initial = engine.add_challenge(self.identity, prompt="solve")

        with mock.patch.object(
            engine,
            "_commit_batch_results",
            side_effect=RuntimeError("simulated crash before wave commit"),
        ), self.assertRaisesRegex(RuntimeError, "before wave commit"):
            engine.run_wave(self.identity, "discovery")

        crashed = engine.store.load(self.identity)
        self.assertEqual(crashed.revision, initial.revision)
        self.assertEqual(crashed.candidates, [])
        self.assertEqual(
            [
                item["value"]
                for item in engine.store.load_candidate_intents(self.identity)
            ],
            ["KCTF{stream_now}"],
        )

        restarted = self.engine_with_executor(RoleExecutor())
        with mock.patch(
            "ctf_os.engine.challenge.print_flag_candidate"
        ) as printed:
            restarted.run_role(
                self.identity,
                Role.RECON,
                instruction="continue after crash",
            )
        recovered = restarted.store.load(self.identity)
        self.assertEqual(printed.call_count, 1)
        self.assertEqual(
            [candidate.value for candidate in recovered.candidates],
            ["KCTF{stream_now}"],
        )
        self.assertEqual(
            restarted.store.load_candidate_intents(self.identity),
            (),
        )

    def test_crash_left_candidate_intent_is_printed_before_reconcile(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(self.identity, prompt="solve")
        engine.store.record_candidate_intent(
            self.identity,
            value="KCTF{intent_before_print_crash}",
            source="crash-window",
        )

        restarted = self.engine_with_executor(RoleExecutor())
        with mock.patch(
            "ctf_os.engine.challenge.print_flag_candidate"
        ) as printed:
            restarted.run_role(
                self.identity,
                Role.RECON,
                instruction="recover the durable intent",
            )

        self.assertEqual(printed.call_count, 1)
        printed_candidate = printed.call_args.args[0]
        self.assertEqual(
            printed_candidate.value,
            "KCTF{intent_before_print_crash}",
        )
        self.assertEqual(
            [item.value for item in restarted.store.load(self.identity).candidates],
            ["KCTF{intent_before_print_crash}"],
        )
        self.assertEqual(
            restarted.store.load_candidate_intents(self.identity),
            (),
        )

    def test_batch_flag_dedupe_is_scoped_before_crash_recovery(
        self,
    ) -> None:
        engine = self.engine_with_executor(
            RoleExecutor(flag_role=Role.EXTRACTOR)
        )
        second_identity = ChallengeIdentity(
            self.identity.contest_id,
            self.identity.category,
            "문제 2",
        )
        engine.add_challenge(self.identity, prompt="solve first")
        second_initial = engine.add_challenge(
            second_identity,
            prompt="solve second",
        )

        with mock.patch(
            "ctf_os.engine.challenge.print_flag_candidate"
        ):
            engine.run_wave(self.identity, "discovery")
            with (
                mock.patch.object(
                    engine,
                    "_commit_batch_results",
                    side_effect=RuntimeError(
                        "simulated second challenge commit crash"
                    ),
                ),
                self.assertRaisesRegex(
                    RuntimeError,
                    "second challenge commit crash",
                ),
            ):
                engine.run_wave(second_identity, "discovery")

        crashed = engine.store.load(second_identity)
        self.assertEqual(crashed.revision, second_initial.revision)
        self.assertEqual(crashed.candidates, [])
        self.assertEqual(
            [
                item["value"]
                for item in engine.store.load_candidate_intents(
                    second_identity
                )
            ],
            ["KCTF{stream_now}"],
        )
        engine.store.reconcile_candidate_intents(second_identity)
        self.assertEqual(
            [
                candidate.value
                for candidate in engine.store.load(
                    second_identity
                ).candidates
            ],
            ["KCTF{stream_now}"],
        )

    def test_wave_without_new_evidence_stalls_without_starting_recovery(
        self,
    ) -> None:
        class NoProgressExecutor(RoleExecutor):
            def run(
                inner_self,
                command,
                *,
                cwd,
                timeout,
                on_stdout_line,
            ):
                del cwd, timeout, on_stdout_line
                role = _role_for(command)
                inner_self.roles.append(role)
                payload = _payload(role)
                payload.update(
                    {
                        "observations": [],
                        "hypotheses": [],
                        "actions": [],
                        "artifacts": [],
                        "progress_markers": [],
                        "flag_candidates": [],
                        "decision": None,
                    }
                )
                _output_path(command).write_text(
                    json.dumps(payload),
                    encoding="utf-8",
                )
                return ProcessOutcome(0, "", 0.01)

        executor = NoProgressExecutor()
        engine = self.engine_with_executor(executor)
        engine.add_challenge(self.identity, prompt="solve")
        engine.transition(self.identity, ChallengeStatus.TRIAGING)
        engine.transition(self.identity, ChallengeStatus.ACTIVE)

        outcome = engine.run_wave(self.identity, "discovery")
        state = engine.store.load(self.identity)

        self.assertEqual(len(outcome.results), 3)
        self.assertEqual(len(executor.roles), 3)
        self.assertEqual(state.status, ChallengeStatus.STALLED)
        self.assertEqual(
            state.metadata[GOVERNOR_METADATA_KEY]["signals"],
            [StallSignal.NO_NEW_EVIDENCE.value],
        )
        self.assertEqual(
            state.metadata[GOVERNOR_METADATA_KEY]["recovery_action"],
            RecoveryAction.CHANGE_OBSERVATION_LAYER.value,
        )

    def test_batch_entrypoints_require_an_operator_solving_prompt(self) -> None:
        executor = RoleExecutor()
        engine = self.engine_with_executor(executor)
        engine.add_challenge(self.identity)

        with self.assertRaisesRegex(EngineError, "problem-solving prompt"):
            engine.run_role(
                self.identity,
                Role.RECON,
                instruction="must not reach the model",
            )
        with self.assertRaisesRegex(EngineError, "problem-solving prompt"):
            engine.run_wave(self.identity, "discovery")
        with self.assertRaisesRegex(EngineError, "problem-solving prompt"):
            engine.run_challenge(self.identity, max_cycles=1)
        self.assertEqual(executor.roles, [])

    def test_model_decisions_preserve_trusted_states_and_use_transitions(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        base = engine.add_challenge(self.identity, prompt="solve")
        base = engine.record_candidate(
            self.identity,
            "KCTF{decision_guard}",
            print_immediately=False,
        )

        for status in (
            ChallengeStatus.READY_TO_SUBMIT,
            ChallengeStatus.SOLVED,
            ChallengeStatus.ABANDONED,
        ):
            for next_stage in (
                "pause",
                "needs_human",
                "complete",
                "discover",
            ):
                with self.subTest(
                    status=status.value,
                    next_stage=next_stage,
                ):
                    state = ChallengeState.from_dict(base.to_dict())
                    state.status = status
                    state.resume_status = None
                    engine._apply_decision(
                        state,
                        {"next_stage": next_stage},
                    )
                    self.assertIs(state.status, status)
                    self.assertIsNone(state.resume_status)

        paused = ChallengeState.from_dict(base.to_dict())
        paused.status = ChallengeStatus.PAUSED
        paused.resume_status = ChallengeStatus.READY_TO_SUBMIT
        engine._apply_decision(paused, {"next_stage": "needs_human"})
        self.assertIs(paused.status, ChallengeStatus.PAUSED)
        self.assertIs(
            paused.resume_status,
            ChallengeStatus.READY_TO_SUBMIT,
        )

        triaging = ChallengeState.from_dict(base.to_dict())
        engine._apply_decision(triaging, {"next_stage": "complete"})
        self.assertIs(triaging.status, ChallengeStatus.TRIAGING)

        active = ChallengeState.from_dict(base.to_dict())
        active.status = ChallengeStatus.ACTIVE
        engine._apply_decision(active, {"next_stage": "complete"})
        self.assertIs(active.status, ChallengeStatus.PROVING)

        pausable = ChallengeState.from_dict(base.to_dict())
        pausable.status = ChallengeStatus.ACTIVE
        engine._apply_decision(pausable, {"next_stage": "pause"})
        self.assertIs(pausable.status, ChallengeStatus.PAUSED)
        self.assertIs(pausable.resume_status, ChallengeStatus.ACTIVE)

    def test_automated_and_direct_model_work_respects_waiting_and_terminal_states(
        self,
    ) -> None:
        executor = RoleExecutor()
        engine = self.engine_with_executor(executor)
        initial = engine.add_challenge(self.identity, prompt="solve")
        waiting = engine.transition(
            self.identity,
            ChallengeStatus.NEEDS_HUMAN,
        )
        unchanged_waiting = engine.run_challenge(
            self.identity,
            prompt="must not silently resume",
            max_cycles=1,
        )
        self.assertEqual(unchanged_waiting.revision, waiting.revision)
        self.assertEqual(unchanged_waiting.prompt, initial.prompt)
        self.assertEqual(executor.roles, [])

        paused = engine.pause(self.identity)
        unchanged_paused = engine.run_challenge(
            self.identity,
            max_cycles=1,
        )
        self.assertEqual(unchanged_paused.revision, paused.revision)
        self.assertEqual(executor.roles, [])
        engine.resume(self.identity)

        candidate_state = engine.record_candidate(
            self.identity,
            "KCTF{abandoned_terminal}",
            print_immediately=False,
        )
        candidate_id = candidate_state.candidates[-1].id
        abandoned = engine.transition(
            self.identity,
            ChallengeStatus.ABANDONED,
        )
        state_path = engine.store.challenge_paths(self.identity).state
        canonical_before = state_path.read_bytes()
        unchanged_terminal = engine.run_challenge(
            self.identity,
            prompt="must not rewrite a terminal challenge",
            max_cycles=1,
        )
        self.assertEqual(unchanged_terminal.revision, abandoned.revision)
        with self.assertRaisesRegex(
            EngineError,
            "cannot be reopened",
        ):
            engine.record_manual_submission(
                self.identity,
                candidate_id,
                outcome="accepted",
                allow_unproved=True,
            )
        self.assertEqual(
            engine.store.load_contest_submissions(
                self.identity.contest_id
            ),
            [],
        )
        with self.assertRaisesRegex(EngineError, "ABANDONED"):
            engine.run_role(
                self.identity,
                Role.RECON,
                instruction="must not reach the model",
            )
        with self.assertRaisesRegex(EngineError, "ABANDONED"):
            engine.run_wave(self.identity, "discovery")
        with self.assertRaisesRegex(EngineError, "ABANDONED"):
            engine.prepare_live_session(self.identity)
        self.assertEqual(executor.roles, [])
        self.assertEqual(state_path.read_bytes(), canonical_before)

    def test_automated_prompt_gate_rechecks_state_inside_the_store_mutator(
        self,
    ) -> None:
        executor = RoleExecutor()
        engine = self.engine_with_executor(executor)
        original = engine.add_challenge(
            self.identity,
            prompt="original prompt",
        )
        real_update_prompt = engine.update_prompt
        paused_bytes: list[bytes] = []

        def pause_then_update(*args, **kwargs):
            engine.pause(self.identity)
            paused_bytes.append(
                engine.store.challenge_paths(self.identity).state.read_bytes()
            )
            return real_update_prompt(*args, **kwargs)

        with mock.patch.object(
            engine,
            "update_prompt",
            side_effect=pause_then_update,
        ):
            paused = engine.run_challenge(
                self.identity,
                prompt="racing replacement",
                max_cycles=1,
            )

        self.assertIs(paused.status, ChallengeStatus.PAUSED)
        self.assertEqual(paused.prompt, original.prompt)
        self.assertEqual(
            engine.store.challenge_paths(self.identity).state.read_bytes(),
            paused_bytes[0],
        )
        self.assertEqual(executor.roles, [])

    def test_operator_prompt_update_remains_ungated_while_paused(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(self.identity, prompt="original prompt")
        paused = engine.pause(self.identity)

        updated = engine.update_prompt(
            self.identity,
            "operator-authored paused prompt",
        )

        self.assertIs(updated.status, ChallengeStatus.PAUSED)
        self.assertEqual(
            updated.prompt,
            "operator-authored paused prompt",
        )
        self.assertEqual(updated.revision, paused.revision + 1)

    def test_automated_loop_stops_after_an_inflight_tool_needs_human(
        self,
    ) -> None:
        class BlockingToolSandbox(FakeSandbox):
            def __init__(inner_self, work: Path) -> None:
                super().__init__(work)
                inner_self.started = threading.Event()
                inner_self.release = threading.Event()

            def run(inner_self, spec):
                inner_self.started.set()
                if not inner_self.release.wait(timeout=2):
                    raise AssertionError("tool was not released")
                return super().run(spec)

        executor = RoleExecutor()
        holder: dict[str, BlockingToolSandbox] = {}

        def sandbox_factory(state, work, policy):
            del state, policy
            holder.setdefault("client", BlockingToolSandbox(work))
            return holder["client"]

        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=executor,
                limiter=FifoModelCallLimiter(1),
                limiter_wait_timeout=2,
                max_schema_retries=0,
            ),
            sandbox_factory=sandbox_factory,
        )
        engine.add_challenge(self.identity, prompt="solve")
        results: list[ChallengeState] = []
        failures: list[BaseException] = []

        def automate() -> None:
            try:
                results.append(
                    engine.run_challenge(
                        self.identity,
                        max_cycles=1,
                    )
                )
            except BaseException as error:
                failures.append(error)

        thread = threading.Thread(target=automate)
        thread.start()
        client: BlockingToolSandbox | None = None
        try:
            deadline = time.monotonic() + 1
            while (
                "client" not in holder
                and time.monotonic() < deadline
            ):
                time.sleep(0.005)
            client = holder.get("client")
            self.assertIsNotNone(client)
            assert client is not None
            self.assertTrue(client.started.wait(timeout=1))
            engine.transition(
                self.identity,
                ChallengeStatus.NEEDS_HUMAN,
            )
            client.release.set()
            thread.join(timeout=2)
        finally:
            if client is not None:
                client.release.set()
            thread.join(timeout=2)

        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(len(results), 1)
        self.assertIs(
            results[0].status,
            ChallengeStatus.NEEDS_HUMAN,
        )
        self.assertEqual(executor.roles, [Role.CAPTAIN])
        self.assertEqual(len(holder["client"].specs), 1)

    def test_direct_wave_is_still_allowed_from_needs_human(
        self,
    ) -> None:
        executor = RoleExecutor()
        engine = self.engine_with_executor(executor)
        engine.add_challenge(self.identity, prompt="solve")
        engine.transition(
            self.identity,
            ChallengeStatus.NEEDS_HUMAN,
        )

        outcome = engine.run_wave(self.identity, "discovery")

        self.assertEqual(len(outcome.results), 3)
        self.assertCountEqual(
            executor.roles,
            [Role.RECON, Role.SPECIALIST, Role.EXTRACTOR],
        )

    def test_automated_provider_queue_stops_when_human_help_is_requested(
        self,
    ) -> None:
        class BlockingAutomatedWaveExecutor:
            def __init__(inner_self) -> None:
                inner_self.lock = threading.Lock()
                inner_self.roles: list[Role] = []
                inner_self.wave_started = threading.Event()
                inner_self.release = threading.Event()

            def run(
                inner_self,
                command,
                *,
                cwd,
                timeout,
                on_stdout_line,
            ):
                del cwd, timeout, on_stdout_line
                role = _role_for(command)
                with inner_self.lock:
                    inner_self.roles.append(role)
                    wave_calls = sum(
                        item is not Role.CAPTAIN
                        for item in inner_self.roles
                    )
                if role is not Role.CAPTAIN:
                    if wave_calls != 1:
                        raise AssertionError(
                            "queued automated provider work started after "
                            "NEEDS_HUMAN"
                        )
                    inner_self.wave_started.set()
                    if not inner_self.release.wait(timeout=2):
                        raise AssertionError(
                            "automated wave call was not released"
                        )
                _output_path(command).write_text(
                    json.dumps(_payload(role)),
                    encoding="utf-8",
                )
                return ProcessOutcome(0, "", 0.01)

        executor = BlockingAutomatedWaveExecutor()
        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=executor,
                limiter=FifoModelCallLimiter(1),
                limiter_wait_timeout=2,
                max_schema_retries=0,
            ),
            sandbox_factory=lambda state, work, policy: FakeSandbox(
                work
            ),
        )
        engine.add_challenge(self.identity, prompt="solve")
        results: list[ChallengeState] = []
        failures: list[BaseException] = []

        def automate() -> None:
            try:
                results.append(
                    engine.run_challenge(
                        self.identity,
                        max_cycles=1,
                        execute_registered_tools=False,
                    )
                )
            except BaseException as error:
                failures.append(error)

        thread = threading.Thread(target=automate)
        thread.start()
        try:
            self.assertTrue(executor.wave_started.wait(timeout=1))
            deadline = time.monotonic() + 1
            while (
                engine.batch_runner.limiter.snapshot().waiting < 2
                and time.monotonic() < deadline
            ):
                time.sleep(0.005)
            self.assertEqual(
                engine.batch_runner.limiter.snapshot().waiting,
                2,
            )
            engine.transition(
                self.identity,
                ChallengeStatus.NEEDS_HUMAN,
            )
            executor.release.set()
            thread.join(timeout=2)
        finally:
            executor.release.set()
            thread.join(timeout=2)

        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(len(results), 1)
        self.assertIs(
            results[0].status,
            ChallengeStatus.NEEDS_HUMAN,
        )
        self.assertEqual(len(executor.roles), 2)
        self.assertIs(executor.roles[0], Role.CAPTAIN)
        state = engine.store.load(self.identity)
        self.assertEqual(
            [run.role for run in state.runs],
            [Role.CAPTAIN.value],
        )

    def test_resume_refreshes_and_invalidates_a_latent_ready_proof(
        self,
    ) -> None:
        input_dir = (
            self.root
            / "incoming"
            / self.identity.contest_id
            / self.identity.category
            / self.identity.challenge_id
        )
        input_dir.mkdir(parents=True)
        (input_dir / "challenge.txt").write_text(
            "version one",
            encoding="utf-8",
        )
        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(self.identity, prompt="solve")
        engine.record_candidate(
            self.identity,
            "KCTF{latent_ready}",
            print_immediately=False,
        )

        def mark_paused_ready(state: ChallengeState) -> None:
            state.status = ChallengeStatus.PAUSED
            state.resume_status = ChallengeStatus.READY_TO_SUBMIT
            state.candidates[0].status = CandidateStatus.READY_TO_SUBMIT

        paused = engine.store.update(self.identity, mark_paused_ready)
        old_manifest = paused.metadata["source_manifest_sha256"]
        (input_dir / "challenge.txt").write_text(
            "version two",
            encoding="utf-8",
        )

        resumed = engine.resume(self.identity)
        self.assertIs(resumed.status, ChallengeStatus.ACTIVE)
        self.assertIsNone(resumed.resume_status)
        self.assertIs(
            resumed.candidates[0].status,
            CandidateStatus.OBSERVED_CANDIDATE,
        )
        self.assertNotEqual(
            resumed.metadata["source_manifest_sha256"],
            old_manifest,
        )

    def test_refresh_ingest_invalidates_a_direct_proving_state(
        self,
    ) -> None:
        input_dir = (
            self.root
            / "incoming"
            / self.identity.contest_id
            / self.identity.category
            / self.identity.challenge_id
        )
        input_dir.mkdir(parents=True)
        source = input_dir / "challenge.bin"
        source.write_bytes(b"version-one")
        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(self.identity, prompt="solve")
        engine.transition(self.identity, ChallengeStatus.ACTIVE)
        engine.transition(self.identity, ChallengeStatus.PROVING)
        state = engine.record_candidate(
            self.identity,
            "KCTF{stale_direct_proof}",
            print_immediately=False,
        )

        def attach_old_proof(current: ChallengeState) -> None:
            current.runs.append(
                RunReference(
                    id="R-old-proof",
                    base_revision=current.revision,
                    status=RunStatus.COMPLETED,
                    role="proof",
                )
            )
            current.candidates[0].status = (
                CandidateStatus.READY_TO_SUBMIT
            )
            current.candidates[0].proof_run_ids.append("R-old-proof")

        proving = engine.store.update(
            self.identity,
            attach_old_proof,
            expected_revision=state.revision,
        )
        old_manifest = proving.metadata["source_manifest_sha256"]
        source.write_bytes(b"version-two")

        refreshed = engine.refresh_ingest(self.identity)

        self.assertIs(refreshed.status, ChallengeStatus.ACTIVE)
        self.assertIs(
            refreshed.candidates[0].status,
            CandidateStatus.OBSERVED_CANDIDATE,
        )
        self.assertEqual(refreshed.candidates[0].proof_run_ids, [])
        self.assertNotEqual(
            refreshed.metadata["source_manifest_sha256"],
            old_manifest,
        )

    def test_wave_preserves_success_timeout_and_invalid_worker_independently(self) -> None:
        engine = self.engine_with_executor(MixedOutcomeExecutor())
        engine.add_challenge(self.identity, prompt="solve")
        terminal = io.StringIO()
        with redirect_stderr(terminal):
            outcome = engine.run_wave(self.identity, "discovery")
        state = engine.store.load(self.identity)
        self.assertEqual(len(outcome.results), 3)
        self.assertEqual(
            [run.status for run in state.runs],
            [RunStatus.COMPLETED, RunStatus.TIMED_OUT, RunStatus.INVALID],
        )
        self.assertTrue(
            all(run.base_revision == outcome.base_revision for run in state.runs)
        )
        self.assertEqual(outcome.committed_revision, outcome.base_revision + 1)
        self.assertEqual(len(state.facts), 1)
        self.assertEqual(len(state.hypotheses), 1)
        self.assertIn("KCTF{partial_timeout}", terminal.getvalue())
        self.assertEqual(state.candidates[0].value, "KCTF{partial_timeout}")
        for run in state.runs[1:]:
            validation = json.loads(
                engine.store.run_paths(
                    self.identity, run_id=run.id
                ).validation.read_text(encoding="utf-8")
            )
            self.assertFalse(validation["ok"])

    def test_existing_base_fact_reference_survives_wave_merge(self) -> None:
        executor = RoleExecutor(observation_ref="F-existing")
        engine = self.engine_with_executor(executor)
        state = engine.add_challenge(self.identity, prompt="solve")

        def add_fact(current):
            current.facts.append(
                Fact(
                    "F-existing",
                    "operator-verified base fact",
                    Provenance.OPERATOR,
                    challenge_id=current.challenge_id,
                )
            )

        engine.store.update(state.identity, add_fact)
        engine.run_wave(self.identity, "discovery")
        merged = engine.store.load(self.identity)
        self.assertTrue(
            all(
                "F-existing" in hypothesis.evidence_fact_ids
                for hypothesis in merged.hypotheses
            )
        )

    def test_reproducer_uses_proof_workspace_not_builder_workspace(self) -> None:
        executor = RoleExecutor()
        engine = self.engine_with_executor(executor)
        engine.add_challenge(self.identity, prompt="solve")
        engine.run_wave(self.identity, "attack")
        self.assertNotEqual(
            executor.working_directories[Role.BUILDER],
            executor.working_directories[Role.REPRODUCER],
        )
        self.assertEqual(
            executor.working_directories[Role.BUILDER].parts[-2:],
            ("artifacts", "workspace"),
        )
        self.assertEqual(
            executor.working_directories[Role.REPRODUCER].parts[-2:],
            ("proof", "workspace"),
        )

    def test_batch_worker_artifacts_remain_immutable_across_waves(self) -> None:
        class BuilderArtifactExecutor(RoleExecutor):
            def __init__(inner_self) -> None:
                super().__init__()
                inner_self.version = 0

            def run(
                inner_self,
                command,
                *,
                cwd,
                timeout,
                on_stdout_line,
            ):
                role = _role_for(command)
                if role is not Role.BUILDER:
                    return super().run(
                        command,
                        cwd=cwd,
                        timeout=timeout,
                        on_stdout_line=on_stdout_line,
                    )
                inner_self.version += 1
                payload = _payload(role)
                source = Path(cwd) / "solve.py"
                content = (
                    f"print('builder version {inner_self.version}')\n"
                ).encode()
                source.write_bytes(content)
                payload["artifacts"] = [
                    {
                        "path": "solve.py",
                        "sha256": hashlib.sha256(content).hexdigest(),
                        "purpose": "current solver",
                    }
                ]
                _output_path(command).write_text(
                    json.dumps(payload),
                    encoding="utf-8",
                )
                return ProcessOutcome(0, "", 0.01)

        engine = self.engine_with_executor(BuilderArtifactExecutor())
        engine.add_challenge(self.identity, prompt="solve")

        engine.run_wave(self.identity, "attack")
        engine.run_wave(self.identity, "attack")

        state = engine.store.load(self.identity)
        artifacts = [
            artifact
            for artifact in state.artifacts
            if artifact.extra.get("source_locator")
            == "artifacts/workspace/solve.py"
        ]
        self.assertEqual(len(artifacts), 2)
        self.assertEqual(len({artifact.path for artifact in artifacts}), 2)
        self.assertTrue(
            all(
                artifact.path.startswith("artifacts/snapshots/")
                for artifact in artifacts
            )
        )
        self.assertTrue(
            all(
                artifact.extra.get("reported_locator") == "solve.py"
                for artifact in artifacts
            )
        )
        paths = engine.store.challenge_paths(self.identity)
        snapshots = [paths.root / artifact.path for artifact in artifacts]
        self.assertEqual(
            [snapshot.read_bytes() for snapshot in snapshots],
            [
                b"print('builder version 1')\n",
                b"print('builder version 2')\n",
            ],
        )
        self.assertTrue(
            all(snapshot.stat().st_mode & 0o222 == 0 for snapshot in snapshots)
        )
        verified = engine.store.verify_artifacts(self.identity)
        self.assertEqual(
            [verified[artifact.id] for artifact in artifacts],
            snapshots,
        )

    def test_batch_artifact_cap_failure_cleans_only_the_new_wave_snapshot(
        self,
    ) -> None:
        class BuilderArtifactExecutor(RoleExecutor):
            def run(
                inner_self,
                command,
                *,
                cwd,
                timeout,
                on_stdout_line,
            ):
                role = _role_for(command)
                if role is not Role.BUILDER:
                    return super().run(
                        command,
                        cwd=cwd,
                        timeout=timeout,
                        on_stdout_line=on_stdout_line,
                    )
                content = b"builder-artifact-18"
                source = Path(cwd) / "solve.bin"
                source.write_bytes(content)
                payload = _payload(role)
                payload["artifacts"] = [
                    {
                        "path": "solve.bin",
                        "sha256": hashlib.sha256(content).hexdigest(),
                        "purpose": "bounded solver",
                    }
                ]
                _output_path(command).write_text(
                    json.dumps(payload),
                    encoding="utf-8",
                )
                return ProcessOutcome(0, "", 0.01)

        config = load_config(self.root)
        config = replace(
            config,
            runtime=replace(
                config.runtime,
                work_tree_max_bytes=24,
            ),
        )
        engine = ChallengeEngine(
            self.root,
            config=config,
            batch_runner=BatchRunner(
                process_executor=BuilderArtifactExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=lambda state, work, policy: FakeSandbox(work),
        )
        engine.add_challenge(self.identity, prompt="solve")
        first = engine.run_wave(self.identity, "attack")
        self.assertEqual(len(engine.store.load(self.identity).artifacts), 1)
        snapshots = engine.store.challenge_paths(
            self.identity
        ).artifacts / "snapshots"
        first_files = sorted(
            path.name for path in snapshots.iterdir() if path.is_file()
        )

        with self.assertRaisesRegex(
            ArtifactValidationError,
            "canonical artifact bytes exceed",
        ):
            engine.run_wave(self.identity, "attack")

        committed = engine.store.load(self.identity)
        self.assertEqual(committed.revision, first.committed_revision)
        self.assertEqual(len(committed.artifacts), 1)
        self.assertEqual(
            sorted(path.name for path in snapshots.iterdir() if path.is_file()),
            first_files,
        )

        committed = engine.store.update(
            self.identity,
            lambda current: current.metadata.update(
                {"post_artifact_snapshot_commit": True}
            ),
        )
        self.assertTrue(
            committed.metadata["post_artifact_snapshot_commit"]
        )

    def test_batch_worker_artifact_snapshot_rejects_symlink_and_hash_race(
        self,
    ) -> None:
        class BuilderArtifactExecutor(RoleExecutor):
            def run(
                inner_self,
                command,
                *,
                cwd,
                timeout,
                on_stdout_line,
            ):
                role = _role_for(command)
                if role is not Role.BUILDER:
                    return super().run(
                        command,
                        cwd=cwd,
                        timeout=timeout,
                        on_stdout_line=on_stdout_line,
                    )
                payload = _payload(role)
                source = Path(cwd) / "solve.py"
                content = b"trusted builder output\n"
                source.write_bytes(content)
                payload["artifacts"] = [
                    {
                        "path": "solve.py",
                        "sha256": hashlib.sha256(content).hexdigest(),
                        "purpose": "race target",
                    }
                ]
                _output_path(command).write_text(
                    json.dumps(payload),
                    encoding="utf-8",
                )
                return ProcessOutcome(0, "", 0.01)

        from ctf_os.sandbox.files import (
            copy_bounded_regular as safe_copy,
        )

        engine = self.engine_with_executor(BuilderArtifactExecutor())
        engine.add_challenge(self.identity, prompt="solve")

        def mutate_before_copy(
            source_root,
            source_locator,
            destination,
            **kwargs,
        ):
            source = Path(source_root) / source_locator
            source.write_bytes(b"mutated after worker report\n")
            return safe_copy(
                source_root,
                source_locator,
                destination,
                **kwargs,
            )

        with mock.patch(
            "ctf_os.engine.challenge.copy_bounded_regular",
            side_effect=mutate_before_copy,
        ):
            outcome = engine.run_wave(self.identity, "attack")

        state = engine.store.load(self.identity)
        builder_run = next(
            run for run in state.runs if run.role == Role.BUILDER.value
        )
        self.assertEqual(builder_run.status, RunStatus.INVALID)
        self.assertIn(
            "hash",
            str(builder_run.extra["normalization_error"]).lower(),
        )
        self.assertFalse(
            any(
                artifact.source_run_id == builder_run.id
                for artifact in state.artifacts
            )
        )
        self.assertEqual(outcome.committed_revision, state.revision)

        paths = engine.store.challenge_paths(self.identity)
        source = paths.artifacts / "workspace" / "solve.py"
        source.unlink()
        outside = self.root / "outside-worker-artifact"
        outside.write_bytes(b"outside")
        source.symlink_to(outside)
        engine.run_wave(self.identity, "attack")
        state = engine.store.load(self.identity)
        builder_runs = [
            run for run in state.runs if run.role == Role.BUILDER.value
        ]
        self.assertEqual(len(builder_runs), 2)
        self.assertTrue(
            all(run.status is RunStatus.INVALID for run in builder_runs)
        )
        self.assertIn(
            "safely",
            str(builder_runs[-1].extra["normalization_error"]).lower(),
        )
        self.assertTrue(source.is_symlink())

    def test_batch_artifact_interrupts_clean_or_preserve_exact_snapshot(
        self,
    ) -> None:
        class BuilderArtifactExecutor(RoleExecutor):
            def run(
                inner_self,
                command,
                *,
                cwd,
                timeout,
                on_stdout_line,
            ):
                role = _role_for(command)
                if role is not Role.BUILDER:
                    return super().run(
                        command,
                        cwd=cwd,
                        timeout=timeout,
                        on_stdout_line=on_stdout_line,
                    )
                content = b"interrupt-safe builder artifact"
                source = Path(cwd) / "builder.bin"
                source.write_bytes(content)
                payload = _payload(role)
                payload["artifacts"] = [
                    {
                        "path": "builder.bin",
                        "sha256": hashlib.sha256(content).hexdigest(),
                        "purpose": "interrupt regression",
                    }
                ]
                _output_path(command).write_text(
                    json.dumps(payload),
                    encoding="utf-8",
                )
                return ProcessOutcome(0, "", 0.01)

        from ctf_os.sandbox.files import (
            copy_bounded_regular as real_copy,
        )

        for stage in (
            "copy",
            "handoff",
            "post-normalize",
            "commit-before",
            "commit-after",
        ):
            with self.subTest(stage=stage):
                root = self.root / f"batch-artifact-{stage}"
                engine = ChallengeEngine(
                    root,
                    batch_runner=BatchRunner(
                        process_executor=BuilderArtifactExecutor(),
                        max_schema_retries=0,
                    ),
                    sandbox_factory=(
                        lambda state, work, policy: FakeSandbox(work)
                    ),
                )
                engine.add_challenge(self.identity, prompt="solve")
                interruption = KeyboardInterrupt(
                    f"synthetic batch artifact {stage} interruption"
                )

                if stage == "copy":

                    def copy_then_interrupt(*args, **kwargs):
                        real_copy(*args, **kwargs)
                        raise interruption

                    patcher = mock.patch(
                        "ctf_os.engine.challenge.copy_bounded_regular",
                        side_effect=copy_then_interrupt,
                    )
                elif stage == "handoff":
                    real_normalize = engine._normalize_result

                    def normalize_then_interrupt(*args, **kwargs):
                        normalized = real_normalize(*args, **kwargs)
                        if normalized[1]:
                            raise interruption
                        return normalized

                    patcher = mock.patch.object(
                        engine,
                        "_normalize_result",
                        side_effect=normalize_then_interrupt,
                    )
                elif stage == "post-normalize":
                    patcher = _interrupt_on_source_line(
                        ChallengeEngine._commit_batch_results,
                        "def apply(state: ChallengeState) -> None:",
                        interruption,
                    )
                else:
                    real_update = engine.store.update
                    interrupted = False

                    def interrupt_batch_commit(
                        identity,
                        mutator,
                        *args,
                        **kwargs,
                    ):
                        nonlocal interrupted
                        if (
                            not interrupted
                            and "_commit_batch_results"
                            in getattr(mutator, "__qualname__", "")
                        ):
                            interrupted = True
                            if stage == "commit-after":
                                real_update(
                                    identity,
                                    mutator,
                                    *args,
                                    **kwargs,
                                )
                            raise interruption
                        return real_update(
                            identity,
                            mutator,
                            *args,
                            **kwargs,
                        )

                    patcher = mock.patch.object(
                        engine.store,
                        "update",
                        side_effect=interrupt_batch_commit,
                    )

                with (
                    patcher,
                    self.assertRaises(KeyboardInterrupt) as raised,
                ):
                    engine.run_wave(self.identity, "attack")

                self.assertIs(raised.exception, interruption)
                committed = engine.store.load(self.identity)
                snapshots = (
                    engine.store.challenge_paths(self.identity).artifacts
                    / "snapshots"
                )
                snapshot_files = (
                    list(snapshots.glob("*.bin"))
                    if snapshots.exists()
                    else []
                )
                expected = 1 if stage == "commit-after" else 0
                self.assertEqual(len(committed.artifacts), expected)
                self.assertEqual(len(snapshot_files), expected)

    def test_batch_later_normalization_failure_cleans_prior_snapshots(
        self,
    ) -> None:
        class BuilderArtifactExecutor(RoleExecutor):
            def run(
                inner_self,
                command,
                *,
                cwd,
                timeout,
                on_stdout_line,
            ):
                role = _role_for(command)
                if role is not Role.BUILDER:
                    return super().run(
                        command,
                        cwd=cwd,
                        timeout=timeout,
                        on_stdout_line=on_stdout_line,
                    )
                content = b"first-role-artifact"
                (Path(cwd) / "artifact.bin").write_bytes(content)
                payload = _payload(role)
                payload["artifacts"] = [
                    {
                        "path": "artifact.bin",
                        "sha256": hashlib.sha256(content).hexdigest(),
                        "purpose": "must be cleaned on later failure",
                    }
                ]
                _output_path(command).write_text(
                    json.dumps(payload),
                    encoding="utf-8",
                )
                return ProcessOutcome(0, "", 0.01)

        engine = self.engine_with_executor(BuilderArtifactExecutor())
        engine.add_challenge(self.identity, prompt="solve")
        real_write = engine.store.write_run_result
        write_calls = 0

        def fail_second_write(*args, **kwargs):
            nonlocal write_calls
            write_calls += 1
            if write_calls == 2:
                raise OSError("second result persistence failed")
            return real_write(*args, **kwargs)

        with (
            mock.patch.object(
                engine.store,
                "write_run_result",
                side_effect=fail_second_write,
            ),
            self.assertRaisesRegex(
                OSError,
                "second result persistence failed",
            ),
        ):
            engine.run_wave(self.identity, "attack")

        state = engine.store.load(self.identity)
        self.assertEqual(state.artifacts, [])
        snapshots = (
            engine.store.challenge_paths(self.identity).artifacts
            / "snapshots"
        )
        self.assertEqual(
            [path for path in snapshots.rglob("*") if path.is_file()],
            [],
        )

    def test_engine_wires_configured_captain_and_worker_efforts(self) -> None:
        executor = RoleExecutor()
        config = load_config(self.root)
        config = replace(
            config,
            models=replace(
                config.models,
                captain_effort="high",
                worker_effort="xhigh",
            ),
        )
        engine = ChallengeEngine(
            self.root,
            config=config,
            batch_runner=BatchRunner(
                process_executor=executor,
                max_schema_retries=0,
            ),
            sandbox_factory=lambda state, work, policy: FakeSandbox(work),
        )
        engine.add_challenge(self.identity, prompt="solve")
        live = engine.prepare_live_session(self.identity)
        self.assertIn('model_reasoning_effort="high"', live.command)
        engine.run_role(
            self.identity,
            Role.CAPTAIN,
            instruction="choose a stage",
        )
        engine.run_role(
            self.identity,
            Role.RECON,
            instruction="inspect",
        )
        self.assertEqual(executor.reasoning_efforts[Role.CAPTAIN], "high")
        self.assertEqual(executor.reasoning_efforts[Role.RECON], "xhigh")
        captain_run = next(
            run for run in engine.store.load(self.identity).runs
            if run.role == Role.CAPTAIN.value
        )
        request = json.loads(
            (
                engine.store.challenge_paths(self.identity).root
                / str(captain_run.request_path)
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(request["reasoning_effort"], "high")
        self.assertEqual(captain_run.extra["reasoning_effort"], "high")

    def test_valid_refusal_is_completed_and_recorded_not_invalid(self) -> None:
        engine = self.engine_with_executor(
            RoleExecutor(refusal_role=Role.RECON)
        )
        engine.add_challenge(self.identity, prompt="solve")
        result = engine.run_role(
            self.identity,
            Role.RECON,
            instruction="inspect",
        )
        state = engine.store.load(self.identity)
        self.assertTrue(result.refused)
        self.assertEqual(state.runs[0].status, RunStatus.COMPLETED)
        self.assertEqual(state.budget.refusals[0]["kind"], "policy")

    def test_live_lock_is_acquired_before_session_files_are_rewritten(self) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        state = engine.add_challenge(self.identity, prompt="solve")
        workspace = (
            engine.store.challenge_paths(state.identity).artifacts
            / "workspace"
        )
        workspace.mkdir(parents=True, exist_ok=True)
        session_context = workspace / "SESSION.md"
        session_context.write_text("active-session-sentinel", encoding="utf-8")
        lock_path = (
            engine.store.challenge_paths(state.identity).runtime
            / "session.lock"
        )
        state_path = engine.store.challenge_paths(state.identity).state
        canonical_before = state_path.read_bytes()
        prompt_before = state.prompt
        revision_before = state.revision
        callback_called = False

        def prepared(_session):
            nonlocal callback_called
            callback_called = True

        with ChallengeLock(lock_path, timeout=0) as session_lock:
            session_lock.acquire()
            with self.assertRaises(SessionAlreadyRunning):
                engine.launch_live(
                    self.identity,
                    prompt="racing solve must not replace the prompt",
                    runner=lambda *args, **kwargs: None,
                    on_prepared=prepared,
                )
            with self.assertRaises(SessionAlreadyRunning):
                engine.run_challenge(
                    self.identity,
                    prompt="racing batch must not replace the prompt",
                    max_cycles=1,
                )
            with self.assertRaises(SessionAlreadyRunning):
                engine.update_prompt(
                    self.identity,
                    "direct prompt update must not race",
                )
            with self.assertRaises(SessionAlreadyRunning):
                engine.add_challenge(
                    self.identity,
                    prompt="add-challenge must not race",
                )
        self.assertFalse(callback_called)
        self.assertEqual(
            session_context.read_text(encoding="utf-8"),
            "active-session-sentinel",
        )
        after = engine.store.load(self.identity)
        self.assertEqual(after.prompt, prompt_before)
        self.assertEqual(after.revision, revision_before)
        self.assertEqual(state_path.read_bytes(), canonical_before)

    def test_registered_command_runs_in_sandbox_and_persists_tool_flag(self) -> None:
        holder: dict[str, FakeSandbox] = {}

        def sandbox_factory(state, work, policy):
            del state, policy
            holder.setdefault("client", FakeSandbox(work))
            return holder["client"]

        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=sandbox_factory,
        )
        state = engine.add_challenge(self.identity, prompt="solve")

        def add_experiment(current):
            current.experiments.append(
                Experiment(
                    "E-manual",
                    [],
                    "/bin/true",
                    "exit zero",
                    "zero",
                    "nonzero",
                    10,
                    status=ExperimentStatus.REGISTERED,
                )
            )

        engine.store.update(state.identity, add_experiment)
        terminal = io.StringIO()
        with redirect_stderr(terminal):
            state = engine.execute_registered_experiments(self.identity)
        experiment = next(
            item for item in state.experiments if item.id == "E-manual"
        )
        self.assertEqual(
            experiment.status,
            ExperimentStatus.AWAITING_EVALUATION,
        )
        self.assertTrue(
            any(fact.provenance is Provenance.EXECUTED for fact in state.facts)
        )
        executed_fact = next(
            fact
            for fact in state.facts
            if fact.provenance is Provenance.EXECUTED
        )
        self.assertNotIn("KCTF{tool_flag}", executed_fact.statement)
        self.assertIn(executed_fact.artifact_id, executed_fact.statement)
        self.assertNotIn("stdout_summary", experiment.result)
        self.assertNotIn("stderr_summary", experiment.result)
        self.assertEqual(state.candidates[0].value, "KCTF{tool_flag}")
        self.assertIn("미제출", terminal.getvalue())

    def test_direct_tool_terminal_preflight_has_no_registration_side_effect(
        self,
    ) -> None:
        for status in (
            ChallengeStatus.PAUSED,
            ChallengeStatus.READY_TO_SUBMIT,
            ChallengeStatus.SOLVED,
            ChallengeStatus.ABANDONED,
        ):
            with self.subTest(status=status.value):
                identity = ChallengeIdentity(
                    self.identity.contest_id,
                    self.identity.category,
                    f"terminal-tool-{status.value}",
                )
                holder: dict[str, FakeSandbox] = {}

                def sandbox_factory(state, work, policy):
                    del state, policy
                    holder.setdefault("client", FakeSandbox(work))
                    return holder["client"]

                engine = ChallengeEngine(
                    self.root,
                    batch_runner=BatchRunner(
                        process_executor=RoleExecutor(),
                        max_schema_retries=0,
                    ),
                    sandbox_factory=sandbox_factory,
                )
                engine.add_challenge(identity, prompt="solve")

                def set_status(current: ChallengeState) -> None:
                    current.resume_status = (
                        current.status
                        if status is ChallengeStatus.PAUSED
                        else None
                    )
                    current.status = status

                terminal = engine.store.update(identity, set_status)
                paths = engine.store.challenge_paths(identity)
                canonical_before = paths.state.read_bytes()
                experiments_before = [
                    item.to_dict() for item in terminal.experiments
                ]

                with self.assertRaisesRegex(
                    EngineError,
                    status.value,
                ):
                    engine.run_tool_command(identity, ("true",))

                unchanged = engine.store.load(identity)
                self.assertEqual(unchanged.revision, terminal.revision)
                self.assertEqual(paths.state.read_bytes(), canonical_before)
                self.assertEqual(
                    [item.to_dict() for item in unchanged.experiments],
                    experiments_before,
                )
                self.assertEqual(holder, {})

    def test_direct_tool_check_to_register_race_uses_revision_cas(
        self,
    ) -> None:
        holder: dict[str, FakeSandbox] = {}

        def sandbox_factory(state, work, policy):
            del state, policy
            holder.setdefault("client", FakeSandbox(work))
            return holder["client"]

        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=sandbox_factory,
        )
        initial = engine.add_challenge(self.identity, prompt="solve")
        experiments_before = [
            item.to_dict() for item in initial.experiments
        ]
        real_register = engine.register_experiment
        injected = False

        def pause_then_register(*args, **kwargs):
            nonlocal injected
            if not injected:
                injected = True
                engine.pause(self.identity)
            return real_register(*args, **kwargs)

        with (
            mock.patch.object(
                engine,
                "register_experiment",
                side_effect=pause_then_register,
            ),
            self.assertRaisesRegex(EngineError, "PAUSED"),
        ):
            engine.run_tool_command(self.identity, ("true",))

        paused = engine.store.load(self.identity)
        self.assertIs(paused.status, ChallengeStatus.PAUSED)
        self.assertEqual(
            [item.to_dict() for item in paused.experiments],
            experiments_before,
        )
        self.assertEqual(holder, {})

    def test_direct_tool_retries_one_benign_candidate_revision_race(
        self,
    ) -> None:
        holder: dict[str, FakeSandbox] = {}

        def sandbox_factory(state, work, policy):
            del state, policy
            holder.setdefault("client", FakeSandbox(work))
            return holder["client"]

        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=sandbox_factory,
        )
        engine.add_challenge(self.identity, prompt="solve")
        real_register = engine.register_experiment
        injected = False

        def flag_then_register(*args, **kwargs):
            nonlocal injected
            if not injected:
                injected = True
                engine.record_candidate(
                    self.identity,
                    "KCTF{benign_registration_race}",
                    print_immediately=False,
                )
            return real_register(*args, **kwargs)

        with mock.patch.object(
            engine,
            "register_experiment",
            side_effect=flag_then_register,
        ):
            completed = engine.run_tool_command(self.identity, ("true",))

        self.assertTrue(injected)
        self.assertTrue(
            any(
                candidate.value == "KCTF{benign_registration_race}"
                for candidate in completed.candidates
            )
        )
        self.assertTrue(
            any(
                experiment.status
                is ExperimentStatus.AWAITING_EVALUATION
                for experiment in completed.experiments
            )
        )
        self.assertIn("client", holder)

    def test_direct_tool_remains_allowed_from_explicit_waiting_states(
        self,
    ) -> None:
        for status in (
            ChallengeStatus.NEEDS_HUMAN,
            ChallengeStatus.STALLED,
        ):
            with self.subTest(status=status.value):
                identity = ChallengeIdentity(
                    self.identity.contest_id,
                    self.identity.category,
                    f"explicit-tool-{status.value}",
                )
                holder: dict[str, FakeSandbox] = {}

                def sandbox_factory(state, work, policy):
                    del state, policy
                    holder.setdefault("client", FakeSandbox(work))
                    return holder["client"]

                engine = ChallengeEngine(
                    self.root,
                    batch_runner=BatchRunner(
                        process_executor=RoleExecutor(),
                        max_schema_retries=0,
                    ),
                    sandbox_factory=sandbox_factory,
                )
                engine.add_challenge(identity, prompt="solve")

                def set_status(current: ChallengeState) -> None:
                    current.status = status
                    current.resume_status = None

                engine.store.update(identity, set_status)
                completed = engine.run_tool_command(
                    identity,
                    ("true",),
                )

                self.assertIs(completed.status, status)
                self.assertEqual(len(holder["client"].specs), 1)

    def test_tool_wave_finishes_one_inflight_run_then_stops_on_pause(
        self,
    ) -> None:
        holder: dict[str, FakeSandbox] = {}
        engine_holder: dict[str, ChallengeEngine] = {}

        class PauseAfterFirstRunSandbox(FakeSandbox):
            def run(inner_self, spec):
                result = super().run(spec)
                if len(inner_self.specs) == 1:
                    engine_holder["engine"].pause(self.identity)
                return result

        def sandbox_factory(state, work, policy):
            del state, policy
            holder.setdefault(
                "client", PauseAfterFirstRunSandbox(work)
            )
            return holder["client"]

        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=sandbox_factory,
        )
        engine_holder["engine"] = engine
        state = engine.add_challenge(self.identity, prompt="solve")

        def add_experiments(current: ChallengeState) -> None:
            for number in range(1, 4):
                current.experiments.append(
                    Experiment(
                        f"E-pause-{number}",
                        [],
                        "/bin/true",
                        "exit zero",
                        "zero",
                        "nonzero",
                        10,
                        status=ExperimentStatus.REGISTERED,
                    )
                )

        engine.store.update(
            state.identity,
            add_experiments,
        )

        with self.assertRaisesRegex(
            EngineError,
            "challenge is PAUSED",
        ):
            engine.execute_registered_experiments(
                self.identity,
                maximum=3,
                experiment_ids=(
                    "E-pause-1",
                    "E-pause-2",
                    "E-pause-3",
                ),
            )

        paused = engine.store.load(self.identity)
        self.assertIs(paused.status, ChallengeStatus.PAUSED)
        statuses = {
            item.id: item.status
            for item in paused.experiments
            if item.id.startswith("E-pause-")
        }
        self.assertIs(
            statuses["E-pause-1"],
            ExperimentStatus.AWAITING_EVALUATION,
        )
        self.assertIs(
            statuses["E-pause-2"],
            ExperimentStatus.REGISTERED,
        )
        self.assertIs(
            statuses["E-pause-3"],
            ExperimentStatus.REGISTERED,
        )
        self.assertEqual(len(holder["client"].specs), 1)
        self.assertEqual(
            len([run for run in paused.runs if run.role == "tool"]),
            1,
        )

    def test_tool_flag_intent_is_durable_before_print_and_cleared_after_commit(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        state = engine.add_challenge(self.identity, prompt="solve")

        def add_experiment(current):
            current.experiments.append(
                Experiment(
                    "E-tool-order",
                    [],
                    "/bin/true",
                    "exit zero",
                    "zero",
                    "nonzero",
                    10,
                    status=ExperimentStatus.REGISTERED,
                )
            )

        engine.store.update(state.identity, add_experiment)
        observations: list[tuple[str, ...]] = []

        def observe_print(detected) -> None:
            current = engine.store.load(self.identity)
            self.assertFalse(
                any(
                    candidate.value == detected.value
                    for candidate in current.candidates
                )
            )
            observations.append(
                tuple(
                    str(item["value"])
                    for item in engine.store.load_candidate_intents(
                        self.identity
                    )
                )
            )

        with mock.patch(
            "ctf_os.engine.challenge.print_flag_candidate",
            side_effect=observe_print,
        ):
            committed = engine.execute_registered_experiments(self.identity)

        self.assertEqual(observations, [("KCTF{tool_flag}",)])
        self.assertEqual(
            [candidate.value for candidate in committed.candidates],
            ["KCTF{tool_flag}"],
        )
        self.assertEqual(
            engine.store.load_candidate_intents(self.identity),
            (),
        )

    def test_failed_tool_flag_intent_is_reprinted_before_next_session_reconcile(
        self,
    ) -> None:
        class FlagThenFailSandbox(FakeSandbox):
            def run(inner_self, spec):
                inner_self.specs.append(spec)
                run = (
                    inner_self.work
                    / ".ctf"
                    / "runs"
                    / "run-00000001"
                )
                run.mkdir(parents=True, exist_ok=True)
                (run / "stdout.log").write_text(
                    "answer KCTF{failed_tool_candidate}\n",
                    encoding="utf-8",
                )
                (run / "stderr.log").write_text("", encoding="utf-8")
                raise RuntimeError("sandbox disconnected after output")

        holder: dict[str, FlagThenFailSandbox] = {}

        def sandbox_factory(state, work, policy):
            del state, policy
            holder.setdefault("client", FlagThenFailSandbox(work))
            return holder["client"]

        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=sandbox_factory,
        )
        state = engine.add_challenge(self.identity, prompt="solve")

        def add_experiment(current):
            current.experiments.append(
                Experiment(
                    "E-tool-fails-after-flag",
                    [],
                    "/bin/false",
                    "candidate appears",
                    "candidate is useful",
                    "no candidate",
                    10,
                    status=ExperimentStatus.REGISTERED,
                )
            )

        engine.store.update(state.identity, add_experiment)
        terminal = io.StringIO()
        with redirect_stderr(terminal):
            failed = engine.execute_registered_experiments(self.identity)

        self.assertIn("KCTF{failed_tool_candidate}", terminal.getvalue())
        self.assertEqual(failed.candidates, [])
        intents = engine.store.load_candidate_intents(self.identity)
        self.assertEqual(
            [item["value"] for item in intents],
            ["KCTF{failed_tool_candidate}"],
        )
        failed_run = next(run for run in failed.runs if run.role == "tool")
        self.assertEqual(intents[0]["source_run_id"], failed_run.id)

        restarted = self.engine_with_executor(RoleExecutor())
        with mock.patch(
            "ctf_os.engine.challenge.print_flag_candidate"
        ) as printed:
            restarted.run_role(
                self.identity,
                Role.RECON,
                instruction="continue after failed tool",
            )
        recovered = restarted.store.load(self.identity)
        recovered_candidate = next(
            candidate
            for candidate in recovered.candidates
            if candidate.value == "KCTF{failed_tool_candidate}"
        )
        self.assertEqual(printed.call_count, 1)
        printed_flag = printed.call_args.args[0]
        self.assertEqual(
            printed_flag.value,
            "KCTF{failed_tool_candidate}",
        )
        self.assertIn(
            failed_run.id,
            printed_flag.source,
        )
        self.assertEqual(recovered_candidate.source_run_id, failed_run.id)
        self.assertEqual(
            restarted.store.load_candidate_intents(self.identity),
            (),
        )

    def test_goal_dependencies_and_single_active_lifecycle_are_atomic(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(self.identity, prompt="solve")

        engine.manage_goal(
            self.identity,
            action="create",
            goal_id="G-base",
            description="establish the primitive",
            activate=True,
        )
        engine.manage_goal(
            self.identity,
            action="create",
            goal_id="G-dependent",
            description="exploit the primitive",
            depends_on=("G-base",),
        )
        with self.assertRaisesRegex(EngineError, "dependencies are incomplete"):
            engine.manage_goal(
                self.identity,
                action="activate",
                goal_id="G-dependent",
            )

        state, _goal_id = engine.manage_goal(
            self.identity,
            action="create",
            goal_id="G-new",
            description="test an alternate path",
            activate=True,
        )
        goals = {goal.id: goal for goal in state.goals}
        self.assertEqual(state.active_goal_id, "G-new")
        self.assertIs(goals["G-new"].status, GoalStatus.ACTIVE)
        self.assertIs(goals["G-base"].status, GoalStatus.PARKED)
        self.assertEqual(
            sum(goal.status is GoalStatus.ACTIVE for goal in state.goals),
            1,
        )

        engine.manage_goal(
            self.identity, action="complete", goal_id="G-new"
        )
        engine.manage_goal(
            self.identity, action="activate", goal_id="G-base"
        )
        engine.manage_goal(
            self.identity, action="complete", goal_id="G-base"
        )
        state, _goal_id = engine.manage_goal(
            self.identity, action="activate", goal_id="G-dependent"
        )
        self.assertEqual(state.active_goal_id, "G-dependent")

    def test_explicit_experiment_evaluations_do_not_infer_from_oracles(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(self.identity, prompt="solve")
        experiment_ids: list[str] = []
        for label in ("keep", "drop", "inconclusive"):
            _state, experiment_id = engine.register_experiment(
                self.identity,
                command=("true",),
                expected_observation=f"{label} probe exits zero",
                keep_if=f"free-form keep text for {label}",
                drop_if=f"free-form drop text for {label}",
            )
            experiment_ids.append(experiment_id)
        state = engine.execute_registered_experiments(
            self.identity, maximum=3
        )
        facts_by_experiment = {
            experiment.id: str(experiment.result["fact_id"])
            for experiment in state.experiments
            if experiment.id in experiment_ids
        }

        for experiment_id, semantic_status in zip(
            experiment_ids,
            (
                ExperimentStatus.KEPT,
                ExperimentStatus.DROPPED,
                ExperimentStatus.INCONCLUSIVE,
            ),
            strict=True,
        ):
            state = engine.evaluate_experiment(
                self.identity,
                experiment_id,
                status=semantic_status,
                reason=f"operator selected {semantic_status.value}",
                evidence_fact_ids=(facts_by_experiment[experiment_id],),
            )

        experiments = {
            experiment.id: experiment for experiment in state.experiments
        }
        self.assertEqual(
            [experiments[item].status for item in experiment_ids],
            [
                ExperimentStatus.KEPT,
                ExperimentStatus.DROPPED,
                ExperimentStatus.INCONCLUSIVE,
            ],
        )
        self.assertTrue(
            all(
                experiments[item].evaluation_reason
                for item in experiment_ids
            )
        )

    def test_experiment_evaluation_requires_its_own_executed_chain(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(self.identity, prompt="solve")
        engine.manage_hypothesis(
            self.identity,
            action="create",
            hypothesis_id="H-own-run",
            statement="the second probe is contradicted",
            falsifier="the second probe's own output is the counterexample",
        )
        _state, first_id = engine.register_experiment(
            self.identity,
            command=("true",),
            expected_observation="first probe",
            keep_if="first probe succeeds",
            drop_if="first probe fails",
        )
        _state, second_id = engine.register_experiment(
            self.identity,
            command=("true",),
            expected_observation="second probe",
            keep_if="second probe supports the hypothesis",
            drop_if="second probe refutes the hypothesis",
            hypothesis_ids=("H-own-run",),
        )
        state = engine.execute_registered_experiments(
            self.identity,
            maximum=2,
        )
        experiments = {item.id: item for item in state.experiments}
        first_fact = str(experiments[first_id].result["fact_id"])
        second_fact = str(experiments[second_id].result["fact_id"])
        original_statement = next(
            item.statement
            for item in state.hypotheses
            if item.id == "H-own-run"
        )

        with self.assertRaisesRegex(EngineError, "immutable"):
            engine.manage_hypothesis(
                self.identity,
                action="update",
                hypothesis_id="H-own-run",
                statement="new meaning after the experiment ran",
            )
        unchanged_hypothesis = next(
            item
            for item in engine.store.load(self.identity).hypotheses
            if item.id == "H-own-run"
        )
        self.assertEqual(
            unchanged_hypothesis.statement,
            original_statement,
        )

        with self.assertRaisesRegex(EngineError, "own run"):
            engine.evaluate_experiment(
                self.identity,
                second_id,
                status=ExperimentStatus.DROPPED,
                reason="unrelated output must not decide this experiment",
                evidence_fact_ids=(first_fact,),
                refute_hypothesis_ids=("H-own-run",),
            )
        rejected = engine.store.load(self.identity)
        rejected_experiment = next(
            item for item in rejected.experiments if item.id == second_id
        )
        rejected_hypothesis = next(
            item for item in rejected.hypotheses if item.id == "H-own-run"
        )
        self.assertIs(
            rejected_experiment.status,
            ExperimentStatus.AWAITING_EVALUATION,
        )
        self.assertIs(rejected_hypothesis.status, HypothesisStatus.OPEN)

        accepted = engine.evaluate_experiment(
            self.identity,
            second_id,
            status=ExperimentStatus.DROPPED,
            reason="the second probe's own output is the counterexample",
            evidence_fact_ids=(second_fact,),
            refute_hypothesis_ids=("H-own-run",),
        )
        accepted_experiment = next(
            item for item in accepted.experiments if item.id == second_id
        )
        accepted_hypothesis = next(
            item for item in accepted.hypotheses if item.id == "H-own-run"
        )
        self.assertIs(accepted_experiment.status, ExperimentStatus.DROPPED)
        self.assertIs(accepted_hypothesis.status, HypothesisStatus.REFUTED)
        self.assertEqual(accepted_hypothesis.refuted_by, second_id)

    def test_model_only_hypothesis_confirmation_is_rejected(self) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(self.identity, prompt="solve")
        engine.manage_hypothesis(
            self.identity,
            action="create",
            hypothesis_id="H-model-only",
            statement="the model guessed the primitive",
            falsifier="run a known-answer test",
        )
        state = engine.record_fact(
            self.identity,
            "the model repeats its guess",
            provenance=Provenance.MODEL_CLAIMED,
        )
        fact_id = state.facts[-1].id

        with self.assertRaisesRegex(
            EngineError, "executed fact linked"
        ):
            engine.manage_hypothesis(
                self.identity,
                action="update",
                hypothesis_id="H-model-only",
                status=HypothesisStatus.CONFIRMED,
                evidence_fact_ids=(fact_id,),
            )
        state = engine.store.load(self.identity)
        self.assertIs(
            state.hypotheses[0].status,
            HypothesisStatus.OPEN,
        )

    def test_candidate_callback_runs_only_after_successful_state_update(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(self.identity, prompt="solve")
        callback_states: list[int] = []

        def observe(_identity, _detected):
            state = engine.store.load(self.identity)
            self.assertTrue(
                any(
                    item.value == "KCTF{ordered_callback}"
                    for item in state.candidates
                )
            )
            callback_states.append(state.revision)

        with mock.patch.object(
            engine,
            "_on_tool_flag",
            side_effect=observe,
        ) as callback:
            engine.record_candidate(
                self.identity,
                "KCTF{ordered_callback}",
            )
            engine.record_candidate(
                self.identity,
                "KCTF{ordered_callback}",
            )

        self.assertEqual(callback.call_count, 2)
        self.assertEqual(len(callback_states), 2)
        state = engine.store.load(self.identity)
        self.assertEqual(
            sum(
                item.value == "KCTF{ordered_callback}"
                for item in state.candidates
            ),
            1,
        )

    def test_operator_candidate_rejects_nonprintable_unicode(self) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        initial = engine.add_challenge(self.identity, prompt="solve")

        for character in (
            "\u0085",
            "\u200b",
            "\u2028",
            "\u2029",
            "\u202e",
        ):
            with (
                self.subTest(character=ascii(character)),
                self.assertRaisesRegex(EngineError, "printable"),
            ):
                engine.record_candidate(
                    self.identity,
                    f"KCTF{{bad{character}flag}}",
                )

        unchanged = engine.store.load(self.identity)
        self.assertEqual(unchanged.revision, initial.revision)
        self.assertEqual(unchanged.candidates, [])

    def test_terminal_flag_dedupe_is_challenge_scoped(self) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        second_identity = ChallengeIdentity(
            self.identity.contest_id,
            self.identity.category,
            "문제 2",
        )
        engine.add_challenge(self.identity, prompt="solve first")
        engine.add_challenge(second_identity, prompt="solve second")
        value = "KCTF{same_value_for_two_challenges}"

        with mock.patch(
            "ctf_os.engine.challenge.print_flag_candidate"
        ) as printed:
            engine.record_candidate(self.identity, value)
            engine.record_candidate(self.identity, value)
            engine.record_candidate(second_identity, value)

        self.assertEqual(printed.call_count, 2)
        self.assertEqual(
            [
                [candidate.value for candidate in engine.store.load(item).candidates]
                for item in (self.identity, second_identity)
            ],
            [[value], [value]],
        )

    def test_terminal_print_failure_does_not_consume_dedupe_key(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(self.identity, prompt="solve")
        value = "KCTF{retry_after_terminal_failure}"

        with mock.patch(
            "ctf_os.engine.challenge.print_flag_candidate",
            side_effect=(OSError("terminal unavailable"), None),
        ) as printed:
            with self.assertRaisesRegex(OSError, "terminal unavailable"):
                engine.record_candidate(self.identity, value)
            engine.record_candidate(self.identity, value)

        self.assertEqual(printed.call_count, 2)
        self.assertEqual(
            [
                candidate.value
                for candidate in engine.store.load(self.identity).candidates
            ],
            [value],
        )

    def test_concurrent_terminal_print_retries_after_first_failure(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(self.identity, prompt="solve")
        detected = DetectedFlag(
            "KCTF{concurrent_terminal_retry}",
            "concurrency regression",
            "now",
        )
        first_entered = threading.Event()
        release_first = threading.Event()
        call_count = 0
        call_lock = threading.Lock()
        failures: list[BaseException] = []

        def print_once(candidate) -> None:
            nonlocal call_count
            del candidate
            with call_lock:
                call_count += 1
                current_call = call_count
            if current_call == 1:
                first_entered.set()
                self.assertTrue(release_first.wait(2))
                raise OSError("first terminal write failed")

        def notify() -> None:
            try:
                engine._on_tool_flag(self.identity, detected)
            except BaseException as error:
                failures.append(error)

        with mock.patch(
            "ctf_os.engine.challenge.print_flag_candidate",
            side_effect=print_once,
        ):
            first = threading.Thread(target=notify)
            first.start()
            self.assertTrue(first_entered.wait(1))
            second = threading.Thread(target=notify)
            second.start()
            release_first.set()
            first.join(timeout=2)
            second.join(timeout=2)
            self.assertFalse(first.is_alive())
            self.assertFalse(second.is_alive())
            engine._on_tool_flag(self.identity, detected)

        self.assertEqual(call_count, 2)
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], OSError)

    def test_batch_falsifier_updates_existing_hypothesis_and_experiment(
        self,
    ) -> None:
        class MutablePayloadExecutor:
            payload: dict[str, object] | None = None

            def run(
                inner_self,
                command,
                *,
                cwd,
                timeout,
                on_stdout_line,
            ):
                del cwd, timeout, on_stdout_line
                if inner_self.payload is None:
                    raise AssertionError("payload was not configured")
                self.assertIs(_role_for(command), Role.FALSIFIER)
                _output_path(command).write_text(
                    json.dumps(inner_self.payload),
                    encoding="utf-8",
                )
                return ProcessOutcome(0, "", 0.01)

        executor = MutablePayloadExecutor()
        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=executor,
                max_schema_retries=0,
            ),
            sandbox_factory=lambda state, work, policy: FakeSandbox(work),
        )
        engine.add_challenge(self.identity, prompt="solve")
        engine.manage_hypothesis(
            self.identity,
            action="create",
            hypothesis_id="H-existing",
            statement="original statement",
            falsifier="run the discriminating probe",
        )
        engine.manage_hypothesis(
            self.identity,
            action="create",
            hypothesis_id="H-unreferenced",
            statement="unrelated open hypothesis",
            falsifier="a separate future probe",
        )
        _state, experiment_id = engine.register_experiment(
            self.identity,
            command=("true",),
            expected_observation="probe exits zero",
            keep_if="result supports the hypothesis",
            drop_if="result refutes the hypothesis",
            hypothesis_ids=("H-existing",),
        )
        executed = engine.execute_registered_experiments(self.identity)
        experiment = next(
            item for item in executed.experiments if item.id == experiment_id
        )
        fact_id = str(experiment.result["fact_id"])
        confirmed, _hypothesis_id = engine.manage_hypothesis(
            self.identity,
            action="update",
            hypothesis_id="H-unreferenced",
            status=HypothesisStatus.CONFIRMED,
            evidence_fact_ids=(fact_id,),
        )
        confirmed_revision = confirmed.revision
        with self.assertRaisesRegex(EngineError, "immutable after evaluation"):
            engine.manage_hypothesis(
                self.identity,
                action="update",
                hypothesis_id="H-unreferenced",
                statement="direct semantic rewrite after confirmation",
                status=HypothesisStatus.CONFIRMED,
            )
        after_direct_rejection = engine.store.load(self.identity)
        self.assertEqual(after_direct_rejection.revision, confirmed_revision)
        direct_hypothesis = next(
            item
            for item in after_direct_rejection.hypotheses
            if item.id == "H-unreferenced"
        )
        self.assertEqual(
            direct_hypothesis.statement,
            "unrelated open hypothesis",
        )
        self.assertIs(
            direct_hypothesis.status,
            HypothesisStatus.CONFIRMED,
        )
        self.assertEqual(direct_hypothesis.evidence_fact_ids, [fact_id])
        payload = _payload(Role.FALSIFIER)
        payload.update(
            {
                "observations": [],
                "hypotheses": [],
                "hypothesis_updates": [
                    {
                        "hypothesis_id": "H-existing",
                        "statement": "revised after the probe",
                        "falsifier": None,
                        "status": "supported",
                        "evidence_fact_ids": [fact_id],
                        "evidence_artifact_ids": [],
                        "evidence_run_ids": [],
                        "confidence": 0.7,
                        "refuted_by": None,
                    },
                    {
                        "hypothesis_id": "H-unreferenced",
                        "statement": "attempted post-hoc confirmation",
                        "falsifier": None,
                        "status": "confirmed",
                        "evidence_fact_ids": [fact_id],
                        "evidence_artifact_ids": [],
                        "evidence_run_ids": [],
                        "confidence": 0.9,
                        "refuted_by": None,
                    }
                ],
                "evaluations": [
                    {
                        "experiment_id": experiment_id,
                        "status": "dropped",
                        "reason": "the probe contradicted the prediction",
                        "evidence_fact_ids": [fact_id],
                        "evidence_artifact_ids": [],
                        "evidence_run_ids": [],
                        "support_hypothesis_ids": [],
                        "refute_hypothesis_ids": ["H-existing"],
                    }
                ],
                "actions": [],
                "progress_markers": [],
            }
        )
        executor.payload = payload

        result = engine.run_role(
            self.identity,
            Role.FALSIFIER,
            instruction="falsify the existing hypothesis",
        )
        self.assertTrue(result.validation.valid)
        state = engine.store.load(self.identity)
        hypothesis = next(
            item for item in state.hypotheses if item.id == "H-existing"
        )
        experiment = next(
            item for item in state.experiments if item.id == experiment_id
        )
        unreferenced = next(
            item
            for item in state.hypotheses
            if item.id == "H-unreferenced"
        )
        self.assertEqual(hypothesis.statement, "original statement")
        self.assertIs(hypothesis.status, HypothesisStatus.REFUTED)
        self.assertEqual(hypothesis.refuted_by, experiment_id)
        self.assertIs(experiment.status, ExperimentStatus.DROPPED)
        self.assertEqual(
            unreferenced.statement,
            "unrelated open hypothesis",
        )
        self.assertIs(unreferenced.status, HypothesisStatus.CONFIRMED)
        self.assertEqual(unreferenced.evidence_fact_ids, [fact_id])
        falsifier_run = next(
            item for item in state.runs
            if item.role == Role.FALSIFIER.value
        )
        self.assertEqual(
            {
                item["hypothesis_id"]
                for item in falsifier_run.extra[
                    "rejected_hypothesis_updates"
                ]
            },
            {"H-existing", "H-unreferenced"},
        )

    def test_batch_unknown_semantic_references_are_contained_per_item(
        self,
    ) -> None:
        class InvalidReferenceExecutor:
            def run(
                inner_self,
                command,
                *,
                cwd,
                timeout,
                on_stdout_line,
            ):
                del inner_self, cwd, timeout, on_stdout_line
                role = _role_for(command)
                self.assertIs(role, Role.CAPTAIN)
                payload = _payload(role)
                payload["hypothesis_updates"] = [
                    {
                        "hypothesis_id": "H-missing",
                        "statement": None,
                        "falsifier": None,
                        "status": "open",
                        "evidence_fact_ids": [],
                        "evidence_artifact_ids": [],
                        "evidence_run_ids": [],
                        "confidence": None,
                        "refuted_by": None,
                    }
                ]
                payload["evaluations"] = [
                    {
                        "experiment_id": "E-missing",
                        "status": "failed",
                        "reason": "the referenced experiment is absent",
                        "evidence_fact_ids": [],
                        "evidence_artifact_ids": [],
                        "evidence_run_ids": [],
                        "support_hypothesis_ids": [],
                        "refute_hypothesis_ids": [],
                    }
                ]
                payload["goal_update"] = {
                    "action": "activate",
                    "goal_id": "G-missing",
                    "description": None,
                    "depends_on": [],
                    "artifact_ids": [],
                    "blocked_reason": None,
                    "activate": False,
                }
                _output_path(command).write_text(
                    json.dumps(payload),
                    encoding="utf-8",
                )
                return ProcessOutcome(0, "", 0.01)

        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=InvalidReferenceExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=lambda state, work, policy: FakeSandbox(work),
        )
        before = engine.add_challenge(self.identity, prompt="solve")

        result = engine.run_role(
            self.identity,
            Role.CAPTAIN,
            instruction="propose bounded next state",
        )

        self.assertTrue(result.validation.valid)
        state = engine.store.load(self.identity)
        self.assertGreater(state.revision, before.revision)
        captain_run = next(
            run for run in state.runs if run.role == Role.CAPTAIN.value
        )
        self.assertEqual(
            captain_run.extra["rejected_hypothesis_updates"][0][
                "hypothesis_id"
            ],
            "H-missing",
        )
        self.assertEqual(
            captain_run.extra["rejected_evaluations"][0][
                "experiment_id"
            ],
            "E-missing",
        )
        self.assertEqual(
            captain_run.extra["rejected_goal_updates"][0]["goal_id"],
            "G-missing",
        )
        self.assertTrue(
            any(
                fact.source_run_id == captain_run.id
                for fact in state.facts
            )
        )

    def test_tool_raw_streams_are_snapshotted_before_workspace_mutation(
        self,
    ) -> None:
        class RawOnlyFlagSandbox(FakeSandbox):
            def run(inner_self, spec):
                inner_self.specs.append(spec)
                raw = inner_self.work / "raw"
                raw.mkdir(exist_ok=True)
                stdout = raw / "stdout.log"
                stderr = raw / "stderr.log"
                stdout.write_text(
                    "bounded prefix\nKCTF{raw_stream_only}\n",
                    encoding="utf-8",
                )
                stderr.write_text("diagnostic\n", encoding="utf-8")
                return SandboxResult(
                    "tool-raw",
                    "completed",
                    0,
                    False,
                    5,
                    "bounded prefix",
                    "diagnostic",
                    stdout.stat().st_size,
                    stderr.stat().st_size,
                    "/work/raw/stdout.log",
                    "/work/raw/stderr.log",
                )

        holder: dict[str, RawOnlyFlagSandbox] = {}

        def sandbox_factory(state, work, policy):
            del state, policy
            holder.setdefault("client", RawOnlyFlagSandbox(work))
            return holder["client"]

        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=sandbox_factory,
        )
        engine.add_challenge(self.identity, prompt="solve")
        _state, experiment_id = engine.register_experiment(
            self.identity,
            command=("true",),
            expected_observation="exit zero",
            keep_if="zero",
            drop_if="nonzero",
        )

        state = engine.execute_registered_experiments(self.identity)

        tool_run = next(run for run in state.runs if run.role == "tool")
        artifacts = [
            artifact
            for artifact in state.artifacts
            if artifact.source_run_id == tool_run.id
        ]
        self.assertEqual(len(artifacts), 2)
        self.assertTrue(
            all(
                artifact.path.startswith("artifacts/snapshots/")
                for artifact in artifacts
            )
        )
        self.assertCountEqual(
            [
                artifact.extra.get("source_locator")
                for artifact in artifacts
            ],
            ["raw/stdout.log", "raw/stderr.log"],
        )
        self.assertTrue(
            any(
                candidate.value == "KCTF{raw_stream_only}"
                for candidate in state.candidates
            )
        )
        paths = engine.store.challenge_paths(self.identity)
        snapshots = {
            artifact.extra["source_locator"]: paths.root / artifact.path
            for artifact in artifacts
        }
        self.assertIn(
            "KCTF{raw_stream_only}",
            snapshots["raw/stdout.log"].read_text(encoding="utf-8"),
        )
        self.assertTrue(
            all(
                snapshot.stat().st_mode & 0o222 == 0
                for snapshot in snapshots.values()
            )
        )

        raw = holder["client"].work / "raw"
        (raw / "stdout.log").write_text("mutated", encoding="utf-8")
        (raw / "stderr.log").write_text("mutated", encoding="utf-8")
        verified = engine.store.verify_artifacts(self.identity)
        self.assertEqual(
            verified[artifacts[0].id],
            paths.root / artifacts[0].path,
        )
        committed = engine.store.update(
            self.identity,
            lambda current: current.metadata.update(
                {"post_tool_snapshot_commit": True}
            ),
        )
        self.assertTrue(committed.metadata["post_tool_snapshot_commit"])

    def test_tool_stdout_snapshot_race_fails_without_misbound_evidence(
        self,
    ) -> None:
        class MutatingRegistrationSandbox(FakeSandbox):
            def register_artifact(
                inner_self,
                locator,
                *,
                maximum_bytes=1 << 34,
            ):
                reference = super().register_artifact(
                    locator,
                    maximum_bytes=maximum_bytes,
                )
                if locator == "raw/stdout.log":
                    (inner_self.work / locator).write_bytes(
                        b"mutated after sandbox registration"
                    )
                return reference

        def sandbox_factory(state, work, policy):
            del state, policy
            return MutatingRegistrationSandbox(work)

        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=sandbox_factory,
        )
        engine.add_challenge(self.identity, prompt="solve")
        _state, experiment_id = engine.register_experiment(
            self.identity,
            command=("true",),
            expected_observation="exit zero",
            keep_if="zero",
            drop_if="nonzero",
        )

        state = engine.execute_registered_experiments(self.identity)

        experiment = next(
            item
            for item in state.experiments
            if item.id == experiment_id
        )
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        self.assertIn(
            "stdout evidence snapshot is unavailable",
            experiment.result["error"],
        )
        tool_run = next(run for run in state.runs if run.role == "tool")
        self.assertIs(tool_run.status, RunStatus.FAILED)
        self.assertFalse(
            any(
                artifact.source_run_id == tool_run.id
                for artifact in state.artifacts
            )
        )
        self.assertFalse(
            any(
                fact.source_run_id == tool_run.id
                for fact in state.facts
            )
        )

    def test_receipt_summary_failure_cleans_snapshot_handoff(
        self,
    ) -> None:
        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=(
                lambda state, work, policy: FakeSandbox(work)
            ),
        )
        engine.add_challenge(
            self.identity,
            prompt="solve",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        _state, experiment_id = engine.register_experiment(
            self.identity,
            command=("true",),
            expected_observation="exit zero",
            keep_if="zero",
            drop_if="nonzero",
        )
        pending_artifacts: list[ArtifactReference] = []
        pending_context: dict[str, object] = {}

        with mock.patch(
            "ctf_os.engine.challenge.summarize_stream_snapshot",
            side_effect=ReceiptSummaryError(
                "synthetic receipt summary failure"
            ),
        ):
            state = engine.execute_registered_experiments(
                self.identity,
                experiment_ids=(experiment_id,),
                _pending_artifact_handoff=pending_artifacts,
                _pending_tool_context=pending_context,
            )

        experiment = next(
            item
            for item in state.experiments
            if item.id == experiment_id
        )
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        self.assertIn(
            "tool stream evidence summary failed",
            experiment.result["error"],
        )
        tool_run = next(run for run in state.runs if run.role == "tool")
        self.assertIs(tool_run.status, RunStatus.FAILED)
        self.assertFalse(
            any(
                artifact.source_run_id == tool_run.id
                for artifact in state.artifacts
            )
        )
        failure_receipt = next(
            receipt
            for receipt in state.receipts
            if receipt.run_id == tool_run.id
        )
        self.assertIsNone(failure_receipt.stdout_artifact_id)
        self.assertIsNone(failure_receipt.stderr_artifact_id)
        self.assertNotIn(
            "stream_evidence",
            failure_receipt.extra,
        )
        snapshots = (
            engine.store.challenge_paths(self.identity).artifacts
            / "snapshots"
        )
        self.assertEqual(list(snapshots.glob("*.log")), [])
        self.assertEqual(pending_artifacts, [])
        self.assertEqual(pending_context, {})

    def test_missing_stdout_diagnostic_failure_cleans_stderr_snapshot(
        self,
    ) -> None:
        class MissingStdoutSandbox(FakeSandbox):
            def register_artifact(
                inner_self,
                locator,
                *,
                maximum_bytes=1 << 34,
            ):
                reference = super().register_artifact(
                    locator,
                    maximum_bytes=maximum_bytes,
                )
                if locator == "raw/stdout.log":
                    (inner_self.work / locator).write_bytes(
                        b"mutated after sandbox registration"
                    )
                return reference

        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=(
                lambda state, work, policy: MissingStdoutSandbox(work)
            ),
        )
        engine.add_challenge(self.identity, prompt="solve")
        _state, experiment_id = engine.register_experiment(
            self.identity,
            command=("true",),
            expected_observation="exit zero",
            keep_if="zero",
            drop_if="nonzero",
        )

        with (
            mock.patch.object(
                engine.store,
                "write_run_result",
                side_effect=OSError("diagnostic filesystem unavailable"),
            ),
            self.assertRaisesRegex(
                OSError,
                "diagnostic filesystem unavailable",
            ),
        ):
            engine.execute_registered_experiments(
                self.identity,
                experiment_ids=(experiment_id,),
            )

        failed = engine.store.load(self.identity)
        experiment = next(
            item
            for item in failed.experiments
            if item.id == experiment_id
        )
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        tool_run = next(run for run in failed.runs if run.role == "tool")
        self.assertIs(tool_run.status, RunStatus.FAILED)
        self.assertFalse(
            any(
                artifact.source_run_id == tool_run.id
                for artifact in failed.artifacts
            )
        )
        snapshots = (
            engine.store.challenge_paths(self.identity).artifacts
            / "snapshots"
        )
        self.assertEqual(
            list(snapshots.glob("*.log")),
            [],
        )

    def test_tool_run_setup_failure_releases_lease_and_finishes_experiment(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(self.identity, prompt="solve")
        state, experiment_id = engine.register_experiment(
            self.identity,
            command=("true",),
            expected_observation="exit zero",
            keep_if="zero",
            drop_if="nonzero",
        )
        self.assertEqual(
            next(
                item
                for item in state.experiments
                if item.id == experiment_id
            ).status,
            ExperimentStatus.REGISTERED,
        )

        with mock.patch.object(
            engine.store,
            "create_run",
            side_effect=OSError("synthetic create failure"),
        ):
            state = engine.execute_registered_experiments(self.identity)

        experiment = next(
            item
            for item in state.experiments
            if item.id == experiment_id
        )
        self.assertEqual(experiment.status, ExperimentStatus.FAILED)
        self.assertIn("could not create tool run", experiment.result["error"])
        self.assertTrue(engine.lease_broker.status().used.is_empty())

    def test_tool_run_setup_interrupt_terminalizes_and_releases_once(
        self,
    ) -> None:
        class CountingLease:
            lease_id = "lease-setup-interrupt"

            def __init__(inner_self) -> None:
                inner_self.released = False
                inner_self.release_calls = 0

            def release(inner_self) -> None:
                inner_self.release_calls += 1
                inner_self.released = True

        class CountingBroker:
            def __init__(inner_self) -> None:
                inner_self.lease = CountingLease()

            def acquire(inner_self, request, *, timeout, owner):
                del request, timeout, owner
                return inner_self.lease

        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(self.identity, prompt="solve")
        _state, experiment_id = engine.register_experiment(
            self.identity,
            command=("true",),
            expected_observation="exit zero",
            keep_if="zero",
            drop_if="nonzero",
        )
        broker = CountingBroker()
        engine.lease_broker = broker  # type: ignore[assignment]
        interruption = KeyboardInterrupt("synthetic setup interrupt")

        with (
            mock.patch.object(
                engine.store,
                "create_run",
                side_effect=interruption,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            engine.execute_registered_experiments(
                self.identity,
                experiment_ids=(experiment_id,),
            )

        self.assertIs(raised.exception, interruption)
        self.assertTrue(broker.lease.released)
        self.assertEqual(broker.lease.release_calls, 1)
        state = engine.store.load(self.identity)
        experiment = next(
            item
            for item in state.experiments
            if item.id == experiment_id
        )
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        tool_run = next(run for run in state.runs if run.role == "tool")
        self.assertIs(tool_run.status, RunStatus.FAILED)

    def test_tool_sandbox_interrupt_terminalizes_and_releases_once(
        self,
    ) -> None:
        interruption = SystemExit(23)

        class InterruptingSandbox(FakeSandbox):
            def run(inner_self, spec):
                inner_self.specs.append(spec)
                raise interruption

        class CountingLease:
            lease_id = "lease-sandbox-interrupt"

            def __init__(inner_self) -> None:
                inner_self.released = False
                inner_self.release_calls = 0

            def release(inner_self) -> None:
                inner_self.release_calls += 1
                inner_self.released = True

        class CountingBroker:
            def __init__(inner_self) -> None:
                inner_self.lease = CountingLease()

            def acquire(inner_self, request, *, timeout, owner):
                del request, timeout, owner
                return inner_self.lease

        engine = self.engine_with_executor(RoleExecutor())
        engine._sandbox_factory = (  # type: ignore[assignment]
            lambda state, work, policy: InterruptingSandbox(work)
        )
        engine.add_challenge(self.identity, prompt="solve")
        _state, experiment_id = engine.register_experiment(
            self.identity,
            command=("true",),
            expected_observation="exit zero",
            keep_if="zero",
            drop_if="nonzero",
        )
        broker = CountingBroker()
        engine.lease_broker = broker  # type: ignore[assignment]

        with self.assertRaises(SystemExit) as raised:
            engine.execute_registered_experiments(
                self.identity,
                experiment_ids=(experiment_id,),
            )

        self.assertIs(raised.exception, interruption)
        self.assertTrue(broker.lease.released)
        self.assertEqual(broker.lease.release_calls, 1)
        state = engine.store.load(self.identity)
        experiment = next(
            item
            for item in state.experiments
            if item.id == experiment_id
        )
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        tool_run = next(run for run in state.runs if run.role == "tool")
        self.assertIs(tool_run.status, RunStatus.FAILED)

    def test_tool_postprocess_interrupts_terminalize_and_clean_exact_artifacts(
        self,
    ) -> None:
        class CleanSandbox(FakeSandbox):
            def run(inner_self, spec):
                inner_self.specs.append(spec)
                raw = inner_self.work / "raw"
                raw.mkdir(exist_ok=True)
                stdout = raw / "stdout.log"
                stderr = raw / "stderr.log"
                stdout.write_text("ordinary output\n", encoding="utf-8")
                stderr.write_text("", encoding="utf-8")
                return SandboxResult(
                    "tool-postprocess",
                    "completed",
                    0,
                    False,
                    5,
                    "ordinary output",
                    "",
                    stdout.stat().st_size,
                    0,
                    "/work/raw/stdout.log",
                    "/work/raw/stderr.log",
                )

        stages = (
            "detector",
            "snapshot",
            "post-snapshot",
            "scan",
            "post-evidence-loop",
            "result",
            "post-result",
            "commit-before",
            "commit-after",
        )
        for stage in stages:
            with self.subTest(stage=stage):
                root = self.root / stage
                engine = ChallengeEngine(
                    root,
                    batch_runner=BatchRunner(
                        process_executor=RoleExecutor(),
                        max_schema_retries=0,
                    ),
                    sandbox_factory=(
                        lambda state, work, policy: CleanSandbox(work)
                    ),
                )
                engine.add_challenge(self.identity, prompt="solve")
                _state, experiment_id = engine.register_experiment(
                    self.identity,
                    command=("true",),
                    expected_observation="exit zero",
                    keep_if="zero",
                    drop_if="nonzero",
                )
                interruption = KeyboardInterrupt(
                    f"synthetic {stage} interruption"
                )

                if stage == "detector":
                    patcher = mock.patch.object(
                        FlagDetector,
                        "feed",
                        side_effect=interruption,
                    )
                elif stage == "snapshot":
                    real_snapshot = engine._snapshot_workspace_file

                    def snapshot_then_interrupt(*args, **kwargs):
                        real_snapshot(*args, **kwargs)
                        raise interruption

                    patcher = mock.patch.object(
                        engine,
                        "_snapshot_workspace_file",
                        side_effect=snapshot_then_interrupt,
                    )
                elif stage == "post-snapshot":
                    real_artifact_reference = ArtifactReference

                    def artifact_then_interrupt(*args, **kwargs):
                        if kwargs.get("sha256") != "0" * 64:
                            raise interruption
                        return real_artifact_reference(*args, **kwargs)

                    patcher = mock.patch(
                        "ctf_os.engine.challenge.ArtifactReference",
                        side_effect=artifact_then_interrupt,
                    )
                elif stage == "scan":
                    patcher = mock.patch.object(
                        FlagDetector,
                        "scan_file",
                        side_effect=interruption,
                    )
                elif stage == "post-evidence-loop":
                    patcher = _interrupt_on_source_line(
                        ChallengeEngine.execute_registered_experiments,
                        "if not artifact_notification_failed:",
                        interruption,
                    )
                elif stage == "result":
                    patcher = mock.patch.object(
                        engine.store,
                        "write_run_result",
                        side_effect=interruption,
                    )
                elif stage == "post-result":
                    patcher = _interrupt_on_source_line(
                        ChallengeEngine.execute_registered_experiments,
                        (
                            'result_fact_id = _record_id("F", '
                            'engine_run_id, "result")'
                        ),
                        interruption,
                    )
                else:
                    real_update = engine.store.update
                    interrupted = False

                    def interrupt_finish(
                        identity,
                        mutator,
                        *args,
                        **kwargs,
                    ):
                        nonlocal interrupted
                        if (
                            not interrupted
                            and getattr(mutator, "__name__", "") == "finish"
                        ):
                            interrupted = True
                            if stage == "commit-after":
                                real_update(
                                    identity,
                                    mutator,
                                    *args,
                                    **kwargs,
                                )
                            raise interruption
                        return real_update(
                            identity,
                            mutator,
                            *args,
                            **kwargs,
                        )

                    patcher = mock.patch.object(
                        engine.store,
                        "update",
                        side_effect=interrupt_finish,
                    )

                with (
                    patcher,
                    self.assertRaises(KeyboardInterrupt) as raised,
                ):
                    engine.execute_registered_experiments(
                        self.identity,
                        experiment_ids=(experiment_id,),
                    )

                self.assertIs(raised.exception, interruption)
                state = engine.store.load(self.identity)
                experiment = next(
                    item
                    for item in state.experiments
                    if item.id == experiment_id
                )
                snapshots = (
                    engine.store.challenge_paths(self.identity).artifacts
                    / "snapshots"
                )
                snapshot_files = (
                    list(snapshots.glob("*.log"))
                    if snapshots.exists()
                    else []
                )
                if stage == "commit-after":
                    self.assertIs(
                        experiment.status,
                        ExperimentStatus.AWAITING_EVALUATION,
                    )
                    self.assertEqual(len(state.artifacts), 2)
                    self.assertEqual(len(snapshot_files), 2)
                    self.assertTrue(
                        any(
                            run.role == "tool"
                            and run.status is RunStatus.COMPLETED
                            for run in state.runs
                        )
                    )
                else:
                    self.assertIs(
                        experiment.status,
                        ExperimentStatus.FAILED,
                    )
                    self.assertEqual(state.artifacts, [])
                    self.assertEqual(snapshot_files, [])
                    self.assertTrue(
                        any(
                            run.role == "tool"
                            and run.status is RunStatus.FAILED
                            for run in state.runs
                        )
                    )

    def test_tool_lease_acquire_failure_does_not_strand_running(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(self.identity, prompt="solve")
        _state, experiment_id = engine.register_experiment(
            self.identity,
            command=("true",),
            expected_observation="exit zero",
            keep_if="zero",
            drop_if="nonzero",
        )

        with (
            mock.patch.object(
                engine.lease_broker,
                "acquire",
                side_effect=OSError("lease state unavailable"),
            ),
            self.assertRaisesRegex(OSError, "lease state unavailable"),
        ):
            engine.execute_registered_experiments(self.identity)

        state = engine.store.load(self.identity)
        experiment = next(
            item
            for item in state.experiments
            if item.id == experiment_id
        )
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        self.assertIn(
            "could not acquire host tool resources",
            experiment.result["error"],
        )
        self.assertFalse(
            any(
                item.status is ExperimentStatus.RUNNING
                for item in state.experiments
            )
        )

    def test_tool_lease_release_failure_does_not_strand_running(
        self,
    ) -> None:
        class ReleaseFailingLease:
            lease_id = "lease-release-failure"
            released = False

            def release(inner_self):
                raise OSError("lease release unavailable")

        class ReleaseFailingBroker:
            def acquire(inner_self, request, *, timeout, owner):
                del inner_self, request, timeout, owner
                return ReleaseFailingLease()

        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(self.identity, prompt="solve")
        _state, experiment_id = engine.register_experiment(
            self.identity,
            command=("true",),
            expected_observation="exit zero",
            keep_if="zero",
            drop_if="nonzero",
        )
        engine.lease_broker = ReleaseFailingBroker()  # type: ignore[assignment]

        with self.assertRaisesRegex(OSError, "lease release unavailable"):
            engine.execute_registered_experiments(self.identity)

        state = engine.store.load(self.identity)
        experiment = next(
            item
            for item in state.experiments
            if item.id == experiment_id
        )
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        self.assertIn(
            "lease release failed",
            experiment.result["error"],
        )
        self.assertEqual(
            sum(
                run.role == "tool" and run.status is RunStatus.FAILED
                for run in state.runs
            ),
            1,
        )
        self.assertFalse(
            any(
                item.status is ExperimentStatus.RUNNING
                for item in state.experiments
            )
        )

    def test_mid_tool_budget_reset_charges_only_post_reset_time(
        self,
    ) -> None:
        engine_holder: dict[str, ChallengeEngine] = {}

        class ResettingSandbox(FakeSandbox):
            def run(inner_self, spec):
                time.sleep(1.05)
                engine_holder["engine"].reset_budget(
                    self.identity,
                    seconds=100,
                )
                time.sleep(0.05)
                return super().run(spec)

        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=(
                lambda state, work, policy: ResettingSandbox(work)
            ),
        )
        engine_holder["engine"] = engine
        engine.add_challenge(
            self.identity,
            prompt="solve",
            budget_seconds=100,
        )
        _state, experiment_id = engine.register_experiment(
            self.identity,
            command=("true",),
            expected_observation="exit zero",
            keep_if="zero",
            drop_if="nonzero",
        )

        state = engine.execute_registered_experiments(
            self.identity,
            experiment_ids=(experiment_id,),
        )

        self.assertEqual(state.budget.spent_seconds, 0)
        tool_run = next(run for run in state.runs if run.role == "tool")
        self.assertGreater(tool_run.extra["wall_seconds"], 1.0)

    def test_tool_completion_reconciles_a_concurrent_candidate_update(
        self,
    ) -> None:
        holder: dict[str, FakeSandbox] = {}
        engine: ChallengeEngine

        class ConcurrentUpdateSandbox(FakeSandbox):
            def run(inner_self, spec):
                engine.record_candidate(
                    self.identity,
                    "KCTF{operator_during_tool}",
                    print_immediately=False,
                )
                return super().run(spec)

        def sandbox_factory(state, work, policy):
            del state, policy
            holder.setdefault("client", ConcurrentUpdateSandbox(work))
            return holder["client"]

        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=sandbox_factory,
        )
        engine.add_challenge(self.identity, prompt="solve")
        _state, experiment_id = engine.register_experiment(
            self.identity,
            command=("true",),
            expected_observation="exit zero",
            keep_if="zero",
            drop_if="nonzero",
        )

        state = engine.execute_registered_experiments(self.identity)

        experiment = next(
            item
            for item in state.experiments
            if item.id == experiment_id
        )
        self.assertEqual(
            experiment.status,
            ExperimentStatus.AWAITING_EVALUATION,
        )
        self.assertTrue(
            any(
                item.value == "KCTF{operator_during_tool}"
                for item in state.candidates
            )
        )
        tool_run = next(run for run in state.runs if run.role == "tool")
        paths = engine.store.challenge_paths(self.identity)
        request_payload = json.loads(
            (paths.root / str(tool_run.request_path)).read_text(
                encoding="utf-8"
            )
        )
        result_payload = json.loads(
            (paths.root / str(tool_run.result_path)).read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            request_payload["base_revision"],
            tool_run.base_revision,
        )
        self.assertEqual(
            result_payload["base_revision"],
            tool_run.base_revision,
        )
        tool_spec = holder["client"].specs[0]
        self.assertIsNotNone(tool_spec.deadline_monotonic_seconds)
        self.assertEqual(
            json.loads(tool_spec.environment[FLAG_PATTERNS_ENV]),
            list(engine.config.runtime.flag_patterns),
        )

    def test_background_tool_start_is_rejected_before_registration(self) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        state = engine.add_challenge(self.identity, prompt="solve")
        before_count = len(state.experiments)
        for command in (
            ("ctf-bg", "--", "sleep", "60"),
            ("setsid", "sleep", "60"),
            ("sh", "-c", "sleep 60 &"),
            ("bash", "-lc", "nohup sleep 60"),
        ):
            with self.subTest(command=command):
                with self.assertRaisesRegex(EngineError, "background|detached"):
                    engine.register_experiment(
                        self.identity,
                        command=command,
                        expected_observation="never",
                        keep_if="never",
                        drop_if="always",
                    )
        after = engine.store.load(self.identity)
        self.assertEqual(len(after.experiments), before_count)

    def test_tool_lease_vector_is_passed_to_the_same_sandbox_run(self) -> None:
        holder: dict[str, FakeSandbox] = {}

        def sandbox_factory(state, work, policy):
            del state, policy
            holder.setdefault("client", FakeSandbox(work))
            return holder["client"]

        config = load_config(self.root)
        config = replace(
            config,
            runtime=replace(config.runtime, image_digest=IMAGE_DIGEST),
        )
        engine = ChallengeEngine(
            self.root,
            config=config,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=sandbox_factory,
        )
        engine.add_challenge(self.identity, prompt="solve")
        engine.run_tool_command(
            self.identity,
            ("true",),
            resource_class="gpu",
            needs_kvm=True,
        )
        spec = holder["client"].specs[-1]
        self.assertEqual(spec.resource_request.cpu, 4)
        self.assertEqual(spec.resource_request.memory_mib, 10 * 1024)
        self.assertEqual(spec.resource_request.gpu, 1)
        self.assertEqual(spec.resource_request.kvm, 1)
        self.assertEqual(spec.resource_request.network, 0)
        state = engine.store.load(self.identity)
        tool_run = state.runs[-1]
        request = json.loads(
            (
                engine.store.challenge_paths(self.identity).root
                / str(tool_run.request_path)
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(request["image"], "ctf-os:core")
        self.assertEqual(request["image_digest"], IMAGE_DIGEST)
        self.assertEqual(request["image_reference"], IMAGE_DIGEST)

    def test_repeated_tool_commit_stalls_with_one_recovery_suggestion(
        self,
    ) -> None:
        holder: dict[str, FakeSandbox] = {}

        def sandbox_factory(state, work, policy):
            del state, policy
            holder.setdefault("client", FakeSandbox(work))
            return holder["client"]

        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=sandbox_factory,
        )
        engine.add_challenge(self.identity, prompt="solve")
        engine.transition(self.identity, ChallengeStatus.TRIAGING)
        engine.transition(self.identity, ChallengeStatus.ACTIVE)

        for _number in range(3):
            state = engine.run_tool_command(self.identity, ("true",))

        self.assertEqual(state.status, ChallengeStatus.STALLED)
        governor = state.metadata[GOVERNOR_METADATA_KEY]
        self.assertEqual(
            governor["signals"],
            [StallSignal.REPEATED_COMMAND.value],
        )
        self.assertEqual(
            governor["recovery_action"],
            RecoveryAction.CHANGE_OBSERVATION_LAYER.value,
        )
        self.assertEqual(
            governor["attempted_recovery_actions"],
            [],
        )
        self.assertEqual(len(holder["client"].specs), 3)

    def test_registered_execution_can_defer_stall_without_changing_default(
        self,
    ) -> None:
        holder: dict[str, FakeSandbox] = {}

        def sandbox_factory(state, work, policy):
            del state, policy
            holder.setdefault("client", FakeSandbox(work))
            return holder["client"]

        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=sandbox_factory,
        )
        engine.add_challenge(self.identity, prompt="solve")
        engine.transition(self.identity, ChallengeStatus.TRIAGING)
        engine.transition(self.identity, ChallengeStatus.ACTIVE)

        for _number in range(3):
            _state, experiment_id = engine.register_experiment(
                self.identity,
                command=("true",),
                expected_observation="command exits",
                keep_if="exit is zero",
                drop_if="command fails",
            )
            state = engine.execute_registered_experiments(
                self.identity,
                experiment_ids=(experiment_id,),
                _record_stall=False,
            )
            self.assertEqual(state.status, ChallengeStatus.ACTIVE)

        _state, experiment_id = engine.register_experiment(
            self.identity,
            command=("true",),
            expected_observation="command exits",
            keep_if="exit is zero",
            drop_if="command fails",
        )
        state = engine.execute_registered_experiments(
            self.identity,
            experiment_ids=(experiment_id,),
        )

        self.assertEqual(state.status, ChallengeStatus.STALLED)
        self.assertEqual(
            state.metadata[GOVERNOR_METADATA_KEY]["signals"],
            [StallSignal.REPEATED_COMMAND.value],
        )
        self.assertEqual(len(holder["client"].specs), 4)

    def test_clean_proof_gates_ready_and_human_submission_is_recorded(self) -> None:
        holder: dict[str, FakeSandbox] = {}

        def sandbox_factory(state, work, policy):
            del state, policy
            holder.setdefault("client", FakeSandbox(work))
            return holder["client"]

        config = load_config(self.root)
        config = replace(
            config,
            runtime=replace(config.runtime, image_digest=IMAGE_DIGEST),
        )
        engine = ChallengeEngine(
            self.root,
            config=config,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=sandbox_factory,
        )
        engine.add_challenge(self.identity, prompt="solve")
        state = engine.record_candidate(
            self.identity,
            "KCTF{proof_flag}",
            print_immediately=False,
        )
        candidate_id = state.candidates[0].id
        state, proof = engine.prove_candidate(
            self.identity,
            candidate_id,
            ("./reproduce.sh",),
        )
        self.assertTrue(proof.passed)
        self.assertEqual(state.status.value, "READY_TO_SUBMIT")
        self.assertEqual(holder["client"].proof_calls, 3)
        self.assertTrue(holder["client"].proof_specs)
        for proof_spec in holder["client"].proof_specs:
            self.assertIsNotNone(
                proof_spec.deadline_monotonic_seconds
            )
            self.assertEqual(
                json.loads(proof_spec.environment[FLAG_PATTERNS_ENV]),
                list(engine.config.runtime.flag_patterns),
            )
        root = engine.store.challenge_paths(self.identity).root
        for run in state.runs:
            request = json.loads(
                (root / str(run.request_path)).read_text(encoding="utf-8")
            )
            self.assertEqual(request["image_reference"], IMAGE_DIGEST)
        result_artifact = next(
            artifact
            for artifact in state.artifacts
            if artifact.path.endswith("/result.json")
        )
        environment = json.loads(
            (root / result_artifact.path)
            .with_name("environment.json")
            .read_text(encoding="utf-8")
        )
        self.assertEqual(environment["image_reference"], IMAGE_DIGEST)
        state = engine.record_manual_submission(
            self.identity,
            candidate_id,
            outcome="accepted",
            response="correct",
        )
        self.assertEqual(state.status.value, "SOLVED")
        history = engine.store.load_contest_submissions(
            self.identity.contest_id
        )
        self.assertEqual(history[0]["status"], "accepted")
        with self.assertRaisesRegex(
            WorkerResultValidationError,
            "accepted candidate outcome is immutable",
        ):
            engine.record_manual_submission(
                self.identity,
                candidate_id,
                outcome="rejected",
                response="stale contradictory response",
            )
        immutable = engine.store.load(self.identity)
        self.assertIs(immutable.status, ChallengeStatus.SOLVED)
        self.assertIs(
            immutable.candidates[0].status,
            CandidateStatus.ACCEPTED,
        )
        self.assertEqual(
            [
                item["status"]
                for item in engine.store.load_contest_submissions(
                    self.identity.contest_id
                )
            ],
            ["accepted"],
        )

    def test_proof_persists_and_prints_other_detected_candidates(
        self,
    ) -> None:
        class AdditionalCandidateSandbox(FakeSandbox):
            def run_clean_proof(
                inner_self,
                spec,
                *,
                input_locators=(),
                proof_inputs=(),
            ):
                result = super().run_clean_proof(
                    spec,
                    input_locators=input_locators,
                    proof_inputs=proof_inputs,
                )
                stdout = inner_self.work / result.stdout_path.removeprefix(
                    "/work/"
                )
                with stdout.open("a", encoding="utf-8") as stream:
                    stream.write("KCTF{proof_alternate}\n")
                return replace(
                    result,
                    stdout_summary=stdout.read_text(encoding="utf-8"),
                    stdout_bytes=stdout.stat().st_size,
                )

        holder: dict[str, AdditionalCandidateSandbox] = {}

        def sandbox_factory(state, work, policy):
            del state, policy
            holder.setdefault(
                "client", AdditionalCandidateSandbox(work)
            )
            return holder["client"]

        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=sandbox_factory,
        )
        engine.add_challenge(self.identity, prompt="solve")
        state = engine.record_candidate(
            self.identity,
            "KCTF{proof_flag}",
            print_immediately=False,
        )
        callback_values: list[str] = []
        real_callback = engine._on_tool_flag

        def observe_committed_candidate(
            identity: ChallengeIdentity,
            detected,
        ) -> None:
            current = engine.store.load(self.identity)
            if (
                detected.value == "KCTF{proof_alternate}"
                and detected.value not in callback_values
            ):
                self.assertFalse(
                    any(
                        candidate.value == detected.value
                        for candidate in current.candidates
                    )
                )
            self.assertTrue(
                any(
                    intent["value"] == detected.value
                    for intent in engine.store.load_candidate_intents(
                        self.identity
                    )
                )
            )
            callback_values.append(detected.value)
            real_callback(identity, detected)

        terminal = io.StringIO()
        with mock.patch.object(
            engine,
            "_on_tool_flag",
            side_effect=observe_committed_candidate,
        ), redirect_stderr(terminal):
            state, proof = engine.prove_candidate(
                self.identity,
                state.candidates[0].id,
                ("./reproduce.sh",),
            )

        self.assertTrue(proof.passed)
        alternate = next(
            candidate
            for candidate in state.candidates
            if candidate.value == "KCTF{proof_alternate}"
        )
        proof_run_ids = {
            run.id for run in state.runs if run.role == "proof"
        }
        self.assertIn(alternate.source_run_id, proof_run_ids)
        self.assertIn("KCTF{proof_alternate}", callback_values)
        self.assertIn("KCTF{proof_alternate}", terminal.getvalue())
        self.assertEqual(
            engine.store.load_candidate_intents(self.identity),
            (),
        )

    def test_blocking_proof_notifies_after_durable_intent_before_return(
        self,
    ) -> None:
        early_candidate = "KCTF{proof_before_return}"

        class BlockingProofSandbox(FakeSandbox):
            def __init__(inner_self, work: Path) -> None:
                super().__init__(work)
                inner_self.command_blocked = threading.Event()
                inner_self.release_command = threading.Event()

            def run_clean_proof(
                inner_self,
                spec,
                *,
                input_locators=(),
                proof_inputs=(),
            ):
                live_run = (
                    inner_self.work.parent
                    / PROOF_LIVE_DIRECTORY
                    / "clean-012345abcdef-abcdefgh"
                    / ".ctf"
                    / "runs"
                    / "run-00000001"
                )
                live_run.mkdir(parents=True)
                private_root = (
                    inner_self.work.parent / PROOF_LIVE_DIRECTORY
                )
                current = private_root
                while True:
                    current.chmod(0o700)
                    if current == live_run:
                        break
                    current = next(
                        child
                        for child in current.iterdir()
                        if child.is_dir()
                    )
                stdout = live_run / "stdout.log"
                stderr = live_run / "stderr.log"
                sidecar = live_run / FLAG_CANDIDATE_SIDECAR
                stdout.write_text(
                    "proof still running\n",
                    encoding="utf-8",
                )
                stderr.write_text(
                    "",
                    encoding="utf-8",
                )
                sidecar.write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "kind": "flag_candidate",
                            "stream": "stdout",
                            "value": early_candidate,
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
                for path in (stdout, stderr, sidecar):
                    path.chmod(0o600)
                inner_self.command_blocked.set()
                if not inner_self.release_command.wait(5):
                    raise AssertionError("proof test release timed out")
                return super().run_clean_proof(
                    spec,
                    input_locators=input_locators,
                    proof_inputs=proof_inputs,
                )

        holder: dict[str, BlockingProofSandbox] = {}

        def sandbox_factory(state, work, policy):
            del state, policy
            holder.setdefault("client", BlockingProofSandbox(work))
            return holder["client"]

        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=sandbox_factory,
        )
        engine.add_challenge(self.identity, prompt="solve")
        state = engine.record_candidate(
            self.identity,
            "KCTF{proof_flag}",
            print_immediately=False,
        )
        candidate_id = state.candidates[0].id
        notified = threading.Event()
        real_callback = engine._on_tool_flag
        callback_state: list[tuple[bool, bool]] = []

        def observe_intent_before_print(identity, detected) -> None:
            if detected.value == early_candidate:
                intent_present = any(
                    intent["value"] == early_candidate
                    for intent in engine.store.load_candidate_intents(
                        self.identity
                    )
                )
                canonical_present = any(
                    candidate.value == early_candidate
                    for candidate in engine.store.load(
                        self.identity
                    ).candidates
                )
                callback_state.append(
                    (intent_present, canonical_present)
                )
                notified.set()
            real_callback(identity, detected)

        results: list[tuple[ChallengeState, object]] = []
        errors: list[BaseException] = []

        def run_proof() -> None:
            try:
                results.append(
                    engine.prove_candidate(
                        self.identity,
                        candidate_id,
                        ("./reproduce.sh",),
                        repetitions=1,
                    )
                )
            except BaseException as error:
                errors.append(error)

        sandbox = engine.sandbox(engine.store.load(self.identity))
        self.assertIsInstance(sandbox, BlockingProofSandbox)
        terminal = io.StringIO()
        thread = threading.Thread(target=run_proof)
        with (
            mock.patch.object(
                engine,
                "_on_tool_flag",
                side_effect=observe_intent_before_print,
            ),
            redirect_stderr(terminal),
        ):
            thread.start()
            try:
                self.assertTrue(sandbox.command_blocked.wait(2))
                self.assertTrue(notified.wait(2))
                self.assertTrue(thread.is_alive())
                self.assertIn(early_candidate, terminal.getvalue())
                self.assertEqual(callback_state, [(True, False)])
                self.assertEqual(
                    engine.store.load(self.identity).submissions,
                    [],
                )
            finally:
                sandbox.release_command.set()
                thread.join(5)

        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 1)
        committed = results[0][0]
        self.assertTrue(
            any(
                candidate.value == early_candidate
                for candidate in committed.candidates
            )
        )
        self.assertEqual(committed.submissions, [])
        self.assertEqual(
            engine.store.load_candidate_intents(self.identity),
            (),
        )

    def test_proof_final_sidecar_survives_raw_scan_cap_and_commits_candidate(
        self,
    ) -> None:
        selected_candidate = "KCTF{proof_flag}"
        late_candidate = "KCTF{proof_after_raw_prefix}"

        class FinalSidecarSandbox(FakeSandbox):
            def run_clean_proof(
                inner_self,
                spec,
                *,
                input_locators=(),
                proof_inputs=(),
            ):
                del input_locators, proof_inputs
                inner_self.proof_specs.append(spec)
                inner_self.proof_calls += 1
                relative = Path("proof") / "clean-fedcba987654"
                directory = inner_self.work / relative
                directory.mkdir(parents=True, mode=0o700)
                (inner_self.work / "proof").chmod(0o700)
                directory.chmod(0o700)
                stdout = directory / "stdout.log"
                stderr = directory / "stderr.log"
                stdout.write_bytes(b"x" * 64)
                stderr.write_bytes(b"")
                sidecar = directory / FLAG_CANDIDATE_SIDECAR
                sidecar.write_text(
                    "".join(
                        json.dumps(
                            {
                                "schema_version": 1,
                                "kind": "flag_candidate",
                                "stream": "stdout",
                                "value": value,
                            }
                        )
                        + "\n"
                        for value in (
                            selected_candidate,
                            late_candidate,
                        )
                    ),
                    encoding="utf-8",
                )
                for path in (stdout, stderr, sidecar):
                    path.chmod(0o600)
                return SandboxResult(
                    "proof-1",
                    "completed",
                    0,
                    False,
                    5,
                    "xxxxxxxx",
                    "",
                    stdout.stat().st_size,
                    0,
                    f"/work/{relative.as_posix()}/stdout.log",
                    f"/work/{relative.as_posix()}/stderr.log",
                )

        config = load_config(self.root)
        config = replace(
            config,
            runtime=replace(
                config.runtime,
                flag_scan_max_bytes=8,
            ),
        )
        engine = ChallengeEngine(
            self.root,
            config=config,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=(
                lambda state, work, policy: FinalSidecarSandbox(work)
            ),
        )
        engine.add_challenge(self.identity, prompt="solve")
        state = engine.record_candidate(
            self.identity,
            selected_candidate,
            print_immediately=False,
        )
        terminal = io.StringIO()
        with redirect_stderr(terminal):
            committed, proof = engine.prove_candidate(
                self.identity,
                state.candidates[0].id,
                ("./reproduce.sh",),
                repetitions=1,
            )

        self.assertFalse(proof.passed)
        self.assertIs(committed.status, ChallengeStatus.ACTIVE)
        selected = next(
            candidate
            for candidate in committed.candidates
            if candidate.value == selected_candidate
        )
        self.assertIs(
            selected.status,
            CandidateStatus.OBSERVED_CANDIDATE,
        )
        self.assertIn(selected_candidate, terminal.getvalue())
        self.assertIn(late_candidate, terminal.getvalue())
        self.assertTrue(
            any(
                candidate.value == late_candidate
                for candidate in committed.candidates
            )
        )
        self.assertEqual(committed.submissions, [])
        self.assertEqual(
            engine.store.load_candidate_intents(self.identity),
            (),
        )

    def test_proof_result_persistence_failure_cleans_evidence_snapshots(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(self.identity, prompt="solve")
        state = engine.record_candidate(
            self.identity,
            "KCTF{proof_flag}",
            print_immediately=False,
        )
        candidate_id = state.candidates[0].id

        with (
            mock.patch.object(
                engine.store,
                "write_run_result",
                side_effect=OSError("proof result storage unavailable"),
            ),
            self.assertRaisesRegex(
                OSError,
                "proof result storage unavailable",
            ),
        ):
            engine.prove_candidate(
                self.identity,
                candidate_id,
                ("./reproduce.sh",),
                repetitions=1,
            )

        failed = engine.store.load(self.identity)
        self.assertIs(failed.status, ChallengeStatus.PROVING)
        self.assertFalse(any(run.role == "proof" for run in failed.runs))
        self.assertTrue(
            any(
                intent["value"] == "KCTF{proof_flag}"
                for intent in engine.store.load_candidate_intents(
                    self.identity
                )
            )
        )
        proof_root = engine.store.challenge_paths(self.identity).proof
        self.assertEqual(
            [
                path
                for path in proof_root.rglob("*")
                if path.is_file()
                and path.name in {"stdout.log", "stderr.log"}
            ],
            [],
        )

    def test_proof_input_interrupts_clean_or_preserve_exact_files(
        self,
    ) -> None:
        for stage in (
            "snapshot",
            "handoff",
            "commit-before",
            "commit-after",
        ):
            with self.subTest(stage=stage):
                root = self.root / f"proof-input-{stage}"
                engine = ChallengeEngine(
                    root,
                    batch_runner=BatchRunner(
                        process_executor=RoleExecutor(),
                        max_schema_retries=0,
                    ),
                    sandbox_factory=(
                        lambda state, work, policy: FakeSandbox(work)
                    ),
                )
                state = engine.add_challenge(self.identity, prompt="solve")
                paths = engine.store.challenge_paths(self.identity)
                workspace = paths.artifacts / "workspace"
                workspace.mkdir(parents=True, exist_ok=True)
                (workspace / "input.bin").write_bytes(b"proof input")
                state = engine.record_candidate(
                    self.identity,
                    "KCTF{proof_flag}",
                    print_immediately=False,
                )
                interruption = KeyboardInterrupt(
                    f"synthetic proof input {stage} interruption"
                )

                if stage == "snapshot":
                    real_snapshot = engine._snapshot_workspace_file

                    def snapshot_then_interrupt(*args, **kwargs):
                        snapshot = real_snapshot(*args, **kwargs)
                        raise interruption

                    patcher = mock.patch.object(
                        engine,
                        "_snapshot_workspace_file",
                        side_effect=snapshot_then_interrupt,
                    )
                elif stage == "handoff":
                    real_prepare = engine._prepare_proof_inputs

                    def prepare_then_interrupt(*args, **kwargs):
                        real_prepare(*args, **kwargs)
                        raise interruption

                    patcher = mock.patch.object(
                        engine,
                        "_prepare_proof_inputs",
                        side_effect=prepare_then_interrupt,
                    )
                else:
                    real_update = engine.store.update
                    interrupted = False

                    def interrupt_input_commit(
                        identity,
                        mutator,
                        *args,
                        **kwargs,
                    ):
                        nonlocal interrupted
                        if (
                            not interrupted
                            and getattr(mutator, "__name__", "")
                            == "register_proof_inputs"
                        ):
                            interrupted = True
                            if stage == "commit-after":
                                real_update(
                                    identity,
                                    mutator,
                                    *args,
                                    **kwargs,
                                )
                            raise interruption
                        return real_update(
                            identity,
                            mutator,
                            *args,
                            **kwargs,
                        )

                    patcher = mock.patch.object(
                        engine.store,
                        "update",
                        side_effect=interrupt_input_commit,
                    )

                with (
                    patcher,
                    self.assertRaises(KeyboardInterrupt) as raised,
                ):
                    engine.prove_candidate(
                        self.identity,
                        state.candidates[0].id,
                        ("./reproduce.sh",),
                        input_locators=("input.bin",),
                        repetitions=1,
                    )

                self.assertIs(raised.exception, interruption)
                committed = engine.store.load(self.identity)
                canonical_paths = {
                    artifact.path for artifact in committed.artifacts
                }
                proof_files = {
                    path.relative_to(paths.root).as_posix()
                    for path in paths.proof.rglob("*")
                    if path.is_file()
                }
                self.assertEqual(proof_files, canonical_paths)
                self.assertEqual(
                    len(committed.artifacts),
                    2 if stage == "commit-after" else 0,
                )
                self.assertEqual(
                    list(workspace.glob(".ctfos-proof-inputs-*")),
                    [],
                )

    def test_tool_recoverable_post_snapshot_error_cleans_exact_file(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(self.identity, prompt="solve")
        _state, experiment_id = engine.register_experiment(
            self.identity,
            command=("true",),
            expected_observation="exit zero",
            keep_if="zero",
            drop_if="nonzero",
        )
        real_snapshot = engine._snapshot_workspace_file

        def snapshot_then_error(*args, **kwargs):
            real_snapshot(*args, **kwargs)
            raise EngineError("synthetic post-snapshot evidence error")

        with mock.patch.object(
            engine,
            "_snapshot_workspace_file",
            side_effect=snapshot_then_error,
        ):
            state = engine.execute_registered_experiments(
                self.identity,
                experiment_ids=(experiment_id,),
            )

        experiment = next(
            item for item in state.experiments if item.id == experiment_id
        )
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        self.assertEqual(state.artifacts, [])
        snapshots = engine.store.challenge_paths(
            self.identity
        ).artifacts / "snapshots"
        self.assertEqual(
            [path for path in snapshots.rglob("*") if path.is_file()],
            [],
        )

    def test_proof_evidence_snapshot_interrupt_cleans_pending_file(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(self.identity, prompt="solve")
        state = engine.record_candidate(
            self.identity,
            "KCTF{proof_flag}",
            print_immediately=False,
        )
        paths = engine.store.challenge_paths(self.identity)
        real_snapshot = engine._snapshot_workspace_file
        interruption = KeyboardInterrupt(
            "synthetic proof evidence snapshot interruption"
        )

        def evidence_snapshot_then_interrupt(*args, **kwargs):
            snapshot = real_snapshot(*args, **kwargs)
            destination = Path(args[3])
            if "evidence" in destination.parts:
                raise interruption
            return snapshot

        with (
            mock.patch.object(
                engine,
                "_snapshot_workspace_file",
                side_effect=evidence_snapshot_then_interrupt,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            engine.prove_candidate(
                self.identity,
                state.candidates[0].id,
                ("./reproduce.sh",),
                repetitions=1,
            )

        self.assertIs(raised.exception, interruption)
        committed = engine.store.load(self.identity)
        canonical_paths = {artifact.path for artifact in committed.artifacts}
        proof_files = {
            path.relative_to(paths.root).as_posix()
            for path in paths.proof.rglob("*")
            if path.is_file()
        }
        self.assertEqual(proof_files, canonical_paths)
        self.assertFalse(
            any("/evidence/" in path for path in proof_files)
        )

    def test_proof_recoverable_post_snapshot_error_cleans_exact_file(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(self.identity, prompt="solve")
        state = engine.record_candidate(
            self.identity,
            "KCTF{proof_flag}",
            print_immediately=False,
        )
        paths = engine.store.challenge_paths(self.identity)
        real_snapshot = engine._snapshot_workspace_file

        def evidence_snapshot_then_error(*args, **kwargs):
            snapshot = real_snapshot(*args, **kwargs)
            destination = Path(args[3])
            if "evidence" in destination.parts:
                raise EngineError(
                    "synthetic post-snapshot proof evidence error"
                )
            return snapshot

        with mock.patch.object(
            engine,
            "_snapshot_workspace_file",
            side_effect=evidence_snapshot_then_error,
        ):
            committed, proof = engine.prove_candidate(
                self.identity,
                state.candidates[0].id,
                ("./reproduce.sh",),
                repetitions=1,
            )

        self.assertFalse(proof.passed)
        self.assertFalse(
            any("/evidence/" in artifact.path for artifact in committed.artifacts)
        )
        self.assertEqual(
            [
                path
                for path in paths.proof.rglob("*")
                if path.is_file()
                and path.name in {"stdout.log", "stderr.log"}
            ],
            [],
        )

    def test_proof_attempt_interrupts_clean_before_and_preserve_after_commit(
        self,
    ) -> None:
        stages = (
            "post-evidence",
            "result-before",
            "result-after",
            "post-result",
            "state-before",
            "state-after",
        )
        for stage in stages:
            with self.subTest(stage=stage):
                root = self.root / f"proof-attempt-{stage}"
                engine = ChallengeEngine(
                    root,
                    batch_runner=BatchRunner(
                        process_executor=RoleExecutor(),
                        max_schema_retries=0,
                    ),
                    sandbox_factory=(
                        lambda state, work, policy: FakeSandbox(work)
                    ),
                )
                engine.add_challenge(self.identity, prompt="solve")
                state = engine.record_candidate(
                    self.identity,
                    "KCTF{proof_flag}",
                    print_immediately=False,
                )
                paths = engine.store.challenge_paths(self.identity)
                interruption = KeyboardInterrupt(
                    f"synthetic proof attempt {stage} interruption"
                )

                if stage == "post-evidence":
                    patcher = _interrupt_on_source_line(
                        ChallengeEngine.prove_candidate,
                        "attempt = ProofAttempt(",
                        interruption,
                    )
                elif stage == "post-result":
                    patcher = _interrupt_on_source_line(
                        ChallengeEngine.prove_candidate,
                        "attempt_run_reference = RunReference(",
                        interruption,
                    )
                elif stage.startswith("result-"):
                    real_write = engine.store.write_run_result

                    def interrupt_result(*args, **kwargs):
                        if stage == "result-after":
                            real_write(*args, **kwargs)
                        raise interruption

                    patcher = mock.patch.object(
                        engine.store,
                        "write_run_result",
                        side_effect=interrupt_result,
                    )
                else:
                    real_update = engine.store.update
                    interrupted = False

                    def interrupt_attempt_commit(
                        identity,
                        mutator,
                        *args,
                        **kwargs,
                    ):
                        nonlocal interrupted
                        if (
                            not interrupted
                            and getattr(mutator, "__name__", "")
                            == "record_attempt"
                        ):
                            interrupted = True
                            if stage == "state-after":
                                real_update(
                                    identity,
                                    mutator,
                                    *args,
                                    **kwargs,
                                )
                            raise interruption
                        return real_update(
                            identity,
                            mutator,
                            *args,
                            **kwargs,
                        )

                    patcher = mock.patch.object(
                        engine.store,
                        "update",
                        side_effect=interrupt_attempt_commit,
                    )

                with (
                    patcher,
                    self.assertRaises(KeyboardInterrupt) as raised,
                ):
                    engine.prove_candidate(
                        self.identity,
                        state.candidates[0].id,
                        ("./reproduce.sh",),
                        repetitions=1,
                    )

                self.assertIs(raised.exception, interruption)
                committed = engine.store.load(self.identity)
                canonical_paths = {
                    artifact.path for artifact in committed.artifacts
                }
                proof_files = {
                    path.relative_to(paths.root).as_posix()
                    for path in paths.proof.rglob("*")
                    if path.is_file()
                }
                self.assertEqual(proof_files, canonical_paths)
                proof_runs = [
                    run for run in committed.runs if run.role == "proof"
                ]
                self.assertEqual(
                    len(proof_runs),
                    1 if stage == "state-after" else 0,
                )
                self.assertEqual(
                    sum(
                        "/evidence/" in artifact.path
                        for artifact in committed.artifacts
                    ),
                    2 if stage == "state-after" else 0,
                )
                self.assertTrue(
                    any(
                        intent["value"] == "KCTF{proof_flag}"
                        for intent in engine.store.load_candidate_intents(
                            self.identity
                        )
                    )
                )

    def test_final_proof_interrupts_clean_before_and_preserve_after_commit(
        self,
    ) -> None:
        for stage in ("write", "commit-before", "commit-after"):
            with self.subTest(stage=stage):
                root = self.root / f"proof-final-{stage}"
                engine = ChallengeEngine(
                    root,
                    batch_runner=BatchRunner(
                        process_executor=RoleExecutor(),
                        max_schema_retries=0,
                    ),
                    sandbox_factory=(
                        lambda state, work, policy: FakeSandbox(work)
                    ),
                )
                engine.add_challenge(self.identity, prompt="solve")
                state = engine.record_candidate(
                    self.identity,
                    "KCTF{proof_flag}",
                    print_immediately=False,
                )
                paths = engine.store.challenge_paths(self.identity)
                interruption = KeyboardInterrupt(
                    f"synthetic final proof {stage} interruption"
                )

                if stage == "write":

                    def interrupt_proof_write(directory, result):
                        del result
                        directory.mkdir(parents=True, exist_ok=True)
                        (directory / ".result.json.tmp").write_text(
                            "partial",
                            encoding="utf-8",
                        )
                        raise interruption

                    patcher = mock.patch(
                        "ctf_os.engine.challenge.write_proof_result",
                        side_effect=interrupt_proof_write,
                    )
                else:
                    real_update = engine.store.update
                    interrupted = False

                    def interrupt_final_commit(
                        identity,
                        mutator,
                        *args,
                        **kwargs,
                    ):
                        nonlocal interrupted
                        if (
                            not interrupted
                            and getattr(mutator, "__name__", "")
                            == "apply_result"
                        ):
                            interrupted = True
                            if stage == "commit-after":
                                real_update(
                                    identity,
                                    mutator,
                                    *args,
                                    **kwargs,
                                )
                            raise interruption
                        return real_update(
                            identity,
                            mutator,
                            *args,
                            **kwargs,
                        )

                    patcher = mock.patch.object(
                        engine.store,
                        "update",
                        side_effect=interrupt_final_commit,
                    )

                with (
                    patcher,
                    self.assertRaises(KeyboardInterrupt) as raised,
                ):
                    engine.prove_candidate(
                        self.identity,
                        state.candidates[0].id,
                        ("./reproduce.sh",),
                        repetitions=1,
                    )

                self.assertIs(raised.exception, interruption)
                committed = engine.store.load(self.identity)
                result_artifacts = [
                    artifact
                    for artifact in committed.artifacts
                    if artifact.path.endswith("/result.json")
                ]
                result_files = list(paths.proof.rglob("result.json"))
                environment_files = list(
                    paths.proof.rglob("environment.json")
                )
                temporary_files = list(
                    paths.proof.rglob(".result.json.tmp")
                )
                self.assertEqual(
                    len(result_artifacts),
                    1 if stage == "commit-after" else 0,
                )
                self.assertEqual(
                    len(result_files),
                    1 if stage == "commit-after" else 0,
                )
                self.assertEqual(
                    len(environment_files),
                    1 if stage == "commit-after" else 0,
                )
                self.assertEqual(temporary_files, [])

    def test_proof_completion_cannot_overwrite_a_concurrent_pause(
        self,
    ) -> None:
        from ctf_os.engine.proof import (
            write_proof_result as real_write_result,
        )

        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(self.identity, prompt="solve")
        state = engine.record_candidate(
            self.identity,
            "KCTF{paused_during_proof}",
            print_immediately=False,
        )
        candidate_id = state.candidates[0].id
        result_paths: list[Path] = []

        def pause_after_result(directory, result):
            path = real_write_result(directory, result)
            result_paths.append(path)
            engine.pause(self.identity)
            return path

        with (
            mock.patch(
                "ctf_os.engine.challenge.write_proof_result",
                side_effect=pause_after_result,
            ),
            self.assertRaisesRegex(
                EngineError,
                "concurrent PAUSED",
            ),
        ):
            engine.prove_candidate(
                self.identity,
                candidate_id,
                ("./reproduce.sh",),
            )

        paused = engine.store.load(self.identity)
        self.assertIs(paused.status, ChallengeStatus.PAUSED)
        self.assertIs(paused.resume_status, ChallengeStatus.PROVING)
        candidate = next(
            item for item in paused.candidates if item.id == candidate_id
        )
        self.assertIs(
            candidate.status,
            CandidateStatus.OBSERVED_CANDIDATE,
        )
        self.assertTrue(candidate.proof_run_ids)
        self.assertEqual(len(result_paths), 1)
        self.assertFalse(result_paths[0].exists())
        root = engine.store.challenge_paths(self.identity).root
        self.assertTrue(paused.artifacts)
        self.assertTrue(
            all(
                (root / artifact.path).is_file()
                for artifact in paused.artifacts
            )
        )
        self.assertFalse(
            any(
                artifact.path
                == result_paths[0].relative_to(root).as_posix()
                for artifact in paused.artifacts
            )
        )

    def test_proof_repetitions_stop_after_the_first_committed_pause(
        self,
    ) -> None:
        holder: dict[str, FakeSandbox] = {}

        def sandbox_factory(state, work, policy):
            del state, policy
            holder.setdefault("client", FakeSandbox(work))
            return holder["client"]

        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=sandbox_factory,
        )
        engine.add_challenge(self.identity, prompt="solve")
        state = engine.record_candidate(
            self.identity,
            "KCTF{proof_flag}",
            print_immediately=False,
        )
        candidate_id = state.candidates[0].id
        real_update = engine.store.update
        paused_after_attempt = False

        def update_then_pause(identity, mutator, *args, **kwargs):
            nonlocal paused_after_attempt
            committed = real_update(identity, mutator, *args, **kwargs)
            if (
                not paused_after_attempt
                and getattr(mutator, "__name__", "") == "record_attempt"
            ):
                paused_after_attempt = True
                engine.pause(self.identity)
            return committed

        with (
            mock.patch.object(
                engine.store,
                "update",
                side_effect=update_then_pause,
            ),
            self.assertRaisesRegex(
                EngineError,
                "concurrent PAUSED",
            ),
        ):
            engine.prove_candidate(
                self.identity,
                candidate_id,
                ("./reproduce.sh",),
            )

        paused = engine.store.load(self.identity)
        self.assertIs(paused.status, ChallengeStatus.PAUSED)
        self.assertIs(paused.resume_status, ChallengeStatus.PROVING)
        self.assertEqual(holder["client"].proof_calls, 1)
        candidate = next(
            item for item in paused.candidates if item.id == candidate_id
        )
        self.assertEqual(len(candidate.proof_run_ids), 1)
        self.assertEqual(
            len([run for run in paused.runs if run.role == "proof"]),
            1,
        )

    def test_manual_rejection_cannot_be_overwritten_by_reproof(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(self.identity, prompt="solve")
        state = engine.record_candidate(
            self.identity,
            "KCTF{manually_rejected}",
            print_immediately=False,
        )
        candidate_id = state.candidates[0].id

        def mark_proving(current: ChallengeState) -> None:
            current.status = ChallengeStatus.PROVING

        proving = engine.store.update(self.identity, mark_proving)
        rejected = engine.record_manual_submission(
            self.identity,
            candidate_id,
            outcome="rejected",
            allow_unproved=True,
        )
        self.assertEqual(rejected.revision, proving.revision + 1)
        with self.assertRaisesRegex(
            EngineError,
            "manual terminal outcome",
        ):
            engine.prove_candidate(
                self.identity,
                candidate_id,
                ("./reproduce.sh",),
            )
        unchanged = engine.store.load(self.identity)
        self.assertIs(unchanged.status, ChallengeStatus.ACTIVE)
        self.assertIs(
            unchanged.candidates[0].status,
            CandidateStatus.REJECTED,
        )

    def test_proof_cannot_skip_new_to_triage_transition(self) -> None:
        holder: dict[str, FakeSandbox] = {}

        def sandbox_factory(state, work, policy):
            del state, policy
            holder.setdefault("client", FakeSandbox(work))
            return holder["client"]

        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=sandbox_factory,
        )
        engine.challenge_input(self.identity).mkdir(parents=True)
        engine.store.create_challenge(self.identity, prompt="solve")
        state = engine.record_candidate(
            self.identity,
            "KCTF{new_state_must_triage}",
            print_immediately=False,
        )

        with self.assertRaisesRegex(EngineError, "before triage"):
            engine.prove_candidate(
                self.identity,
                state.candidates[0].id,
                ("/bin/true",),
            )

        unchanged = engine.store.load(self.identity)
        self.assertIs(unchanged.status, ChallengeStatus.NEW)
        self.assertEqual(holder, {})

    def test_raw_new_state_pause_resumes_exactly_to_new(self) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        engine.challenge_input(self.identity).mkdir(parents=True)
        created = engine.store.create_challenge(
            self.identity,
            prompt="not triaged yet",
        )
        self.assertIs(created.status, ChallengeStatus.NEW)

        paused = engine.pause(self.identity)
        self.assertIs(paused.status, ChallengeStatus.PAUSED)
        self.assertIs(paused.resume_status, ChallengeStatus.NEW)

        resumed = engine.resume(self.identity)
        self.assertIs(resumed.status, ChallengeStatus.NEW)
        self.assertIsNone(resumed.resume_status)
        self.assertIsNone(resumed.active_goal)

    def test_session_boundary_recovers_orphaned_running_experiment(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(self.identity, prompt="solve")
        _state, experiment_id = engine.register_experiment(
            self.identity,
            command=("/bin/true",),
            expected_observation="exit zero",
            keep_if="zero",
            drop_if="nonzero",
        )

        def simulate_crash_after_mark_running(state):
            experiment = next(
                item
                for item in state.experiments
                if item.id == experiment_id
            )
            experiment.status = ExperimentStatus.RUNNING

        engine.store.update(
            self.identity,
            simulate_crash_after_mark_running,
        )

        recovered = engine.execute_registered_experiments(
            self.identity,
            experiment_ids=(experiment_id,),
        )
        experiment = next(
            item
            for item in recovered.experiments
            if item.id == experiment_id
        )
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        self.assertIn("orphaned tool execution", experiment.result["error"])
        self.assertIn("orphan_recovered_at", experiment.extra)
        self.assertFalse(
            any(
                item.status is ExperimentStatus.RUNNING
                for item in recovered.experiments
            )
        )

    def test_invalid_summary_candidate_does_not_strand_tool_run(
        self,
    ) -> None:
        class InvalidSummarySandbox(FakeSandbox):
            def run(inner_self, spec):
                inner_self.specs.append(spec)
                raw = inner_self.work / "invalid-summary"
                raw.mkdir(exist_ok=True)
                stdout = raw / "stdout.log"
                stderr = raw / "stderr.log"
                stdout.write_text("no candidate\n", encoding="utf-8")
                stderr.write_text("", encoding="utf-8")
                return SandboxResult(
                    "tool-invalid-summary",
                    "completed",
                    0,
                    False,
                    5,
                    "noise KCTF{bad\tflag}",
                    "",
                    stdout.stat().st_size,
                    0,
                    "/work/invalid-summary/stdout.log",
                    "/work/invalid-summary/stderr.log",
                )

        holder: dict[str, InvalidSummarySandbox] = {}

        def sandbox_factory(state, work, policy):
            del state, policy
            holder.setdefault("client", InvalidSummarySandbox(work))
            return holder["client"]

        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=sandbox_factory,
        )
        state = engine.add_challenge(self.identity, prompt="solve")
        state, experiment_id = engine.register_experiment(
            self.identity,
            command=("/bin/true",),
            expected_observation="exit zero",
            keep_if="zero",
            drop_if="nonzero",
        )

        completed = engine.execute_registered_experiments(
            self.identity,
            experiment_ids=(experiment_id,),
        )
        experiment = next(
            item
            for item in completed.experiments
            if item.id == experiment_id
        )
        self.assertIs(
            experiment.status,
            ExperimentStatus.AWAITING_EVALUATION,
        )
        self.assertEqual(completed.candidates, [])
        self.assertEqual(
            engine.store.load_candidate_intents(self.identity),
            (),
        )
        self.assertTrue(
            any(run.status is RunStatus.COMPLETED for run in completed.runs)
        )

    def test_summary_callback_failure_terminalizes_tool_run(
        self,
    ) -> None:
        class SummaryFlagSandbox(FakeSandbox):
            def run(inner_self, spec):
                inner_self.specs.append(spec)
                raw = inner_self.work / "summary-callback"
                raw.mkdir(exist_ok=True)
                stdout = raw / "stdout.log"
                stderr = raw / "stderr.log"
                stdout.write_text("no raw candidate\n", encoding="utf-8")
                stderr.write_text("", encoding="utf-8")
                return SandboxResult(
                    "tool-summary-callback",
                    "completed",
                    0,
                    False,
                    5,
                    "KCTF{summary_callback_failure}",
                    "",
                    stdout.stat().st_size,
                    0,
                    "/work/summary-callback/stdout.log",
                    "/work/summary-callback/stderr.log",
                )

        holder: dict[str, SummaryFlagSandbox] = {}

        def sandbox_factory(state, work, policy):
            del state, policy
            holder.setdefault("client", SummaryFlagSandbox(work))
            return holder["client"]

        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=sandbox_factory,
        )
        engine.add_challenge(self.identity, prompt="solve")
        _state, experiment_id = engine.register_experiment(
            self.identity,
            command=("/bin/true",),
            expected_observation="exit zero",
            keep_if="zero",
            drop_if="nonzero",
        )

        with mock.patch.object(
            engine.store,
            "record_candidate_intent",
            side_effect=WorkerResultValidationError(
                "synthetic intent failure"
            ),
        ):
            failed = engine.execute_registered_experiments(
                self.identity,
                experiment_ids=(experiment_id,),
            )

        experiment = next(
            item for item in failed.experiments if item.id == experiment_id
        )
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        self.assertIn("flag notification failed", str(experiment.result))
        self.assertTrue(
            any(run.status is RunStatus.FAILED for run in failed.runs)
        )
        self.assertFalse(
            any(
                item.status is ExperimentStatus.RUNNING
                for item in failed.experiments
            )
        )

    def test_live_tailer_notification_failure_is_fatal_and_terminal(
        self,
    ) -> None:
        callback_attempted = threading.Event()

        class LiveOnlyFlagSandbox(FakeSandbox):
            def run(inner_self, spec):
                inner_self.specs.append(spec)
                raw = (
                    inner_self.work
                    / ".ctf"
                    / "runs"
                    / "run-00000001"
                )
                raw.mkdir(parents=True)
                stdout = raw / "stdout.log"
                stderr = raw / "stderr.log"
                stdout.write_text(
                    "KCTF{live_only_notification_failure}\n",
                    encoding="utf-8",
                )
                stderr.write_text("", encoding="utf-8")
                if not callback_attempted.wait(1):
                    raise AssertionError(
                        "live flag tailer did not observe the candidate"
                    )
                return SandboxResult(
                    "tool-live-only-callback",
                    "completed",
                    0,
                    False,
                    5,
                    "clean summary",
                    "",
                    stdout.stat().st_size,
                    0,
                    "/work/.ctf/runs/run-00000001/stdout.log",
                    "/work/.ctf/runs/run-00000001/stderr.log",
                )

        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=(
                lambda state, work, policy: LiveOnlyFlagSandbox(work)
            ),
        )
        engine.add_challenge(self.identity, prompt="solve")
        _state, experiment_id = engine.register_experiment(
            self.identity,
            command=("/bin/true",),
            expected_observation="exit zero",
            keep_if="zero",
            drop_if="nonzero",
        )

        def fail_intent(*_args, **_kwargs):
            callback_attempted.set()
            raise OSError("candidate intent unavailable")

        with (
            mock.patch.object(
                engine.store,
                "record_candidate_intent",
                side_effect=fail_intent,
            ),
            self.assertRaisesRegex(
                FlagNotificationError,
                "candidate notification failed",
            ),
        ):
            engine.execute_registered_experiments(
                self.identity,
                experiment_ids=(experiment_id,),
            )

        failed = engine.store.load(self.identity)
        experiment = next(
            item for item in failed.experiments if item.id == experiment_id
        )
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        self.assertIn("flag notification failed", experiment.result["error"])
        self.assertEqual(failed.candidates, [])
        self.assertEqual(
            engine.store.load_candidate_intents(self.identity),
            (),
        )
        self.assertEqual(
            sum(
                run.role == "tool" and run.status is RunStatus.FAILED
                for run in failed.runs
            ),
            1,
        )

    def test_artifact_scan_callback_failure_terminalizes_tool_run(
        self,
    ) -> None:
        class ArtifactOnlyFlagSandbox(FakeSandbox):
            def run(inner_self, spec):
                inner_self.specs.append(spec)
                raw = inner_self.work / "artifact-only-callback"
                raw.mkdir(exist_ok=True)
                stdout = raw / "stdout.log"
                stderr = raw / "stderr.log"
                stdout.write_text(
                    "KCTF{artifact_only_callback_failure}\n",
                    encoding="utf-8",
                )
                stderr.write_text("", encoding="utf-8")
                return SandboxResult(
                    "tool-artifact-callback",
                    "completed",
                    0,
                    False,
                    5,
                    "clean summary",
                    "",
                    stdout.stat().st_size,
                    0,
                    "/work/artifact-only-callback/stdout.log",
                    "/work/artifact-only-callback/stderr.log",
                )

        holder: dict[str, ArtifactOnlyFlagSandbox] = {}

        def sandbox_factory(state, work, policy):
            del state, policy
            holder.setdefault(
                "client",
                ArtifactOnlyFlagSandbox(work),
            )
            return holder["client"]

        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=sandbox_factory,
        )
        engine.add_challenge(self.identity, prompt="solve")
        _state, experiment_id = engine.register_experiment(
            self.identity,
            command=("/bin/true",),
            expected_observation="exit zero",
            keep_if="zero",
            drop_if="nonzero",
        )

        with mock.patch.object(
            engine.store,
            "record_candidate_intent",
            side_effect=RuntimeError("corrupt intent journal"),
        ):
            failed = engine.execute_registered_experiments(
                self.identity,
                experiment_ids=(experiment_id,),
            )

        experiment = next(
            item for item in failed.experiments if item.id == experiment_id
        )
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        self.assertTrue(
            any(run.status is RunStatus.FAILED for run in failed.runs)
        )
        self.assertEqual(failed.candidates, [])
        self.assertEqual(failed.artifacts, [])
        self.assertEqual(
            engine.store.load_candidate_intents(self.identity),
            (),
        )
        self.assertFalse(
            any(
                item.status is ExperimentStatus.RUNNING
                for item in failed.experiments
            )
        )

    def test_sandbox_and_diagnostic_write_failures_do_not_strand_running(
        self,
    ) -> None:
        class FailingSandbox(FakeSandbox):
            def run(inner_self, spec):
                inner_self.specs.append(spec)
                raise RuntimeError("synthetic sandbox failure")

        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=(
                lambda state, work, policy: FailingSandbox(work)
            ),
        )
        engine.add_challenge(self.identity, prompt="solve")
        _state, experiment_id = engine.register_experiment(
            self.identity,
            command=("/bin/true",),
            expected_observation="exit zero",
            keep_if="zero",
            drop_if="nonzero",
        )

        with (
            mock.patch.object(
                engine.store,
                "write_run_result",
                side_effect=OSError("diagnostic filesystem unavailable"),
            ),
            self.assertRaisesRegex(
                OSError,
                "diagnostic filesystem unavailable",
            ),
        ):
            engine.execute_registered_experiments(
                self.identity,
                experiment_ids=(experiment_id,),
            )

        failed = engine.store.load(self.identity)
        experiment = next(
            item for item in failed.experiments if item.id == experiment_id
        )
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        self.assertEqual(
            sum(
                run.role == "tool" and run.status is RunStatus.FAILED
                for run in failed.runs
            ),
            1,
        )
        self.assertFalse(
            any(
                item.status is ExperimentStatus.RUNNING
                for item in failed.experiments
            )
        )

    def test_summary_callback_and_diagnostic_write_failures_do_not_strand_running(
        self,
    ) -> None:
        class SummaryFlagSandbox(FakeSandbox):
            def run(inner_self, spec):
                inner_self.specs.append(spec)
                raw = inner_self.work / "summary-double-failure"
                raw.mkdir(exist_ok=True)
                stdout = raw / "stdout.log"
                stderr = raw / "stderr.log"
                stdout.write_text("ordinary output\n", encoding="utf-8")
                stderr.write_text("", encoding="utf-8")
                return SandboxResult(
                    "tool-summary-double-failure",
                    "completed",
                    0,
                    False,
                    5,
                    "KCTF{summary_double_failure}",
                    "",
                    stdout.stat().st_size,
                    0,
                    "/work/summary-double-failure/stdout.log",
                    "/work/summary-double-failure/stderr.log",
                )

        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=(
                lambda state, work, policy: SummaryFlagSandbox(work)
            ),
        )
        engine.add_challenge(self.identity, prompt="solve")
        _state, experiment_id = engine.register_experiment(
            self.identity,
            command=("/bin/true",),
            expected_observation="exit zero",
            keep_if="zero",
            drop_if="nonzero",
        )

        with (
            mock.patch.object(
                engine.store,
                "record_candidate_intent",
                side_effect=WorkerResultValidationError(
                    "synthetic intent failure"
                ),
            ),
            mock.patch.object(
                engine.store,
                "write_run_result",
                side_effect=OSError("diagnostic filesystem unavailable"),
            ),
            self.assertRaisesRegex(
                OSError,
                "diagnostic filesystem unavailable",
            ),
        ):
            engine.execute_registered_experiments(
                self.identity,
                experiment_ids=(experiment_id,),
            )

        failed = engine.store.load(self.identity)
        experiment = next(
            item for item in failed.experiments if item.id == experiment_id
        )
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        self.assertEqual(
            sum(
                run.role == "tool" and run.status is RunStatus.FAILED
                for run in failed.runs
            ),
            1,
        )
        self.assertFalse(
            any(
                item.status is ExperimentStatus.RUNNING
                for item in failed.experiments
            )
        )

    def test_artifact_callback_and_diagnostic_write_failures_do_not_strand_running(
        self,
    ) -> None:
        class ArtifactFlagSandbox(FakeSandbox):
            def run(inner_self, spec):
                inner_self.specs.append(spec)
                raw = inner_self.work / "artifact-double-failure"
                raw.mkdir(exist_ok=True)
                stdout = raw / "stdout.log"
                stderr = raw / "stderr.log"
                stdout.write_text(
                    "KCTF{artifact_double_failure}\n",
                    encoding="utf-8",
                )
                stderr.write_text("", encoding="utf-8")
                return SandboxResult(
                    "tool-artifact-double-failure",
                    "completed",
                    0,
                    False,
                    5,
                    "ordinary summary",
                    "",
                    stdout.stat().st_size,
                    0,
                    "/work/artifact-double-failure/stdout.log",
                    "/work/artifact-double-failure/stderr.log",
                )

        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=(
                lambda state, work, policy: ArtifactFlagSandbox(work)
            ),
        )
        engine.add_challenge(self.identity, prompt="solve")
        _state, experiment_id = engine.register_experiment(
            self.identity,
            command=("/bin/true",),
            expected_observation="exit zero",
            keep_if="zero",
            drop_if="nonzero",
        )

        with (
            mock.patch.object(
                engine.store,
                "record_candidate_intent",
                side_effect=RuntimeError("corrupt intent journal"),
            ),
            mock.patch.object(
                engine.store,
                "write_run_result",
                side_effect=OSError("diagnostic filesystem unavailable"),
            ),
            self.assertRaisesRegex(
                OSError,
                "diagnostic filesystem unavailable",
            ),
        ):
            engine.execute_registered_experiments(
                self.identity,
                experiment_ids=(experiment_id,),
            )

        failed = engine.store.load(self.identity)
        experiment = next(
            item for item in failed.experiments if item.id == experiment_id
        )
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        self.assertEqual(
            sum(
                run.role == "tool" and run.status is RunStatus.FAILED
                for run in failed.runs
            ),
            1,
        )
        self.assertFalse(
            any(
                item.status is ExperimentStatus.RUNNING
                for item in failed.experiments
            )
        )

    def test_tool_result_write_failure_does_not_strand_running(
        self,
    ) -> None:
        class CleanSandbox(FakeSandbox):
            def run(inner_self, spec):
                inner_self.specs.append(spec)
                raw = inner_self.work / "clean-result-write"
                raw.mkdir(exist_ok=True)
                stdout = raw / "stdout.log"
                stderr = raw / "stderr.log"
                stdout.write_text("ordinary output\n", encoding="utf-8")
                stderr.write_text("", encoding="utf-8")
                return SandboxResult(
                    "tool-result-write",
                    "completed",
                    0,
                    False,
                    5,
                    "ordinary output",
                    "",
                    stdout.stat().st_size,
                    0,
                    "/work/clean-result-write/stdout.log",
                    "/work/clean-result-write/stderr.log",
                )

        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=(
                lambda state, work, policy: CleanSandbox(work)
            ),
        )
        engine.add_challenge(self.identity, prompt="solve")
        _state, experiment_id = engine.register_experiment(
            self.identity,
            command=("/bin/true",),
            expected_observation="exit zero",
            keep_if="zero",
            drop_if="nonzero",
        )

        with (
            mock.patch.object(
                engine.store,
                "write_run_result",
                side_effect=OSError("result filesystem unavailable"),
            ),
            self.assertRaisesRegex(OSError, "filesystem unavailable"),
        ):
            engine.execute_registered_experiments(
                self.identity,
                experiment_ids=(experiment_id,),
            )

        failed = engine.store.load(self.identity)
        experiment = next(
            item for item in failed.experiments if item.id == experiment_id
        )
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        self.assertFalse(
            any(
                item.status is ExperimentStatus.RUNNING
                for item in failed.experiments
            )
        )
        failed_tool_runs = [
            run
            for run in failed.runs
            if run.role == "tool" and run.status is RunStatus.FAILED
        ]
        self.assertEqual(len(failed_tool_runs), 1)
        self.assertEqual(failed.artifacts, [])

    def test_tool_finish_uses_minimal_terminal_state_at_state_cap(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(self.identity, prompt="solve")
        _state, experiment_id = engine.register_experiment(
            self.identity,
            command=("/bin/true",),
            expected_observation="exit zero",
            keep_if="zero",
            drop_if="nonzero",
        )
        real_update = engine.store.update
        rejected_finish = False
        rejected_detailed_failure = False

        def cap_updates(identity, mutator, *args, **kwargs):
            nonlocal rejected_finish, rejected_detailed_failure
            name = getattr(mutator, "__name__", "")
            if name == "finish" and not rejected_finish:
                rejected_finish = True
                raise WorkerResultValidationError(
                    "canonical state JSON exceeds test cap"
                )
            if (
                rejected_finish
                and name == "apply"
                and not rejected_detailed_failure
            ):
                rejected_detailed_failure = True
                raise WorkerResultValidationError(
                    "detailed failure state exceeds test cap"
                )
            return real_update(identity, mutator, *args, **kwargs)

        with (
            mock.patch.object(
                engine.store,
                "update",
                side_effect=cap_updates,
            ),
            self.assertRaisesRegex(
                WorkerResultValidationError,
                "canonical state JSON",
            ),
        ):
            engine.execute_registered_experiments(
                self.identity,
                experiment_ids=(experiment_id,),
            )

        failed = engine.store.load(self.identity)
        experiment = next(
            item for item in failed.experiments if item.id == experiment_id
        )
        self.assertTrue(rejected_finish)
        self.assertTrue(rejected_detailed_failure)
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        self.assertIsNone(experiment.result)
        self.assertFalse(
            any(
                item.status is ExperimentStatus.RUNNING
                for item in failed.experiments
            )
        )

    def test_workspace_artifact_registration_creates_immutable_snapshot(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        state = engine.add_challenge(self.identity, prompt="solve")
        paths = engine.store.challenge_paths(state.identity)
        workspace = paths.artifacts / "workspace"
        workspace.mkdir(parents=True, exist_ok=True)
        source = workspace / "report.txt"
        source.write_text("first version", encoding="utf-8")

        state, artifact = engine.register_workspace_artifact(
            self.identity,
            "report.txt",
        )
        snapshot = paths.root / artifact.path
        self.assertTrue(
            artifact.path.startswith("artifacts/snapshots/"),
            artifact.path,
        )
        self.assertEqual(snapshot.read_text(encoding="utf-8"), "first version")
        self.assertEqual(artifact.extra["source_locator"], "report.txt")
        self.assertEqual(snapshot.stat().st_mode & 0o222, 0)

        source.write_text("mutated later", encoding="utf-8")
        verified = engine.store.verify_artifacts(self.identity)
        self.assertEqual(verified[artifact.id], snapshot)
        self.assertEqual(snapshot.read_text(encoding="utf-8"), "first version")

        outside = self.root / "outside.txt"
        outside.write_text("outside", encoding="utf-8")
        (workspace / "unsafe-link").symlink_to(outside)
        with self.assertRaisesRegex(EngineError, "symlink|safely|regular"):
            engine.register_workspace_artifact(
                self.identity,
                "unsafe-link",
            )
        outside_directory = self.root / "outside-directory"
        outside_directory.mkdir()
        (outside_directory / "secret.txt").write_text(
            "outside",
            encoding="utf-8",
        )
        (workspace / "unsafe-directory").symlink_to(
            outside_directory,
            target_is_directory=True,
        )
        with self.assertRaisesRegex(EngineError, "safely"):
            engine.register_workspace_artifact(
                self.identity,
                "unsafe-directory/secret.txt",
            )

    def test_workspace_artifact_registration_rejects_hash_copy_race(
        self,
    ) -> None:
        class MutatingRegistrationSandbox(FakeSandbox):
            def register_artifact(
                inner_self,
                locator,
                *,
                maximum_bytes=1 << 34,
            ):
                reference = super().register_artifact(
                    locator,
                    maximum_bytes=maximum_bytes,
                )
                (inner_self.work / locator).write_bytes(
                    b"mutated after registration"
                )
                return reference

        def sandbox_factory(state, work, policy):
            del state, policy
            return MutatingRegistrationSandbox(work)

        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=sandbox_factory,
        )
        state = engine.add_challenge(self.identity, prompt="solve")
        paths = engine.store.challenge_paths(state.identity)
        workspace = paths.artifacts / "workspace"
        workspace.mkdir(parents=True, exist_ok=True)
        (workspace / "race.txt").write_bytes(b"registered bytes")

        with self.assertRaisesRegex(EngineError, "snapshotted safely"):
            engine.register_workspace_artifact(
                self.identity,
                "race.txt",
            )

        snapshots = paths.artifacts / "snapshots"
        self.assertEqual(
            [path for path in snapshots.iterdir() if path.is_file()],
            [],
        )

    def test_workspace_artifact_cas_race_removes_only_new_orphan_snapshot(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        state = engine.add_challenge(self.identity, prompt="solve")
        paths = engine.store.challenge_paths(state.identity)
        workspace = paths.artifacts / "workspace"
        workspace.mkdir(parents=True, exist_ok=True)
        (workspace / "race.txt").write_bytes(b"candidate artifact")
        snapshots = paths.artifacts / "snapshots"
        snapshots.mkdir(parents=True, exist_ok=True)
        sentinel = snapshots / "preexisting.bin"
        sentinel.write_bytes(b"keep")
        real_snapshot = engine._snapshot_workspace_file

        def snapshot_then_change_revision(*args, **kwargs):
            snapshot = real_snapshot(*args, **kwargs)
            engine.record_candidate(
                self.identity,
                "KCTF{artifact_cas_race}",
                print_immediately=False,
            )
            return snapshot

        with (
            mock.patch.object(
                engine,
                "_snapshot_workspace_file",
                side_effect=snapshot_then_change_revision,
            ),
            self.assertRaises(RevisionConflict),
        ):
            engine.register_workspace_artifact(
                self.identity,
                "race.txt",
            )

        committed = engine.store.load(self.identity)
        self.assertEqual(committed.artifacts, [])
        self.assertTrue(
            any(
                candidate.value == "KCTF{artifact_cas_race}"
                for candidate in committed.candidates
            )
        )
        self.assertEqual(
            [path.name for path in snapshots.iterdir() if path.is_file()],
            [sentinel.name],
        )
        self.assertEqual(sentinel.read_bytes(), b"keep")

    def test_workspace_artifact_interrupts_clean_or_preserve_exact_snapshot(
        self,
    ) -> None:
        for stage in (
            "snapshot",
            "post-snapshot",
            "commit-before",
            "commit-after",
            "duplicate-post-commit",
        ):
            with self.subTest(stage=stage):
                root = self.root / f"workspace-artifact-{stage}"
                engine = ChallengeEngine(
                    root,
                    batch_runner=BatchRunner(
                        process_executor=RoleExecutor(),
                        max_schema_retries=0,
                    ),
                    sandbox_factory=(
                        lambda state, work, policy: FakeSandbox(work)
                    ),
                )
                state = engine.add_challenge(self.identity, prompt="solve")
                paths = engine.store.challenge_paths(state.identity)
                workspace = paths.artifacts / "workspace"
                workspace.mkdir(parents=True, exist_ok=True)
                (workspace / "evidence.bin").write_bytes(b"evidence")
                if stage == "duplicate-post-commit":
                    engine.register_workspace_artifact(
                        self.identity,
                        "evidence.bin",
                    )
                interruption = KeyboardInterrupt(
                    f"synthetic workspace artifact {stage} interruption"
                )

                if stage == "snapshot":
                    real_snapshot = engine._snapshot_workspace_file

                    def snapshot_then_interrupt(*args, **kwargs):
                        real_snapshot(*args, **kwargs)
                        raise interruption

                    patcher = mock.patch.object(
                        engine,
                        "_snapshot_workspace_file",
                        side_effect=snapshot_then_interrupt,
                    )
                elif stage == "post-snapshot":
                    real_artifact_reference = ArtifactReference

                    def artifact_then_interrupt(*args, **kwargs):
                        if kwargs.get("sha256") != "0" * 64:
                            raise interruption
                        return real_artifact_reference(*args, **kwargs)

                    patcher = mock.patch(
                        "ctf_os.engine.challenge.ArtifactReference",
                        side_effect=artifact_then_interrupt,
                    )
                elif stage == "duplicate-post-commit":
                    patcher = _interrupt_on_source_line(
                        ChallengeEngine.register_workspace_artifact,
                        "if selected[0].id != artifact.id:",
                        interruption,
                    )
                else:
                    real_update = engine.store.update
                    interrupted = False

                    def interrupt_artifact_commit(
                        identity,
                        mutator,
                        *args,
                        **kwargs,
                    ):
                        nonlocal interrupted
                        if (
                            not interrupted
                            and "register_workspace_artifact"
                            in getattr(mutator, "__qualname__", "")
                        ):
                            interrupted = True
                            if stage == "commit-after":
                                real_update(
                                    identity,
                                    mutator,
                                    *args,
                                    **kwargs,
                                )
                            raise interruption
                        return real_update(
                            identity,
                            mutator,
                            *args,
                            **kwargs,
                        )

                    patcher = mock.patch.object(
                        engine.store,
                        "update",
                        side_effect=interrupt_artifact_commit,
                    )

                with (
                    patcher,
                    self.assertRaises(KeyboardInterrupt) as raised,
                ):
                    engine.register_workspace_artifact(
                        self.identity,
                        "evidence.bin",
                    )

                self.assertIs(raised.exception, interruption)
                committed = engine.store.load(self.identity)
                snapshots = paths.artifacts / "snapshots"
                snapshot_files = (
                    list(snapshots.glob("*.bin"))
                    if snapshots.exists()
                    else []
                )
                expected = (
                    1
                    if stage in {"commit-after", "duplicate-post-commit"}
                    else 0
                )
                self.assertEqual(len(committed.artifacts), expected)
                self.assertEqual(len(snapshot_files), expected)

    def test_workspace_artifact_dedupes_and_over_cap_cleans_new_snapshot(
        self,
    ) -> None:
        config = load_config(self.root)
        config = replace(
            config,
            runtime=replace(
                config.runtime,
                work_tree_max_bytes=10,
            ),
        )
        engine = ChallengeEngine(
            self.root,
            config=config,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=lambda state, work, policy: FakeSandbox(work),
        )
        state = engine.add_challenge(self.identity, prompt="solve")
        paths = engine.store.challenge_paths(state.identity)
        workspace = paths.artifacts / "workspace"
        workspace.mkdir(parents=True, exist_ok=True)
        (workspace / "first.bin").write_bytes(b"123456")
        (workspace / "second.bin").write_bytes(b"abcdef")
        (workspace / "oversized.bin").write_bytes(b"01234567890")

        state, first = engine.register_workspace_artifact(
            self.identity,
            "first.bin",
        )
        deduped_state, duplicate = engine.register_workspace_artifact(
            self.identity,
            "first.bin",
        )
        self.assertEqual(duplicate.id, first.id)
        self.assertEqual(len(deduped_state.artifacts), 1)

        with self.assertRaisesRegex(
            ArtifactValidationError,
            "canonical artifact bytes exceed",
        ):
            engine.register_workspace_artifact(
                self.identity,
                "second.bin",
            )
        with self.assertRaisesRegex(EngineError, "snapshotted safely"):
            engine.register_workspace_artifact(
                self.identity,
                "oversized.bin",
            )

        committed = engine.store.load(self.identity)
        self.assertEqual([item.id for item in committed.artifacts], [first.id])
        snapshots = paths.artifacts / "snapshots"
        self.assertEqual(
            [path.name for path in snapshots.iterdir() if path.is_file()],
            [Path(first.path).name],
        )

    def test_tool_artifact_cap_failure_cleans_exact_new_stream_snapshots(
        self,
    ) -> None:
        config = load_config(self.root)
        config = replace(
            config,
            runtime=replace(
                config.runtime,
                work_tree_max_bytes=30,
            ),
        )
        engine = ChallengeEngine(
            self.root,
            config=config,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=lambda state, work, policy: FakeSandbox(work),
        )
        state = engine.add_challenge(self.identity, prompt="solve")
        paths = engine.store.challenge_paths(state.identity)
        workspace = paths.artifacts / "workspace"
        workspace.mkdir(parents=True, exist_ok=True)
        (workspace / "baseline.bin").write_bytes(b"0123456789")
        _state, baseline = engine.register_workspace_artifact(
            self.identity,
            "baseline.bin",
        )

        with self.assertRaisesRegex(
            ArtifactValidationError,
            "canonical artifact bytes exceed",
        ):
            engine.run_tool_command(self.identity, ("true",))

        committed = engine.store.load(self.identity)
        self.assertEqual(
            [item.id for item in committed.artifacts],
            [baseline.id],
        )
        self.assertFalse(
            any(
                experiment.status is ExperimentStatus.RUNNING
                for experiment in committed.experiments
            )
        )
        self.assertTrue(
            any(
                experiment.status is ExperimentStatus.FAILED
                for experiment in committed.experiments
            )
        )
        self.assertTrue(
            any(run.status is RunStatus.FAILED for run in committed.runs)
        )
        snapshots = paths.artifacts / "snapshots"
        self.assertEqual(
            [path.name for path in snapshots.iterdir() if path.is_file()],
            [Path(baseline.path).name],
        )

    def test_proof_snapshots_inputs_once_and_records_one_manifest(self) -> None:
        class MutatingInputSandbox(FakeSandbox):
            def run_clean_proof(
                inner_self,
                spec,
                *,
                input_locators=(),
                proof_inputs=(),
            ):
                result = super().run_clean_proof(
                    spec,
                    input_locators=input_locators,
                    proof_inputs=proof_inputs,
                )
                if inner_self.proof_calls == 1:
                    (inner_self.work / "input.bin").write_bytes(
                        b"changed after first proof"
                    )
                return result

        holder: dict[str, MutatingInputSandbox] = {}

        def sandbox_factory(state, work, policy):
            del state, policy
            holder.setdefault("client", MutatingInputSandbox(work))
            return holder["client"]

        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=sandbox_factory,
        )
        state = engine.add_challenge(self.identity, prompt="solve")
        workspace = engine.store.challenge_paths(state.identity).artifacts / "workspace"
        workspace.mkdir(parents=True, exist_ok=True)
        (workspace / "input.bin").write_bytes(b"proof input v1")
        state = engine.record_candidate(
            self.identity,
            "KCTF{proof_flag}",
            print_immediately=False,
        )

        state, proof = engine.prove_candidate(
            self.identity,
            state.candidates[0].id,
            ("./reproduce.sh",),
            input_locators=("input.bin",),
        )

        self.assertTrue(proof.passed)
        self.assertEqual(len(holder["client"].proof_input_calls), 3)
        self.assertEqual(
            holder["client"].proof_input_calls,
            [(("input.bin", b"proof input v1"),)] * 3,
        )
        paths = engine.store.challenge_paths(self.identity)
        proof_runs = [run for run in state.runs if run.role == "proof"]
        manifest_hashes = set()
        manifest_paths = set()
        for run in proof_runs:
            request = json.loads(
                (paths.root / str(run.request_path)).read_text(
                    encoding="utf-8"
                )
            )
            result = json.loads(
                (paths.root / str(run.result_path)).read_text(
                    encoding="utf-8"
                )
            )
            manifest_hashes.add(request["input_manifest_sha256"])
            manifest_hashes.add(result["input_manifest_sha256"])
            manifest_paths.add(request["input_manifest_path"])
            manifest_paths.add(result["input_manifest_path"])
        self.assertEqual(len(manifest_hashes), 1)
        self.assertEqual(len(manifest_paths), 1)
        manifest_path = paths.root / manifest_paths.pop()
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["inputs"][0]["locator"], "input.bin")
        snapshot = paths.root / manifest["inputs"][0]["snapshot_path"]
        self.assertEqual(snapshot.read_bytes(), b"proof input v1")
        input_reference = next(
            artifact
            for artifact in state.artifacts
            if artifact.path == manifest["inputs"][0]["snapshot_path"]
        )
        self.assertEqual(input_reference.size, len(b"proof input v1"))
        self.assertEqual(
            input_reference.extra["kind"],
            "proof_input",
        )

        result_artifact = next(
            artifact
            for artifact in state.artifacts
            if artifact.path.endswith("/result.json")
        )
        environment = json.loads(
            (paths.root / result_artifact.path)
            .with_name("environment.json")
            .read_text(encoding="utf-8")
        )
        self.assertEqual(
            environment["input_manifest_sha256"],
            next(iter(manifest_hashes)),
        )
        self.assertEqual(
            environment["input_manifest_path"],
            manifest_path.relative_to(paths.root).as_posix(),
        )
        mutable_stdout = workspace / "proof" / "clean-1" / "stdout.log"
        mutable_stdout.write_text("tampered", encoding="utf-8")
        verified = engine.store.verify_artifacts(self.identity)
        proof_stdout = next(
            artifact
            for artifact in state.artifacts
            if artifact.source_run_id == proof_runs[0].id
            and artifact.path.endswith("/stdout.log")
        )
        self.assertEqual(
            verified[proof_stdout.id].read_text(encoding="utf-8"),
            "KCTF{proof_flag}\n",
        )

    def test_proof_input_cap_failure_cleans_exact_uncommitted_copies(
        self,
    ) -> None:
        config = load_config(self.root)
        config = replace(
            config,
            runtime=replace(
                config.runtime,
                work_tree_max_bytes=10,
            ),
        )
        engine = ChallengeEngine(
            self.root,
            config=config,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=lambda state, work, policy: FakeSandbox(work),
        )
        state = engine.add_challenge(self.identity, prompt="solve")
        paths = engine.store.challenge_paths(self.identity)
        workspace = paths.artifacts / "workspace"
        workspace.mkdir(parents=True, exist_ok=True)
        (workspace / "input.bin").write_bytes(b"123456")
        state = engine.record_candidate(
            self.identity,
            "KCTF{proof_flag}",
            print_immediately=False,
        )

        with self.assertRaisesRegex(
            ArtifactValidationError,
            "canonical artifact bytes exceed",
        ):
            engine.prove_candidate(
                self.identity,
                state.candidates[0].id,
                ("./reproduce.sh",),
                input_locators=("input.bin",),
            )

        committed = engine.store.load(self.identity)
        self.assertEqual(committed.artifacts, [])
        self.assertEqual(
            [path for path in paths.proof.rglob("*") if path.is_file()],
            [],
        )

    def test_proof_early_error_releases_session_lock(self) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(self.identity, prompt="solve")
        with self.assertRaisesRegex(EngineError, "unknown candidate"):
            engine.prove_candidate(
                self.identity,
                "C-does-not-exist",
                ("./reproduce.sh",),
            )
        lock = ChallengeLock(
            engine.store.challenge_paths(self.identity).runtime
            / "session.lock",
            timeout=0,
        ).acquire()
        lock.release()

    def test_proof_rejects_summary_only_candidate_without_both_raw_artifacts(
        self,
    ) -> None:
        class MissingStderrArtifactSandbox(FakeSandbox):
            def register_artifact(
                inner_self,
                locator,
                *,
                maximum_bytes=1 << 34,
            ):
                if str(locator).endswith("stderr.log"):
                    raise OSError("synthetic artifact failure")
                return super().register_artifact(
                    locator,
                    maximum_bytes=maximum_bytes,
                )

        holder: dict[str, MissingStderrArtifactSandbox] = {}

        def sandbox_factory(state, work, policy):
            del state, policy
            holder.setdefault(
                "client", MissingStderrArtifactSandbox(work)
            )
            return holder["client"]

        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=sandbox_factory,
        )
        engine.add_challenge(self.identity, prompt="solve")
        state = engine.record_candidate(
            self.identity,
            "KCTF{proof_flag}",
            print_immediately=False,
        )

        state, proof = engine.prove_candidate(
            self.identity,
            state.candidates[0].id,
            ("./reproduce.sh",),
        )

        self.assertFalse(proof.passed)
        self.assertEqual(state.status.value, "ACTIVE")
        root = engine.store.challenge_paths(self.identity).root
        proof_runs = [run for run in state.runs if run.role == "proof"]
        self.assertTrue(proof_runs)
        for run in proof_runs:
            payload = json.loads(
                (root / str(run.result_path)).read_text(encoding="utf-8")
            )
            self.assertFalse(payload["durable_evidence_complete"])
            self.assertTrue(payload["artifact_errors"])

    def test_multiple_operator_candidates_receive_unique_ids(self) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(self.identity, prompt="solve")
        engine.record_candidate(
            self.identity,
            "KCTF{candidate_one}",
            print_immediately=False,
        )
        state = engine.record_candidate(
            self.identity,
            "KCTF{candidate_two}",
            print_immediately=False,
        )
        self.assertEqual(
            [item.value for item in state.candidates],
            ["KCTF{candidate_one}", "KCTF{candidate_two}"],
        )
        self.assertEqual(len({item.id for item in state.candidates}), 2)

    def test_batch_context_preparation_cannot_reanchor_issued_deadline(
        self,
    ) -> None:
        executor = RoleExecutor()
        engine = self.engine_with_executor(executor)
        engine.add_challenge(
            self.identity,
            prompt="solve",
            budget_seconds=2,
        )
        real_build = build_context_pack

        def delayed_context(*args, **kwargs):
            context = real_build(*args, **kwargs)
            time.sleep(2.2)
            return context

        with mock.patch(
            "ctf_os.engine.challenge.build_context_pack",
            side_effect=delayed_context,
        ):
            result = engine.run_role(
                self.identity,
                Role.RECON,
                instruction="inspect without extending the issued deadline",
            )

        state = engine.store.load(self.identity)
        self.assertFalse(result.success)
        self.assertEqual(result.attempts[-1].returncode, 124)
        self.assertTrue(result.attempts[-1].timed_out)
        self.assertEqual(executor.roles, [])
        self.assertIs(
            next(
                run
                for run in state.runs
                if run.id == result.invocation.run_id
            ).status,
            RunStatus.TIMED_OUT,
        )

    def test_wave_roles_share_one_deadline_before_context_preparation(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(
            self.identity,
            prompt="solve",
            budget_seconds=60,
        )

        outcome = engine.run_wave(self.identity, "discovery")

        self.assertEqual(len(outcome.results), 3)
        self.assertEqual(
            len(
                {
                    result.invocation.deadline_monotonic_seconds
                    for result in outcome.results
                }
            ),
            1,
        )
        self.assertEqual(
            len(
                {
                    result.invocation.deadline_epoch_seconds
                    for result in outcome.results
                }
            ),
            1,
        )

    def test_batch_host_normalization_after_deadline_returns_failure(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        before = engine.add_challenge(
            self.identity,
            prompt="solve",
            budget_seconds=2,
        )
        real_normalize = engine._normalize_result

        def delayed_normalize(*args, **kwargs):
            normalized = real_normalize(*args, **kwargs)
            time.sleep(2.2)
            return normalized

        with mock.patch.object(
            engine,
            "_normalize_result",
            side_effect=delayed_normalize,
        ):
            result = engine.run_role(
                self.identity,
                Role.RECON,
                instruction="return one bounded proposal",
            )

        state = engine.store.load(self.identity)
        run = next(
            run for run in state.runs
            if run.id == result.invocation.run_id
        )
        self.assertFalse(result.success)
        self.assertEqual(result.attempts[-1].returncode, 124)
        self.assertTrue(result.attempts[-1].timed_out)
        self.assertIs(run.status, RunStatus.TIMED_OUT)
        self.assertEqual(len(state.facts), len(before.facts))
        self.assertEqual(len(state.artifacts), len(before.artifacts))
        self.assertEqual(
            [
                failure.kind
                for failure in result.failures
                if failure.kind == "challenge_budget_expired"
            ],
            ["challenge_budget_expired"],
        )

    def test_batch_lock_wait_crossing_deadline_cannot_commit_success(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(
            self.identity,
            prompt="solve",
            budget_seconds=2,
        )
        real_update = engine.store.update
        delayed = False

        def delay_batch_mutator(*args, **kwargs):
            nonlocal delayed
            arguments = list(args)
            mutator = (
                arguments[1]
                if len(arguments) > 1 and callable(arguments[1])
                else kwargs.get("mutator")
            )
            if (
                not delayed
                and callable(mutator)
                and "_commit_batch_results.<locals>.apply"
                in mutator.__qualname__
            ):
                delayed = True

                def late_mutator(state):
                    time.sleep(2.2)
                    return mutator(state)

                if len(arguments) > 1 and callable(arguments[1]):
                    arguments[1] = late_mutator
                else:
                    kwargs["mutator"] = late_mutator
            return real_update(*arguments, **kwargs)

        with mock.patch.object(
            engine.store,
            "update",
            side_effect=delay_batch_mutator,
        ):
            result = engine.run_role(
                self.identity,
                Role.RECON,
                instruction="exercise locked deadline eligibility",
            )

        state = engine.store.load(self.identity)
        run = next(
            run for run in state.runs
            if run.id == result.invocation.run_id
        )
        self.assertTrue(delayed)
        self.assertFalse(result.success)
        self.assertTrue(result.attempts[-1].timed_out)
        self.assertIs(run.status, RunStatus.TIMED_OUT)
        self.assertFalse(
            any(fact.source_run_id == run.id for fact in state.facts)
        )

    def test_tool_host_evidence_after_deadline_terminalizes_failure(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(
            self.identity,
            prompt="solve",
            budget_seconds=2,
        )
        real_snapshot = engine._snapshot_workspace_file
        delayed = False

        def delayed_snapshot(*args, **kwargs):
            nonlocal delayed
            snapshot = real_snapshot(*args, **kwargs)
            if not delayed:
                delayed = True
                time.sleep(2.2)
            return snapshot

        with mock.patch.object(
            engine,
            "_snapshot_workspace_file",
            side_effect=delayed_snapshot,
        ):
            state = engine.run_tool_command(
                self.identity,
                ("true",),
                timeout_seconds=30,
            )

        tool_run = next(run for run in state.runs if run.role == "tool")
        experiment = next(
            item
            for item in state.experiments
            if item.result
            and item.result.get("error")
            and tool_run.id in {
                run.id for run in state.runs
            }
        )
        self.assertTrue(delayed)
        self.assertIs(tool_run.status, RunStatus.FAILED)
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        self.assertFalse(
            any(
                artifact.source_run_id == tool_run.id
                for artifact in state.artifacts
            )
        )
        self.assertFalse(
            any(fact.source_run_id == tool_run.id for fact in state.facts)
        )

    def test_tool_lock_wait_crossing_deadline_cannot_await_evaluation(
        self,
    ) -> None:
        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(
            self.identity,
            prompt="solve",
            budget_seconds=2,
        )
        real_update = engine.store.update
        delayed = False

        def delay_tool_mutator(*args, **kwargs):
            nonlocal delayed
            arguments = list(args)
            mutator = (
                arguments[1]
                if len(arguments) > 1 and callable(arguments[1])
                else kwargs.get("mutator")
            )
            if (
                not delayed
                and callable(mutator)
                and (
                    "execute_registered_experiments.<locals>.finish"
                    in mutator.__qualname__
                )
            ):
                delayed = True

                def late_mutator(state):
                    time.sleep(2.2)
                    return mutator(state)

                if len(arguments) > 1 and callable(arguments[1]):
                    arguments[1] = late_mutator
                else:
                    kwargs["mutator"] = late_mutator
            return real_update(*arguments, **kwargs)

        with mock.patch.object(
            engine.store,
            "update",
            side_effect=delay_tool_mutator,
        ):
            state = engine.run_tool_command(
                self.identity,
                ("true",),
                timeout_seconds=30,
            )

        tool_run = next(run for run in state.runs if run.role == "tool")
        experiment = next(
            item
            for item in state.experiments
            if item.status is ExperimentStatus.FAILED
            and item.result
            and "error" in item.result
        )
        self.assertTrue(delayed)
        self.assertIs(tool_run.status, RunStatus.FAILED)
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        self.assertNotIn(
            ExperimentStatus.AWAITING_EVALUATION,
            [item.status for item in state.experiments],
        )

    def test_proof_host_evidence_after_deadline_cannot_be_ready(
        self,
    ) -> None:
        identity = ChallengeIdentity(
            self.identity.contest_id,
            "forensics",
            self.identity.challenge_id,
        )
        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(
            identity,
            prompt="solve",
            budget_seconds=2,
        )
        state = engine.record_candidate(
            identity,
            "KCTF{proof_flag}",
            print_immediately=False,
        )
        candidate_id = state.candidates[0].id
        real_snapshot = engine._snapshot_workspace_file
        delayed = False

        def delayed_snapshot(*args, **kwargs):
            nonlocal delayed
            snapshot = real_snapshot(*args, **kwargs)
            if not delayed:
                delayed = True
                time.sleep(2.2)
            return snapshot

        with mock.patch.object(
            engine,
            "_snapshot_workspace_file",
            side_effect=delayed_snapshot,
        ):
            committed, proof = engine.prove_candidate(
                identity,
                candidate_id,
                ("./reproduce.sh",),
            )

        proof_run = next(
            run for run in committed.runs if run.role == "proof"
        )
        candidate = next(
            item
            for item in committed.candidates
            if item.id == candidate_id
        )
        self.assertTrue(delayed)
        self.assertFalse(proof.passed)
        self.assertIs(committed.status, ChallengeStatus.ACTIVE)
        self.assertIs(
            candidate.status,
            CandidateStatus.OBSERVED_CANDIDATE,
        )
        self.assertIs(proof_run.status, RunStatus.TIMED_OUT)
        self.assertFalse(
            any(
                artifact.source_run_id == proof_run.id
                for artifact in committed.artifacts
            )
        )

    def test_proof_lock_wait_crossing_deadline_cannot_be_ready(
        self,
    ) -> None:
        identity = ChallengeIdentity(
            self.identity.contest_id,
            "forensics",
            self.identity.challenge_id,
        )
        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(
            identity,
            prompt="solve",
            budget_seconds=2,
        )
        state = engine.record_candidate(
            identity,
            "KCTF{proof_flag}",
            print_immediately=False,
        )
        candidate_id = state.candidates[0].id
        real_update = engine.store.update
        delayed = False

        def delay_attempt_mutator(*args, **kwargs):
            nonlocal delayed
            arguments = list(args)
            mutator = (
                arguments[1]
                if len(arguments) > 1 and callable(arguments[1])
                else kwargs.get("mutator")
            )
            if (
                not delayed
                and callable(mutator)
                and (
                    "prove_candidate.<locals>.record_attempt"
                    in mutator.__qualname__
                )
            ):
                delayed = True

                def late_mutator(state):
                    time.sleep(2.2)
                    return mutator(state)

                if len(arguments) > 1 and callable(arguments[1]):
                    arguments[1] = late_mutator
                else:
                    kwargs["mutator"] = late_mutator
            return real_update(*arguments, **kwargs)

        with mock.patch.object(
            engine.store,
            "update",
            side_effect=delay_attempt_mutator,
        ):
            committed, proof = engine.prove_candidate(
                identity,
                candidate_id,
                ("./reproduce.sh",),
            )

        proof_run = next(
            run for run in committed.runs if run.role == "proof"
        )
        self.assertTrue(delayed)
        self.assertFalse(proof.passed)
        self.assertIs(committed.status, ChallengeStatus.ACTIVE)
        self.assertIs(proof_run.status, RunStatus.TIMED_OUT)

    def test_proof_final_lock_wait_crossing_deadline_cannot_be_ready(
        self,
    ) -> None:
        identity = ChallengeIdentity(
            self.identity.contest_id,
            "forensics",
            self.identity.challenge_id,
        )
        engine = self.engine_with_executor(RoleExecutor())
        engine.add_challenge(
            identity,
            prompt="solve",
            budget_seconds=2,
        )
        state = engine.record_candidate(
            identity,
            "KCTF{proof_flag}",
            print_immediately=False,
        )
        candidate_id = state.candidates[0].id
        real_update = engine.store.update
        delayed = False

        def delay_final_mutator(*args, **kwargs):
            nonlocal delayed
            arguments = list(args)
            mutator = (
                arguments[1]
                if len(arguments) > 1 and callable(arguments[1])
                else kwargs.get("mutator")
            )
            if (
                not delayed
                and callable(mutator)
                and (
                    "prove_candidate.<locals>.apply_result"
                    in mutator.__qualname__
                )
            ):
                delayed = True

                def late_mutator(state):
                    time.sleep(2.2)
                    return mutator(state)

                if len(arguments) > 1 and callable(arguments[1]):
                    arguments[1] = late_mutator
                else:
                    kwargs["mutator"] = late_mutator
            return real_update(*arguments, **kwargs)

        with mock.patch.object(
            engine.store,
            "update",
            side_effect=delay_final_mutator,
        ):
            committed, proof = engine.prove_candidate(
                identity,
                candidate_id,
                ("./reproduce.sh",),
            )

        candidate = next(
            item
            for item in committed.candidates
            if item.id == candidate_id
        )
        self.assertTrue(delayed)
        self.assertFalse(proof.passed)
        self.assertIs(committed.status, ChallengeStatus.ACTIVE)
        self.assertIs(
            candidate.status,
            CandidateStatus.OBSERVED_CANDIDATE,
        )
        self.assertFalse(
            any(
                artifact.path.endswith("/result.json")
                for artifact in committed.artifacts
            )
        )

    def test_provider_start_recheck_does_not_move_issued_deadline_on_reset(
        self,
    ) -> None:
        executor = RoleExecutor()
        engine = self.engine_with_executor(executor)
        original = engine.add_challenge(
            self.identity,
            prompt="solve",
            budget_seconds=60,
        )
        original_monotonic, original_epoch = (
            engine._budget_deadline_pair(original, 60)
        )
        original_invocation = engine._make_invocation(
            original,
            Role.RECON,
            prefix="reset-shorter",
            instruction="use the already-issued deadline",
            deadline_monotonic_seconds=original_monotonic,
            deadline_epoch_seconds=original_epoch,
        )

        def shorten_to_expired(current: ChallengeState) -> None:
            current.budget.deadline_utc = "2000-01-01T00:00:00Z"
            current.budget.allocated_seconds = 1

        engine.store.update(self.identity, shorten_to_expired)
        shorter_result = engine.batch_runner.run(
            original_invocation,
            before_provider_start=lambda: engine._before_provider_start(
                self.identity
            ),
        )
        self.assertTrue(shorter_result.success)
        self.assertEqual(
            shorter_result.deadline_monotonic_seconds,
            original_monotonic,
        )

        extended = engine.reset_budget(self.identity, 120)
        extended_monotonic, extended_epoch = (
            engine._budget_deadline_pair(extended, 120)
        )
        expiring_invocation = engine._make_invocation(
            extended,
            Role.RECON,
            prefix="reset-longer",
            instruction="do not extend the already-issued deadline",
            deadline_monotonic_seconds=extended_monotonic,
            deadline_epoch_seconds=extended_epoch,
        )
        short_deadline = time.monotonic() + 0.05
        expiring_invocation = replace(
            expiring_invocation,
            deadline_monotonic_seconds=short_deadline,
            deadline_epoch_seconds=time.time() + 0.05,
        )
        engine.reset_budget(self.identity, 300)
        time.sleep(0.07)
        longer_result = engine.batch_runner.run(
            expiring_invocation,
            before_provider_start=lambda: engine._before_provider_start(
                self.identity
            ),
        )
        self.assertFalse(longer_result.success)
        self.assertTrue(longer_result.attempts[-1].timed_out)
        self.assertEqual(len(executor.roles), 1)

        engine.pause(self.identity)
        with self.assertRaises(Exception) as raised:
            engine._before_provider_start(self.identity)
        self.assertIn("PAUSED", str(raised.exception))

    def test_reproof_keeps_each_evaluation_artifact_immutable(self) -> None:
        holder: dict[str, FakeSandbox] = {}

        def sandbox_factory(state, work, policy):
            del state, policy
            holder.setdefault("client", FakeSandbox(work))
            return holder["client"]

        engine = ChallengeEngine(
            self.root,
            batch_runner=BatchRunner(
                process_executor=RoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=sandbox_factory,
        )
        engine.add_challenge(self.identity, prompt="solve")
        state = engine.record_candidate(
            self.identity,
            "KCTF{proof_flag}",
            print_immediately=False,
        )
        candidate_id = state.candidates[0].id
        first, first_proof = engine.prove_candidate(
            self.identity,
            candidate_id,
            ("./reproduce.sh",),
        )
        second, second_proof = engine.prove_candidate(
            self.identity,
            candidate_id,
            ("./reproduce.sh",),
        )
        self.assertTrue(first_proof.passed)
        self.assertTrue(second_proof.passed)
        result_artifacts = [
            artifact
            for artifact in second.artifacts
            if artifact.path.startswith(f"proof/{candidate_id}/")
            and artifact.path.endswith("/result.json")
        ]
        self.assertEqual(len(result_artifacts), 2)
        self.assertEqual(len({item.path for item in result_artifacts}), 2)
        for artifact in result_artifacts:
            result_path = (
                engine.store.challenge_paths(self.identity).root
                / artifact.path
            )
            self.assertTrue(result_path.is_file())
            self.assertTrue((result_path.parent / "environment.json").is_file())
        self.assertEqual(first.status.value, "READY_TO_SUBMIT")
        self.assertEqual(second.status.value, "READY_TO_SUBMIT")


if __name__ == "__main__":
    unittest.main()
