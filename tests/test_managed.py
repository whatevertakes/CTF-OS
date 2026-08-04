from __future__ import annotations

import copy
import hashlib
import json
import signal
import shlex
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

import ctf_os.engine.challenge as challenge_module
import ctf_os.managed as managed_module
import ctf_os.migration as migration_module
from ctf_os.adapters import get_adapter
from ctf_os.codex import (
    BatchRunner,
    FifoModelCallLimiter,
    ProcessOutcome,
    Role,
)
from ctf_os.capabilities import (
    required_managed_capabilities_for_category,
)
from ctf_os.config import load_config
from ctf_os.engine.challenge import (
    ChallengeEngine,
    EngineError,
    SessionAlreadyRunning,
    _proof_argv_contains_credential_material,
)
from ctf_os.engine.checkpoint_projection import (
    checkpoint_action_reference,
    managed_registered_selection_binding,
)
from ctf_os.engine.context_pack import build_context_pack
from ctf_os.engine.resume_capsule import (
    ResumeCapsulePolicy,
    render_resume_capsule,
)
from ctf_os.lifecycle import close_challenge, create_checkpoint
from ctf_os.managed import (
    ManagedError,
    ManagedOrchestrator,
    ManagedRegisteredExperimentReferenceError,
)
from ctf_os.migration import (
    apply_migration,
    plan_migration,
    rollback_migration,
)
from ctf_os.models import (
    ArtifactReference,
    CandidateStatus,
    ChallengeIdentity,
    ChallengeStatus,
    Experiment,
    ExperimentKind,
    ExperimentStatus,
    Fact,
    Falsifier,
    Hypothesis,
    HypothesisStatus,
    ManagedCycle,
    ManagedWave,
    ModelValidationError,
    Provenance,
    RunOrigin,
    RunReference,
    RunStatus,
    SessionStatus,
    WaveKind,
)
from ctf_os.sandbox import SandboxResult
from ctf_os.schema import (
    RUN_ENVELOPE_SCHEMA_VERSION,
    STATE_SCHEMA_VERSION,
)
from ctf_os.storage import (
    quarantine_unreachable,
    restore_quarantine,
    storage_plan,
)
from ctf_os.store import (
    ChallengeLock,
    MigrationInProgress,
    RevisionConflict,
)
from ctf_os.store.atomic import (
    StrictJSONError,
    atomic_write_json,
    canonical_json_record,
    read_json,
    strict_json_loads,
)
from ctf_os.store.files import sha256_file
from ctf_os.workspace_publish import (
    publish_builder_file,
    reconcile_workspace_publishes,
)
from tests.test_engine import (
    FakeSandbox,
    _elf64_image,
    _output_path,
    _payload,
    _rev_inventory_payload,
    _role_for,
)


IMAGE_DIGEST = "sha256:" + "b" * 64
CANONICAL_REFERENCE_PAYLOAD = b"canonical managed evidence\n"
CANONICAL_REFERENCE_ID = "A-existing-canonical-evidence"
CANONICAL_REFERENCE_PATH = (
    f"artifacts/snapshots/{CANONICAL_REFERENCE_ID}.log"
)
CANONICAL_REFERENCE_SHA256 = hashlib.sha256(
    CANONICAL_REFERENCE_PAYLOAD
).hexdigest()
BUILDER_SOLVER_PAYLOAD = (
    b"#!/usr/bin/env python3\n"
    b"print('immutable builder solver reached')\n"
)
MUTATED_BUILDER_SOLVER_PAYLOAD = b"print('mutable source changed')\n"


class ProbeRoleExecutor:
    """Contract-valid fake model whose worker actions are independent probes."""

    def __init__(
        self,
        *,
        invalid_role: Role | None = None,
        invalid_command_role: Role | None = None,
        source_reference_role: Role | None = None,
        network_target: tuple[str, int] | None = None,
        captain_hypothesis_count: int = 3,
        captain_stage: str = "attack",
        proof_candidate_id: str | None = None,
        proof_artifact_id: str | None = None,
        proof_artifact_purpose: str = "reproducer",
        proof_extra_action: bool = False,
        command_by_role: dict[Role, str] | None = None,
        captain_hypothesis_ids: tuple[str, ...] | None = None,
        captain_action_hypothesis_ids: tuple[str, ...] | None = None,
    ) -> None:
        self.invalid_role = invalid_role
        self.invalid_command_role = invalid_command_role
        self.source_reference_role = source_reference_role
        self.network_target = network_target
        self.captain_hypothesis_count = captain_hypothesis_count
        self.captain_stage = captain_stage
        self.proof_candidate_id = proof_candidate_id
        self.proof_artifact_id = proof_artifact_id
        self.proof_artifact_purpose = proof_artifact_purpose
        self.proof_extra_action = proof_extra_action
        self.command_by_role = dict(command_by_role or {})
        self.captain_hypothesis_ids = captain_hypothesis_ids
        self.captain_action_hypothesis_ids = (
            captain_action_hypothesis_ids
        )
        self.lock = threading.Lock()
        self.active = 0
        self.max_active = 0
        self.roles: list[Role] = []
        self.prompts: list[tuple[Role, str]] = []

    def _prepare_output_payload(
        self,
        *,
        command,
        cwd,
        role: Role,
        payload: dict[str, object],
    ) -> None:
        """Allow test executors to prepare one payload before it is written."""
        del command, cwd, role, payload

    def run(self, command, *, cwd, timeout, on_stdout_line):
        del timeout
        role = _role_for(command)
        with self.lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            self.roles.append(role)
            self.prompts.append((role, command.stdin))
        try:
            payload = _payload(role)
            if role is Role.CAPTAIN:
                payload["decision"] = {
                    "next_stage": self.captain_stage,
                    "reason": "synthetic managed routing decision",
                }
            if role is not Role.CAPTAIN:
                payload["hypotheses"] = []
            schema_index = command.argv.index("--output-schema")
            output_schema = json.loads(
                Path(command.argv[schema_index + 1]).read_text(
                    encoding="utf-8"
                )
            )
            contract_version = output_schema["properties"][
                "schema_version"
            ]["enum"][0]
            current_run_id = Path(
                command.argv[schema_index + 1]
            ).parent.name
            if contract_version == 2:
                payload["schema_version"] = 2
                if role is Role.CAPTAIN:
                    payload["decision"]["selected_experiment"] = None
                    hypothesis_count = (
                        len(self.captain_hypothesis_ids)
                        if self.captain_hypothesis_ids is not None
                        else self.captain_hypothesis_count
                    )
                    payload["hypotheses"] = [
                        {
                            "id": f"hyp-{index}",
                            "claim": (
                                f"independent managed hypothesis {index}"
                            ),
                            "evidence": ["obs-1"],
                            "unknowns": [
                                f"unknown discriminator {index}"
                            ],
                            "experiment": (
                                f"run bounded discriminator {index}"
                            ),
                            "success_oracle": (
                                f"observe distinct behavior {index}"
                            ),
                            "falsifier": (
                                f"behavior {index} remains unchanged"
                            ),
                        }
                        for index in range(
                            1, hypothesis_count + 1
                        )
                    ]
                for action in payload["actions"]:
                    action.update(
                        {
                            "hypothesis_ids": (
                                [
                                    item.replace(
                                        "{run_id}",
                                        current_run_id,
                                    )
                                    for item in (
                                        self.captain_action_hypothesis_ids
                                        or ("hyp-1",)
                                    )
                                ]
                                if role is Role.CAPTAIN
                                else []
                            ),
                            "expected_observation": (
                                "the bounded probe exits normally"
                            ),
                            "keep_if": "the observation is reproduced",
                            "drop_if": "the observation is absent",
                            "timeout_seconds": 30,
                            "resource_class": "light",
                            "network_target_id": (
                                self.network_target[0]
                                if self.network_target is not None
                                else None
                            ),
                            "network_target_generation": (
                                self.network_target[1]
                                if self.network_target is not None
                                else None
                            ),
                        }
                    )
                    if (
                        action.get("kind") == "command"
                        and role in self.command_by_role
                    ):
                        action["command"] = self.command_by_role[role]
                if (
                    role is Role.REPRODUCER
                    and self.proof_candidate_id is not None
                ):
                    payload["actions"] = [
                        {
                            "kind": "prove_candidate",
                            "description": (
                                "replay the engine-bound tool result"
                            ),
                            "candidate_id": self.proof_candidate_id,
                            "inputs": (
                                [
                                    {
                                        "artifact_id": (
                                            self.proof_artifact_id
                                        ),
                                        "purpose": (
                                            self.proof_artifact_purpose
                                        ),
                                    }
                                ]
                                if self.proof_artifact_id is not None
                                else []
                            ),
                        }
                    ]
                    if self.proof_extra_action:
                        payload["actions"].append(
                            {
                                "kind": "command",
                                "description": "unexpected extra proof action",
                                "command": "true",
                                "artifact_path": None,
                                "hypothesis_ids": [],
                                "expected_observation": "true exits zero",
                                "keep_if": "the command exits zero",
                                "drop_if": "the command fails",
                                "timeout_seconds": 1,
                                "resource_class": "light",
                                "network_target_id": None,
                                "network_target_generation": None,
                            }
                        )
                if (
                    role is self.invalid_command_role
                    and payload["actions"]
                ):
                    payload["actions"][0]["command"] = ""
            if (
                role is Role.CAPTAIN
                and self.captain_hypothesis_ids is not None
            ):
                for hypothesis, hypothesis_id in zip(
                    payload["hypotheses"],
                    self.captain_hypothesis_ids,
                    strict=True,
                ):
                    hypothesis["id"] = hypothesis_id.replace(
                        "{run_id}",
                        current_run_id,
                    )
            if role is self.invalid_role:
                on_stdout_line(
                    json.dumps(
                        {
                            "type": "item.completed",
                            "text": "candidate KCTF{provisional_wave}",
                        }
                    )
                    + "\n"
                )
                payload["artifacts"] = [
                    {
                        "path": "missing.bin",
                        "sha256": None,
                        "purpose": "force normalization failure",
                    }
                ]
            if role is self.source_reference_role:
                content = b"\x7fELFmanaged"
                payload["artifacts"] = [
                    {
                        "path": "challenge.bin",
                        "sha256": hashlib.sha256(content).hexdigest(),
                        "purpose": "canonical source reference",
                    }
                ]
            time.sleep(0.01)
            self._prepare_output_payload(
                command=command,
                cwd=cwd,
                role=role,
                payload=payload,
            )
            _output_path(command).write_text(
                json.dumps(payload),
                encoding="utf-8",
            )
            return ProcessOutcome(0, "", 0.01)
        finally:
            with self.lock:
                self.active -= 1


class CanonicalArtifactEchoExecutor(ProbeRoleExecutor):
    """Have the Captain repeat one supplied artifact binding."""

    def __init__(self, *, path: str, sha256: str) -> None:
        super().__init__()
        self.path = path
        self.sha256 = sha256

    def _prepare_output_payload(
        self,
        *,
        command,
        cwd,
        role: Role,
        payload: dict[str, object],
    ) -> None:
        del command, cwd
        if role is Role.CAPTAIN:
            payload["artifacts"] = [
                {
                    "path": self.path,
                    "sha256": self.sha256,
                    "purpose": "existing canonical evidence",
                }
            ]


class BuilderPublicationExecutor(ProbeRoleExecutor):
    """Publish one Builder solver and execute it as a generic action."""

    def __init__(self) -> None:
        super().__init__(
            command_by_role={Role.BUILDER: "python3 solver.py"},
        )
        self.solver_path: Path | None = None

    def _prepare_output_payload(
        self,
        *,
        command,
        cwd,
        role: Role,
        payload: dict[str, object],
    ) -> None:
        del command
        if role is not Role.BUILDER:
            return
        self.solver_path = Path(cwd) / "solver.py"
        self.solver_path.write_bytes(BUILDER_SOLVER_PAYLOAD)
        payload["artifacts"] = [
            {
                "path": "solver.py",
                "sha256": hashlib.sha256(
                    BUILDER_SOLVER_PAYLOAD
                ).hexdigest(),
                "purpose": "generic action solver",
            }
        ]


class BuilderPublicationSandbox(FakeSandbox):
    """Mutate the model workspace, then observe the isolated action input."""

    def __init__(
        self,
        work: Path,
        executor: BuilderPublicationExecutor,
    ) -> None:
        super().__init__(work)
        self.executor = executor
        self.observed_solver: bytes | None = None
        self.builder_action_calls = 0

    def initialize_workspace(self, *, deadline_monotonic_seconds=None):
        super().initialize_workspace(
            deadline_monotonic_seconds=deadline_monotonic_seconds
        )
        source = self.executor.solver_path
        if source is not None:
            source.write_bytes(MUTATED_BUILDER_SOLVER_PAYLOAD)

    def run(self, spec):
        if (
            spec.argv[:2] == ("/bin/sh", "-lc")
            and spec.argv[2]
            in {"python3 solver.py", "python3 /work/solver.py"}
        ):
            self.builder_action_calls += 1
            solver = self.work / "solver.py"
            self.observed_solver = (
                solver.read_bytes() if solver.is_file() else None
            )
        return super().run(spec)


class ToolConcurrency:
    def __init__(self, *, expected_lanes: int) -> None:
        self.lock = threading.Lock()
        self.active = 0
        self.maximum = 0
        self.rendezvous = threading.Barrier(expected_lanes)

    def enter(self) -> None:
        with self.lock:
            self.active += 1
            self.maximum = max(self.maximum, self.active)
        self.rendezvous.wait(timeout=5)

    def leave(self) -> None:
        with self.lock:
            self.active -= 1


class SlowSandbox(FakeSandbox):
    def __init__(self, work: Path, concurrency: ToolConcurrency) -> None:
        super().__init__(work)
        self.concurrency = concurrency

    def run(self, spec):
        self.concurrency.enter()
        try:
            time.sleep(0.15)
            return super().run(spec)
        finally:
            self.concurrency.leave()


class ReplaySandbox(FakeSandbox):
    """Tool and clean proof both expose the same replay candidate."""

    def run(self, spec):
        result = super().run(spec)
        stdout = self.work / "raw" / "stdout.log"
        payload = "answer KCTF{proof_flag}\n"
        stdout.write_text(payload, encoding="utf-8")
        return replace(
            result,
            stdout_summary=payload.strip(),
            stdout_bytes=stdout.stat().st_size,
        )

    def run_clean_proof(self, spec, **kwargs):
        result = super().run_clean_proof(spec, **kwargs)
        if spec.network_target is not None:
            return result
        stdout = self.work / result.stdout_path.removeprefix("/work/")
        payload = "negative control: remote target disabled\n"
        stdout.write_text(payload, encoding="utf-8")
        return replace(
            result,
            stdout_summary=payload.strip(),
            stdout_bytes=stdout.stat().st_size,
        )


class AlwaysReplaySandbox(ReplaySandbox):
    """Unsafe replay double used to prove the negative control catches it."""

    def run_clean_proof(self, spec, **kwargs):
        return FakeSandbox.run_clean_proof(self, spec, **kwargs)


class RevManagedProofSandbox(FakeSandbox):
    """Complete v2 inventory, source, and six-run Rev proof double."""

    def __init__(
        self,
        work: Path,
        source: bytes,
        *,
        accepted_input: bytes,
        negative_emits_flag: bool = False,
        transport_exit_ordinal: int | None = None,
        orchestration_error_ordinal: int | None = None,
    ) -> None:
        super().__init__(work)
        self.source = source
        self.accepted_input = accepted_input
        self.negative_emits_flag = negative_emits_flag
        self.transport_exit_ordinal = transport_exit_ordinal
        self.orchestration_error_ordinal = (
            orchestration_error_ordinal
        )
        self.tool_calls = 0

    @staticmethod
    def _result(
        *,
        run_id: str,
        stdout: Path,
        stderr: Path,
        stdout_path: str,
        stderr_path: str,
        exit_code: int = 0,
    ) -> SandboxResult:
        stdout_size = stdout.stat().st_size
        stderr_size = stderr.stat().st_size
        return SandboxResult(
            run_id=run_id,
            status="completed" if exit_code == 0 else "failed",
            exit_code=exit_code,
            timed_out=False,
            duration_ms=5,
            stdout_summary=stdout.read_text(
                encoding="utf-8",
                errors="replace",
            ),
            stderr_summary=stderr.read_text(
                encoding="utf-8",
                errors="replace",
            ),
            stdout_bytes=stdout_size,
            stderr_bytes=stderr_size,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            stdout_stored_bytes=stdout_size,
            stderr_stored_bytes=stderr_size,
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
        )

    def run(self, spec):
        self.specs.append(spec)
        self.tool_calls += 1
        relative = Path("raw") / f"managed-{self.tool_calls}"
        directory = self.work / relative
        directory.mkdir(parents=True, exist_ok=False)
        stdout = directory / "stdout.log"
        stderr = directory / "stderr.log"
        if "/opt/ctf-templates/rev/inventory_v2.py" in spec.argv:
            stdout.write_bytes(_rev_inventory_payload(self.source))
        else:
            stdout.write_bytes(b"answer KCTF{rev_proof_flag}\n")
        stderr.write_bytes(b"")
        return self._result(
            run_id=f"managed-{self.tool_calls}",
            stdout=stdout,
            stderr=stderr,
            stdout_path=f"/work/{relative.as_posix()}/stdout.log",
            stderr_path=f"/work/{relative.as_posix()}/stderr.log",
        )

    def run_clean_proof(
        self,
        spec,
        *,
        input_locators=(),
        proof_inputs=(),
    ):
        del input_locators
        self.proof_specs.append(spec)
        self.proof_calls += 1
        self.assert_no_network(spec)
        captured_inputs = []
        for item in proof_inputs:
            payload = (self.work / item.source_locator).read_bytes()
            self.assert_input_binding(item, payload)
            captured_inputs.append((item.destination_locator, payload))
        self.proof_input_calls.append(tuple(captured_inputs))
        payload = captured_inputs[0][1]
        if self.orchestration_error_ordinal == self.proof_calls:
            raise RuntimeError("synthetic Rev sandbox orchestration error")
        positive = payload == self.accepted_input
        relative = Path("proof") / f"rev-clean-{self.proof_calls}"
        directory = self.work / relative
        directory.mkdir(parents=True, exist_ok=False)
        stdout = directory / "stdout.log"
        stderr = directory / "stderr.log"
        if positive or (
            self.negative_emits_flag and self.proof_calls == 4
        ):
            stdout.write_bytes(b"KCTF{rev_proof_flag}\n")
        else:
            stdout.write_bytes(b"rejected\n")
        stderr.write_bytes(b"")
        exit_code = (
            125
            if self.transport_exit_ordinal == self.proof_calls
            else 7
            if not positive
            else 0
        )
        return self._result(
            run_id=f"rev-proof-{self.proof_calls}",
            stdout=stdout,
            stderr=stderr,
            stdout_path=f"/work/{relative.as_posix()}/stdout.log",
            stderr_path=f"/work/{relative.as_posix()}/stderr.log",
            exit_code=exit_code,
        )

    @staticmethod
    def assert_no_network(spec) -> None:
        if spec.network_target is not None:
            raise AssertionError("Rev proof unexpectedly enabled network")

    @staticmethod
    def assert_input_binding(item, payload: bytes) -> None:
        if hashlib.sha256(payload).hexdigest() != item.sha256:
            raise AssertionError("Rev proof input hash mismatch")
        if len(payload) != item.size_bytes:
            raise AssertionError("Rev proof input size mismatch")
        if item.destination_locator != "oracle/accepted-input.bin":
            raise AssertionError("Rev proof input destination changed")


class ReceiptCanarySandbox(FakeSandbox):
    canary = "RECEIPT_CANARY route-count=7"
    credential = "must-not-reach-model"

    def __init__(self, work: Path) -> None:
        super().__init__(work)
        self._receipt_lock = threading.Lock()
        self._receipt_counter = 0

    def run(self, spec):
        self.specs.append(spec)
        with self._receipt_lock:
            self._receipt_counter += 1
            ordinal = self._receipt_counter
        relative = Path("raw") / f"receipt-{ordinal}"
        raw = self.work / relative
        raw.mkdir(parents=True, exist_ok=False)
        stdout = raw / "stdout.log"
        stderr = raw / "stderr.log"
        payload = (
            f"{self.canary}\n"
            f"Authorization: Bearer {self.credential}\n"
        )
        stdout.write_text(payload, encoding="utf-8")
        stderr.write_bytes(b"")
        return SandboxResult(
            run_id=f"tool-{ordinal}",
            status="completed",
            exit_code=0,
            timed_out=False,
            duration_ms=5,
            # The transport tail intentionally contains the credential.  The
            # receipt integration must read only the immutable snapshot and
            # redact it rather than forwarding this field.
            stdout_summary=payload,
            stderr_summary="",
            stdout_bytes=stdout.stat().st_size,
            stderr_bytes=0,
            stdout_path=f"/work/{relative.as_posix()}/stdout.log",
            stderr_path=f"/work/{relative.as_posix()}/stderr.log",
            stdout_stored_bytes=stdout.stat().st_size,
            stderr_stored_bytes=0,
            stdout_limit_bytes=4096,
            stderr_limit_bytes=4096,
            stdout_truncated=False,
            stderr_truncated=False,
            stdout_truncation_known=True,
            stderr_truncation_known=True,
            stdout_capture_complete=True,
            stderr_capture_complete=True,
            stdout_summary_truncated=False,
            stderr_summary_truncated=False,
        )


class FailingSandbox(FakeSandbox):
    def run(self, spec):
        del spec
        self.work.mkdir(parents=True, exist_ok=True)
        (self.work / "failed-stage.txt").write_text(
            "provisional",
            encoding="utf-8",
        )
        raise RuntimeError("synthetic sandbox failure")


class ManagedV2Tests(unittest.TestCase):
    def test_managed_proof_credential_screen_is_executable_aware(self):
        allowed = (
            ("python3", "-u", "solver.py"),
            ("python3", "-i", "solver.py"),
            ("ssh", "-p", "2222", "challenge.example"),
            ("curl", "-i", "https://challenge.example"),
            (
                "solver",
                "--config",
                "challenge.toml",
                "--user",
                "alice",
                "--session",
                "debug",
            ),
        )
        blocked = (
            ("curl", "-u", "alice:secret", "https://challenge.example"),
            ("curl", "--cookie=session=secret", "https://challenge.example"),
            ("ssh", "-i", "operator-key", "challenge.example"),
            ("solver", "--access-code", "opaque"),
            ("solver", "ACCESS_CODE=opaque"),
            ("solver", "Authorization: Bearer opaque"),
        )
        for argv in allowed:
            with self.subTest(argv=argv):
                self.assertFalse(
                    _proof_argv_contains_credential_material(argv)
                )
        for argv in blocked:
            with self.subTest(argv=argv):
                self.assertTrue(
                    _proof_argv_contains_credential_material(argv)
                )

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.identity = ChallengeIdentity("Managed CTF", "rev", "one")
        incoming = (
            self.root
            / "incoming"
            / self.identity.contest_id
            / self.identity.category
            / self.identity.challenge_id
        )
        incoming.mkdir(parents=True)
        (incoming / "challenge.bin").write_bytes(b"\x7fELFmanaged")

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def engine(
        self,
        executor: ProbeRoleExecutor,
        *,
        sandbox_factory=None,
    ) -> ChallengeEngine:
        config = load_config(self.root)
        config = replace(
            config,
            runtime=replace(
                config.runtime,
                image_digest=IMAGE_DIGEST,
            ),
            resources=replace(
                config.resources,
                provider_max_concurrent_calls=1,
                max_standard_jobs=3,
            ),
        )
        runner = BatchRunner(
            process_executor=executor,
            limiter=FifoModelCallLimiter(1),
            limiter_wait_timeout=2,
            max_schema_retries=0,
        )
        return ChallengeEngine(
            self.root,
            config=config,
            batch_runner=runner,
            sandbox_factory=(
                sandbox_factory
                or (lambda state, work, policy: FakeSandbox(work))
            ),
        )

    @staticmethod
    def capability(_digest: str):
        return {
            "ok": True,
            "schema_version": 2,
            "capabilities": {
                "convert": {},
                "sqlite_readonly": {},
                "z3": {},
                "ortools": {},
                "angr_python": {},
            },
        }

    def add_v2(self, engine: ChallengeEngine):
        return engine.add_challenge(
            self.identity,
            prompt="solve this one challenge",
            state_schema_version=STATE_SCHEMA_VERSION,
        )

    def seed_canonical_artifact(
        self,
        engine: ChallengeEngine,
    ) -> ArtifactReference:
        destination = (
            engine.store.challenge_paths(self.identity).root
            / CANONICAL_REFERENCE_PATH
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(CANONICAL_REFERENCE_PAYLOAD)
        destination.chmod(0o400)
        reference = ArtifactReference(
            id=CANONICAL_REFERENCE_ID,
            path=CANONICAL_REFERENCE_PATH,
            sha256=CANONICAL_REFERENCE_SHA256,
            size=len(CANONICAL_REFERENCE_PAYLOAD),
            extra={"purpose": "existing canonical evidence"},
        )
        current = engine.store.load(self.identity)

        def seed(state):
            state.artifacts.append(copy.deepcopy(reference))

        engine.store.update(
            self.identity,
            seed,
            expected_revision=current.revision,
        )
        return reference

    def test_preflight_passes_category_requirements_to_production_probe(self):
        engine = self.engine(ProbeRoleExecutor())
        self.add_v2(engine)
        calls = []

        def probe(digest, *, required):
            calls.append((digest, required))
            return {
                "ok": True,
                "schema_version": 2,
                "required": sorted(required),
                "available": sorted(required),
                "missing": [],
            }

        with mock.patch.object(
            managed_module,
            "inspect_pinned_capabilities",
            probe,
        ):
            report = ManagedOrchestrator(
                engine,
                capability_probe=probe,
            ).preflight(self.identity)

        self.assertTrue(report.ok, report.issues)
        self.assertEqual(
            calls,
            [
                (
                    IMAGE_DIGEST,
                    required_managed_capabilities_for_category("rev"),
                )
            ],
        )

    def seed_managed_remote_action(
        self,
        engine: ChallengeEngine,
        endpoint: str,
    ) -> tuple[str, str]:
        state = engine.add_network_target(
            self.identity,
            endpoint,
            docker_network="ctfos-proxy",
            enforcement="proxy",
        )
        target = state.targets[-1]
        engine.select_network_target(self.identity, target.id)
        _state, experiment_id = engine.register_experiment(
            self.identity,
            command=("python3", "-c", "print('managed remote')"),
            expected_observation="remote output",
            keep_if="output exists",
            drop_if="output is absent",
            network_target=endpoint,
        )
        run_id = f"R-managed-remote-{experiment_id}"

        def bind_source(current):
            current.runs.append(
                RunReference(
                    id=run_id,
                    base_revision=current.revision,
                    status=RunStatus.CREATED,
                    role=Role.BUILDER.value,
                    origin=RunOrigin.MANAGED_MODEL,
                    configuration_epoch=current.configuration_epoch,
                )
            )
            experiment = next(
                item
                for item in current.experiments
                if item.id == experiment_id
            )
            experiment.source_run_id = run_id

        engine.store.update(self.identity, bind_source)
        return target.id, experiment_id

    def pwn_crash_registration_fixture(
        self,
        *,
        suffix: str,
        category: str = "pwn",
        wave_name: str = "attack",
        role: Role = Role.BUILDER,
        contract_version: int = 2,
        artifact_sizes: tuple[int, ...] = (4,),
        action_locator: str = "payload.bin",
        hypothesis_reference: str = "local",
        reprocess_count: int = 1,
        action_count: int = 1,
    ):
        identity = ChallengeIdentity(
            "Managed CTF",
            category,
            f"pwn-crash-{suffix}",
        )
        incoming = (
            self.root
            / "incoming"
            / identity.contest_id
            / identity.category
            / identity.challenge_id
        )
        incoming.mkdir(parents=True)
        (incoming / "challenge.bin").write_bytes(b"\x7fELFpwn-crash")
        engine = self.engine(ProbeRoleExecutor())
        engine.add_challenge(
            identity,
            prompt="verify one local stdin crash",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        _state, session_id = orchestrator._reserve_session(identity, None)
        _state, cycle = orchestrator._reserve_cycle(identity, session_id)
        _state, wave, role_runs = orchestrator._reserve_wave(
            identity,
            session_id,
            cycle.id,
            wave_name,
        )
        run_id = (
            role_runs[role]
            if role in role_runs
            else next(iter(role_runs.values()))
        )
        local_hypothesis_id = "builder-local"
        canonical_hypothesis_id = (
            f"H-{run_id}-{local_hypothesis_id}"
        )
        challenge_paths = engine.store.challenge_paths(identity)
        snapshot_directory = challenge_paths.artifacts / "snapshots"
        snapshot_directory.mkdir(parents=True, exist_ok=True)
        artifact_payloads: list[tuple[str, bytes]] = []
        for index, size in enumerate(artifact_sizes, start=1):
            artifact_id = f"A-{run_id}-{index}"
            payload_bytes = bytes((index & 0xFF,)) * size
            artifact_path = snapshot_directory / f"{artifact_id}.bin"
            artifact_path.write_bytes(payload_bytes)
            artifact_path.chmod(0o400)
            artifact_payloads.append((artifact_id, payload_bytes))

        def seed(state):
            run = next(item for item in state.runs if item.id == run_id)
            run.status = RunStatus.COMPLETED
            run.result_path = f"runs/{run_id}/result.json"
            run.validation_path = f"runs/{run_id}/validation.json"
            run.extra["semantic_merge"] = True
            state.hypotheses.append(
                Hypothesis(
                    id=canonical_hypothesis_id,
                    statement="the exact payload triggers a target crash",
                    falsifier=Falsifier(
                        "empty stdin or exact replay does not preserve a fault"
                    ),
                    source_run_id=run_id,
                )
            )
            for artifact_id, payload_bytes in artifact_payloads:
                state.artifacts.append(
                    ArtifactReference(
                        id=artifact_id,
                        path=(
                            "artifacts/snapshots/"
                            f"{artifact_id}.bin"
                        ),
                        sha256=hashlib.sha256(payload_bytes).hexdigest(),
                        source_run_id=run_id,
                        size=len(payload_bytes),
                        extra={
                            "reported_locator": "payload.bin",
                            "purpose": "crash payload",
                        },
                    )
                )

        engine.store.update(identity, seed)
        requested_hypothesis = (
            canonical_hypothesis_id
            if hypothesis_reference == "canonical"
            else "unknown-hypothesis"
            if hypothesis_reference == "missing"
            else local_hypothesis_id
        )
        result = mock.Mock(
            invocation=mock.Mock(
                role=role,
                run_id=run_id,
                contract_version=contract_version,
            ),
            output={
                "hypotheses": [
                    {
                        "id": local_hypothesis_id,
                        "claim": "the exact payload crashes the target",
                    }
                ],
                "actions": [
                    {
                        "kind": "verify_pwn_crash",
                        "description": "verify the crash",
                        "payload_artifact_path": action_locator,
                        "hypothesis_id": requested_hypothesis,
                    }
                    for _ in range(action_count)
                ],
            },
        )
        state = engine.store.load(identity)
        for _ in range(reprocess_count):
            state = orchestrator._register_pwn_crash_actions(
                identity,
                wave,
                (result,),
            )
        return state, run_id, canonical_hypothesis_id

    @staticmethod
    def pwn_crash_experiments(state):
        return [
            item
            for item in state.experiments
            if item.extra.get("engine_executor")
            == "pwn_crash_differential_v1"
        ]

    def test_pwn_crash_registration_accepts_local_and_canonical_hypotheses(
        self,
    ):
        for reference in ("local", "canonical"):
            with self.subTest(reference=reference):
                state, run_id, hypothesis_id = (
                    self.pwn_crash_registration_fixture(
                        suffix=f"valid-{reference}",
                        hypothesis_reference=reference,
                    )
                )
                experiments = self.pwn_crash_experiments(state)
                self.assertEqual(len(experiments), 1)
                experiment = experiments[0]
                self.assertEqual(
                    experiment.command,
                    "ctfos-engine:pwn-crash-v1",
                )
                self.assertEqual(experiment.hypothesis_ids, [hypothesis_id])
                self.assertEqual(len(experiment.artifact_ids), 1)
                self.assertEqual(experiment.source_run_id, run_id)
                self.assertIs(
                    experiment.kind,
                    ExperimentKind.STRATEGIC,
                )
                self.assertIs(
                    experiment.status,
                    ExperimentStatus.REGISTERED,
                )
                self.assertEqual(
                    experiment.extra["managed_action_kind"],
                    "verify_pwn_crash",
                )
                request = experiment.extra["pwn_crash_request"]
                self.assertEqual(
                    set(request),
                    {
                        "schema_version",
                        "contract_id",
                        "contract_version",
                        "contract_fingerprint",
                        "protocol",
                        "configuration_epoch",
                        "payload_artifact_id",
                        "payload_reported_locator",
                        "payload_sha256",
                        "payload_size_bytes",
                        "hypothesis_id",
                        "source_builder_run_id",
                    },
                )
                self.assertEqual(request["schema_version"], 1)
                self.assertEqual(
                    request["payload_artifact_id"],
                    experiment.artifact_ids[0],
                )
                self.assertEqual(
                    request["payload_reported_locator"],
                    "payload.bin",
                )
                self.assertEqual(request["payload_size_bytes"], 4)
                self.assertEqual(request["hypothesis_id"], hypothesis_id)
                self.assertEqual(request["source_builder_run_id"], run_id)
                self.assertTrue(
                    {
                        "command",
                        "network_target",
                        "signal",
                        "verdict",
                        "recipe_sha256",
                    }.isdisjoint(request)
                )

    def test_pwn_crash_registration_requires_v2_pwn_attack_builder(self):
        cases = (
            {
                "suffix": "wrong-category",
                "category": "rev",
                "reason": "category pwn",
            },
            {
                "suffix": "wrong-wave",
                "wave_name": "discovery",
                "reason": "ATTACK wave",
            },
            {
                "suffix": "wrong-role",
                "role": Role.FALSIFIER,
                "reason": "ATTACK Builder",
            },
            {
                "suffix": "wrong-contract",
                "contract_version": 1,
                "reason": "v2 role contract",
            },
        )
        for case in cases:
            with self.subTest(case=case["suffix"]):
                kwargs = {
                    key: value
                    for key, value in case.items()
                    if key != "reason"
                }
                state, run_id, _hypothesis_id = (
                    self.pwn_crash_registration_fixture(**kwargs)
                )
                self.assertEqual(self.pwn_crash_experiments(state), [])
                run = next(item for item in state.runs if item.id == run_id)
                self.assertIn(
                    case["reason"],
                    run.extra["rejected_actions"][-1]["reason"],
                )

    def test_pwn_crash_registration_rejects_unsafe_payload_or_hypothesis(
        self,
    ):
        cases = (
            {
                "suffix": "missing-payload",
                "artifact_sizes": (),
                "reprocess_count": 2,
                "reason": "exactly one normalized artifact",
            },
            {
                "suffix": "ambiguous-payload",
                "artifact_sizes": (4, 4),
                "reason": "observed 2",
            },
            {
                "suffix": "empty-payload",
                "artifact_sizes": (0,),
                "reason": "non-empty",
            },
            {
                "suffix": "oversize-payload",
                "artifact_sizes": (1024 * 1024 + 1,),
                "reason": "at most 1048576 bytes",
            },
            {
                "suffix": "unsafe-locator",
                "action_locator": "../payload.bin",
                "reason": "safe relative path",
            },
            {
                "suffix": "missing-hypothesis",
                "hypothesis_reference": "missing",
                "reason": "active local or canonical hypothesis",
            },
        )
        for case in cases:
            with self.subTest(case=case["suffix"]):
                kwargs = {
                    key: value
                    for key, value in case.items()
                    if key != "reason"
                }
                state, run_id, _hypothesis_id = (
                    self.pwn_crash_registration_fixture(**kwargs)
                )
                self.assertEqual(self.pwn_crash_experiments(state), [])
                run = next(item for item in state.runs if item.id == run_id)
                self.assertIn(
                    case["reason"],
                    run.extra["rejected_actions"][-1]["reason"],
                )
                if case["suffix"] == "missing-payload":
                    self.assertEqual(len(run.extra["rejected_actions"]), 1)

    def test_pwn_crash_registration_bounds_distinct_rejections(self):
        state, run_id, _hypothesis_id = (
            self.pwn_crash_registration_fixture(
                suffix="bounded-rejections",
                artifact_sizes=(),
                action_count=70,
                reprocess_count=2,
            )
        )
        run = next(item for item in state.runs if item.id == run_id)
        self.assertEqual(len(run.extra["rejected_actions"]), 64)
        self.assertEqual(
            [item["action"] for item in run.extra["rejected_actions"]],
            [str(index) for index in range(1, 65)],
        )

    def test_selected_pwn_crash_nonpass_always_creates_failure_capsule(
        self,
    ):
        from tests.test_pwn_crash_execution import (
            PwnCrashExecutionTests,
            _SandboxCoordinator,
        )

        cases = (
            (
                "inconclusive",
                (
                    ("exited", 139, None),
                    ("exited", 139, None),
                    ("exited", 139, None),
                    ("exited", 0, None),
                    ("exited", 0, None),
                    ("exited", 0, None),
                ),
                (),
                ExperimentStatus.INCONCLUSIVE,
            ),
            (
                "failed",
                PwnCrashExecutionTests._confirming_statuses(),
                (2,),
                ExperimentStatus.FAILED,
            ),
            (
                "confirmed",
                PwnCrashExecutionTests._confirming_statuses(),
                (),
                ExperimentStatus.KEPT,
            ),
        )
        for (
            label,
            statuses,
            truncated_ordinals,
            expected_status,
        ) in cases:
            with self.subTest(label=label):
                fixture = PwnCrashExecutionTests(
                    "test_confirmed_gate_uses_six_clean_networkless_fixed_calls"
                )
                fixture.setUp()
                try:
                    coordinator = _SandboxCoordinator(
                        statuses,
                        truncated_ordinals=truncated_ordinals,
                    )
                    (
                        engine,
                        experiment_id,
                        _artifact_path,
                        _payload,
                    ) = fixture._fixture(coordinator)
                    executed = fixture._execute(engine, experiment_id)
                    experiment = next(
                        item
                        for item in executed.experiments
                        if item.id == experiment_id
                    )
                    self.assertIs(experiment.status, expected_status)
                    cycle = executed.cycles[0]
                    wave = executed.waves[0]
                    orchestrator = ManagedOrchestrator(
                        engine,
                        capability_probe=fixture._capability,
                    )
                    checkpointed = (
                        orchestrator._checkpoint_selected_actions(
                            fixture.identity,
                            cycle.session_id,
                            cycle.id,
                            wave,
                            (experiment_id,),
                            note="typed Pwn gate checkpoint",
                        )
                    )
                    capsule = checkpointed.checkpoints[
                        -1
                    ].failure_capsule
                    if expected_status is ExperimentStatus.KEPT:
                        self.assertIsNone(capsule)
                        continue

                    self.assertIsNotNone(capsule)
                    assert capsule is not None
                    evaluation = experiment.result[
                        "pwn_crash_evidence"
                    ]["evaluation"]
                    expected_reason = (
                        orchestrator._bounded_pwn_crash_failure_reason(
                            evaluation["verdict"],
                            evaluation["reason_code"],
                        )
                    )
                    self.assertEqual(capsule.reason_code, expected_reason)
                    self.assertEqual(capsule.stage, "attack")
                    self.assertEqual(
                        capsule.state_revision_after,
                        checkpointed.revision,
                    )

                    pwn_run_ids = set(experiment.evidence_run_ids)
                    pwn_receipt_ids = set(
                        experiment.evidence_receipt_ids
                    )
                    stream_artifact_ids = {
                        artifact.id
                        for artifact in checkpointed.artifacts
                        if (
                            artifact.source_run_id in pwn_run_ids
                            and artifact.extra.get("stream")
                            in {"stdout", "stderr"}
                        )
                    }
                    self.assertEqual(len(pwn_run_ids), 6)
                    self.assertEqual(len(pwn_receipt_ids), 6)
                    self.assertEqual(len(stream_artifact_ids), 12)
                    self.assertTrue(
                        pwn_run_ids.issubset(capsule.run_ids)
                    )
                    self.assertTrue(
                        pwn_receipt_ids.issubset(capsule.receipt_ids)
                    )
                    self.assertTrue(
                        stream_artifact_ids.issubset(
                            capsule.artifact_ids
                        )
                    )
                    self.assertNotEqual(
                        checkpointed.status,
                        ChallengeStatus.READY_TO_SUBMIT,
                    )
                finally:
                    fixture.tearDown()

    def test_selected_pwn_crash_setup_failure_uses_fixed_capsule_reason(
        self,
    ):
        from tests.test_pwn_crash_execution import (
            PwnCrashExecutionTests,
            _SandboxCoordinator,
        )

        fixture = PwnCrashExecutionTests(
            "test_confirmed_gate_uses_six_clean_networkless_fixed_calls"
        )
        fixture.setUp()
        try:
            coordinator = _SandboxCoordinator(
                PwnCrashExecutionTests._confirming_statuses()
            )
            engine, experiment_id, _artifact_path, _payload = (
                fixture._fixture(coordinator)
            )
            with mock.patch.object(
                engine,
                "_execute_pwn_crash_differential",
                side_effect=EngineError("synthetic setup failure"),
            ):
                executed = fixture._execute(engine, experiment_id)
            experiment = next(
                item
                for item in executed.experiments
                if item.id == experiment_id
            )
            self.assertIs(experiment.status, ExperimentStatus.FAILED)
            self.assertNotIn(
                "pwn_crash_evidence",
                experiment.result or {},
            )
            cycle = executed.cycles[0]
            wave = executed.waves[0]
            checkpointed = ManagedOrchestrator(
                engine,
                capability_probe=fixture._capability,
            )._checkpoint_selected_actions(
                fixture.identity,
                cycle.session_id,
                cycle.id,
                wave,
                (experiment_id,),
                note=None,
            )
            capsule = checkpointed.checkpoints[-1].failure_capsule
            self.assertIsNotNone(capsule)
            assert capsule is not None
            self.assertEqual(
                capsule.reason_code,
                "pwn_crash_setup_failed",
            )
            self.assertEqual(capsule.stage, "attack")
        finally:
            fixture.tearDown()

    def execute_managed_source_fixture(
        self,
        orchestrator: ManagedOrchestrator,
        engine: ChallengeEngine,
        identity: ChallengeIdentity,
        experiment_id: str,
    ):
        _state, session_id = orchestrator._reserve_session(identity, None)
        _state, cycle = orchestrator._reserve_cycle(identity, session_id)
        orchestrator._mark_action_selection(
            identity,
            session_id,
            cycle.id,
            (experiment_id,),
        )
        engine.execute_registered_experiments(
            identity,
            maximum=1,
            experiment_ids=(experiment_id,),
            _session_owned=True,
            _automated=True,
        )
        orchestrator._checkpoint(
            identity,
            session_id,
            cycle.id,
            note="managed source replay fixture",
        )
        return orchestrator._finish_session(
            identity,
            session_id,
            status=SessionStatus.COMPLETED,
            reason="managed source replay fixture completed",
        )

    def run_managed_rev_proof_fixture(
        self,
        *,
        negative_emits_flag: bool = False,
        transport_exit_ordinal: int | None = None,
        orchestration_error_ordinal: int | None = None,
        proof_execution_hook=None,
    ):
        source = (
            self.root
            / "incoming"
            / self.identity.contest_id
            / self.identity.category
            / self.identity.challenge_id
            / "challenge.bin"
        ).read_bytes()
        accepted_input = b"OPEN-SESAME\n"
        executor = ProbeRoleExecutor(
            captain_stage="proof",
            proof_artifact_purpose="accepted_input",
        )
        sandboxes_by_work: dict[Path, RevManagedProofSandbox] = {}

        def sandbox_factory(state, work, policy):
            del state
            if policy.allow_targets:
                raise AssertionError(
                    "managed Rev proof sandbox must deny network"
                )
            key = work.resolve()
            sandbox = sandboxes_by_work.get(key)
            if sandbox is None:
                sandbox = RevManagedProofSandbox(
                    work,
                    source,
                    accepted_input=accepted_input,
                    negative_emits_flag=negative_emits_flag,
                    transport_exit_ordinal=transport_exit_ordinal,
                    orchestration_error_ordinal=(
                        orchestration_error_ordinal
                    ),
                )
                sandboxes_by_work[key] = sandbox
            return sandbox

        engine = self.engine(
            executor,
            sandbox_factory=sandbox_factory,
        )
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        state = self.add_v2(engine)
        inventory_experiment = next(
            item
            for item in state.experiments
            if item.extra.get("adapter_spec_template_id")
            == "inventory_observation"
        )
        self.execute_managed_source_fixture(
            orchestrator,
            engine,
            self.identity,
            inventory_experiment.id,
        )
        state = engine.store.load(self.identity)
        accepted_path = engine._workspace(state) / "accepted-input.bin"
        accepted_path.write_bytes(accepted_input)
        _state, accepted_artifact = engine.register_workspace_artifact(
            self.identity,
            "accepted-input.bin",
        )
        _state, source_experiment_id = engine.register_experiment(
            self.identity,
            command=("/bin/true",),
            expected_observation="the tool emits the solved candidate",
            keep_if="the candidate is present in durable stdout",
            drop_if="the candidate is absent",
        )
        self.execute_managed_source_fixture(
            orchestrator,
            engine,
            self.identity,
            source_experiment_id,
        )
        state = engine.store.load(self.identity)
        candidate = next(
            item
            for item in state.candidates
            if item.value == "KCTF{rev_proof_flag}"
        )
        executor.proof_candidate_id = candidate.id
        executor.proof_artifact_id = accepted_artifact.id

        execute_proof = lambda: orchestrator.run_cycle(self.identity)
        committed = (
            proof_execution_hook(engine, execute_proof)
            if proof_execution_hook is not None
            else execute_proof()
        )
        proof_experiment = next(
            item
            for item in committed.experiments
            if item.kind is ExperimentKind.PROOF
        )
        sandbox = sandboxes_by_work[
            engine._workspace(committed).resolve()
        ]
        return (
            committed,
            proof_experiment,
            candidate,
            sandbox,
            accepted_input,
        )

    def test_rev_managed_stdin_proof_passes_six_clean_runs(self):
        (
            state,
            proof_experiment,
            candidate,
            sandbox,
            accepted_input,
        ) = self.run_managed_rev_proof_fixture()

        self.assertEqual(state.status, ChallengeStatus.READY_TO_SUBMIT)
        self.assertEqual(state.submissions, [])
        self.assertIs(
            proof_experiment.status,
            ExperimentStatus.COMPLETED,
        )
        result = proof_experiment.result
        self.assertTrue(result["proof_result"]["passed"])
        envelope = result["rev_proof_evidence"]
        self.assertEqual(
            envelope["protocol"],
            "rev_original_binary_stdin_candidate_v1",
        )
        self.assertEqual(
            envelope["evaluation_sha256"],
            next(
                item
                for item in state.artifacts
                if item.id == envelope["evaluation_artifact_id"]
            ).sha256,
        )
        self.assertEqual(
            next(
                item
                for item in state.candidates
                if item.id == candidate.id
            ).status,
            CandidateStatus.READY_TO_SUBMIT,
        )
        proof_runs = [
            item
            for item in state.runs
            if item.origin is RunOrigin.PROOF
        ]
        self.assertEqual(len(proof_runs), 6)
        self.assertTrue(
            all(item.status is RunStatus.COMPLETED for item in proof_runs)
        )
        self.assertEqual(sandbox.proof_calls, 6)
        self.assertEqual(
            [call[0][1] for call in sandbox.proof_input_calls[:3]],
            [accepted_input] * 3,
        )
        self.assertEqual(
            [call[0][0] for call in sandbox.proof_input_calls],
            ["oracle/accepted-input.bin"] * 6,
        )
        self.assertEqual(
            [call[0][1] for call in sandbox.proof_input_calls[3:]],
            [
                bytes((accepted_input[0] ^ 0x01,))
                + accepted_input[1:],
                accepted_input[:-1]
                + bytes((accepted_input[-1] ^ 0x80,)),
                accepted_input[:-1],
            ],
        )
        recipe = proof_experiment.proof_recipe
        self.assertIsNotNone(recipe)
        assert recipe is not None
        self.assertEqual(
            recipe.argv,
            (
                "/usr/bin/python3",
                "/opt/ctf-templates/rev/stdin_exec.py",
                "--binary",
                "/challenge/challenge.bin",
                "--input",
                "/work/oracle/accepted-input.bin",
            ),
        )
        state.validate()

    @unittest.skipUnless(
        hasattr(signal, "setitimer"),
        "requires a bounded POSIX interval timer",
    )
    def test_rev_writer_callbacks_never_reenter_storage_admission(self):
        observations: dict[str, int] = {}

        def proof_execution_hook(engine, execute_proof):
            original_update = engine.store.update
            original_admission = engine._enforce_storage_admission
            original_prepare = engine._prepare_rev_adapter_source_snapshot
            inside_writer_callback = False
            external_admissions = 0

            def wrap_callback(callback):
                def wrapped(*args, **kwargs):
                    nonlocal inside_writer_callback
                    previous = inside_writer_callback
                    inside_writer_callback = True
                    try:
                        return callback(*args, **kwargs)
                    finally:
                        inside_writer_callback = previous

                wrapped.__name__ = getattr(
                    callback,
                    "__name__",
                    "wrapped",
                )
                return wrapped

            def monitored_update(*args, **kwargs):
                positional = list(args)
                for index in (1, 3):
                    if (
                        len(positional) > index
                        and callable(positional[index])
                    ):
                        positional[index] = wrap_callback(
                            positional[index]
                        )
                        break
                callback = kwargs.get("mutator")
                if callback is not None:
                    kwargs["mutator"] = wrap_callback(callback)
                for name in ("commit_guard", "pre_replace_guard"):
                    callback = kwargs.get(name)
                    if callback is not None:
                        kwargs[name] = wrap_callback(callback)
                return original_update(*positional, **kwargs)

            def monitored_admission(*args, **kwargs):
                nonlocal external_admissions
                if inside_writer_callback:
                    raise AssertionError(
                        "storage admission reentered from a state writer "
                        "callback"
                    )
                external_admissions += 1
                return original_admission(*args, **kwargs)

            def monitored_prepare(*args, **kwargs):
                if (
                    inside_writer_callback
                    and kwargs.get("allow_create") is not False
                ):
                    raise AssertionError(
                        "Rev source snapshot creation was allowed under "
                        "the state writer lock"
                    )
                return original_prepare(*args, **kwargs)

            def expired(_signum, _frame):
                raise AssertionError(
                    "Rev proof execution exceeded the deadlock timeout"
                )

            previous_handler = signal.signal(signal.SIGALRM, expired)
            try:
                signal.setitimer(signal.ITIMER_REAL, 10.0)
                with (
                    mock.patch.object(
                        engine.store,
                        "update",
                        side_effect=monitored_update,
                    ),
                    mock.patch.object(
                        engine,
                        "_enforce_storage_admission",
                        side_effect=monitored_admission,
                    ),
                    mock.patch.object(
                        engine,
                        "_prepare_rev_adapter_source_snapshot",
                        side_effect=monitored_prepare,
                    ),
                ):
                    committed = execute_proof()
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0.0)
                signal.signal(signal.SIGALRM, previous_handler)
            observations["external_admissions"] = external_admissions
            return committed

        state, proof_experiment, _candidate, sandbox, _accepted = (
            self.run_managed_rev_proof_fixture(
                proof_execution_hook=proof_execution_hook,
            )
        )
        self.assertGreater(observations["external_admissions"], 0)
        self.assertIs(
            proof_experiment.status,
            ExperimentStatus.COMPLETED,
        )
        self.assertEqual(sandbox.proof_calls, 6)
        self.assertIs(state.status, ChallengeStatus.READY_TO_SUBMIT)

    def test_rev_managed_stdin_semantic_falsification_completes(self):
        state, proof_experiment, candidate, sandbox, _accepted = (
            self.run_managed_rev_proof_fixture(
                negative_emits_flag=True,
            )
        )

        self.assertEqual(state.status, ChallengeStatus.ACTIVE)
        self.assertIs(
            proof_experiment.status,
            ExperimentStatus.COMPLETED,
        )
        self.assertFalse(
            proof_experiment.result["proof_result"]["passed"]
        )
        self.assertIn(
            "negative_flag_candidate_observed",
            proof_experiment.result["rev_proof_evidence"][
                "evaluation"
            ]["failure_codes"],
        )
        self.assertEqual(sandbox.proof_calls, 6)
        self.assertEqual(state.submissions, [])
        self.assertEqual(
            next(
                item
                for item in state.candidates
                if item.id == candidate.id
            ).status,
            CandidateStatus.OBSERVED_CANDIDATE,
        )

    def test_rev_managed_stdin_exit_125_is_structural_failure(self):
        state, proof_experiment, _candidate, sandbox, _accepted = (
            self.run_managed_rev_proof_fixture(
                transport_exit_ordinal=2,
            )
        )

        self.assertEqual(state.status, ChallengeStatus.ACTIVE)
        self.assertIs(
            proof_experiment.status,
            ExperimentStatus.FAILED,
        )
        failure_codes = proof_experiment.result[
            "rev_proof_evidence"
        ]["evaluation"]["failure_codes"]
        self.assertIn("target_transport_exit_125", failure_codes)
        self.assertEqual(sandbox.proof_calls, 6)
        proof_runs = [
            item
            for item in state.runs
            if item.origin is RunOrigin.PROOF
        ]
        self.assertIs(proof_runs[1].status, RunStatus.FAILED)

    def test_rev_managed_stdin_orchestration_error_is_evidenced(self):
        state, proof_experiment, _candidate, sandbox, _accepted = (
            self.run_managed_rev_proof_fixture(
                orchestration_error_ordinal=2,
            )
        )

        self.assertEqual(state.status, ChallengeStatus.ACTIVE)
        self.assertIs(
            proof_experiment.status,
            ExperimentStatus.FAILED,
        )
        evaluation = proof_experiment.result[
            "rev_proof_evidence"
        ]["evaluation"]
        self.assertIn(
            "orchestration_incomplete",
            evaluation["failure_codes"],
        )
        self.assertEqual(sandbox.proof_calls, 6)
        self.assertEqual(len(proof_experiment.artifact_ids), 14)
        failed_run = [
            item
            for item in state.runs
            if item.origin is RunOrigin.PROOF
        ][1]
        self.assertIs(failed_run.status, RunStatus.FAILED)
        failed_artifacts = [
            item
            for item in state.artifacts
            if item.source_run_id == failed_run.id
        ]
        self.assertEqual(len(failed_artifacts), 2)
        self.assertTrue(
            all(
                item.size == 0
                and item.extra.get("capture_placeholder") is True
                for item in failed_artifacts
            )
        )
        state.validate()

    def test_rev_managed_stdin_final_guard_rejects_late_deadline(self):
        expired = False
        final_revalidations = 0

        def expire_after_final_streams(engine, execute_proof):
            original_revalidate = (
                engine._revalidate_rev_proof_attempt
            )
            original_deadline_gate = (
                engine._require_before_hard_deadline
            )

            def revalidate_then_expire(*args, **kwargs):
                nonlocal expired, final_revalidations
                result = original_revalidate(*args, **kwargs)
                if kwargs.get("revalidate_external_pins") is False:
                    final_revalidations += 1
                    if final_revalidations == 6:
                        expired = True
                return result

            def deadline_gate(deadline, operation):
                if expired:
                    raise challenge_module._HardDeadlineExpired(
                        "synthetic deadline after final stream rescan"
                    )
                return original_deadline_gate(deadline, operation)

            with (
                mock.patch.object(
                    engine,
                    "_revalidate_rev_proof_attempt",
                    side_effect=revalidate_then_expire,
                ),
                mock.patch.object(
                    engine,
                    "_require_before_hard_deadline",
                    side_effect=deadline_gate,
                ),
            ):
                return execute_proof()

        state, proof_experiment, candidate, sandbox, _accepted = (
            self.run_managed_rev_proof_fixture(
                proof_execution_hook=expire_after_final_streams,
            )
        )

        self.assertTrue(expired)
        self.assertEqual(final_revalidations, 6)
        self.assertEqual(sandbox.proof_calls, 6)
        self.assertEqual(state.status, ChallengeStatus.ACTIVE)
        self.assertIs(
            proof_experiment.status,
            ExperimentStatus.FAILED,
        )
        self.assertEqual(
            next(
                item
                for item in state.candidates
                if item.id == candidate.id
            ).status,
            CandidateStatus.OBSERVED_CANDIDATE,
        )

    def test_rev_managed_stdin_final_guard_rejects_source_toctou(self):
        source_changed = False
        final_revalidations = 0

        def mutate_after_final_streams(engine, execute_proof):
            original_revalidate = (
                engine._revalidate_rev_proof_attempt
            )

            def revalidate_then_mutate(*args, **kwargs):
                nonlocal source_changed, final_revalidations
                result = original_revalidate(*args, **kwargs)
                if kwargs.get("revalidate_external_pins") is False:
                    final_revalidations += 1
                    if final_revalidations == 6:
                        source = (
                            engine.challenge_input(self.identity)
                            / "challenge.bin"
                        )
                        source.write_bytes(b"\x7fELFchanged-after-scan")
                        source_changed = True
                return result

            with mock.patch.object(
                engine,
                "_revalidate_rev_proof_attempt",
                side_effect=revalidate_then_mutate,
            ):
                return execute_proof()

        state, proof_experiment, candidate, sandbox, _accepted = (
            self.run_managed_rev_proof_fixture(
                proof_execution_hook=mutate_after_final_streams,
            )
        )

        self.assertTrue(source_changed)
        self.assertEqual(final_revalidations, 6)
        self.assertEqual(sandbox.proof_calls, 6)
        self.assertEqual(state.status, ChallengeStatus.ACTIVE)
        self.assertIs(
            proof_experiment.status,
            ExperimentStatus.FAILED,
        )
        self.assertEqual(
            next(
                item
                for item in state.candidates
                if item.id == candidate.id
            ).status,
            CandidateStatus.OBSERVED_CANDIDATE,
        )

    def test_rev_managed_stdin_final_guard_rejects_config_toctou(self):
        config_changed = False
        final_revalidations = 0

        def mutate_after_final_streams(engine, execute_proof):
            original_revalidate = (
                engine._revalidate_rev_proof_attempt
            )

            def revalidate_then_mutate(*args, **kwargs):
                nonlocal config_changed, final_revalidations
                result = original_revalidate(*args, **kwargs)
                if kwargs.get("revalidate_external_pins") is False:
                    final_revalidations += 1
                    if final_revalidations == 6:
                        engine.config = replace(
                            engine.config,
                            runtime=replace(
                                engine.config.runtime,
                                image_digest=(
                                    "sha256:" + "c" * 64
                                ),
                            ),
                        )
                        config_changed = True
                return result

            with mock.patch.object(
                engine,
                "_revalidate_rev_proof_attempt",
                side_effect=revalidate_then_mutate,
            ):
                return execute_proof()

        state, proof_experiment, candidate, sandbox, _accepted = (
            self.run_managed_rev_proof_fixture(
                proof_execution_hook=mutate_after_final_streams,
            )
        )

        self.assertTrue(config_changed)
        self.assertEqual(final_revalidations, 6)
        self.assertEqual(sandbox.proof_calls, 6)
        self.assertEqual(state.status, ChallengeStatus.ACTIVE)
        self.assertIs(
            proof_experiment.status,
            ExperimentStatus.FAILED,
        )
        self.assertEqual(
            next(
                item
                for item in state.candidates
                if item.id == candidate.id
            ).status,
            CandidateStatus.OBSERVED_CANDIDATE,
        )

    def test_rev_managed_stdin_pre_replace_deadline_is_atomic(self):
        final_margin_checks = 0

        def expire_at_pre_replace(engine, execute_proof):
            original_deadline_gate = (
                engine._require_before_hard_deadline
            )

            def deadline_gate(deadline, operation):
                nonlocal final_margin_checks
                if (
                    operation
                    == "Rev proof final pre-replace safety margin"
                ):
                    final_margin_checks += 1
                    if final_margin_checks == 2:
                        raise challenge_module._HardDeadlineExpired(
                            "synthetic atomic pre-replace deadline"
                        )
                return original_deadline_gate(deadline, operation)

            with mock.patch.object(
                engine,
                "_require_before_hard_deadline",
                side_effect=deadline_gate,
            ):
                return execute_proof()

        state, proof_experiment, candidate, sandbox, _accepted = (
            self.run_managed_rev_proof_fixture(
                proof_execution_hook=expire_at_pre_replace,
            )
        )

        self.assertEqual(final_margin_checks, 2)
        self.assertEqual(sandbox.proof_calls, 6)
        self.assertEqual(state.status, ChallengeStatus.ACTIVE)
        self.assertIs(
            proof_experiment.status,
            ExperimentStatus.FAILED,
        )
        self.assertEqual(
            next(
                item
                for item in state.candidates
                if item.id == candidate.id
            ).status,
            CandidateStatus.OBSERVED_CANDIDATE,
        )

    def test_rev_managed_stdin_interrupt_cleans_pending_streams(self):
        captured_engines = []

        def interrupt_scan(engine, execute_proof):
            captured_engines.append(engine)
            with mock.patch.object(
                engine,
                "_scan_rev_proof_stream_artifacts",
                side_effect=KeyboardInterrupt(
                    "synthetic Rev stream-scan interruption"
                ),
            ):
                return execute_proof()

        with self.assertRaises(KeyboardInterrupt):
            self.run_managed_rev_proof_fixture(
                proof_execution_hook=interrupt_scan,
            )

        engine = captured_engines[0]
        state = engine.store.load(self.identity)
        paths = engine.store.challenge_paths(self.identity)
        canonical_paths = {
            paths.root / artifact.path
            for artifact in state.artifacts
        }
        proof_files = {
            path
            for path in paths.proof.rglob("*")
            if path.is_file()
        }
        self.assertEqual(proof_files - canonical_paths, set())
        self.assertFalse(
            any(
                path.name in {"stdout.log", "stderr.log"}
                for path in proof_files
            )
        )

    def test_rev_managed_stdin_interrupt_cleans_pending_evaluation(self):
        captured_engines = []
        original_atomic_write = challenge_module.atomic_write_bytes

        def interrupt_evaluation_write(path, payload, *, mode=0o600):
            original_atomic_write(path, payload, mode=mode)
            if Path(path).name == "evaluation.json":
                raise KeyboardInterrupt(
                    "synthetic Rev evaluation-write interruption"
                )

        def interrupt_evaluation(engine, execute_proof):
            captured_engines.append(engine)
            with mock.patch.object(
                challenge_module,
                "atomic_write_bytes",
                side_effect=interrupt_evaluation_write,
            ):
                return execute_proof()

        with self.assertRaises(KeyboardInterrupt):
            self.run_managed_rev_proof_fixture(
                proof_execution_hook=interrupt_evaluation,
            )

        engine = captured_engines[0]
        state = engine.store.load(self.identity)
        paths = engine.store.challenge_paths(self.identity)
        canonical_paths = {
            paths.root / artifact.path
            for artifact in state.artifacts
        }
        proof_files = {
            path
            for path in paths.proof.rglob("*")
            if path.is_file()
        }
        self.assertEqual(proof_files - canonical_paths, set())
        self.assertFalse(
            any(path.name == "evaluation.json" for path in proof_files)
        )

    def test_rev_managed_stdin_interrupt_after_commit_preserves_evidence(
        self,
    ):
        captured_engines = []

        def interrupt_after_commit(engine, execute_proof):
            captured_engines.append(engine)
            original_update = engine.store.update
            interrupted = False

            def update_then_interrupt(*args, **kwargs):
                nonlocal interrupted
                committed = original_update(*args, **kwargs)
                if (
                    not interrupted
                    and any(
                        isinstance(experiment.result, dict)
                        and "rev_proof_evidence"
                        in experiment.result
                        for experiment in committed.experiments
                    )
                ):
                    interrupted = True
                    raise KeyboardInterrupt(
                        "synthetic Rev post-commit interruption"
                    )
                return committed

            with mock.patch.object(
                engine.store,
                "update",
                side_effect=update_then_interrupt,
            ):
                return execute_proof()

        with self.assertRaises(KeyboardInterrupt):
            self.run_managed_rev_proof_fixture(
                proof_execution_hook=interrupt_after_commit,
            )

        engine = captured_engines[0]
        state = engine.store.load(self.identity)
        paths = engine.store.challenge_paths(self.identity)
        canonical_paths = {
            paths.root / artifact.path
            for artifact in state.artifacts
        }
        proof_files = {
            path
            for path in paths.proof.rglob("*")
            if path.is_file()
        }
        self.assertEqual(proof_files - canonical_paths, set())
        self.assertEqual(state.status, ChallengeStatus.PAUSED)
        self.assertEqual(
            state.resume_status,
            ChallengeStatus.READY_TO_SUBMIT,
        )
        proof_experiment = next(
            item
            for item in state.experiments
            if item.kind is ExperimentKind.PROOF
        )
        self.assertIs(
            proof_experiment.status,
            ExperimentStatus.COMPLETED,
        )
        self.assertTrue(
            any(path.name == "evaluation.json" for path in proof_files)
        )

    def test_proof_wave_records_remote_replay_without_full_proof_or_submission(
        self,
    ):
        identity = ChallengeIdentity("Managed CTF", "pwn", "proof")
        incoming = (
            self.root
            / "incoming"
            / identity.contest_id
            / identity.category
            / identity.challenge_id
        )
        incoming.mkdir(parents=True)
        (incoming / "challenge.bin").write_bytes(b"\x7fELFmanaged-pwn")
        executor = ProbeRoleExecutor(captain_stage="proof")
        sandboxes: list[ReplaySandbox] = []
        sandboxes_by_work: dict[Path, ReplaySandbox] = {}

        def sandbox_factory(state, work, policy):
            del state, policy
            key = work.resolve()
            sandbox = sandboxes_by_work.get(key)
            if sandbox is None:
                sandbox = ReplaySandbox(work)
                sandboxes_by_work[key] = sandbox
                sandboxes.append(sandbox)
            return sandbox

        engine = self.engine(
            executor,
            sandbox_factory=sandbox_factory,
        )
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        state = engine.add_challenge(
            identity,
            prompt="prove one existing pwn candidate",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        endpoint = "https://pwn.example:443"
        state = engine.add_network_target(
            identity,
            endpoint,
            docker_network="ctfos-proxy",
            enforcement="proxy",
        )
        target = state.targets[-1]
        state = engine.select_network_target(identity, target.id)
        solver = engine._workspace(state) / "solver.py"
        solver.write_text(
            "print('derive candidate from immutable challenge input')\n",
            encoding="utf-8",
        )
        _state, solver_artifact = engine.register_workspace_artifact(
            identity,
            "solver.py",
        )
        _state, source_experiment_id = engine.register_experiment(
            identity,
            command=("python3", "solver.py"),
            expected_observation="the tool emits a candidate",
            keep_if="the candidate is present in durable output",
            drop_if="the candidate is absent",
            network_target=endpoint,
        )
        self.execute_managed_source_fixture(
            orchestrator,
            engine,
            identity,
            source_experiment_id,
        )
        source_state = engine.store.load(identity)
        self.assertIn(
            "KCTF{proof_flag}",
            [item.value for item in source_state.candidates],
        )
        candidate = next(
            item
            for item in source_state.candidates
            if item.value == "KCTF{proof_flag}"
        )
        executor.proof_candidate_id = candidate.id
        executor.proof_artifact_id = solver_artifact.id

        with mock.patch.object(
            engine,
            "record_manual_submission",
            wraps=engine.record_manual_submission,
        ) as submission:
            state = orchestrator.run_cycle(identity)

        submission.assert_not_called()
        self.assertEqual(state.status, ChallengeStatus.ACTIVE)
        self.assertEqual(state.submissions, [])
        replayed_candidate = next(
            item for item in state.candidates if item.id == candidate.id
        )
        self.assertEqual(
            replayed_candidate.status,
            CandidateStatus.OBSERVED_CANDIDATE,
        )
        wave = state.waves[-1]
        self.assertEqual(
            set(wave.role_run_ids),
            {"validator", "reproducer", "evidence_auditor"},
        )
        proof_cycle = next(
            item for item in state.cycles if item.id == wave.cycle_id
        )
        proof_cycle_run_ids = {
            proof_cycle.captain_run_id,
            *wave.role_run_ids.values(),
        }
        self.assertFalse(
            any(
                item.status is ExperimentStatus.REGISTERED
                and item.source_run_id in proof_cycle_run_ids
                for item in state.experiments
            ),
            "proof-cycle non-proof actions must not pollute the frontier",
        )
        proof_experiments = [
            item
            for item in state.experiments
            if item.kind is ExperimentKind.PROOF
        ]
        self.assertEqual(len(proof_experiments), 1)
        proof_experiment = proof_experiments[0]
        self.assertEqual(
            proof_experiment.status,
            ExperimentStatus.COMPLETED,
        )
        self.assertFalse(proof_experiment.result["passed"])
        self.assertEqual(proof_experiment.result["total_attempts"], 10)
        self.assertEqual(proof_experiment.result["successful_attempts"], 10)
        self.assertEqual(
            len(proof_experiment.result["negative_control_run_ids"]),
            1,
        )
        self.assertIn(
            "causal_oracle_unavailable",
            "\n".join(proof_experiment.result["failures"]),
        )
        recipe = proof_experiment.proof_recipe
        self.assertIsNotNone(recipe)
        assert recipe is not None
        self.assertEqual(recipe.argv, ("python3", "solver.py"))
        self.assertEqual(recipe.inputs[0].artifact_id, solver_artifact.id)
        self.assertEqual(recipe.inputs[0].destination, "solver.py")
        self.assertEqual(recipe.image_reference, IMAGE_DIGEST)
        self.assertEqual(recipe.network_target_id, target.id)
        self.assertEqual(
            recipe.network_target_generation,
            target.generation,
        )
        self.assertEqual(recipe.network_endpoint, endpoint)
        source_request = engine.store.run_paths(
            identity,
            run_id=recipe.source_run_id,
        ).request
        self.assertEqual(
            recipe.source_request_sha256,
            hashlib.sha256(source_request.read_bytes()).hexdigest(),
        )
        self.assertEqual(recipe.policy.trial_count, 10)
        self.assertEqual(recipe.policy.negative_control_repetitions, 1)
        self.assertEqual(
            recipe.policy.negative_control_timeout_seconds,
            30,
        )
        self.assertEqual(
            recipe.policy.oracle_protocol,
            "remote_pwn_replay_negative_control_v1",
        )
        proof_runs = [
            run for run in state.runs if run.origin is RunOrigin.PROOF
        ]
        self.assertEqual(len(proof_runs), 11)
        self.assertEqual(len(proof_experiment.evidence_run_ids), 11)
        unlinked = copy.deepcopy(state)
        unlinked_proof = next(
            item
            for item in unlinked.experiments
            if item.id == proof_experiment.id
        )
        unlinked_proof.artifact_ids.remove(solver_artifact.id)
        with self.assertRaisesRegex(
            ModelValidationError,
            "is not linked through experiment artifact_ids",
        ):
            unlinked.validate()
        self.assertTrue(
            all(
                run.session_id == wave.session_id
                and run.cycle_id == wave.cycle_id
                and run.wave_id == wave.id
                and run.configuration_epoch == state.configuration_epoch
                and run.extra["proof_experiment_id"]
                == proof_experiment.id
                and run.extra["recipe_sha256"]
                == recipe.recipe_sha256
                for run in proof_runs
            )
        )
        self.assertEqual(
            sum(
                run.extra.get("negative_control") is True
                for run in proof_runs
            ),
            1,
        )
        control_specs = [
            spec
            for spec in sandboxes[0].proof_specs
            if spec.network_target is None
        ]
        self.assertEqual(len(control_specs), 1)
        self.assertLessEqual(control_specs[0].timeout_seconds or 31, 30)
        self.assertEqual(sandboxes[0].proof_calls, 11)
        self.assertEqual(
            sandboxes[0].proof_input_calls,
            [(("solver.py", solver.read_bytes()),)] * 11,
        )
        self.assertIsNotNone(state.active_managed_session_id)
        self.assertEqual(state.sessions[-1].status, SessionStatus.RUNNING)
        tampered = copy.deepcopy(state)
        source_experiment = next(
            item
            for item in tampered.experiments
            if item.id == recipe.source_experiment_id
        )
        source_experiment.kind = ExperimentKind.PROOF
        with self.assertRaisesRegex(
            ModelValidationError,
            "source run is not linked by its source experiment",
        ):
            tampered.validate()

    def test_proof_wave_rejects_candidate_without_a_tool_source(self):
        identity = ChallengeIdentity(
            "Managed CTF", "pwn", "proof-no-source"
        )
        incoming = (
            self.root
            / "incoming"
            / identity.contest_id
            / identity.category
            / identity.challenge_id
        )
        incoming.mkdir(parents=True)
        (incoming / "challenge.bin").write_bytes(b"\x7fELFno-source")
        executor = ProbeRoleExecutor(captain_stage="proof")
        engine = self.engine(executor)
        engine.add_challenge(
            identity,
            prompt="reject a model-only candidate",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        state = engine.record_candidate(
            identity,
            "KCTF{proof_flag}",
            print_immediately=False,
        )
        candidate = next(
            item
            for item in state.candidates
            if item.value == "KCTF{proof_flag}"
        )
        executor.proof_candidate_id = candidate.id

        state = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        ).run_cycle(identity)

        self.assertNotEqual(
            state.status,
            ChallengeStatus.READY_TO_SUBMIT,
        )
        self.assertEqual(state.submissions, [])
        self.assertFalse(
            any(
                item.kind is ExperimentKind.PROOF
                for item in state.experiments
            )
        )
        self.assertIn(
            "exactly one valid engine-bound replay recipe",
            state.checkpoints[-1].note or "",
        )
        capsule = state.checkpoints[-1].failure_capsule
        self.assertIsNotNone(capsule)
        assert capsule is not None
        self.assertEqual(capsule.reason_code, "proof_recipe_invalid")
        self.assertEqual(state.waves[-1].status, "invalid")
        self.assertEqual(state.status, ChallengeStatus.TRIAGING)
        self.assertIsNotNone(state.active_managed_session_id)
        self.assertEqual(state.sessions[-1].status, SessionStatus.RUNNING)

    def test_managed_proof_rejects_operator_tool_source(self):
        engine = self.engine(ProbeRoleExecutor())
        self.add_v2(engine)
        _state, experiment_id = engine.register_experiment(
            self.identity,
            command=("true",),
            expected_observation="the operator tool emits a candidate",
            keep_if="the candidate is present",
            drop_if="the candidate is absent",
        )
        state = engine.execute_registered_experiments(
            self.identity,
            experiment_ids=(experiment_id,),
        )
        candidate = next(
            item
            for item in state.candidates
            if item.value == "KCTF{tool_flag}"
        )

        with self.assertRaisesRegex(
            EngineError,
            "operator tool candidates must use the explicit ctfos prove",
        ):
            engine._managed_proof_replay_source(state, candidate.id)

    def test_proof_wave_rejects_reproducer_extra_action(self):
        identity = ChallengeIdentity(
            "Managed CTF",
            "pwn",
            "proof-extra-action",
        )
        incoming = (
            self.root
            / "incoming"
            / identity.contest_id
            / identity.category
            / identity.challenge_id
        )
        incoming.mkdir(parents=True)
        (incoming / "challenge.bin").write_bytes(b"\x7fELFextra-action")
        executor = ProbeRoleExecutor(
            captain_stage="proof",
            proof_extra_action=True,
        )
        sandboxes_by_work: dict[Path, ReplaySandbox] = {}

        def sandbox_factory(state, work, policy):
            del state, policy
            key = work.resolve()
            if key not in sandboxes_by_work:
                sandboxes_by_work[key] = ReplaySandbox(work)
            return sandboxes_by_work[key]

        engine = self.engine(
            executor,
            sandbox_factory=sandbox_factory,
        )
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        state = engine.add_challenge(
            identity,
            prompt="reject an extra proof-wave action",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        endpoint = "https://extra-action.example:443"
        state = engine.add_network_target(
            identity,
            endpoint,
            docker_network="ctfos-proxy",
            enforcement="proxy",
        )
        engine.select_network_target(identity, state.targets[-1].id)
        _state, source_experiment_id = engine.register_experiment(
            identity,
            command=("true",),
            expected_observation="the remote tool emits a candidate",
            keep_if="the candidate is present",
            drop_if="the candidate is absent",
            network_target=endpoint,
        )
        self.execute_managed_source_fixture(
            orchestrator,
            engine,
            identity,
            source_experiment_id,
        )
        source_state = engine.store.load(identity)
        candidate = next(
            item
            for item in source_state.candidates
            if item.value == "KCTF{proof_flag}"
        )
        executor.proof_candidate_id = candidate.id

        state = orchestrator.run_cycle(identity)

        self.assertFalse(
            any(
                item.kind is ExperimentKind.PROOF
                for item in state.experiments
            )
        )
        self.assertIn(
            "exactly one valid engine-bound replay recipe",
            state.checkpoints[-1].note or "",
        )
        proof_cycle = state.cycles[-1]
        proof_run_ids = {
            proof_cycle.captain_run_id,
            *(
                state.waves[-1].role_run_ids.values()
                if proof_cycle.wave_id is not None
                else ()
            ),
        }
        self.assertFalse(
            any(
                item.status is ExperimentStatus.REGISTERED
                and item.source_run_id in proof_run_ids
                for item in state.experiments
            )
        )

    def test_proof_wave_rejects_source_argv_with_candidate_literal(self):
        identity = ChallengeIdentity(
            "Managed CTF", "pwn", "proof-literal"
        )
        incoming = (
            self.root
            / "incoming"
            / identity.contest_id
            / identity.category
            / identity.challenge_id
        )
        incoming.mkdir(parents=True)
        (incoming / "challenge.bin").write_bytes(b"\x7fELFliteral")
        executor = ProbeRoleExecutor(captain_stage="proof")
        sandboxes: list[ReplaySandbox] = []
        sandboxes_by_work: dict[Path, ReplaySandbox] = {}

        def sandbox_factory(state, work, policy):
            del state, policy
            key = work.resolve()
            sandbox = sandboxes_by_work.get(key)
            if sandbox is None:
                sandbox = ReplaySandbox(work)
                sandboxes_by_work[key] = sandbox
                sandboxes.append(sandbox)
            return sandbox

        engine = self.engine(
            executor,
            sandbox_factory=sandbox_factory,
        )
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        engine.add_challenge(
            identity,
            prompt="reject a hardcoded candidate replay",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        endpoint = "https://literal-pwn.example:443"
        state = engine.add_network_target(
            identity,
            endpoint,
            docker_network="ctfos-proxy",
            enforcement="proxy",
        )
        engine.select_network_target(identity, state.targets[-1].id)
        _state, source_experiment_id = engine.register_experiment(
            identity,
            command=(
                "python3",
                "-c",
                "print('KCTF{proof_flag}')",
            ),
            expected_observation="the tool emits a candidate",
            keep_if="the candidate is present",
            drop_if="the candidate is absent",
            network_target=endpoint,
        )
        self.execute_managed_source_fixture(
            orchestrator,
            engine,
            identity,
            source_experiment_id,
        )
        state = engine.store.load(identity)
        candidate = next(
            item
            for item in state.candidates
            if item.value == "KCTF{proof_flag}"
        )
        executor.proof_candidate_id = candidate.id

        state = orchestrator.run_cycle(identity)

        self.assertNotEqual(
            state.status,
            ChallengeStatus.READY_TO_SUBMIT,
        )
        self.assertEqual(sandboxes[0].proof_calls, 0)
        self.assertEqual(state.submissions, [])
        self.assertFalse(
            any(
                item.kind is ExperimentKind.PROOF
                for item in state.experiments
            )
        )
        for credential_command in (
            "python3 solver.py --token=credential-looking-value",
            "curl -u alice:credential-looking-value https://pwn.example",
            "curl -b credential-looking-value https://pwn.example",
        ):
            credential_state = copy.deepcopy(engine.store.load(identity))
            credential_source = next(
                item
                for item in credential_state.experiments
                if isinstance(item.result, dict)
                and item.result.get("run_id") == candidate.source_run_id
            )
            credential_source.command = credential_command
            with (
                self.subTest(command=credential_command.split()[1]),
                self.assertRaisesRegex(
                    EngineError,
                    "appears to contain credential material",
                ),
            ):
                engine._managed_proof_replay_source(
                    credential_state,
                    candidate.id,
                )

    def test_remote_negative_control_blocks_encoded_candidate_replay(self):
        identity = ChallengeIdentity(
            "Managed CTF", "pwn", "proof-encoded"
        )
        incoming = (
            self.root
            / "incoming"
            / identity.contest_id
            / identity.category
            / identity.challenge_id
        )
        incoming.mkdir(parents=True)
        (incoming / "challenge.bin").write_bytes(b"\x7fELFencoded")
        executor = ProbeRoleExecutor(captain_stage="proof")
        sandboxes: list[AlwaysReplaySandbox] = []
        sandboxes_by_work: dict[Path, AlwaysReplaySandbox] = {}

        def sandbox_factory(state, work, policy):
            del state, policy
            key = work.resolve()
            sandbox = sandboxes_by_work.get(key)
            if sandbox is None:
                sandbox = AlwaysReplaySandbox(work)
                sandboxes_by_work[key] = sandbox
                sandboxes.append(sandbox)
            return sandbox

        engine = self.engine(
            executor,
            sandbox_factory=sandbox_factory,
        )
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        state = engine.add_challenge(
            identity,
            prompt="negative-control an encoded output replay",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        endpoint = "https://encoded-pwn.example:443"
        state = engine.add_network_target(
            identity,
            endpoint,
            docker_network="ctfos-proxy",
            enforcement="proxy",
        )
        target = state.targets[-1]
        state = engine.select_network_target(identity, target.id)
        solver = engine._workspace(state) / "solver.py"
        encoded = b"S0NURntwcm9vZl9mbGFnfQ=="
        solver.write_bytes(b"encoded = b'" + encoded + b"'\n")
        self.assertNotIn(b"KCTF{proof_flag}", solver.read_bytes())
        _state, solver_artifact = engine.register_workspace_artifact(
            identity,
            "solver.py",
        )
        _state, source_experiment_id = engine.register_experiment(
            identity,
            command=("python3", "solver.py"),
            expected_observation="the tool emits a candidate",
            keep_if="the candidate is present",
            drop_if="the candidate is absent",
            network_target=endpoint,
        )
        self.execute_managed_source_fixture(
            orchestrator,
            engine,
            identity,
            source_experiment_id,
        )
        source_state = engine.store.load(identity)
        candidate = next(
            item
            for item in source_state.candidates
            if item.value == "KCTF{proof_flag}"
        )
        executor.proof_candidate_id = candidate.id
        executor.proof_artifact_id = solver_artifact.id

        state = orchestrator.run_cycle(identity)

        self.assertEqual(state.status, ChallengeStatus.ACTIVE)
        self.assertEqual(state.submissions, [])
        proof_experiment = next(
            item
            for item in state.experiments
            if item.kind is ExperimentKind.PROOF
        )
        self.assertEqual(
            proof_experiment.status,
            ExperimentStatus.COMPLETED,
        )
        self.assertFalse(proof_experiment.result["passed"])
        self.assertIn(
            "candidate reproduced without the remote target",
            "\n".join(proof_experiment.result["failures"]),
        )
        proof_runs = [
            run for run in state.runs if run.origin is RunOrigin.PROOF
        ]
        self.assertEqual(len(proof_runs), 11)
        self.assertEqual(
            sum(
                run.extra.get("negative_control") is True
                for run in proof_runs
            ),
            1,
        )

    def test_reconcile_finishes_terminal_session_after_completed_checkpoint(
        self,
    ):
        engine = self.engine(ProbeRoleExecutor())
        self.add_v2(engine)
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        _state, session_id = orchestrator._reserve_session(
            self.identity,
            None,
        )
        _state, cycle = orchestrator._reserve_cycle(
            self.identity,
            session_id,
        )
        checkpointed = orchestrator._checkpoint(
            self.identity,
            session_id,
            cycle.id,
            note="durable terminal checkpoint",
        )
        self.assertIsNotNone(cycle.id)
        self.assertIsNotNone(checkpointed.active_managed_session_id)

        def mark_terminal(state):
            state.status = ChallengeStatus.READY_TO_SUBMIT

        terminal = engine.store.update(self.identity, mark_terminal)
        self.assertEqual(
            terminal.active_managed_session_id,
            session_id,
        )

        recovered = orchestrator.reconcile(self.identity)

        self.assertIsNone(recovered.active_managed_session_id)
        session = next(
            item for item in recovered.sessions if item.id == session_id
        )
        self.assertEqual(session.status, SessionStatus.COMPLETED)
        self.assertIn("terminal challenge", session.stop_reason or "")

    def test_managed_checkpoint_does_not_duplicate_large_command(self):
        engine = self.engine(ProbeRoleExecutor())
        self.add_v2(engine)
        large_argument = "M" * 16_000
        _state, experiment_id = engine.register_experiment(
            self.identity,
            command=("python3", "-c", large_argument),
            expected_observation="a bounded observation",
            keep_if="the observation advances the goal",
            drop_if="the observation is absent",
        )
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        _state, session_id = orchestrator._reserve_session(
            self.identity,
            None,
        )
        _state, cycle = orchestrator._reserve_cycle(
            self.identity,
            session_id,
        )

        checkpointed = orchestrator._checkpoint(
            self.identity,
            session_id,
            cycle.id,
            note="bounded action projection",
        )

        experiment = next(
            item
            for item in checkpointed.experiments
            if item.id == experiment_id
        )
        checkpoint = checkpointed.checkpoints[-1]
        self.assertIn(
            checkpoint_action_reference(experiment),
            checkpoint.next_actions,
        )
        rendered = canonical_json_record(checkpoint.to_dict())
        self.assertNotIn(large_argument, rendered)
        self.assertLess(len(rendered.encode("ascii")), 2_000)

    def test_reconcile_is_noop_for_idle_open_session_with_completed_cycle(
        self,
    ) -> None:
        executor = ProbeRoleExecutor()
        engine = self.engine(executor)
        self.add_v2(engine)
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        _state, session_id = orchestrator._reserve_session(
            self.identity,
            None,
        )
        current = engine.store.load(self.identity)

        def add_completed_cycle(state):
            state.cycles.append(
                ManagedCycle(
                    id="MC-idle-completed",
                    session_id=session_id,
                    ordinal=1,
                    phase="completed",
                    configuration_epoch=state.configuration_epoch,
                    completed_at="2026-08-03T00:00:00Z",
                )
            )

        before = engine.store.update(
            self.identity,
            add_completed_cycle,
            expected_revision=current.revision,
        )

        locked_before, recovered = orchestrator.reconcile_explicit(
            self.identity
        )

        self.assertEqual(locked_before.to_dict(), before.to_dict())
        self.assertEqual(recovered.to_dict(), before.to_dict())
        self.assertEqual(recovered.revision, before.revision)
        self.assertEqual(
            recovered.active_managed_session_id,
            session_id,
        )
        session = next(
            item for item in recovered.sessions if item.id == session_id
        )
        self.assertIs(session.status, SessionStatus.RUNNING)
        self.assertEqual(executor.roles, [])

    def test_managed_public_wrappers_refresh_empty_init_before_cartography(
        self,
    ) -> None:
        for wrapper_name in ("run_cycle", "run_cycles"):
            with self.subTest(wrapper=wrapper_name):
                identity = ChallengeIdentity(
                    "Managed CTF",
                    "rev",
                    f"late-input-{wrapper_name}",
                )
                incoming = (
                    self.root
                    / "incoming"
                    / identity.contest_id
                    / identity.category
                    / identity.challenge_id
                )
                incoming.mkdir(parents=True)
                events: list[tuple[str, object]] = []
                events_lock = threading.Lock()

                class OrderedExecutor(ProbeRoleExecutor):
                    def run(
                        inner_self,
                        command,
                        *,
                        cwd,
                        timeout,
                        on_stdout_line,
                    ):
                        with events_lock:
                            events.append(
                                ("model", _role_for(command).value)
                            )
                        return super().run(
                            command,
                            cwd=cwd,
                            timeout=timeout,
                            on_stdout_line=on_stdout_line,
                        )

                class OrderedSandbox(FakeSandbox):
                    def run(inner_self, spec):
                        with events_lock:
                            events.append(("tool", tuple(spec.argv)))
                        return super().run(spec)

                engine = self.engine(
                    OrderedExecutor(),
                    sandbox_factory=(
                        lambda state, work, policy: OrderedSandbox(work)
                    ),
                )
                initial = engine.add_challenge(
                    identity,
                    prompt="solve input added after session creation",
                    state_schema_version=STATE_SCHEMA_VERSION,
                )
                self.assertFalse(
                    any(
                        experiment.extra.get("adapter_seed") is True
                        for experiment in initial.experiments
                    )
                )
                (incoming / "challenge.bin").write_bytes(
                    b"\x7fELFmanaged-late-input"
                )
                orchestrator = ManagedOrchestrator(
                    engine,
                    capability_probe=self.capability,
                )

                if wrapper_name == "run_cycle":
                    state = orchestrator.run_cycle(identity)
                else:
                    state = orchestrator.run_cycles(
                        identity,
                        max_cycles=1,
                    )

                seed_experiments = [
                    experiment
                    for experiment in state.experiments
                    if experiment.extra.get("adapter_seed") is True
                ]
                self.assertEqual(
                    [
                        experiment.extra["adapter_spec_template_id"]
                        for experiment in seed_experiments
                    ],
                    [
                        "inventory_observation",
                        "assembly_observation",
                        "dynamic_observation",
                    ],
                )
                first_cycle = state.cycles[0]
                self.assertTrue(
                    {
                        experiment.id for experiment in seed_experiments
                    }.issubset(first_cycle.selected_action_ids)
                )
                seed_run_ids = {
                    run.extra.get("experiment_id")
                    for run in state.runs
                    if run.origin is RunOrigin.MANAGED_TOOL
                }
                self.assertTrue(
                    {
                        experiment.id for experiment in seed_experiments
                    }.issubset(seed_run_ids)
                )
                captain_index = events.index(
                    ("model", Role.CAPTAIN.value)
                )
                pre_captain_argv = {
                    tuple(payload)
                    for kind, payload in events[:captain_index]
                    if kind == "tool"
                }
                self.assertTrue(
                    any(
                        argv[:2]
                        == (
                            "python3",
                            "/opt/ctf-templates/rev/inventory_v2.py",
                        )
                        for argv in pre_captain_argv
                    )
                )
                self.assertTrue(
                    any(
                        (argv and argv[0] == "objdump")
                        or (
                            len(argv) >= 3
                            and argv[:2] == ("/bin/sh", "-lc")
                            and "/usr/bin/objdump -d --" in argv[2]
                        )
                        for argv in pre_captain_argv
                    )
                )
                self.assertTrue(
                    any(
                        (argv and argv[0] == "ctfwrap")
                        or (
                            len(argv) >= 3
                            and argv[:2] == ("/bin/sh", "-lc")
                            and "ctfwrap --" in argv[2]
                        )
                        for argv in pre_captain_argv
                    )
                )

    def test_pwn_managed_refresh_replaces_only_unbound_or_stale_seeds(
        self,
    ) -> None:
        identity = ChallengeIdentity(
            "Managed CTF",
            "pwn",
            "bound-cartography",
        )
        incoming = (
            self.root
            / "incoming"
            / identity.contest_id
            / identity.category
            / identity.challenge_id
        )
        incoming.mkdir(parents=True)
        library = incoming / "libc-2.23.so"
        library.write_bytes(_elf64_image(3, program_types=(1,)))
        library.chmod(0o755)
        challenge = incoming / "zone"
        challenge.write_bytes(_elf64_image(3, program_types=(3,)))
        challenge.chmod(0o755)
        engine = self.engine(ProbeRoleExecutor())
        state = engine.add_challenge(
            identity,
            prompt="solve the selected pwn challenge",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        legacy_ids = [
            experiment.id
            for experiment in state.experiments
            if experiment.extra.get("adapter_seed") is True
        ]
        self.assertEqual(len(legacy_ids), 3)

        def make_legacy_plan_stale(current):
            current.metadata["adapter_primary_source"] = "libc-2.23.so"
            seeds = [
                experiment
                for experiment in current.experiments
                if experiment.id in legacy_ids
            ]
            for experiment in seeds:
                experiment.command = experiment.command.replace(
                    "/challenge/zone",
                    "/challenge/libc-2.23.so",
                )
            seeds[0].status = ExperimentStatus.CANCELLED

        engine.store.update(identity, make_legacy_plan_stale)
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        _state, session_id = orchestrator._reserve_session(
            identity,
            "S-current-plan",
        )

        refreshed = engine.synchronize_managed_adapter_seed_plan(
            identity,
            session_id,
        )
        old = [
            experiment
            for experiment in refreshed.experiments
            if experiment.id in legacy_ids
        ]
        self.assertEqual(
            {experiment.status for experiment in old},
            {ExperimentStatus.CANCELLED},
        )
        self.assertTrue(
            all(
                "/challenge/libc-2.23.so" in experiment.command
                for experiment in old
            )
        )
        bound = [
            experiment
            for experiment in refreshed.experiments
            if (
                experiment.extra.get("adapter_seed") is True
                and experiment.id not in legacy_ids
            )
        ]
        self.assertEqual(len(bound), 3)
        self.assertTrue(
            all(
                experiment.status is ExperimentStatus.REGISTERED
                and "/challenge/zone" in experiment.command
                for experiment in bound
            )
        )
        self.assertTrue(
            all(
                experiment.extra["adapter_plan_sha256"]
                == refreshed.metadata["adapter_seed_plan_sha256"]
                and experiment.extra["source_binding"]
                == refreshed.metadata["adapter_seed_source_binding"]
                and experiment.extra["source_binding"]["path"] == "zone"
                for experiment in bound
            )
        )
        first_bound_ids = {experiment.id for experiment in bound}
        unchanged = engine.synchronize_managed_adapter_seed_plan(
            identity,
            session_id,
        )
        self.assertEqual(unchanged.revision, refreshed.revision)

        _state, cycle = orchestrator._reserve_cycle(
            identity,
            session_id,
        )
        orchestrator._mark_action_selection(
            identity,
            session_id,
            cycle.id,
            tuple(sorted(first_bound_ids)),
        )
        executed = orchestrator._execute_selected_actions(
            identity,
            tuple(sorted(first_bound_ids)),
        )
        assert executed is not None
        self.assertFalse(
            any(
                experiment.status is ExperimentStatus.REGISTERED
                for experiment in executed.experiments
                if experiment.id in first_bound_ids
            )
        )
        orchestrator._finish_session(
            identity,
            session_id,
            status=SessionStatus.COMPLETED,
            reason="one human-opened session completed",
        )
        _state, reopened_session = orchestrator._reserve_session(
            identity,
            "S-reopened-same-plan",
        )
        reopened = engine.synchronize_managed_adapter_seed_plan(
            identity,
            reopened_session,
        )
        self.assertEqual(
            {
                experiment.id
                for experiment in reopened.experiments
                if (
                    experiment.extra.get("adapter_seed") is True
                    and experiment.id not in legacy_ids
                )
            },
            first_bound_ids,
        )
        self.assertFalse(
            any(
                experiment.status is ExperimentStatus.REGISTERED
                for experiment in reopened.experiments
                if experiment.id in first_bound_ids
            )
        )

    def test_managed_sync_replaces_legacy_nyu_metadata_primary_seeds(
        self,
    ) -> None:
        engine = self.engine(ProbeRoleExecutor())
        cases = (
            ("crypto", "README.md"),
            ("forensics", "qr_code.txt"),
            ("misc", "output"),
        )
        for category, handout_name in cases:
            with self.subTest(category=category):
                identity = ChallengeIdentity(
                    "Managed CTF",
                    category,
                    f"legacy-nyu-metadata-primary-{category}",
                )
                incoming = (
                    self.root
                    / "incoming"
                    / identity.contest_id
                    / identity.category
                    / identity.challenge_id
                )
                incoming.mkdir(parents=True)
                (incoming / "nyu_public_metadata.json").write_text(
                    '{"case_id":"public-provenance"}\n',
                    encoding="utf-8",
                )
                (incoming / handout_name).write_text(
                    "public challenge handout\n",
                    encoding="utf-8",
                )
                state = engine.add_challenge(
                    identity,
                    prompt="solve the selected challenge",
                    state_schema_version=STATE_SCHEMA_VERSION,
                )
                legacy_ids = {
                    experiment.id
                    for experiment in state.experiments
                    if experiment.extra.get("adapter_seed") is True
                }
                self.assertTrue(legacy_ids)
                self.assertEqual(
                    state.metadata["adapter_primary_source"],
                    handout_name,
                )

                def restore_legacy_metadata_binding(current):
                    current.metadata["adapter_primary_source"] = (
                        "nyu_public_metadata.json"
                    )
                    for experiment in current.experiments:
                        if experiment.id not in legacy_ids:
                            continue
                        experiment.command = experiment.command.replace(
                            f"/challenge/{handout_name}",
                            "/challenge/nyu_public_metadata.json",
                        )

                engine.store.update(
                    identity,
                    restore_legacy_metadata_binding,
                )
                orchestrator = ManagedOrchestrator(
                    engine,
                    capability_probe=self.capability,
                )
                _state, session_id = orchestrator._reserve_session(
                    identity,
                    f"S-rebind-public-handout-{category}",
                )

                synchronized = (
                    engine.synchronize_managed_adapter_seed_plan(
                        identity,
                        session_id,
                    )
                )

                old = [
                    experiment
                    for experiment in synchronized.experiments
                    if experiment.id in legacy_ids
                ]
                self.assertTrue(
                    all(
                        experiment.status
                        is ExperimentStatus.CANCELLED
                        for experiment in old
                    )
                )
                replacement = [
                    experiment
                    for experiment in synchronized.experiments
                    if (
                        experiment.extra.get("adapter_seed") is True
                        and experiment.id not in legacy_ids
                    )
                ]
                self.assertEqual(
                    len(replacement),
                    len(legacy_ids),
                )
                self.assertTrue(
                    all(
                        experiment.status
                        is ExperimentStatus.REGISTERED
                        and experiment.extra["source_binding"]["path"]
                        == handout_name
                        for experiment in replacement
                    )
                )
                self.assertEqual(
                    synchronized.metadata["adapter_primary_source"],
                    handout_name,
                )
                self.assertFalse(synchronized.runs)

    def test_managed_model_commands_preserve_exact_posix_shell_scripts(
        self,
    ) -> None:
        heredoc = (
            "cat <<'PY'\n"
            "literal & data\n"
            "$(sleep 60 &)\n"
            "PY\n"
        )
        multiline = (
            "set -u\n"
            "value=managed\n"
            "printf '%s\\n' \"$value\"\n"
        )
        executor = ProbeRoleExecutor(
            command_by_role={
                Role.CAPTAIN: heredoc,
                Role.BUILDER: multiline,
            }
        )
        sandboxes: list[FakeSandbox] = []

        def sandbox_factory(state, work, policy):
            del state, policy
            sandbox = FakeSandbox(work)
            sandboxes.append(sandbox)
            return sandbox

        engine = self.engine(
            executor,
            sandbox_factory=sandbox_factory,
        )
        self.add_v2(engine)
        state = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        ).run_cycle(self.identity)

        runs = {run.id: run for run in state.runs}
        managed_commands = [
            experiment
            for experiment in state.experiments
            if (
                experiment.source_run_id in runs
                and runs[experiment.source_run_id].origin
                is RunOrigin.MANAGED_MODEL
                and experiment.extra.get("managed_command_protocol")
                == "posix_sh_lc_v1"
            )
        ]
        scripts = {
            shlex.split(experiment.command)[2]
            for experiment in managed_commands
        }
        self.assertIn(heredoc, scripts)
        self.assertIn(multiline, scripts)
        self.assertTrue(
            all(
                tuple(shlex.split(experiment.command)[:2])
                == ("/bin/sh", "-lc")
                and experiment.command
                == shlex.join(tuple(shlex.split(experiment.command)))
                and experiment.extra.get(
                    "managed_semantic_evaluation_contract_version"
                )
                == 2
                for experiment in managed_commands
            )
        )
        executed_scripts = {
            spec.argv[2]
            for sandbox in sandboxes
            for spec in sandbox.specs
            if spec.argv[:2] == ("/bin/sh", "-lc")
        }
        self.assertIn(heredoc, executed_scripts)
        self.assertIn(multiline, executed_scripts)

    def test_managed_builder_publication_is_staged_as_exact_action_input(
        self,
    ) -> None:
        executor = BuilderPublicationExecutor()
        sandboxes: list[BuilderPublicationSandbox] = []

        def sandbox_factory(state, work, policy):
            del state, policy
            sandbox = BuilderPublicationSandbox(work, executor)
            sandboxes.append(sandbox)
            return sandbox

        engine = self.engine(
            executor,
            sandbox_factory=sandbox_factory,
        )
        self.add_v2(engine)
        state = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        ).run_cycle(self.identity)

        builder_run = next(
            run
            for run in state.runs
            if run.role == Role.BUILDER.value
            and run.origin is RunOrigin.MANAGED_MODEL
        )
        publication = next(
            artifact
            for artifact in state.artifacts
            if artifact.source_run_id == builder_run.id
            and artifact.extra.get("source_locator") == "solver.py"
        )
        experiment = next(
            item
            for item in state.experiments
            if item.source_run_id == builder_run.id
            and item.extra.get("managed_action_input_binding") is not None
        )
        binding = experiment.extra["managed_action_input_binding"]
        self.assertEqual(binding["protocol"], "same_run_publications_v1")
        self.assertEqual(binding["source_run_id"], builder_run.id)
        self.assertEqual(binding["total_bytes"], len(BUILDER_SOLVER_PAYLOAD))
        self.assertEqual(
            binding["artifacts"],
            [
                {
                    "artifact_id": publication.id,
                    "canonical_path": publication.path,
                    "destination": "solver.py",
                    "sha256": publication.sha256,
                    "size_bytes": publication.size,
                    "source_run_id": builder_run.id,
                }
            ],
        )
        self.assertIn(publication.id, experiment.artifact_ids)

        action_sandbox = next(
            sandbox
            for sandbox in sandboxes
            if sandbox.builder_action_calls
        )
        self.assertEqual(action_sandbox.initializations, 1)
        self.assertEqual(
            action_sandbox.observed_solver,
            BUILDER_SOLVER_PAYLOAD,
        )

        self.assertEqual(
            executor.solver_path.read_bytes(),
            MUTATED_BUILDER_SOLVER_PAYLOAD,
        )
        paths = engine.store.challenge_paths(self.identity)
        snapshot = paths.root / publication.path
        self.assertEqual(snapshot.read_bytes(), BUILDER_SOLVER_PAYLOAD)
        tool_run = next(
            run
            for run in state.runs
            if run.extra.get("experiment_id") == experiment.id
        )
        self.assertEqual(
            tool_run.extra["managed_action_input_binding"],
            binding,
        )
        request = read_json(paths.root / str(tool_run.request_path))
        self.assertEqual(request["managed_action_input_binding"], binding)

        resolved = engine._resolve_managed_action_inputs(
            state,
            experiment,
        )
        tamper_work = paths.runtime / "test-managed-input-tamper"
        tamper_work.mkdir(mode=0o700)
        snapshot.chmod(0o600)
        snapshot.write_bytes(b"X" * len(BUILDER_SOLVER_PAYLOAD))
        snapshot.chmod(0o400)
        try:
            with self.assertRaisesRegex(
                EngineError,
                "could not be staged safely",
            ):
                engine._stage_managed_action_inputs(
                    state,
                    experiment,
                    tamper_work,
                    resolved,
                )
        finally:
            snapshot.chmod(0o600)
            snapshot.write_bytes(BUILDER_SOLVER_PAYLOAD)
            snapshot.chmod(0o400)
        self.assertFalse((tamper_work / "solver.py").exists())

        collision_work = paths.runtime / "test-managed-input-collision"
        collision_work.mkdir(mode=0o700)
        collision = collision_work / "solver.py"
        collision.write_bytes(b"initialized challenge owns this path")
        with self.assertRaisesRegex(EngineError, "would overwrite"):
            engine._stage_managed_action_inputs(
                state,
                experiment,
                collision_work,
                resolved,
            )
        self.assertEqual(
            collision.read_bytes(),
            b"initialized challenge owns this path",
        )

    def test_managed_absolute_work_input_requires_same_run_publication(
        self,
    ) -> None:
        executor = ProbeRoleExecutor(
            command_by_role={
                Role.BUILDER: "python3 /work/prior-run-solver.py",
            }
        )
        sandboxes: list[FakeSandbox] = []

        def sandbox_factory(state, work, policy):
            del state, policy
            sandbox = FakeSandbox(work)
            sandboxes.append(sandbox)
            return sandbox

        engine = self.engine(
            executor,
            sandbox_factory=sandbox_factory,
        )
        self.add_v2(engine)
        state = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        ).run_cycle(self.identity)

        builder_run = next(
            run
            for run in state.runs
            if run.role == Role.BUILDER.value
            and run.origin is RunOrigin.MANAGED_MODEL
        )
        self.assertFalse(
            any(
                item.source_run_id == builder_run.id
                and item.extra.get("managed_command_protocol")
                == "posix_sh_lc_v1"
                for item in state.experiments
            )
        )
        self.assertTrue(
            any(
                "absolute /work input without a same-run publication binding"
                in str(item.get("reason", ""))
                for item in builder_run.extra.get("rejected_actions", [])
            )
        )
        self.assertFalse(
            any(
                spec.argv[:2] == ("/bin/sh", "-lc")
                and "/work/prior-run-solver.py" in spec.argv[2]
                for sandbox in sandboxes
                for spec in sandbox.specs
            )
        )

    def test_managed_absolute_work_input_rejects_prior_run_publication(
        self,
    ) -> None:
        engine = self.engine(ProbeRoleExecutor())
        self.add_v2(engine)
        payload = b"print('prior run must remain unavailable')\n"
        prior_artifact = ArtifactReference(
            id="A-prior-run-solver",
            path="artifacts/snapshots/A-prior-run-solver.py",
            sha256=hashlib.sha256(payload).hexdigest(),
            source_run_id="MR-prior-builder",
            size=len(payload),
            extra={"source_locator": "prior-run-solver.py"},
        )
        snapshot = (
            engine.store.challenge_paths(self.identity).root
            / prior_artifact.path
        )
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_bytes(payload)
        snapshot.chmod(0o400)

        def seed_prior_publication(state):
            state.runs.append(
                RunReference(
                    id="MR-prior-builder",
                    base_revision=state.revision,
                    status=RunStatus.CREATED,
                    role=Role.BUILDER.value,
                    origin=RunOrigin.MANAGED_MODEL,
                    configuration_epoch=state.configuration_epoch,
                )
            )
            state.artifacts.append(prior_artifact)

        state = engine.store.update(
            self.identity,
            seed_prior_publication,
        )
        canonical_prior = next(
            item for item in state.artifacts if item.id == prior_artifact.id
        )

        with self.assertRaisesRegex(
            EngineError,
            "not a bounded immutable same-run artifact",
        ):
            engine._managed_action_inputs(
                "MR-current-builder",
                (canonical_prior,),
            )

        after = engine.store.load(self.identity)
        self.assertEqual(after.revision, state.revision)
        self.assertEqual(after.artifacts, state.artifacts)

    def test_managed_absolute_work_input_accepts_same_run_publication(
        self,
    ) -> None:
        executor = BuilderPublicationExecutor()
        executor.command_by_role[Role.BUILDER] = (
            "python3 /work/solver.py"
        )
        sandboxes: list[BuilderPublicationSandbox] = []

        def sandbox_factory(state, work, policy):
            del state, policy
            sandbox = BuilderPublicationSandbox(work, executor)
            sandboxes.append(sandbox)
            return sandbox

        engine = self.engine(
            executor,
            sandbox_factory=sandbox_factory,
        )
        self.add_v2(engine)
        state = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        ).run_cycle(self.identity)

        builder_run = next(
            run
            for run in state.runs
            if run.role == Role.BUILDER.value
            and run.origin is RunOrigin.MANAGED_MODEL
        )
        experiment = next(
            item
            for item in state.experiments
            if item.source_run_id == builder_run.id
            and item.extra.get("managed_action_input_binding") is not None
        )
        self.assertEqual(
            shlex.split(experiment.command)[2],
            "python3 /work/solver.py",
        )
        action_sandbox = next(
            sandbox
            for sandbox in sandboxes
            if sandbox.builder_action_calls
        )
        self.assertEqual(
            action_sandbox.observed_solver,
            BUILDER_SOLVER_PAYLOAD,
        )

    def test_bound_builder_action_precedes_timeout_tiebreak(self) -> None:
        engine = self.engine(ProbeRoleExecutor())
        state = self.add_v2(engine)
        hypothesis_id = "H-action-priority"
        state.hypotheses.append(
            Hypothesis(
                id=hypothesis_id,
                statement="one shared strategic hypothesis",
                falsifier=Falsifier(description="run a bounded check"),
            )
        )
        cycle = ManagedCycle(
            id="MC-action-priority",
            session_id="S-action-priority",
            ordinal=1,
            phase="wave_reserved",
            configuration_epoch=state.configuration_epoch,
            captain_run_id="MR-captain",
            wave_id="MW-action-priority",
        )
        wave = ManagedWave(
            id="MW-action-priority",
            session_id=cycle.session_id,
            cycle_id=cycle.id,
            kind=WaveKind.ATTACK,
            role_run_ids={
                Role.BUILDER.value: "MR-builder",
                Role.FALSIFIER.value: "MR-falsifier",
                Role.REPRODUCER.value: "MR-reproducer",
            },
            snapshot_revision=state.revision,
            configuration_epoch=state.configuration_epoch,
        )
        state.cycles.append(cycle)
        state.waves.append(wave)

        def action(
            experiment_id: str,
            source_run_id: str,
            timeout_seconds: int,
            *,
            extra: dict[str, object] | None = None,
        ) -> Experiment:
            return Experiment(
                id=experiment_id,
                hypothesis_ids=[hypothesis_id],
                command=f"printf '%s\\n' {experiment_id}",
                expected_observation="a bounded discriminating result",
                keep_if="the result supports the hypothesis",
                drop_if="the result refutes the hypothesis",
                timeout_seconds=timeout_seconds,
                source_run_id=source_run_id,
                extra=dict(extra or {}),
            )

        builder = action(
            "E-builder-bound",
            "MR-builder",
            300,
            extra={
                "managed_command_protocol": "posix_sh_lc_v1",
                "managed_action_input_binding": {
                    "schema_version": 1,
                    "protocol": "same_run_publications_v1",
                    "source_run_id": "MR-builder",
                    "artifacts": [{"artifact_id": "A-builder-solver"}],
                    "total_bytes": 1,
                },
            },
        )
        state.experiments.extend(
            [
                action("E-falsifier-fast", "MR-falsifier", 30),
                action("E-captain", "MR-captain", 90),
                action("E-reproducer", "MR-reproducer", 120),
                builder,
            ]
        )

        self.assertEqual(
            ManagedOrchestrator._select_actions(state, wave),
            (
                "E-builder-bound",
                "E-falsifier-fast",
                "E-captain",
            ),
        )

        builder.extra.clear()
        self.assertEqual(
            ManagedOrchestrator._select_actions(state, wave),
            (
                "E-falsifier-fast",
                "E-captain",
                "E-reproducer",
            ),
        )

    def _action_selection_fixture(
        self,
        kind: WaveKind,
    ) -> tuple[ChallengeState, ManagedWave, dict[str, str]]:
        engine = self.engine(ProbeRoleExecutor())
        state = self.add_v2(engine)
        role_run_ids = {
            Role.BUILDER.value: "MR-selection-builder",
            Role.FALSIFIER.value: "MR-selection-falsifier",
            Role.REPRODUCER.value: "MR-selection-reproducer",
        }
        cycle = ManagedCycle(
            id=f"MC-selection-{kind.value}",
            session_id=f"S-selection-{kind.value}",
            ordinal=1,
            phase="wave_reserved",
            configuration_epoch=state.configuration_epoch,
            captain_run_id="MR-selection-captain",
            wave_id=f"MW-selection-{kind.value}",
        )
        wave = ManagedWave(
            id=str(cycle.wave_id),
            session_id=cycle.session_id,
            cycle_id=cycle.id,
            kind=kind,
            role_run_ids=dict(role_run_ids),
            snapshot_revision=state.revision,
            configuration_epoch=state.configuration_epoch,
        )
        state.cycles.append(cycle)
        state.waves.append(wave)
        state.runs.extend(
            RunReference(
                id=run_id,
                base_revision=state.revision,
                status=RunStatus.COMPLETED,
                role=role,
                origin=RunOrigin.MANAGED_MODEL,
                session_id=cycle.session_id,
                cycle_id=cycle.id,
                wave_id=wave.id,
                configuration_epoch=state.configuration_epoch,
            )
            for role, run_id in role_run_ids.items()
        )
        return state, wave, role_run_ids

    @staticmethod
    def _selection_probe(
        experiment_id: str,
        source_run_id: str,
        *,
        hypothesis_ids: tuple[str, ...] = (),
        command: str = "/bin/sh -lc 'printf exact-discovery-probe'",
        expected_observation: str = "the exact bounded probe completes",
        keep_if: str = "the exact output is present",
        drop_if: str = "the exact output is absent",
        timeout_seconds: int = 30,
        resource_class: str = "light",
        kind: ExperimentKind = ExperimentKind.PROBE,
        extra: dict[str, object] | None = None,
    ) -> Experiment:
        return Experiment(
            id=experiment_id,
            hypothesis_ids=list(hypothesis_ids),
            command=command,
            expected_observation=expected_observation,
            keep_if=keep_if,
            drop_if=drop_if,
            timeout_seconds=timeout_seconds,
            resource_class=resource_class,
            kind=kind,
            source_run_id=source_run_id,
            extra=dict(extra or {}),
        )

    @staticmethod
    def _seed_existing_managed_command(
        engine: ChallengeEngine,
        identity: ChallengeIdentity,
        *,
        experiment_id: str,
        command_script: str,
        expected_observation: str,
        keep_if: str,
        drop_if: str,
    ) -> Experiment:
        current = engine.store.load(identity)
        source_run_id = f"MR-source-{experiment_id}"
        seeded = Experiment(
            id=experiment_id,
            hypothesis_ids=[],
            command=shlex.join(("/bin/sh", "-lc", command_script)),
            expected_observation=expected_observation,
            keep_if=keep_if,
            drop_if=drop_if,
            timeout_seconds=37,
            resource_class="light",
            kind=ExperimentKind.PROBE,
            source_run_id=source_run_id,
            extra={
                "configuration_epoch": current.configuration_epoch,
                "managed_contract_version": 2,
                "managed_command_protocol": "posix_sh_lc_v1",
            },
        )

        def apply(state):
            state.runs.append(
                RunReference(
                    id=source_run_id,
                    base_revision=state.revision,
                    status=RunStatus.COMPLETED,
                    request_path=f"runs/{source_run_id}/request.json",
                    result_path=f"runs/{source_run_id}/result.json",
                    validation_path=(
                        f"runs/{source_run_id}/validation.json"
                    ),
                    role=Role.EXTRACTOR.value,
                    origin=RunOrigin.MANAGED_MODEL,
                    configuration_epoch=state.configuration_epoch,
                    extra={
                        "contract_version": 2,
                        "semantic_merge": True,
                    },
                )
            )
            state.experiments.append(copy.deepcopy(seeded))

        committed = engine.store.update(
            identity,
            apply,
            expected_revision=current.revision,
        )
        return next(
            item for item in committed.experiments if item.id == experiment_id
        )

    def test_captain_selects_existing_registered_command_by_exact_hashes(
        self,
    ) -> None:
        class ExistingSelectionExecutor(ProbeRoleExecutor):
            def __init__(self) -> None:
                super().__init__(captain_stage="attack")
                self.reference: dict[str, object] | None = None

            def _prepare_output_payload(
                self,
                *,
                command,
                cwd,
                role,
                payload,
            ) -> None:
                del command, cwd
                if role is Role.CAPTAIN:
                    assert self.reference is not None
                    payload["decision"]["selected_experiment"] = dict(
                        self.reference
                    )

        executor = ExistingSelectionExecutor()
        sandboxes: list[FakeSandbox] = []

        def sandbox_factory(state, work, policy):
            del state, policy
            sandbox = FakeSandbox(work)
            sandboxes.append(sandbox)
            return sandbox

        engine = self.engine(executor, sandbox_factory=sandbox_factory)
        self.add_v2(engine)
        command_canary = "existing-command-body-collision-canary"
        selected = self._seed_existing_managed_command(
            engine,
            self.identity,
            experiment_id="E-existing-collision",
            command_script=f"printf '%s\\n' {command_canary}",
            expected_observation="SELECTED_EXPECTED_EXACT_68",
            keep_if="SELECTED_KEEP_EXACT_68",
            drop_if="SELECTED_DROP_EXACT_68",
        )
        unrelated = self._seed_existing_managed_command(
            engine,
            self.identity,
            experiment_id="E-unrelated-pending",
            command_script="printf '%s\\n' unrelated-command-body-canary",
            expected_observation="UNRELATED_EXPECTED_MUST_NOT_PROJECT",
            keep_if="UNRELATED_KEEP_MUST_NOT_PROJECT",
            drop_if="UNRELATED_DROP_MUST_NOT_PROJECT",
        )
        binding = managed_registered_selection_binding(selected)
        executor.reference = {
            key: binding[key]
            for key in (
                "experiment_id",
                "command_sha256",
                "contract_sha256",
            )
        }

        state = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        ).run_cycle(self.identity)

        cycle = state.cycles[-1]
        self.assertIn(selected.id, cycle.selected_action_ids)
        self.assertEqual(
            cycle.extra["managed_registered_selection_v1"],
            binding,
        )
        selected_after = next(
            item for item in state.experiments if item.id == selected.id
        )
        unrelated_after = next(
            item for item in state.experiments if item.id == unrelated.id
        )
        self.assertIsNot(
            selected_after.status,
            ExperimentStatus.REGISTERED,
        )
        self.assertIs(
            unrelated_after.status,
            ExperimentStatus.REGISTERED,
        )
        self.assertTrue(
            any(
                command_canary in " ".join(spec.argv)
                for sandbox in sandboxes
                for spec in sandbox.specs
            )
        )
        worker_prompts = [
            prompt
            for role, prompt in executor.prompts
            if role in {Role.BUILDER, Role.FALSIFIER, Role.REPRODUCER}
        ]
        self.assertEqual(len(worker_prompts), 3)
        for prompt in worker_prompts:
            self.assertIn("SELECTED_EXPECTED_EXACT_68", prompt)
            self.assertIn("SELECTED_KEEP_EXACT_68", prompt)
            self.assertIn("SELECTED_DROP_EXACT_68", prompt)
            self.assertIn(str(binding["command_sha256"]), prompt)
            self.assertIn(str(binding["contract_sha256"]), prompt)
            self.assertIn('"timeout_seconds":37', prompt)
            self.assertIn('"resource_class":"light"', prompt)
            self.assertNotIn(command_canary, prompt)
            self.assertNotIn("unrelated-command-body-canary", prompt)
            self.assertNotIn("UNRELATED_EXPECTED_MUST_NOT_PROJECT", prompt)

    def test_registered_reference_rejects_unknown_status_hash_and_type(
        self,
    ) -> None:
        engine = self.engine(ProbeRoleExecutor())
        self.add_v2(engine)
        selected = self._seed_existing_managed_command(
            engine,
            self.identity,
            experiment_id="E-existing-negative",
            command_script="true",
            expected_observation="expected",
            keep_if="keep",
            drop_if="drop",
        )
        state = engine.store.load(self.identity)
        binding = managed_registered_selection_binding(selected)
        reference = {
            key: binding[key]
            for key in (
                "experiment_id",
                "command_sha256",
                "contract_sha256",
            )
        }
        validated = ManagedOrchestrator._validate_registered_experiment_reference(
            state,
            reference,
            next_stage="attack",
        )
        self.assertEqual(validated.id, selected.id)

        invalid_references = []
        unknown = dict(reference)
        unknown["experiment_id"] = "E-unknown"
        invalid_references.append(unknown)
        command_mismatch = dict(reference)
        command_mismatch["command_sha256"] = "0" * 64
        invalid_references.append(command_mismatch)
        contract_mismatch = dict(reference)
        contract_mismatch["contract_sha256"] = "1" * 64
        invalid_references.append(contract_mismatch)
        for invalid in invalid_references:
            with self.subTest(reference=invalid):
                with self.assertRaises(
                    ManagedRegisteredExperimentReferenceError
                ):
                    ManagedOrchestrator._validate_registered_experiment_reference(
                        state,
                        invalid,
                        next_stage="attack",
                    )

        nonregistered = copy.deepcopy(state)
        next(
            item
            for item in nonregistered.experiments
            if item.id == selected.id
        ).status = ExperimentStatus.CANCELLED
        with self.assertRaises(ManagedRegisteredExperimentReferenceError):
            ManagedOrchestrator._validate_registered_experiment_reference(
                nonregistered,
                reference,
                next_stage="attack",
            )

        legacy = copy.deepcopy(state)
        next(
            item
            for item in legacy.experiments
            if item.id == selected.id
        ).extra.pop("managed_command_protocol")
        with self.assertRaises(ManagedRegisteredExperimentReferenceError):
            ManagedOrchestrator._validate_registered_experiment_reference(
                legacy,
                reference,
                next_stage="attack",
            )

        unmerged = copy.deepcopy(state)
        next(
            item
            for item in unmerged.runs
            if item.id == selected.source_run_id
        ).extra["semantic_merge"] = False
        with self.assertRaises(ManagedRegisteredExperimentReferenceError):
            ManagedOrchestrator._validate_registered_experiment_reference(
                unmerged,
                reference,
                next_stage="attack",
            )

        invalid_utf8 = copy.deepcopy(state)
        next(
            item
            for item in invalid_utf8.experiments
            if item.id == selected.id
        ).expected_observation = "\ud800"
        with self.assertRaises(ManagedRegisteredExperimentReferenceError):
            ManagedOrchestrator._validate_registered_experiment_reference(
                invalid_utf8,
                reference,
                next_stage="attack",
            )

    def test_discovery_preserves_roles_and_deduplicates_exact_workers(
        self,
    ) -> None:
        executor = ProbeRoleExecutor(captain_stage="discover")
        engine = self.engine(executor)
        self.add_v2(engine)

        state = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        ).run_cycle(self.identity)

        wave = state.waves[-1]
        cycle = next(item for item in state.cycles if item.id == wave.cycle_id)
        self.assertIs(wave.kind, WaveKind.DISCOVERY)
        self.assertEqual(len(wave.role_run_ids), 3)
        worker_runs = [
            item
            for item in state.runs
            if item.id in wave.role_run_ids.values()
        ]
        self.assertEqual(len(worker_runs), 3)
        self.assertEqual(
            {item.role for item in worker_runs},
            set(wave.role_run_ids),
        )
        self.assertEqual(
            {item.status for item in worker_runs},
            {RunStatus.COMPLETED},
        )
        wave_run_ids = {
            cycle.captain_run_id,
            *wave.role_run_ids.values(),
        }
        wave_experiments = [
            item
            for item in state.experiments
            if item.source_run_id in wave_run_ids
        ]
        self.assertEqual(len(wave_experiments), 4)
        selected_wave_action_ids = {
            item.id
            for item in wave_experiments
            if item.id in cycle.selected_action_ids
        }
        selected_wave_actions = [
            item
            for item in wave_experiments
            if item.id in selected_wave_action_ids
        ]
        self.assertEqual(len(selected_wave_action_ids), 2)
        self.assertEqual(
            sum(
                item.kind is ExperimentKind.STRATEGIC
                for item in selected_wave_actions
            ),
            1,
        )
        self.assertEqual(
            sum(
                item.kind is ExperimentKind.PROBE
                for item in selected_wave_actions
            ),
            1,
        )

    def test_discovery_does_not_merge_different_hypotheses(self) -> None:
        state, wave, role_run_ids = self._action_selection_fixture(
            WaveKind.DISCOVERY
        )
        hypothesis_ids = ("H-discovery-first", "H-discovery-second")
        state.hypotheses.extend(
            Hypothesis(
                id=hypothesis_id,
                statement=f"distinct semantic claim {hypothesis_id}",
                falsifier=Falsifier(description="run the bounded probe"),
            )
            for hypothesis_id in hypothesis_ids
        )
        state.experiments.extend(
            [
                self._selection_probe(
                    "E-discovery-first-hypothesis",
                    role_run_ids[Role.BUILDER.value],
                    hypothesis_ids=(hypothesis_ids[0],),
                    kind=ExperimentKind.STRATEGIC,
                ),
                self._selection_probe(
                    "E-discovery-second-hypothesis",
                    role_run_ids[Role.FALSIFIER.value],
                    hypothesis_ids=(hypothesis_ids[1],),
                    kind=ExperimentKind.STRATEGIC,
                ),
            ]
        )

        self.assertEqual(
            ManagedOrchestrator._select_actions(state, wave),
            (
                "E-discovery-first-hypothesis",
                "E-discovery-second-hypothesis",
            ),
        )

    def test_discovery_does_not_merge_oracle_differences(self) -> None:
        state, wave, role_run_ids = self._action_selection_fixture(
            WaveKind.DISCOVERY
        )
        hypothesis_id = "H-discovery-shared"
        state.hypotheses.append(
            Hypothesis(
                id=hypothesis_id,
                statement="one shared semantic claim",
                falsifier=Falsifier(description="run the bounded probe"),
            )
        )
        base_values = {
            "expected_observation": "the exact bounded probe completes",
            "keep_if": "the exact output is present",
            "drop_if": "the exact output is absent",
        }
        differences = {
            "expected_observation": "a distinct observation is emitted",
            "keep_if": "a distinct keep predicate is satisfied",
            "drop_if": "a distinct drop predicate is satisfied",
        }
        for field, changed_value in differences.items():
            with self.subTest(field=field):
                state.experiments.clear()
                first = self._selection_probe(
                    f"E-discovery-{field}-base",
                    role_run_ids[Role.BUILDER.value],
                    hypothesis_ids=(hypothesis_id,),
                    kind=ExperimentKind.STRATEGIC,
                    **base_values,
                )
                changed = dict(base_values)
                changed[field] = changed_value
                second = self._selection_probe(
                    f"E-discovery-{field}-changed",
                    role_run_ids[Role.FALSIFIER.value],
                    hypothesis_ids=(hypothesis_id,),
                    kind=ExperimentKind.STRATEGIC,
                    **changed,
                )
                state.experiments.extend((first, second))

                self.assertEqual(
                    ManagedOrchestrator._select_actions(state, wave),
                    (first.id, second.id),
                )

    def test_discovery_merges_only_fully_identical_semantics(self) -> None:
        state, wave, role_run_ids = self._action_selection_fixture(
            WaveKind.DISCOVERY
        )
        state.experiments.extend(
            self._selection_probe(
                f"E-discovery-identical-{role}",
                run_id,
            )
            for role, run_id in role_run_ids.items()
        )

        self.assertEqual(
            ManagedOrchestrator._select_actions(state, wave),
            ("E-discovery-identical-builder",),
        )

    def test_discovery_same_role_command_selects_one_oracle(self) -> None:
        state, wave, role_run_ids = self._action_selection_fixture(
            WaveKind.DISCOVERY
        )
        source_run_id = role_run_ids[Role.BUILDER.value]
        state.experiments.extend(
            [
                self._selection_probe(
                    "E-discovery-same-approach-base",
                    source_run_id,
                ),
                self._selection_probe(
                    "E-discovery-same-approach-different-oracle",
                    source_run_id,
                    expected_observation="a distinct observation is emitted",
                ),
            ]
        )

        self.assertEqual(
            ManagedOrchestrator._select_actions(state, wave),
            ("E-discovery-same-approach-base",),
        )

    def test_discovery_command_difference_is_not_merged(self) -> None:
        state, wave, role_run_ids = self._action_selection_fixture(
            WaveKind.DISCOVERY
        )
        source_run_id = role_run_ids[Role.BUILDER.value]
        state.experiments.extend(
            [
                self._selection_probe(
                    "E-discovery-command-first",
                    source_run_id,
                    command="/bin/sh -lc 'printf first-probe'",
                ),
                self._selection_probe(
                    "E-discovery-command-second",
                    source_run_id,
                    command="/bin/sh -lc 'printf second-probe'",
                ),
            ]
        )

        self.assertEqual(
            ManagedOrchestrator._select_actions(state, wave),
            (
                "E-discovery-command-first",
                "E-discovery-command-second",
            ),
        )

    def test_discovery_duplicate_does_not_consume_role_approach(self) -> None:
        state, wave, role_run_ids = self._action_selection_fixture(
            WaveKind.DISCOVERY
        )
        state.experiments.extend(
            [
                self._selection_probe(
                    "E-discovery-builder-base",
                    role_run_ids[Role.BUILDER.value],
                ),
                self._selection_probe(
                    "E-discovery-falsifier-a-duplicate",
                    role_run_ids[Role.FALSIFIER.value],
                ),
                self._selection_probe(
                    "E-discovery-falsifier-b-distinct",
                    role_run_ids[Role.FALSIFIER.value],
                    expected_observation="a distinct observation is emitted",
                ),
                self._selection_probe(
                    "E-discovery-reproducer-third",
                    role_run_ids[Role.REPRODUCER.value],
                    command="/bin/sh -lc 'printf third-probe'",
                ),
            ]
        )

        self.assertEqual(
            ManagedOrchestrator._select_actions(state, wave),
            (
                "E-discovery-builder-base",
                "E-discovery-falsifier-b-distinct",
                "E-discovery-reproducer-third",
            ),
        )

    def test_discovery_does_not_merge_target_or_input_differences(self) -> None:
        state, wave, role_run_ids = self._action_selection_fixture(
            WaveKind.DISCOVERY
        )
        source_run_ids = tuple(role_run_ids.values())
        binding_source_run_id = source_run_ids[0]

        def execution_extra(
            *,
            generation: int,
            artifact_sha256: str,
        ) -> dict[str, object]:
            return {
                "configuration_epoch": state.configuration_epoch,
                "managed_contract_version": 2,
                "managed_command_protocol": "posix_sh_lc_v1",
                "network_target": "https://selection.example:443",
                "network_target_id": "T-selection",
                "network_target_generation": generation,
                "managed_action_input_binding": {
                    "schema_version": 1,
                    "protocol": "same_run_publications_v1",
                    "source_run_id": binding_source_run_id,
                    "artifacts": [
                        {
                            "artifact_id": f"A-{artifact_sha256[0]}",
                            "canonical_path": (
                                "artifacts/snapshots/selection-input"
                            ),
                            "destination": "solver.py",
                            "sha256": artifact_sha256,
                            "size_bytes": 1,
                            "source_run_id": binding_source_run_id,
                        }
                    ],
                    "total_bytes": 1,
                },
            }

        state.experiments.extend(
            [
                self._selection_probe(
                    "E-discovery-base-binding",
                    source_run_ids[0],
                    extra=execution_extra(
                        generation=1,
                        artifact_sha256="a" * 64,
                    ),
                ),
                self._selection_probe(
                    "E-discovery-new-generation",
                    source_run_ids[1],
                    extra=execution_extra(
                        generation=2,
                        artifact_sha256="a" * 64,
                    ),
                ),
                self._selection_probe(
                    "E-discovery-new-binding",
                    source_run_ids[2],
                    extra=execution_extra(
                        generation=1,
                        artifact_sha256="b" * 64,
                    ),
                ),
            ]
        )

        self.assertEqual(
            ManagedOrchestrator._select_actions(state, wave),
            (
                "E-discovery-base-binding",
                "E-discovery-new-generation",
                "E-discovery-new-binding",
            ),
        )

    def test_discovery_does_not_merge_resource_or_timeout_differences(
        self,
    ) -> None:
        state, wave, role_run_ids = self._action_selection_fixture(
            WaveKind.DISCOVERY
        )
        source_run_ids = tuple(role_run_ids.values())
        state.experiments.extend(
            [
                self._selection_probe(
                    "E-discovery-base-resources",
                    source_run_ids[0],
                ),
                self._selection_probe(
                    "E-discovery-heavy-resource",
                    source_run_ids[1],
                    resource_class="heavy",
                ),
                self._selection_probe(
                    "E-discovery-longer-timeout",
                    source_run_ids[2],
                    timeout_seconds=31,
                ),
            ]
        )

        self.assertEqual(
            ManagedOrchestrator._select_actions(state, wave),
            (
                "E-discovery-base-resources",
                "E-discovery-heavy-resource",
                "E-discovery-longer-timeout",
            ),
        )

    def test_attack_keeps_cross_role_exact_executions_independent(self) -> None:
        state, wave, role_run_ids = self._action_selection_fixture(
            WaveKind.ATTACK
        )
        shared_extra = {
            "configuration_epoch": state.configuration_epoch,
            "managed_contract_version": 2,
            "managed_command_protocol": "posix_sh_lc_v1",
        }
        state.experiments.extend(
            self._selection_probe(
                f"E-attack-{role}",
                run_id,
                extra=shared_extra,
            )
            for role, run_id in role_run_ids.items()
        )

        with mock.patch.object(
            ManagedOrchestrator,
            "_discovery_execution_fingerprint",
            side_effect=AssertionError("discovery dedup crossed into attack"),
        ):
            self.assertEqual(
                ManagedOrchestrator._select_actions(state, wave),
                (
                    "E-attack-builder",
                    "E-attack-falsifier",
                    "E-attack-reproducer",
                ),
            )

    def test_proof_selection_bypasses_discovery_dedup(self) -> None:
        state, wave, role_run_ids = self._action_selection_fixture(
            WaveKind.PROOF
        )
        state.experiments.append(
            Experiment(
                id="E-proof-strict-recipe",
                hypothesis_ids=[],
                command="proof replay is engine owned",
                expected_observation="the exact candidate replay succeeds",
                keep_if="the replay proves the candidate",
                drop_if="the replay does not prove the candidate",
                timeout_seconds=30,
                kind=ExperimentKind.PROOF,
                source_run_id=role_run_ids[Role.REPRODUCER.value],
                proof_recipe=mock.sentinel.proof_recipe,
            )
        )

        with mock.patch.object(
            ManagedOrchestrator,
            "_discovery_execution_fingerprint",
            side_effect=AssertionError("discovery dedup crossed into proof"),
        ):
            self.assertEqual(
                ManagedOrchestrator._select_actions(state, wave),
                ("E-proof-strict-recipe",),
            )

    def test_managed_model_background_script_is_rejected_before_registration(
        self,
    ) -> None:
        executor = ProbeRoleExecutor(
            command_by_role={
                Role.CAPTAIN: "sh -c 'sleep 60 &'",
                Role.BUILDER: "eval 'sleep 60 &'",
                Role.FALSIFIER: 'x="$(sleep 60 &)"',
                Role.REPRODUCER: (
                    "cat <<EOF\n"
                    "$(sleep 60 &)\n"
                    "EOF\n"
                ),
            }
        )
        engine = self.engine(executor)
        self.add_v2(engine)
        state = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        ).run_cycle(self.identity)

        self.assertFalse(
            any(
                experiment.extra.get("managed_command_protocol")
                == "posix_sh_lc_v1"
                for experiment in state.experiments
            )
        )
        rejected = [
            rejection
            for run in state.runs
            if run.origin is RunOrigin.MANAGED_MODEL
            for rejection in run.extra.get("rejected_actions", [])
        ]
        self.assertTrue(rejected)
        self.assertTrue(
            all(
                "background" in str(item.get("reason", ""))
                or "detached" in str(item.get("reason", ""))
                or "foreground" in str(item.get("reason", ""))
                for item in rejected
            )
        )

    def test_legacy_managed_commands_retire_without_reinterpretation(
        self,
    ) -> None:
        sandboxes: list[FakeSandbox] = []

        def sandbox_factory(state, work, policy):
            del state, policy
            sandbox = FakeSandbox(work)
            sandboxes.append(sandbox)
            return sandbox

        engine = self.engine(
            ProbeRoleExecutor(),
            sandbox_factory=sandbox_factory,
        )
        self.add_v2(engine)
        _state, operator_id = engine.register_experiment(
            self.identity,
            command=("python3", "-c", "print('operator argv')"),
            expected_observation="operator output",
            keep_if="output exists",
            drop_if="output is absent",
        )
        legacy_script = (
            "printf '%s' $(touch /work/legacy-side-effect)"
        )
        second_legacy_script = (
            "printf '%s' $(touch /work/legacy-second-side-effect)"
        )

        def seed(current):
            current.runs.append(
                RunReference(
                    id="R-legacy-managed-model",
                    base_revision=current.revision,
                    status=RunStatus.CREATED,
                    origin=RunOrigin.MANAGED_MODEL,
                    role="builder",
                )
            )
            common = {
                "hypothesis_ids": [],
                "expected_observation": "bounded output",
                "keep_if": "output exists",
                "drop_if": "output is absent",
                "timeout_seconds": 30,
                "kind": ExperimentKind.PROBE,
                "source_run_id": "R-legacy-managed-model",
            }
            current.experiments.extend(
                [
                    Experiment(
                        id="E-legacy-managed",
                        command=legacy_script,
                        status=ExperimentStatus.REGISTERED,
                        **common,
                    ),
                    Experiment(
                        id="E-legacy-managed-second",
                        command=second_legacy_script,
                        status=ExperimentStatus.REGISTERED,
                        **common,
                    ),
                    Experiment(
                        id="E-invalid-unrelated-managed",
                        command="invalid\x00legacy",
                        status=ExperimentStatus.REGISTERED,
                        **common,
                    ),
                    Experiment(
                        id="E-running-managed",
                        command="set -u\ntrue\n",
                        status=ExperimentStatus.RUNNING,
                        **common,
                    ),
                    Experiment(
                        id="E-completed-managed",
                        command="printf completed",
                        status=ExperimentStatus.COMPLETED,
                        **common,
                    ),
                    Experiment(
                        id="E-engine-managed",
                        command="ctfos-engine:synthetic",
                        status=ExperimentStatus.REGISTERED,
                        extra={"engine_executor": "synthetic_v1"},
                        **common,
                    ),
                ]
            )

        seeded = engine.store.update(self.identity, seed)
        adapter_before = {
            item.id: item.command
            for item in seeded.experiments
            if item.extra.get("adapter_seed") is True
        }
        operator_before = next(
            item.command
            for item in seeded.experiments
            if item.id == operator_id
        )
        operator_executed = engine.execute_registered_experiments(
            self.identity,
            experiment_ids=(operator_id,),
        )
        self.assertIs(
            next(
                item.status
                for item in operator_executed.experiments
                if item.id == "E-legacy-managed"
            ),
            ExperimentStatus.REGISTERED,
        )
        self.assertIs(
            next(
                item.status
                for item in operator_executed.experiments
                if item.id == "E-invalid-unrelated-managed"
            ),
            ExperimentStatus.REGISTERED,
        )
        self.assertIn(
            ("python3", "-c", "print('operator argv')"),
            [
                spec.argv
                for sandbox in sandboxes
                for spec in sandbox.specs
            ],
        )
        spec_count = sum(len(sandbox.specs) for sandbox in sandboxes)

        retired = engine.execute_registered_experiments(
            self.identity,
            maximum=1,
            experiment_ids=(
                "E-legacy-managed",
                "E-legacy-managed-second",
            ),
        )
        legacy = next(
            item
            for item in retired.experiments
            if item.id == "E-legacy-managed"
        )
        self.assertIs(legacy.status, ExperimentStatus.CANCELLED)
        self.assertEqual(legacy.command, legacy_script)
        self.assertEqual(
            legacy.extra["cancelled_reason"],
            "legacy_managed_command_semantics_ambiguous",
        )
        self.assertNotIn("managed_command_protocol", legacy.extra)
        second_legacy = next(
            item
            for item in retired.experiments
            if item.id == "E-legacy-managed-second"
        )
        self.assertIs(
            second_legacy.status,
            ExperimentStatus.REGISTERED,
        )
        self.assertEqual(second_legacy.command, second_legacy_script)
        self.assertEqual(
            sum(len(sandbox.specs) for sandbox in sandboxes),
            spec_count,
        )
        self.assertFalse(
            (engine._workspace(retired) / "legacy-side-effect").exists()
        )
        unchanged = engine._retire_registered_legacy_managed_commands(
            self.identity,
            retired,
            eligible_experiment_ids=("E-legacy-managed",),
        )
        self.assertEqual(unchanged.revision, retired.revision)

        second_retired = engine.execute_registered_experiments(
            self.identity,
            experiment_ids=("E-legacy-managed-second",),
        )
        second_legacy = next(
            item
            for item in second_retired.experiments
            if item.id == "E-legacy-managed-second"
        )
        self.assertIs(
            second_legacy.status,
            ExperimentStatus.CANCELLED,
        )
        self.assertEqual(
            sum(len(sandbox.specs) for sandbox in sandboxes),
            spec_count,
        )

        invalid_retired = engine.execute_registered_experiments(
            self.identity,
            experiment_ids=("E-invalid-unrelated-managed",),
        )
        invalid = next(
            item
            for item in invalid_retired.experiments
            if item.id == "E-invalid-unrelated-managed"
        )
        self.assertIs(invalid.status, ExperimentStatus.CANCELLED)
        self.assertEqual(
            invalid.extra["cancelled_reason"],
            "legacy_managed_command_semantics_ambiguous",
        )
        self.assertEqual(
            sum(len(sandbox.specs) for sandbox in sandboxes),
            spec_count,
        )

        for experiment_id, expected in (
            ("E-running-managed", "set -u\ntrue\n"),
            ("E-completed-managed", "printf completed"),
            ("E-engine-managed", "ctfos-engine:synthetic"),
            (operator_id, operator_before),
        ):
            self.assertEqual(
                next(
                    item.command
                    for item in invalid_retired.experiments
                    if item.id == experiment_id
                ),
                expected,
            )
        self.assertEqual(
            {
                item.id: item.command
                for item in invalid_retired.experiments
                if item.extra.get("adapter_seed") is True
            },
            adapter_before,
        )

        proof_like = Experiment(
            id="E-proof-boundary",
            hypothesis_ids=[],
            command="true",
            expected_observation="proof",
            keep_if="proof",
            drop_if="not proof",
            timeout_seconds=1,
            kind=ExperimentKind.PROOF,
            status=ExperimentStatus.REGISTERED,
            source_run_id="R-legacy-managed-model",
        )
        self.assertFalse(
            engine._legacy_managed_shell_experiment(
                proof_like,
                {
                    "R-legacy-managed-model": next(
                        run
                        for run in invalid_retired.runs
                        if run.id == "R-legacy-managed-model"
                    )
                },
            )
        )

    def test_managed_hypothesis_ids_preserve_current_and_namespace_foreign(
        self,
    ):
        executor = ProbeRoleExecutor(
            captain_hypothesis_ids=(
                "H-{run_id}-hyp-1",
                "hyp-2",
                "H-foreign-run-hyp-3",
            ),
            captain_action_hypothesis_ids=(
                "H-{run_id}-hyp-1",
                "H-foreign-run-hyp-3",
            ),
        )
        engine = self.engine(executor)
        self.add_v2(engine)

        state = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        ).run_cycle(self.identity)

        captain_run_id = state.cycles[0].captain_run_id
        current_id = f"H-{captain_run_id}-hyp-1"
        foreign_id = (
            f"H-{captain_run_id}-H-foreign-run-hyp-3"
        )
        self.assertEqual(
            {item.id for item in state.hypotheses},
            {
                current_id,
                f"H-{captain_run_id}-hyp-2",
                foreign_id,
            },
        )
        self.assertNotIn(
            f"H-{captain_run_id}-{current_id}",
            {item.id for item in state.hypotheses},
        )
        captain_experiment = next(
            item
            for item in state.experiments
            if item.source_run_id == captain_run_id
        )
        self.assertEqual(
            captain_experiment.hypothesis_ids,
            [current_id, foreign_id],
        )

    def test_late_wave_actions_accept_supported_frontier_only(self):
        supported_id = "H-captain-supported"
        confirmed_id = "H-captain-confirmed"
        refuted_id = "H-captain-refuted"

        class LateWaveExecutor(ProbeRoleExecutor):
            def _prepare_output_payload(
                self,
                *,
                command,
                cwd,
                role: Role,
                payload: dict[str, object],
            ) -> None:
                del command, cwd
                if role is Role.CAPTAIN:
                    return
                actions = payload["actions"]
                assert isinstance(actions, list) and len(actions) == 1
                template = actions[0]
                assert isinstance(template, dict)
                payload["actions"] = [
                    {
                        **copy.deepcopy(template),
                        "hypothesis_ids": [hypothesis_id],
                    }
                    for hypothesis_id in (
                        supported_id,
                        confirmed_id,
                        refuted_id,
                        "H-missing",
                    )
                ]

        engine = self.engine(LateWaveExecutor())
        self.add_v2(engine)
        evidence_payload = b"captain evaluation evidence\n"
        evidence_run_id = "R-captain-evaluation"
        evidence_artifact_id = "A-captain-evaluation"
        evidence_fact_id = "F-captain-evaluation"
        evidence_path = (
            engine.store.challenge_paths(self.identity).artifacts
            / "snapshots"
            / f"{evidence_artifact_id}.log"
        )
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        evidence_path.write_bytes(evidence_payload)
        evidence_path.chmod(0o400)

        def seed_evaluated_frontier(state):
            state.runs.append(
                RunReference(
                    id=evidence_run_id,
                    base_revision=state.revision,
                    status=RunStatus.COMPLETED,
                )
            )
            state.artifacts.append(
                ArtifactReference(
                    id=evidence_artifact_id,
                    path=(
                        "artifacts/snapshots/"
                        f"{evidence_artifact_id}.log"
                    ),
                    sha256=hashlib.sha256(evidence_payload).hexdigest(),
                    source_run_id=evidence_run_id,
                    size=len(evidence_payload),
                )
            )
            state.facts.append(
                Fact(
                    id=evidence_fact_id,
                    statement="Captain evaluated the shared frontier",
                    provenance=Provenance.EXECUTED,
                    challenge_id=state.challenge_id,
                    source_run_id=evidence_run_id,
                    artifact_id=evidence_artifact_id,
                    locator=(
                        "artifacts/snapshots/"
                        f"{evidence_artifact_id}.log"
                    ),
                    supports=[supported_id, confirmed_id],
                    contradicts=[refuted_id],
                )
            )
            state.hypotheses.extend(
                [
                    Hypothesis(
                        id=supported_id,
                        statement="the remote approach is supported",
                        falsifier=Falsifier("repeat the bounded action"),
                        status=HypothesisStatus.SUPPORTED,
                        evidence_fact_ids=[evidence_fact_id],
                    ),
                    Hypothesis(
                        id=confirmed_id,
                        statement="a resolved control is confirmed",
                        falsifier=Falsifier("invalidate the control"),
                        status=HypothesisStatus.CONFIRMED,
                        evidence_fact_ids=[evidence_fact_id],
                    ),
                    Hypothesis(
                        id=refuted_id,
                        statement="a discarded approach is refuted",
                        falsifier=Falsifier("recover the discarded path"),
                        status=HypothesisStatus.REFUTED,
                        evidence_fact_ids=[evidence_fact_id],
                        refuted_by=evidence_fact_id,
                    ),
                ]
            )

        engine.store.update(self.identity, seed_evaluated_frontier)
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        _state, session_id = orchestrator._reserve_session(
            self.identity,
            None,
        )
        _state, cycle = orchestrator._reserve_cycle(
            self.identity,
            session_id,
        )
        _state, _wave, role_runs = orchestrator._reserve_wave(
            self.identity,
            session_id,
            cycle.id,
            "attack",
        )
        outcome = engine.run_wave(
            self.identity,
            "attack",
            _session_owned=True,
            _automated=True,
            _reserved_run_ids=role_runs,
            _semantic_barrier=True,
            _managed_workspace=True,
        )
        state = engine.store.load(self.identity)
        wave_run_ids = {
            result.invocation.run_id for result in outcome.results
        }
        registered = [
            experiment
            for experiment in state.experiments
            if experiment.source_run_id in wave_run_ids
        ]

        self.assertEqual(
            len(registered),
            3,
            [
                (
                    run.id,
                    run.status.value,
                    run.extra.get("contract_errors"),
                    run.extra.get("rejected_actions"),
                )
                for run in state.runs
                if run.id in wave_run_ids
            ],
        )
        self.assertTrue(
            all(
                experiment.hypothesis_ids == [supported_id]
                for experiment in registered
            )
        )
        for run in state.runs:
            if run.id not in wave_run_ids:
                continue
            rejections = run.extra.get("rejected_actions", [])
            self.assertEqual(
                [item["action"] for item in rejections],
                ["2", "3", "4"],
            )
            self.assertTrue(
                all(
                    str(item["reason"]).startswith(
                        "unknown or inactive hypothesis ids:"
                    )
                    for item in rejections
                )
            )

    def test_strategic_actions_cancel_if_frontier_terminalizes_before_start(
        self,
    ) -> None:
        sandboxes: list[FakeSandbox] = []

        def sandbox_factory(state, work, policy):
            del state, policy
            sandbox = FakeSandbox(work)
            sandboxes.append(sandbox)
            return sandbox

        engine = self.engine(
            ProbeRoleExecutor(),
            sandbox_factory=sandbox_factory,
        )
        self.add_v2(engine)
        confirmed_id = "H-prestart-confirmed"
        refuted_id = "H-prestart-refuted"
        for hypothesis_id in (confirmed_id, refuted_id):
            engine.manage_hypothesis(
                self.identity,
                action="create",
                hypothesis_id=hypothesis_id,
                statement=f"frontier claim for {hypothesis_id}",
                falsifier=f"falsify {hypothesis_id}",
            )
        experiment_ids = []
        for hypothesis_id in (confirmed_id, refuted_id):
            _state, experiment_id = engine.register_experiment(
                self.identity,
                command=("python3", "-c", "print('must not run')"),
                expected_observation="bounded output",
                keep_if="output exists",
                drop_if="output is absent",
                hypothesis_ids=(hypothesis_id,),
            )
            experiment_ids.append(experiment_id)

        evidence_payload = b"pre-start frontier evaluation\n"
        evidence_run_id = "R-prestart-frontier-evaluation"
        evidence_artifact_id = "A-prestart-frontier-evaluation"
        evidence_fact_id = "F-prestart-frontier-evaluation"
        evidence_locator = (
            "artifacts/snapshots/"
            f"{evidence_artifact_id}.log"
        )
        evidence_path = (
            engine.store.challenge_paths(self.identity).root
            / evidence_locator
        )
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        evidence_path.write_bytes(evidence_payload)
        evidence_path.chmod(0o400)

        def terminalize_frontier(state):
            state.runs.append(
                RunReference(
                    id=evidence_run_id,
                    base_revision=state.revision,
                    status=RunStatus.COMPLETED,
                )
            )
            state.artifacts.append(
                ArtifactReference(
                    id=evidence_artifact_id,
                    path=evidence_locator,
                    sha256=hashlib.sha256(evidence_payload).hexdigest(),
                    source_run_id=evidence_run_id,
                    size=len(evidence_payload),
                )
            )
            state.facts.append(
                Fact(
                    id=evidence_fact_id,
                    statement="the frontier was resolved before tool start",
                    provenance=Provenance.EXECUTED,
                    challenge_id=state.challenge_id,
                    source_run_id=evidence_run_id,
                    artifact_id=evidence_artifact_id,
                    locator=evidence_locator,
                    supports=[confirmed_id],
                    contradicts=[refuted_id],
                )
            )
            hypotheses = {
                item.id: item for item in state.hypotheses
            }
            confirmed = hypotheses[confirmed_id]
            confirmed.status = HypothesisStatus.CONFIRMED
            confirmed.evidence_fact_ids = [evidence_fact_id]
            refuted = hypotheses[refuted_id]
            refuted.status = HypothesisStatus.REFUTED
            refuted.refuted_by = evidence_fact_id
            refuted.evidence_fact_ids = [evidence_fact_id]

        before = engine.store.update(
            self.identity,
            terminalize_frontier,
        )
        run_ids_before = [item.id for item in before.runs]

        after = engine.execute_registered_experiments(
            self.identity,
            maximum=2,
            experiment_ids=tuple(experiment_ids),
        )

        selected = {
            item.id: item
            for item in after.experiments
            if item.id in experiment_ids
        }
        self.assertEqual(set(selected), set(experiment_ids))
        for hypothesis_id, experiment_id in zip(
            (confirmed_id, refuted_id),
            experiment_ids,
            strict=True,
        ):
            experiment = selected[experiment_id]
            self.assertIs(
                experiment.status,
                ExperimentStatus.CANCELLED,
            )
            self.assertEqual(
                experiment.extra["cancelled_reason"],
                "inactive_strategic_hypothesis_before_execution",
            )
            rejection = experiment.extra["execution_rejection"]
            self.assertEqual(
                rejection["inactive_hypothesis_ids"],
                [hypothesis_id],
            )
            self.assertFalse(rejection["missing_hypothesis_binding"])
        self.assertEqual([item.id for item in after.runs], run_ids_before)
        self.assertEqual(sandboxes, [])

    def test_managed_hypothesis_collisions_are_contained_per_item(self):
        executor = ProbeRoleExecutor(
            captain_hypothesis_ids=(
                "hyp-1",
                "H-{run_id}-hyp-1",
                "H-{run_id}-",
                "hyp-2",
                "hyp-3",
            ),
            captain_action_hypothesis_ids=(
                "H-{run_id}-hyp-1",
            ),
        )
        engine = self.engine(executor)
        self.add_v2(engine)

        state = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        ).run_cycle(self.identity)

        captain_run_id = state.cycles[0].captain_run_id
        self.assertEqual(
            {item.id for item in state.hypotheses},
            {
                f"H-{captain_run_id}-hyp-1",
                f"H-{captain_run_id}-hyp-2",
                f"H-{captain_run_id}-hyp-3",
            },
        )
        captain = next(
            item for item in state.runs if item.id == captain_run_id
        )
        self.assertIs(captain.status, RunStatus.COMPLETED)
        rejections = captain.extra[
            "rejected_hypothesis_proposals"
        ]
        self.assertEqual(
            {
                item["hypothesis_id"]
                for item in rejections
            },
            {
                f"H-{captain_run_id}-hyp-1",
                f"H-{captain_run_id}-",
            },
        )
        self.assertTrue(
            any("collides" in item["reason"] for item in rejections)
        )
        self.assertTrue(
            any("empty" in item["reason"] for item in rejections)
        )
        self.assertIsNotNone(state.cycles[0].wave_id)

    def test_non_managed_hypothesis_keeps_ordinary_prefixing(self):
        executor = ProbeRoleExecutor(
            captain_hypothesis_ids=("H-{run_id}-hyp-1",),
        )
        engine = self.engine(executor)
        self.add_v2(engine)

        result = engine.run_role(
            self.identity,
            Role.CAPTAIN,
            instruction="publish one ordinary hypothesis",
        )
        state = engine.store.load(self.identity)

        run_id = result.invocation.run_id
        self.assertEqual(
            [item.id for item in state.hypotheses],
            [f"H-{run_id}-H-{run_id}-hyp-1"],
        )
        experiment = next(
            item
            for item in state.experiments
            if item.source_run_id == run_id
        )
        self.assertEqual(result.invocation.contract_version, 1)
        self.assertNotIn("managed_command_protocol", experiment.extra)
        self.assertEqual(
            experiment.extra[
                "managed_semantic_evaluation_contract_version"
            ],
            2,
        )

    def test_managed_cycle_reserves_three_roles_and_runs_probe_lanes(self):
        executor = ProbeRoleExecutor()
        concurrency = ToolConcurrency(expected_lanes=3)
        engine = self.engine(
            executor,
            sandbox_factory=lambda state, work, policy: SlowSandbox(
                work, concurrency
            ),
        )
        self.add_v2(engine)
        state = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        ).run_cycle(self.identity)

        self.assertEqual(len(state.sessions), 1)
        self.assertEqual(len(state.cycles), 1)
        self.assertEqual(len(state.waves), 1)
        wave = state.waves[0]
        self.assertEqual(
            set(wave.role_run_ids),
            {"builder", "falsifier", "reproducer"},
        )
        self.assertEqual(len(set(wave.role_run_ids.values())), 3)
        wave_runs = [
            run for run in state.runs if run.id in wave.role_run_ids.values()
        ]
        self.assertEqual(
            {run.status for run in wave_runs},
            {RunStatus.COMPLETED},
        )
        self.assertEqual(executor.max_active, 1)
        self.assertEqual(concurrency.maximum, 3)

        tool_runs = [
            run
            for run in state.runs
            if run.origin is RunOrigin.MANAGED_TOOL
        ]
        # Three deterministic cartography seeds run before the model wave,
        # then three independently sourced model actions are executed.
        self.assertEqual(len(tool_runs), 6)
        self.assertEqual(len(state.receipts), 6)
        self.assertTrue(
            all(receipt.stdout_artifact_id for receipt in state.receipts)
        )
        self.assertEqual(len(state.checkpoints), 1)
        self.assertEqual(len(state.hypotheses), 3)
        self.assertTrue(
            all(
                hypothesis.extra["unknowns"]
                and hypothesis.extra["experiment"]
                and hypothesis.extra["success_oracle"]
                for hypothesis in state.hypotheses
            )
        )
        self.assertFalse(
            any(
                "KCTF{tool_flag}" in fact.statement
                for fact in state.facts
            )
        )
        paths = engine.store.challenge_paths(self.identity)
        for run in wave_runs:
            provider_path = paths.runs / run.id / "provider.json"
            self.assertTrue(provider_path.is_file())
            provider = read_json(provider_path)
            self.assertEqual(provider["status"], "completed")
            self.assertTrue(provider["provider_started"])
            for field in (
                "provider_wait_seconds",
                "provider_process_span_seconds",
                "model_call_wall_seconds",
            ):
                self.assertIs(type(provider[field]), float)
                self.assertGreaterEqual(provider[field], 0.0)
                self.assertEqual(run.extra[field], provider[field])
        wave_experiments = [
            item
            for item in state.experiments
            if item.source_run_id in wave.role_run_ids.values()
        ]
        self.assertEqual(len(wave_experiments), 3)
        self.assertTrue(
            all(
                item.timeout_seconds == 30
                and item.resource_class == "light"
                and item.extra["managed_contract_version"] == 2
                for item in wave_experiments
            )
        )

    def test_initial_cartography_defers_stall_until_captain_runs(self):
        executor = ProbeRoleExecutor()
        engine = self.engine(executor)
        self.add_v2(engine)
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        observed_controls: list[tuple[bool, bool]] = []
        stall_evaluation_roles: list[tuple[Role, ...]] = []
        observed_lock = threading.Lock()
        original_execute = engine.execute_registered_experiments
        original_record_stall = engine._record_stall_if_needed

        def observe_execution(*args, **kwargs):
            selected = tuple(kwargs.get("experiment_ids") or ())
            if (
                selected
                and kwargs.get("_pending_artifact_handoff") is None
            ):
                current = engine.store.load(self.identity)
                experiments = {
                    item.id: item for item in current.experiments
                }
                with observed_lock:
                    observed_controls.extend(
                        (
                            experiments[experiment_id].extra.get(
                                "adapter_seed"
                            )
                            is True,
                            kwargs.get("_record_stall", True),
                        )
                        for experiment_id in selected
                    )
            return original_execute(*args, **kwargs)

        def observe_stall(state):
            with executor.lock:
                stall_evaluation_roles.append(tuple(executor.roles))
            return original_record_stall(state)

        with (
            mock.patch.object(
                engine,
                "execute_registered_experiments",
                side_effect=observe_execution,
            ),
            mock.patch.object(
                engine,
                "_record_stall_if_needed",
                side_effect=observe_stall,
            ),
        ):
            state = orchestrator.run_cycle(self.identity)

        self.assertIn(Role.CAPTAIN, executor.roles)
        self.assertTrue(stall_evaluation_roles)
        self.assertTrue(
            all(
                Role.CAPTAIN in roles
                for roles in stall_evaluation_roles
            )
        )
        adapter_controls = {
            record_stall
            for adapter_seed, record_stall in observed_controls
            if adapter_seed
        }
        model_controls = {
            record_stall
            for adapter_seed, record_stall in observed_controls
            if not adapter_seed
        }
        self.assertEqual(adapter_controls, {False})
        # Selected managed actions also defer their individual commits; their
        # bounded wave is evaluated once only after every lane has joined.
        self.assertEqual(model_controls, {False})
        self.assertNotEqual(state.status, ChallengeStatus.NEEDS_HUMAN)

    def test_selected_action_wave_records_stall_once_after_all_actions(
        self,
    ):
        engine = self.engine(ProbeRoleExecutor())
        state = self.add_v2(engine)
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        _state, session_id = orchestrator._reserve_session(
            self.identity,
            "S-stall-wave",
        )
        state = engine.synchronize_managed_adapter_seed_plan(
            self.identity,
            session_id,
        )
        _state, cycle = orchestrator._reserve_cycle(
            self.identity,
            session_id,
        )
        selected = tuple(
            item.id
            for item in state.experiments
            if (
                item.extra.get("adapter_seed") is True
                and item.status is ExperimentStatus.REGISTERED
            )
        )
        self.assertEqual(len(selected), 3)
        orchestrator._mark_action_selection(
            self.identity,
            session_id,
            cycle.id,
            selected,
        )
        per_action_controls: list[bool] = []
        original_execute = engine.execute_registered_experiments

        def observe_execution(*args, **kwargs):
            if (
                kwargs.get("experiment_ids")
                and kwargs.get("_pending_artifact_handoff") is None
            ):
                per_action_controls.append(
                    kwargs.get("_record_stall", True)
                )
            return original_execute(*args, **kwargs)

        with (
            mock.patch.object(
                engine,
                "execute_registered_experiments",
                side_effect=observe_execution,
            ),
            mock.patch.object(
                engine,
                "_record_stall_if_needed",
                wraps=engine._record_stall_if_needed,
            ) as record_stall,
        ):
            completed = orchestrator._execute_selected_actions(
                self.identity,
                selected,
            )

        self.assertEqual(len(per_action_controls), 3)
        self.assertEqual(set(per_action_controls), {False})
        record_stall.assert_called_once()
        self.assertEqual(
            record_stall.call_args.args[0].revision,
            completed.revision,
        )
        self.assertTrue(
            all(
                item.status is not ExperimentStatus.REGISTERED
                for item in completed.experiments
                if item.id in selected
            )
        )

    def test_managed_wave_defers_stall_until_selected_actions_commit(self):
        engine = self.engine(ProbeRoleExecutor())
        self.add_v2(engine)
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        observed_receipt_counts: list[int] = []

        def force_stall_after_bounded_evidence(state):
            cycle = state.cycles[-1]
            selected_ids = set(cycle.selected_action_ids)
            selected = [
                item
                for item in state.experiments
                if item.id in selected_ids
            ]
            # Three adapter seeds and all three selected role actions must be
            # durable before the governor may stop managed execution.
            self.assertEqual(len(state.receipts), 6)
            self.assertEqual(len(selected), 6)
            self.assertTrue(
                all(
                    item.status is not ExperimentStatus.REGISTERED
                    for item in selected
                )
            )
            observed_receipt_counts.append(len(state.receipts))

            def apply(current):
                current.status = ChallengeStatus.STALLED

            return engine.store.update(
                self.identity,
                apply,
                expected_revision=state.revision,
            )

        with mock.patch.object(
            engine,
            "_record_stall_if_needed",
            side_effect=force_stall_after_bounded_evidence,
        ) as record_stall:
            state = orchestrator.run_cycle(self.identity)

        record_stall.assert_called_once()
        self.assertEqual(observed_receipt_counts, [6])
        self.assertIs(state.status, ChallengeStatus.STALLED)
        self.assertIsNone(state.active_managed_session_id)
        self.assertIs(state.sessions[-1].status, SessionStatus.PAUSED)
        self.assertEqual(state.cycles[-1].phase, "completed")
        self.assertEqual(state.waves[-1].status, "completed")

    def test_managed_empty_selection_evaluates_stall_after_wave(self):
        engine = self.engine(ProbeRoleExecutor())
        self.add_v2(engine)
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )

        with (
            mock.patch.object(
                orchestrator,
                "_select_actions",
                return_value=(),
            ),
            mock.patch.object(
                engine,
                "_record_stall_if_needed",
                wraps=engine._record_stall_if_needed,
            ) as record_stall,
        ):
            state = orchestrator.run_cycle(self.identity)

        record_stall.assert_called_once()
        self.assertEqual(len(state.receipts), 3)
        self.assertEqual(
            len(state.cycles[-1].selected_action_ids),
            3,
        )
        self.assertEqual(state.cycles[-1].phase, "completed")
        self.assertEqual(state.waves[-1].status, "completed")

    def test_worker_stop_with_empty_selection_closes_managed_session(self):
        engine = self.engine(ProbeRoleExecutor())
        self.add_v2(engine)
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        original_run_wave = engine.run_wave

        def run_wave_then_pause(*args, **kwargs):
            outcome = original_run_wave(*args, **kwargs)
            current = engine.store.load(self.identity)

            def apply(state):
                state.resume_status = state.status
                state.status = ChallengeStatus.PAUSED

            engine.store.update(
                self.identity,
                apply,
                expected_revision=current.revision,
            )
            return outcome

        with (
            mock.patch.object(
                engine,
                "run_wave",
                side_effect=run_wave_then_pause,
            ),
            mock.patch.object(
                orchestrator,
                "_select_actions",
                return_value=(),
            ),
        ):
            state = orchestrator.run_cycle(self.identity)

        self.assertIs(state.status, ChallengeStatus.PAUSED)
        self.assertIsNone(state.active_managed_session_id)
        self.assertIs(state.sessions[-1].status, SessionStatus.PAUSED)
        self.assertEqual(state.cycles[-1].phase, "completed")
        self.assertEqual(state.waves[-1].status, "completed")

    def test_managed_receipt_evidence_reaches_first_captain_safely(
        self,
    ):
        executor = ProbeRoleExecutor()

        def sandbox_factory(state, work, policy):
            del state, policy
            return ReceiptCanarySandbox(work)

        engine = self.engine(
            executor,
            sandbox_factory=sandbox_factory,
        )
        self.add_v2(engine)
        captain_context_states = []
        original_context_builder = challenge_module.build_context_pack

        def capture_captain_context(state, *args, **kwargs):
            if kwargs.get("role") == Role.CAPTAIN.value:
                captain_context_states.append(copy.deepcopy(state))
            return original_context_builder(state, *args, **kwargs)

        with mock.patch.object(
            challenge_module,
            "build_context_pack",
            side_effect=capture_captain_context,
        ):
            state = ManagedOrchestrator(
                engine,
                capability_probe=self.capability,
            ).run_cycle(self.identity)
        self.assertEqual(len(captain_context_states), 1)
        self.assertEqual(engine._managed_storage_admissions, {})

        managed_receipts = [
            receipt
            for receipt in state.receipts
            if receipt.experiment_id.startswith("E-MR-")
        ]
        self.assertEqual(len(managed_receipts), 3)
        self.assertTrue(
            all(
                receipt.outcome.value == "succeeded"
                and receipt.extra.get("semantic_authority") is False
                and receipt.extra.get("semantic_witness_available") is False
                for receipt in managed_receipts
            )
        )

        captain_prompts = [
            prompt
            for role, prompt in executor.prompts
            if role is Role.CAPTAIN
        ]
        self.assertEqual(len(captain_prompts), 1)
        self.assertIn(
            ReceiptCanarySandbox.canary,
            captain_prompts[0],
        )
        self.assertNotIn(
            ReceiptCanarySandbox.credential,
            captain_prompts[0],
        )

        paths = engine.store.challenge_paths(self.identity)
        captain_run_id = state.cycles[0].captain_run_id
        captain_paths = engine.store.run_paths(
            self.identity,
            run_id=captain_run_id,
        )
        captain_request = read_json(captain_paths.request)
        archived_context = (
            paths.root / captain_request["context_path"]
        )
        archive_text = archived_context.read_text(encoding="utf-8")
        self.assertIn(ReceiptCanarySandbox.canary, archive_text)
        self.assertNotIn(
            ReceiptCanarySandbox.credential,
            archive_text,
        )
        archive_records = [
            strict_json_loads(line)
            for line in archive_text.splitlines()
            if line
        ]
        recent_records = [
            item
            for item in archive_records
            if item.get("kind") == "recent_execution_receipt"
        ]
        self.assertEqual(len(recent_records), 3)
        recent_ids = {item["id"] for item in recent_records}
        self.assertFalse(
            any(
                item.get("kind") == "execution_receipt"
                and item.get("id") in recent_ids
                for item in archive_records
            )
        )
        for record in recent_records:
            stdout = record["streams"]["stdout"]
            self.assertIn(
                ReceiptCanarySandbox.canary,
                stdout["head"]["text"],
            )
            self.assertEqual(stdout["head"]["byte_start"], 0)
            self.assertEqual(len(stdout["sha256"]), 64)
            self.assertTrue(
                stdout["path"].startswith("artifacts/snapshots/")
            )

        final_context = build_context_pack(
            state,
            get_adapter(state.category),
            state_path=paths.state,
            max_chars=65_536,
        )
        final_records = [
            strict_json_loads(line)
            for line in final_context.text.splitlines()
            if line
        ]
        semantic_receipt_records = [
            item
            for item in final_records
            if item.get("kind") == "recent_execution_receipt"
            and "semantic_authority" in item
        ]
        self.assertTrue(semantic_receipt_records)
        self.assertTrue(
            all(
                item["semantic_authority"] is False
                and item["semantic_witness_available"] is False
                and item["semantic_evaluation_contract_version"] == 2
                for item in semantic_receipt_records
            )
        )

        receipt = state.receipts[0]
        self.assertEqual(
            receipt.extra["line_count_basis"],
            "transport_summary_tail",
        )
        stdout_evidence = receipt.extra["stream_evidence"]["stdout"]
        artifact = next(
            item
            for item in state.artifacts
            if item.id == receipt.stdout_artifact_id
        )
        snapshot = paths.root / artifact.path
        raw_output = snapshot.read_text(encoding="utf-8")
        self.assertIn(ReceiptCanarySandbox.canary, raw_output)
        self.assertIn(ReceiptCanarySandbox.credential, raw_output)
        self.assertNotIn(
            ReceiptCanarySandbox.credential,
            json.dumps(
                receipt.extra["stream_evidence"],
                sort_keys=True,
            ),
        )
        self.assertIn("[REDACTED]", stdout_evidence["head"]["text"])
        self.assertEqual(stdout_evidence["artifact_id"], artifact.id)
        self.assertEqual(stdout_evidence["path"], artifact.path)
        self.assertEqual(stdout_evidence["sha256"], artifact.sha256)
        self.assertEqual(stdout_evidence["stored_bytes"], artifact.size)
        self.assertEqual(
            hashlib.sha256(snapshot.read_bytes()).hexdigest(),
            stdout_evidence["sha256"],
        )
        self.assertEqual(stdout_evidence["head"]["byte_start"], 0)
        self.assertEqual(
            stdout_evidence["head"]["byte_end"],
            artifact.size,
        )

        pressure = build_context_pack(
            captain_context_states[0],
            get_adapter(captain_context_states[0].category),
            state_path=paths.state,
            max_chars=4096,
        )
        self.assertLessEqual(len(pressure.text), 4096)
        pressure_records = [
            strict_json_loads(line)
            for line in pressure.text.splitlines()
            if line
        ]
        pressure_receipts = [
            item
            for item in pressure_records
            if item.get("kind") == "recent_execution_receipt"
        ]
        self.assertTrue(pressure_receipts)
        self.assertTrue(
            {item["id"] for item in pressure_receipts} <= recent_ids
        )
        self.assertEqual(
            pressure_receipts[0]["id"],
            captain_context_states[0].receipts[-1].id,
        )
        newest_stdout = pressure_receipts[0]["streams"]["stdout"]
        self.assertIn(
            ReceiptCanarySandbox.canary,
            newest_stdout["head"]["text"],
        )
        self.assertTrue(newest_stdout["path"])
        self.assertEqual(len(newest_stdout["sha256"]), 64)

        tampered_path = copy.deepcopy(state)
        tampered_path.receipts[0].extra["stream_evidence"]["stdout"][
            "path"
        ] = "artifacts/snapshots/tampered.log"
        with self.assertRaisesRegex(
            ModelValidationError,
            "path does not match",
        ):
            tampered_path.validate()

        tampered_hash = copy.deepcopy(state)
        tampered_hash.receipts[0].extra["stream_evidence"]["stdout"][
            "sha256"
        ] = "0" * 64
        with self.assertRaisesRegex(
            ModelValidationError,
            "SHA-256 does not match",
        ):
            tampered_hash.validate()

        tampered_size = copy.deepcopy(state)
        tampered_size.receipts[0].extra["stream_evidence"]["stdout"][
            "stored_bytes"
        ] += 1
        with self.assertRaisesRegex(
            ModelValidationError,
            "size does not match",
        ):
            tampered_size.validate()

        tampered_schema = copy.deepcopy(state)
        tampered_schema.receipts[0].extra["stream_evidence"]["stdout"][
            "unexpected"
        ] = True
        with self.assertRaisesRegex(
            ModelValidationError,
            "invalid nested schema",
        ):
            tampered_schema.validate()

        tampered_range = copy.deepcopy(state)
        tampered_stdout = tampered_range.receipts[0].extra[
            "stream_evidence"
        ]["stdout"]
        tampered_stdout["head"]["byte_end"] = (
            tampered_stdout["stored_bytes"] + 1
        )
        with self.assertRaisesRegex(
            ModelValidationError,
            "invalid byte range",
        ):
            tampered_range.validate()

        tampered_truncation = copy.deepcopy(state)
        tampered_stdout = tampered_truncation.receipts[0].extra[
            "stream_evidence"
        ]["stdout"]
        tampered_stdout["truncated"] = True
        with self.assertRaisesRegex(
            ModelValidationError,
            "truncation value is inconsistent",
        ):
            tampered_truncation.validate()

    def test_managed_storage_admission_covers_failure_request_snapshot(self):
        engine = self.engine(ProbeRoleExecutor())
        self.add_v2(engine)
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        _state, session_id = orchestrator._reserve_session(
            self.identity,
            "S-failure-request-admission",
        )
        state = engine.synchronize_managed_adapter_seed_plan(
            self.identity,
            session_id,
        )
        selected = tuple(
            item.id
            for item in state.experiments
            if (
                item.extra.get("adapter_seed") is True
                and item.status is ExperimentStatus.REGISTERED
            )
        )
        self.assertEqual(len(selected), 3)

        admitted: list[int] = []

        def capture_admission(_identity, *, requested_bytes=None):
            self.assertIsNotNone(requested_bytes)
            admitted.append(requested_bytes)
            return {}

        with mock.patch.object(
            engine,
            "_enforce_storage_admission",
            side_effect=capture_admission,
        ):
            reservation = engine._admit_managed_tool_action_batch_storage(
                self.identity,
                experiment_ids=selected,
            )
        try:
            per_stream_limit = min(
                challenge_module.DEFAULT_STREAM_CAPTURE_MAX_BYTES,
                engine.config.runtime.work_tree_max_bytes // 4,
            )
            expected_without_failure_snapshots = len(selected) * (
                engine.config.runtime.work_tree_max_bytes
                + 2 * per_stream_limit
                + 6 * challenge_module.MAX_RUN_DOCUMENT_BYTES
            )
            current = engine.store.load(self.identity, recover=False)
            registered = {item.id: item for item in current.experiments}
            for experiment_id in selected:
                experiment = registered[experiment_id]
                if (
                    experiment.extra.get("adapter_seed") is True
                    and experiment.extra.get("adapter_name") == "reversing"
                ):
                    expected_without_failure_snapshots += (
                        challenge_module.REV_INVENTORY_V2_MAX_SOURCE_BYTES
                    )
                if engine._is_forensic_index_experiment(current, experiment):
                    expected_without_failure_snapshots += (
                        challenge_module.FORENSIC_INDEX_MAX_BYTES
                    )
            self.assertEqual(admitted, [reservation.requested_bytes])
            self.assertEqual(
                reservation.requested_bytes
                - expected_without_failure_snapshots,
                len(selected)
                * challenge_module._FAILURE_TOOL_REQUEST_SNAPSHOT_MAX_BYTES,
            )
        finally:
            engine._release_managed_tool_action_batch_storage(reservation)

        run_id = "R-failure-request-admission"
        experiment_id = selected[0]
        base_revision = engine.store.load(self.identity).revision
        engine.store.create_run(
            self.identity,
            run_id=run_id,
            request={
                "kind": "tool",
                "experiment_id": experiment_id,
            },
            base_revision=base_revision,
        )
        copy_arguments: list[dict[str, object]] = []
        original_copy = challenge_module.copy_bounded_regular

        def capture_copy(*args, **kwargs):
            copy_arguments.append(dict(kwargs))
            return original_copy(*args, **kwargs)

        with mock.patch.object(
            challenge_module,
            "copy_bounded_regular",
            side_effect=capture_copy,
        ):
            request = engine._failure_tool_request(
                self.identity,
                experiment_id,
                run_id,
                storage_pre_admitted=True,
            )
        self.assertIsNotNone(request)
        self.assertEqual(len(copy_arguments), 1)
        self.assertEqual(
            copy_arguments[0]["maximum_bytes"],
            challenge_module._FAILURE_TOOL_REQUEST_SNAPSHOT_MAX_BYTES,
        )
        self.assertIsNone(copy_arguments[0]["source_size_admission"])

    def test_attack_route_with_insufficient_frontier_creates_repair_checkpoint(
        self,
    ):
        executor = ProbeRoleExecutor(captain_hypothesis_count=2)
        engine = self.engine(executor)
        self.add_v2(engine)

        state = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        ).run_cycle(self.identity)

        self.assertNotEqual(state.status, ChallengeStatus.NEEDS_HUMAN)
        self.assertIsNotNone(state.active_managed_session_id)
        self.assertEqual(len(state.waves), 0)
        self.assertEqual(len(state.hypotheses), 2)
        self.assertEqual(len(state.checkpoints), 1)
        capsule = state.checkpoints[-1].failure_capsule
        self.assertIsNotNone(capsule)
        assert capsule is not None
        self.assertEqual(capsule.reason_code, "frontier_routing_invalid")
        self.assertEqual(capsule.stage, "captain")
        self.assertEqual(capsule.state_revision_after, state.revision)
        self.assertLessEqual(
            capsule.state_revision_before,
            capsule.state_revision_after,
        )
        self.assertEqual(len(capsule.fingerprint_sha256), 64)
        self.assertIn(
            "only 2 distinct complete active hypotheses",
            state.checkpoints[-1].note,
        )
        captain = next(
            run for run in state.runs if run.role == Role.CAPTAIN.value
        )
        self.assertEqual(captain.status, RunStatus.COMPLETED)
        self.assertIn("rejected_decisions", captain.extra)

    def test_run_cycles_pauses_after_timed_out_captain_exhausts_budget(
        self,
    ) -> None:
        class CaptainTimeoutExecutor(ProbeRoleExecutor):
            def run(
                inner_self,
                command,
                *,
                cwd,
                timeout,
                on_stdout_line,
            ):
                outcome = super().run(
                    command,
                    cwd=cwd,
                    timeout=timeout,
                    on_stdout_line=on_stdout_line,
                )
                if _role_for(command) is Role.CAPTAIN:
                    return replace(
                        outcome,
                        returncode=124,
                        timed_out=True,
                    )
                return outcome

        executor = CaptainTimeoutExecutor()
        engine = self.engine(executor)
        self.add_v2(engine)
        engine.reset_budget(self.identity, 3_600)
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        _state, session_id = orchestrator._reserve_session(
            self.identity,
            None,
        )
        _state, cycle = orchestrator._reserve_cycle(
            self.identity,
            session_id,
        )
        captain = engine.run_role(
            self.identity,
            Role.CAPTAIN,
            prefix="managed-timeout-captain",
            instruction="produce one bounded routing decision",
            _session_owned=True,
            _automated=True,
            _reserved_run_id=cycle.captain_run_id,
            _managed_workspace=True,
        )
        self.assertFalse(captain.completed)
        checkpointed = orchestrator._checkpoint_invalid_cycle(
            self.identity,
            session_id,
            cycle.id,
            reason_code="captain_contract_invalid",
            reason="Captain result was not contract-valid",
            note=None,
        )

        def exhaust_budget(state):
            state.budget.spent_seconds = state.budget.allocated_seconds

        engine.store.update(
            self.identity,
            exhaust_budget,
            expected_revision=checkpointed.revision,
        )
        state = orchestrator.run_cycles(
            self.identity,
            max_cycles=1,
            session_id=session_id,
        )

        self.assertIs(state.status, ChallengeStatus.PAUSED)
        self.assertIsNone(state.active_managed_session_id)
        self.assertEqual(len(state.cycles), 1)
        self.assertEqual(len(state.checkpoints), 1)
        timed_out_captain = next(
            item
            for item in state.runs
            if item.id == cycle.captain_run_id
        )
        self.assertIs(timed_out_captain.status, RunStatus.TIMED_OUT)
        self.assertIsNotNone(timed_out_captain.result_path)
        self.assertIsNotNone(timed_out_captain.validation_path)
        self.assertTrue(
            (
                engine.store.challenge_paths(self.identity).root
                / str(timed_out_captain.result_path)
            ).is_file()
        )
        self.assertTrue(
            (
                engine.store.challenge_paths(self.identity).root
                / str(timed_out_captain.validation_path)
            ).is_file()
        )
        session = state.sessions[-1]
        self.assertIs(session.status, SessionStatus.PAUSED)
        self.assertIn(
            "challenge wall-clock budget is exhausted",
            session.stop_reason or "",
        )
        self.assertEqual(state.submissions, [])
        state.validate()

    def test_run_cycle_checkpoints_captain_timeout_before_contract_error(
        self,
    ) -> None:
        class CaptainTimeoutExecutor(ProbeRoleExecutor):
            def run(
                inner_self,
                command,
                *,
                cwd,
                timeout,
                on_stdout_line,
            ):
                outcome = super().run(
                    command,
                    cwd=cwd,
                    timeout=timeout,
                    on_stdout_line=on_stdout_line,
                )
                if _role_for(command) is Role.CAPTAIN:
                    return replace(
                        outcome,
                        returncode=124,
                        timed_out=True,
                    )
                return outcome

        engine = self.engine(CaptainTimeoutExecutor())
        self.add_v2(engine)

        state = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        ).run_cycle(self.identity)

        captain = next(
            run for run in state.runs if run.role == Role.CAPTAIN.value
        )
        self.assertIs(captain.status, RunStatus.TIMED_OUT)
        self.assertEqual(len(state.waves), 0)
        capsule = state.checkpoints[-1].failure_capsule
        self.assertIsNotNone(capsule)
        assert capsule is not None
        self.assertEqual(capsule.reason_code, "captain_timed_out")
        self.assertNotEqual(
            capsule.reason_code,
            "captain_contract_invalid",
        )
        self.assertIn("timed out", state.checkpoints[-1].note or "")
        state.validate()

    def test_run_cycle_prioritizes_challenge_budget_expiry_for_captain(
        self,
    ) -> None:
        class CaptainTimeoutExecutor(ProbeRoleExecutor):
            def run(
                inner_self,
                command,
                *,
                cwd,
                timeout,
                on_stdout_line,
            ):
                outcome = super().run(
                    command,
                    cwd=cwd,
                    timeout=timeout,
                    on_stdout_line=on_stdout_line,
                )
                if _role_for(command) is Role.CAPTAIN:
                    return replace(
                        outcome,
                        returncode=124,
                        timed_out=True,
                    )
                return outcome

        engine = self.engine(CaptainTimeoutExecutor())
        self.add_v2(engine)
        real_run = engine.batch_runner.run

        def inject_budget_expiry(invocation, **kwargs):
            result = real_run(invocation, **kwargs)
            if invocation.role is not Role.CAPTAIN:
                return result
            self.assertTrue(result.failures)
            return replace(
                result,
                failures=(
                    *result.failures,
                    replace(
                        result.failures[-1],
                        kind="challenge_budget_expired",
                        message=(
                            "challenge wall-clock budget expired during "
                            "the provider call"
                        ),
                        retryable=False,
                    ),
                ),
            )

        with mock.patch.object(
            engine.batch_runner,
            "run",
            side_effect=inject_budget_expiry,
        ):
            state = ManagedOrchestrator(
                engine,
                capability_probe=self.capability,
            ).run_cycle(self.identity)

        captain = next(
            run for run in state.runs if run.role == Role.CAPTAIN.value
        )
        self.assertIs(captain.status, RunStatus.TIMED_OUT)
        capsule = state.checkpoints[-1].failure_capsule
        self.assertIsNotNone(capsule)
        assert capsule is not None
        self.assertEqual(
            capsule.reason_code,
            "challenge_budget_expired",
        )
        self.assertNotEqual(
            capsule.reason_code,
            "captain_contract_invalid",
        )
        self.assertIn(
            "wall-clock budget expired",
            state.checkpoints[-1].note or "",
        )
        state.validate()

    def test_invalid_role_preserves_valid_sibling_evidence_without_full_merge(
        self,
    ):
        executor = ProbeRoleExecutor(invalid_role=Role.FALSIFIER)
        engine = self.engine(executor)
        self.add_v2(engine)
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        state = orchestrator.run_cycle(self.identity)

        self.assertNotEqual(state.status, ChallengeStatus.NEEDS_HUMAN)
        self.assertIsNotNone(state.active_managed_session_id)
        self.assertEqual(len(state.checkpoints), 1)
        capsule = state.checkpoints[-1].failure_capsule
        self.assertIsNotNone(capsule)
        assert capsule is not None
        self.assertEqual(capsule.reason_code, "analysis_wave_invalid")
        self.assertEqual(capsule.stage, "attack")
        self.assertEqual(capsule.state_revision_after, state.revision)
        self.assertIn(
            "analysis wave was invalid",
            state.checkpoints[-1].note,
        )
        self.assertNotIn(
            "cannot snapshot reported artifact",
            state.checkpoints[-1].note,
        )
        wave = state.waves[0]
        self.assertEqual(wave.status, "invalid")
        wave_run_ids = set(wave.role_run_ids.values())
        self.assertEqual(
            len([run for run in state.runs if run.id in wave_run_ids]),
            3,
        )
        self.assertTrue(
            all(
                run.extra.get("provisional_wave_output") is True
                for run in state.runs
                if run.id in wave_run_ids
            )
        )
        wave_runs = {
            run.id: run for run in state.runs if run.id in wave_run_ids
        }
        valid_sibling_ids = {
            run.id
            for run in wave_runs.values()
            if run.status is RunStatus.COMPLETED
        }
        invalid_run_ids = wave_run_ids - valid_sibling_ids
        self.assertTrue(valid_sibling_ids)
        self.assertEqual(len(invalid_run_ids), 1)
        failed_run = wave_runs[next(iter(invalid_run_ids))]
        self.assertEqual(
            failed_run.extra["managed_rejection_v1"]["issues"],
            [
                {
                    "code": "reported_artifact_unavailable",
                    "kind": "reported_artifact",
                    "pointer": "/artifacts/0/path",
                }
            ],
        )
        self.assertEqual(
            {
                run.id
                for run in wave_runs.values()
                if run.extra.get("partial_semantic_merge") is True
            },
            valid_sibling_ids,
        )
        self.assertTrue(
            all(
                run.extra.get("semantic_merge") is False
                for run in wave_runs.values()
            )
        )
        self.assertEqual(
            {
                fact.source_run_id
                for fact in state.facts
                if fact.source_run_id in wave_run_ids
            },
            valid_sibling_ids,
        )
        self.assertFalse(
            any(
                fact.source_run_id in invalid_run_ids
                for fact in state.facts
            )
        )
        self.assertFalse(
            any(
                hypothesis.source_run_id in wave_run_ids
                for hypothesis in state.hypotheses
            )
        )
        self.assertFalse(
            any(
                experiment.source_run_id in wave_run_ids
                for experiment in state.experiments
            )
        )
        self.assertIn(
            "KCTF{provisional_wave}",
            {candidate.value for candidate in state.candidates},
        )

    def test_empty_command_rejection_reenters_next_cycle_as_typed_pointer(
        self,
    ):
        executor = ProbeRoleExecutor(
            invalid_command_role=Role.BUILDER,
        )
        engine = self.engine(executor)
        self.add_v2(engine)
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )

        first = orchestrator.run_cycle(self.identity)
        capsule = first.checkpoints[-1].failure_capsule
        self.assertIsNotNone(capsule)
        assert capsule is not None
        builder = next(
            run
            for run in first.runs
            if run.id in capsule.run_ids
            and run.role == Role.BUILDER.value
        )
        self.assertEqual(builder.status, RunStatus.INVALID)
        self.assertEqual(
            builder.extra["managed_rejection_v1"]["issues"],
            [
                {
                    "code": "required_text_missing",
                    "kind": "role_output",
                    "pointer": "/actions/0/command",
                }
            ],
        )
        tampered = copy.deepcopy(first)
        tampered_builder = next(
            run for run in tampered.runs if run.id == builder.id
        )
        tampered_builder.extra["managed_rejection_v1"]["issues"][0][
            "pointer"
        ] = "/FLAG_secret"
        with self.assertRaisesRegex(
            ModelValidationError,
            "invalid managed rejection",
        ):
            build_context_pack(
                tampered,
                get_adapter(tampered.category),
                state_path=engine.store.challenge_paths(
                    self.identity
                ).state,
            )
        pressure_capsule = render_resume_capsule(
            first,
            state_path=engine.store.challenge_paths(
                self.identity
            ).state,
            policy=ResumeCapsulePolicy(max_bytes=1536),
        )
        self.assertIn("required_text_missing", pressure_capsule.text)
        self.assertIn("/actions/0/command", pressure_capsule.text)

        executor.invalid_command_role = None
        orchestrator.run_cycle(self.identity)
        next_prompt = [
            prompt
            for role, prompt in executor.prompts
            if role is Role.CAPTAIN
        ][-1]
        self.assertIn("required_text_missing", next_prompt)
        self.assertIn("/actions/0/command", next_prompt)
        self.assertNotIn("command action requires text", next_prompt)

    def test_failure_capsule_reenters_next_cycle_without_raw_failure_text(
        self,
    ):
        executor = ProbeRoleExecutor(invalid_role=Role.FALSIFIER)
        engine = self.engine(executor)
        self.add_v2(engine)
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        raw_contract = "RAW-CONTRACT-CANARY"
        raw_normalization = "RAW-NORMALIZATION-CANARY"
        raw_failure = "RAW-FAILURE-CANARY"
        operator_canary = "RAW-OPERATOR-NOTE-CANARY"
        original_checkpoint_invalid = (
            orchestrator._checkpoint_invalid_cycle
        )
        injected = False

        def checkpoint_with_raw_diagnostics(
            identity,
            session_id,
            cycle_id,
            *,
            reason_code,
            reason,
            note,
        ):
            nonlocal injected
            if not injected:
                current = engine.store.load(identity)

                def add_raw_diagnostics(state):
                    failed_run = next(
                        run
                        for run in state.runs
                        if run.cycle_id == cycle_id
                        and run.role == Role.FALSIFIER.value
                    )
                    failed_run.extra["contract_errors"] = [
                        raw_contract
                    ]
                    failed_run.extra[
                        "normalization_error"
                    ] = raw_normalization
                    failed_run.extra["failures"] = [
                        {
                            "kind": "synthetic_failure",
                            "message": raw_failure,
                            "retryable": False,
                        }
                    ]

                engine.store.update(
                    identity,
                    add_raw_diagnostics,
                    expected_revision=current.revision,
                )
                injected = True
            return original_checkpoint_invalid(
                identity,
                session_id,
                cycle_id,
                reason_code=reason_code,
                reason=reason,
                note=note,
            )

        with mock.patch.object(
            orchestrator,
            "_checkpoint_invalid_cycle",
            side_effect=checkpoint_with_raw_diagnostics,
        ):
            first = orchestrator.run_cycle(
                self.identity,
                note=operator_canary,
            )

        capsule = first.checkpoints[-1].failure_capsule
        self.assertIsNotNone(capsule)
        assert capsule is not None
        self.assertEqual(capsule.reason_code, "analysis_wave_invalid")
        self.assertEqual(capsule.stage, "attack")
        self.assertEqual(capsule.state_revision_after, first.revision)
        failed_run = next(
            run
            for run in first.runs
            if run.id in capsule.run_ids
            and run.role == Role.FALSIFIER.value
        )
        self.assertIsNotNone(failed_run.validation_path)
        self.assertNotIn(raw_contract, first.checkpoints[-1].note or "")
        self.assertNotIn(
            raw_normalization,
            first.checkpoints[-1].note or "",
        )
        self.assertNotIn(raw_failure, first.checkpoints[-1].note or "")
        self.assertIn(operator_canary, first.checkpoints[-1].note or "")

        executor.invalid_role = None
        orchestrator.run_cycle(self.identity)
        captain_prompts = [
            prompt
            for role, prompt in executor.prompts
            if role is Role.CAPTAIN
        ]
        self.assertGreaterEqual(len(captain_prompts), 2)
        next_prompt = captain_prompts[-1]
        self.assertIn(capsule.reason_code, next_prompt)
        self.assertIn(capsule.fingerprint_sha256, next_prompt)
        self.assertIn(str(failed_run.validation_path), next_prompt)
        self.assertIn("reported_artifact_unavailable", next_prompt)
        self.assertIn("/artifacts/0/path", next_prompt)
        for canary in (
            raw_contract,
            raw_normalization,
            raw_failure,
            operator_canary,
        ):
            self.assertNotIn(canary, next_prompt)

    def test_failure_checkpoint_rejects_intervening_state_update(self):
        engine = self.engine(ProbeRoleExecutor())
        self.add_v2(engine)
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        _state, session_id = orchestrator._reserve_session(
            self.identity,
            None,
        )
        before, cycle = orchestrator._reserve_cycle(
            self.identity,
            session_id,
        )
        real_builder = managed_module.build_failure_capsule

        def build_after_intervening_update(current, **kwargs):
            capsule = real_builder(current, **kwargs)
            engine.store.update(
                self.identity,
                lambda _state: None,
                expected_revision=current.revision,
            )
            return capsule

        with mock.patch(
            "ctf_os.managed.build_failure_capsule",
            side_effect=build_after_intervening_update,
        ):
            with self.assertRaises(RevisionConflict):
                orchestrator._checkpoint(
                    self.identity,
                    session_id,
                    cycle.id,
                    note="race regression",
                    failure_reason_code="captain_contract_invalid",
                    failure_stage="captain",
                )

        after = engine.store.load(self.identity)
        self.assertEqual(after.revision, before.revision + 1)
        self.assertEqual(after.checkpoints, [])
        self.assertIsNone(
            next(
                item for item in after.cycles if item.id == cycle.id
            ).checkpoint_id
        )

    def test_failure_checkpoint_rejects_mismatched_capsule_revision(self):
        engine = self.engine(ProbeRoleExecutor())
        self.add_v2(engine)
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        _state, session_id = orchestrator._reserve_session(
            self.identity,
            None,
        )
        before, cycle = orchestrator._reserve_cycle(
            self.identity,
            session_id,
        )
        real_builder = managed_module.build_failure_capsule

        def build_with_stale_revision(current, **kwargs):
            capsule = real_builder(current, **kwargs)
            return replace(
                capsule,
                state_revision_after=current.revision,
            )

        with mock.patch(
            "ctf_os.managed.build_failure_capsule",
            side_effect=build_with_stale_revision,
        ):
            with self.assertRaisesRegex(
                ManagedError,
                "does not bind the pending checkpoint revision",
            ):
                orchestrator._checkpoint(
                    self.identity,
                    session_id,
                    cycle.id,
                    note="stale capsule regression",
                    failure_reason_code="captain_contract_invalid",
                    failure_stage="captain",
                )

        after = engine.store.load(self.identity)
        self.assertEqual(after.revision, before.revision)
        self.assertEqual(after.checkpoints, [])

    def test_managed_source_artifact_reference_does_not_invalidate_wave(
        self,
    ):
        executor = ProbeRoleExecutor(source_reference_role=Role.FALSIFIER)
        engine = self.engine(executor)
        self.add_v2(engine)

        state = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        ).run_cycle(self.identity)

        falsifier = next(
            run
            for run in state.runs
            if run.role == Role.FALSIFIER.value
        )
        self.assertEqual(falsifier.status, RunStatus.COMPLETED)
        self.assertEqual(
            falsifier.extra["source_references"],
            [
                {
                    "path": "challenge.bin",
                    "sha256": hashlib.sha256(
                        b"\x7fELFmanaged"
                    ).hexdigest(),
                    "size": len(b"\x7fELFmanaged"),
                    "purpose": "canonical source reference",
                    "kind": "immutable_challenge_input",
                }
            ],
        )
        self.assertFalse(
            any(
                artifact.source_run_id == falsifier.id
                for artifact in state.artifacts
            )
        )

    def test_managed_exact_canonical_artifact_reference_is_non_owning(
        self,
    ):
        executor = CanonicalArtifactEchoExecutor(
            path=CANONICAL_REFERENCE_PATH,
            sha256=CANONICAL_REFERENCE_SHA256,
        )
        engine = self.engine(executor)
        self.add_v2(engine)
        reference = self.seed_canonical_artifact(engine)

        state = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        ).run_cycle(self.identity)

        captain = next(
            run
            for run in state.runs
            if run.role == Role.CAPTAIN.value
        )
        self.assertEqual(captain.status, RunStatus.COMPLETED)
        self.assertEqual(
            captain.extra["source_references"],
            [
                {
                    "artifact_id": reference.id,
                    "path": reference.path,
                    "sha256": reference.sha256,
                    "size": reference.size,
                    "source_run_id": None,
                    "purpose": "existing canonical evidence",
                    "kind": "canonical_artifact",
                }
            ],
        )
        self.assertEqual(
            [
                artifact.id
                for artifact in state.artifacts
                if artifact.path == reference.path
            ],
            [reference.id],
        )
        self.assertFalse(
            any(
                artifact.source_run_id == captain.id
                for artifact in state.artifacts
            )
        )
        self.assertEqual(len(state.waves), 1)

    def test_managed_mismatched_canonical_artifact_reference_checkpoints_captain(
        self,
    ):
        executor = CanonicalArtifactEchoExecutor(
            path=CANONICAL_REFERENCE_PATH,
            sha256="0" * 64,
        )
        engine = self.engine(executor)
        self.add_v2(engine)
        self.seed_canonical_artifact(engine)

        state = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        ).run_cycle(self.identity)

        captain = next(
            run
            for run in state.runs
            if run.role == Role.CAPTAIN.value
        )
        self.assertEqual(captain.status, RunStatus.INVALID)
        self.assertFalse(captain.extra["contract_valid"])
        self.assertIn(
            "outside the captain workspace",
            str(captain.extra["normalization_error"]),
        )
        self.assertEqual(len(state.waves), 0)
        self.assertNotEqual(state.status, ChallengeStatus.NEEDS_HUMAN)
        self.assertEqual(state.sessions[-1].status, SessionStatus.RUNNING)
        self.assertIsNotNone(state.cycles[-1].checkpoint_id)
        capsule = state.checkpoints[-1].failure_capsule
        self.assertIsNotNone(capsule)
        assert capsule is not None
        self.assertEqual(
            capsule.reason_code,
            "captain_contract_invalid",
        )

    def test_deadline_expiry_recomputes_provisional_contract_valid(self):
        engine = self.engine(ProbeRoleExecutor())
        self.add_v2(engine)
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        state, session_id = orchestrator._reserve_session(
            self.identity,
            None,
        )
        state, cycle = orchestrator._reserve_cycle(
            self.identity,
            session_id,
        )
        assert cycle.captain_run_id is not None
        invocation = engine._make_invocation(
            state,
            Role.CAPTAIN,
            prefix="captain",
            instruction="return one contract-valid managed result",
            deadline_monotonic_seconds=time.monotonic() + 60,
            deadline_epoch_seconds=time.time() + 60,
            run_id=cycle.captain_run_id,
            managed_workspace=True,
        )
        result = engine.batch_runner.run(invocation)
        self.assertTrue(result.completed)
        self.assertTrue(result.validation.valid)
        expired = replace(
            result,
            deadline_monotonic_seconds=time.monotonic() - 1,
        )

        provisional = engine._persist_reserved_run_terminal(
            self.identity,
            expired,
        )
        provisional_run = next(
            run
            for run in provisional.runs
            if run.id == cycle.captain_run_id
        )
        self.assertTrue(provisional_run.extra["contract_valid"])

        committed = engine._commit_batch_results(
            provisional,
            (expired,),
            semantic_barrier=True,
        )
        final_run = next(
            run
            for run in committed.runs
            if run.id == cycle.captain_run_id
        )
        self.assertIs(final_run.status, RunStatus.TIMED_OUT)
        self.assertFalse(final_run.extra["contract_valid"])
        validation = read_json(
            engine.store.challenge_paths(self.identity).root
            / str(final_run.validation_path)
        )
        self.assertFalse(validation["ok"])
        challenge_root = engine.store.challenge_paths(self.identity).root
        self.assertEqual(
            final_run.extra["result_sha256"],
            sha256_file(challenge_root / str(final_run.result_path)),
        )
        self.assertEqual(
            final_run.extra["validation_sha256"],
            sha256_file(challenge_root / str(final_run.validation_path)),
        )

    def test_terminal_provider_retry_preserves_not_started_marker(self):
        engine = self.engine(ProbeRoleExecutor())
        self.add_v2(engine)
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        state, session_id = orchestrator._reserve_session(
            self.identity,
            None,
        )
        state, cycle = orchestrator._reserve_cycle(
            self.identity,
            session_id,
        )
        assert cycle.captain_run_id is not None
        invocation = engine._make_invocation(
            state,
            Role.CAPTAIN,
            prefix="captain",
            instruction="return one contract-valid managed result",
            deadline_monotonic_seconds=time.monotonic() + 60,
            deadline_epoch_seconds=time.time() + 60,
            run_id=cycle.captain_run_id,
            managed_workspace=True,
        )
        result = engine.batch_runner.run(invocation)
        provider_path = (
            engine.store.run_paths(
                self.identity,
                run_id=cycle.captain_run_id,
            ).root
            / "provider.json"
        )
        run_paths = engine.store.run_paths(
            self.identity,
            run_id=cycle.captain_run_id,
        )
        with (
            mock.patch(
                "ctf_os.engine.challenge.utc_now",
                return_value="2026-08-03T00:00:00Z",
            ),
            mock.patch(
                "ctf_os.store.files.utc_now",
                return_value="2026-08-03T00:00:00Z",
            ),
            mock.patch.object(
                engine.store,
                "update",
                side_effect=RevisionConflict(1, 2),
            ),
            self.assertRaises(RevisionConflict),
        ):
            engine._persist_reserved_run_terminal(self.identity, result)

        first_provider = read_json(provider_path)
        first_hashes = {
            "result": sha256_file(run_paths.result),
            "validation": sha256_file(run_paths.validation),
        }
        first_result = read_json(run_paths.result)
        corrupt_result = dict(first_result)
        corrupt_result["schema_version"] = True
        atomic_write_json(run_paths.result, corrupt_result)
        with self.assertRaisesRegex(
            EngineError,
            "provisional result retry mismatch",
        ):
            engine._persist_reserved_run_terminal(self.identity, result)
        atomic_write_json(run_paths.result, first_result)
        with (
            mock.patch(
                "ctf_os.engine.challenge.utc_now",
                return_value="2026-08-03T00:00:01Z",
            ),
            mock.patch(
                "ctf_os.store.files.utc_now",
                return_value="2026-08-03T00:00:01Z",
            ),
        ):
            committed = engine._persist_reserved_run_terminal(
                self.identity,
                result,
            )

        provider = read_json(provider_path)
        self.assertFalse(provider["provider_started"])
        self.assertEqual(provider["status"], "completed")
        self.assertEqual(
            provider["finished_at"],
            first_provider["finished_at"],
        )
        self.assertEqual(
            sha256_file(run_paths.result),
            first_hashes["result"],
        )
        self.assertEqual(
            sha256_file(run_paths.validation),
            first_hashes["validation"],
        )
        terminal_run = next(
            item
            for item in committed.runs
            if item.id == cycle.captain_run_id
        )
        self.assertEqual(
            terminal_run.extra["provider_completed_at"],
            first_provider["finished_at"],
        )

    def test_terminal_provider_rejects_corrupt_identity_and_start_marker(self):
        engine = self.engine(ProbeRoleExecutor())
        self.add_v2(engine)
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        state, session_id = orchestrator._reserve_session(
            self.identity,
            None,
        )
        state, cycle = orchestrator._reserve_cycle(
            self.identity,
            session_id,
        )
        assert cycle.captain_run_id is not None
        invocation = engine._make_invocation(
            state,
            Role.CAPTAIN,
            prefix="captain",
            instruction="return one contract-valid managed result",
            deadline_monotonic_seconds=time.monotonic() + 60,
            deadline_epoch_seconds=time.time() + 60,
            run_id=cycle.captain_run_id,
            managed_workspace=True,
        )
        result = engine.batch_runner.run(invocation)
        run_paths = engine.store.run_paths(
            self.identity,
            run_id=cycle.captain_run_id,
        )
        provider_path = run_paths.root / "provider.json"

        request_record = read_json(run_paths.request)
        corrupted_request = dict(request_record)
        corrupted_request["contest_id"] = "EVIL"
        corrupted_request["base_revision"] = (
            state.revision + 999
        )
        atomic_write_json(run_paths.request, corrupted_request)
        with self.assertRaisesRegex(
            EngineError,
            "request record binding mismatch",
        ):
            engine._persist_reserved_run_terminal(self.identity, result)
        atomic_write_json(run_paths.request, request_record)

        atomic_write_json(
            provider_path,
            {
                "schema_version": True,
                "status": "running",
                "run_id": cycle.captain_run_id,
                "configuration_epoch": state.configuration_epoch,
                "started_at": "2026-08-03T00:00:00Z",
            },
        )
        with self.assertRaisesRegex(EngineError, "schema version is invalid"):
            engine._persist_reserved_run_terminal(self.identity, result)

        atomic_write_json(
            provider_path,
            {
                "status": "running",
                "run_id": "MR-WRONG",
                "configuration_epoch": state.configuration_epoch,
                "started_at": "2026-08-03T00:00:00Z",
            },
        )
        with self.assertRaisesRegex(EngineError, "run id mismatch"):
            engine._persist_reserved_run_terminal(self.identity, result)

        atomic_write_json(
            provider_path,
            {
                "status": "running",
                "run_id": cycle.captain_run_id,
                "configuration_epoch": state.configuration_epoch + 1,
                "started_at": "2026-08-03T00:00:00Z",
            },
        )
        with self.assertRaisesRegex(
            EngineError,
            "configuration epoch mismatch",
        ):
            engine._persist_reserved_run_terminal(self.identity, result)

        atomic_write_json(
            provider_path,
            {
                "schema_version": 1,
                "status": "running",
                "run_id": cycle.captain_run_id,
                "configuration_epoch": state.configuration_epoch,
                "started_at": None,
                "provider_started": True,
            },
        )
        with self.assertRaisesRegex(EngineError, "start binding is invalid"):
            engine._persist_reserved_run_terminal(self.identity, result)

        atomic_write_json(
            provider_path,
            {
                "status": "running",
                "run_id": cycle.captain_run_id,
                "configuration_epoch": state.configuration_epoch,
                "started_at": "2026-08-03T00:00:00Z",
                "provider_started": "false",
            },
        )
        with self.assertRaisesRegex(EngineError, "start marker is invalid"):
            engine._persist_reserved_run_terminal(self.identity, result)

        current = engine.store.load(self.identity)
        run = next(
            item
            for item in current.runs
            if item.id == cycle.captain_run_id
        )
        self.assertIs(run.status, RunStatus.CREATED)

    def test_terminal_provider_sidecar_binds_stale_reserved_epoch(self):
        engine = self.engine(ProbeRoleExecutor())
        self.add_v2(engine)
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        state, session_id = orchestrator._reserve_session(
            self.identity,
            None,
        )
        state, cycle = orchestrator._reserve_cycle(
            self.identity,
            session_id,
        )
        assert cycle.captain_run_id is not None
        invocation = engine._make_invocation(
            state,
            Role.CAPTAIN,
            prefix="captain",
            instruction="return one contract-valid managed result",
            deadline_monotonic_seconds=time.monotonic() + 60,
            deadline_epoch_seconds=time.time() + 60,
            run_id=cycle.captain_run_id,
            managed_workspace=True,
        )
        result = engine.batch_runner.run(invocation)
        engine.add_network_target(
            self.identity,
            "https://managed-epoch-bump.example:443",
            docker_network="ctfos-test-proxy",
            enforcement="proxy",
        )
        with (
            mock.patch.object(
                engine.store,
                "update",
                side_effect=RevisionConflict(1, 2),
            ),
            self.assertRaises(RevisionConflict),
        ):
            engine._persist_reserved_run_terminal(self.identity, result)

        provider_path = (
            engine.store.run_paths(
                self.identity,
                run_id=cycle.captain_run_id,
            ).root
            / "provider.json"
        )
        provider = read_json(provider_path)
        self.assertEqual(
            provider["configuration_epoch"],
            state.configuration_epoch,
        )
        recovered = orchestrator.reconcile(self.identity)
        run = next(
            item
            for item in recovered.runs
            if item.id == cycle.captain_run_id
        )
        self.assertIs(run.status, RunStatus.INTERRUPTED)

    def test_all_terminal_wave_runs_become_ready_to_reduce(self):
        engine = self.engine(ProbeRoleExecutor())
        self.add_v2(engine)
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        state, session_id = orchestrator._reserve_session(
            self.identity,
            None,
        )
        state, cycle = orchestrator._reserve_cycle(
            self.identity,
            session_id,
        )
        state, wave, role_runs = orchestrator._reserve_wave(
            self.identity,
            session_id,
            cycle.id,
            "discovery",
        )
        invocations = [
            engine._make_invocation(
                state,
                Role(role_name),
                prefix=role_name,
                instruction="return one contract-valid managed result",
                deadline_monotonic_seconds=time.monotonic() + 60,
                deadline_epoch_seconds=time.time() + 60,
                run_id=run_id,
                managed_workspace=True,
            )
            for role_name, run_id in role_runs.items()
        ]
        for invocation in invocations:
            result = engine.batch_runner.run(invocation)
            state = engine._persist_reserved_run_terminal(
                self.identity,
                result,
            )

        terminal_wave = next(
            item for item in state.waves if item.id == wave.id
        )
        self.assertEqual(terminal_wave.status, "ready_to_reduce")

    def test_reconcile_terminalizes_running_provider_without_result(self):
        engine = self.engine(ProbeRoleExecutor())
        self.add_v2(engine)
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        _state, session_id = orchestrator._reserve_session(
            self.identity,
            None,
        )
        _state, cycle = orchestrator._reserve_cycle(
            self.identity,
            session_id,
        )
        assert cycle.captain_run_id is not None
        engine._mark_reserved_run_running(
            self.identity,
            cycle.captain_run_id,
        )

        recovered = orchestrator.reconcile(self.identity)

        run = next(
            item
            for item in recovered.runs
            if item.id == cycle.captain_run_id
        )
        provider_path = (
            engine.store.run_paths(self.identity, run_id=run.id).root
            / "provider.json"
        )
        provider = read_json(provider_path)
        self.assertIs(run.status, RunStatus.INTERRUPTED)
        self.assertEqual(provider["status"], "interrupted")
        self.assertTrue(provider["provider_started"])
        self.assertEqual(provider["recovered_by"], "managed_reconcile")
        self.assertEqual(
            run.extra["provider_outcome_status"],
            "interrupted",
        )
        self.assertEqual(
            run.extra["provider_completed_at"],
            provider["finished_at"],
        )
        root = engine.store.challenge_paths(self.identity).root
        self.assertEqual(
            run.extra["request_sha256"],
            sha256_file(root / str(run.request_path)),
        )
        self.assertEqual(
            run.extra["result_sha256"],
            sha256_file(root / str(run.result_path)),
        )
        self.assertEqual(
            run.extra["validation_sha256"],
            sha256_file(root / str(run.validation_path)),
        )

    def test_reconcile_imports_terminal_provider_timing_after_state_crash(self):
        engine = self.engine(ProbeRoleExecutor())
        self.add_v2(engine)
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        state, session_id = orchestrator._reserve_session(
            self.identity,
            None,
        )
        state, cycle = orchestrator._reserve_cycle(
            self.identity,
            session_id,
        )
        assert cycle.captain_run_id is not None
        invocation = engine._make_invocation(
            state,
            Role.CAPTAIN,
            prefix="captain",
            instruction="return one contract-valid managed result",
            deadline_monotonic_seconds=time.monotonic() + 60,
            deadline_epoch_seconds=time.time() + 60,
            run_id=cycle.captain_run_id,
            managed_workspace=True,
        )
        result = engine.batch_runner.run(
            invocation,
            before_provider_start=lambda: engine._mark_reserved_run_running(
                self.identity,
                cycle.captain_run_id,
            ),
        )
        with (
            mock.patch.object(
                engine.store,
                "update",
                side_effect=RevisionConflict(1, 2),
            ),
            self.assertRaises(RevisionConflict),
        ):
            engine._persist_reserved_run_terminal(self.identity, result)

        provider_path = (
            engine.store.run_paths(
                self.identity,
                run_id=cycle.captain_run_id,
            ).root
            / "provider.json"
        )
        durable_provider = read_json(provider_path)
        recovered = orchestrator.reconcile(self.identity)
        run = next(
            item
            for item in recovered.runs
            if item.id == cycle.captain_run_id
        )
        recovered_provider = read_json(provider_path)

        self.assertIs(run.status, RunStatus.COMPLETED)
        self.assertTrue(run.extra["recovered_from_durable_result"])
        self.assertTrue(run.extra["provider_started"])
        self.assertEqual(recovered_provider["status"], "completed")
        self.assertEqual(
            recovered_provider["recovered_by"],
            "managed_reconcile",
        )
        for field in (
            "provider_wait_seconds",
            "provider_process_span_seconds",
            "model_call_wall_seconds",
            "attempt_count",
        ):
            self.assertEqual(
                recovered_provider[field],
                durable_provider[field],
            )
            self.assertEqual(run.extra[field], durable_provider[field])
        self.assertEqual(
            run.extra["provider_completed_at"],
            durable_provider["finished_at"],
        )
        root = engine.store.challenge_paths(self.identity).root
        self.assertEqual(
            run.extra["request_sha256"],
            sha256_file(root / str(run.request_path)),
        )
        self.assertEqual(
            run.extra["result_sha256"],
            sha256_file(root / str(run.result_path)),
        )
        self.assertEqual(
            run.extra["validation_sha256"],
            sha256_file(root / str(run.validation_path)),
        )

    def test_reconcile_rejects_unbound_durable_documents(self):
        engine = self.engine(ProbeRoleExecutor())
        self.add_v2(engine)
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        state, session_id = orchestrator._reserve_session(
            self.identity,
            None,
        )
        state, cycle = orchestrator._reserve_cycle(
            self.identity,
            session_id,
        )
        assert cycle.captain_run_id is not None
        run = next(
            item
            for item in state.runs
            if item.id == cycle.captain_run_id
        )
        paths = engine.store.run_paths(self.identity, run_id=run.id)
        malicious_identity = {
            "contest_id": "EVIL",
            "category": "x",
            "challenge_id": "y",
        }
        atomic_write_json(
            paths.request,
            {
                # JSON booleans must not compare equal to integer protocol
                # versions (True == 1 in ordinary Python equality).
                "schema_version": True,
                **malicious_identity,
                "run_id": run.id,
                "base_revision": run.base_revision + 999,
                "configuration_epoch": run.configuration_epoch,
                "kind": "model",
                "role": run.role,
                "model": run.model,
                "state_revision": run.base_revision,
                "contract_version": run.extra["contract_version"],
                "thread_continuity_v1": copy.deepcopy(
                    run.extra["thread_continuity_v1"]
                ),
            },
        )
        atomic_write_json(
            paths.result,
            {
                "schema_version": True,
                **malicious_identity,
                "run_id": run.id,
                "base_revision": run.base_revision + 999,
                "status": RunStatus.COMPLETED.value,
                "provisional_managed_result": True,
                "artifacts": [],
            },
        )
        atomic_write_json(
            paths.validation,
            {
                "run_id": run.id,
                "base_revision": run.base_revision + 999,
                "ok": True,
                "validated_at": "2026-08-03T00:00:00Z",
                "provisional_managed_result": True,
            },
        )

        recovered = orchestrator.reconcile(self.identity)
        recovered_run = next(
            item for item in recovered.runs if item.id == run.id
        )
        self.assertIs(recovered_run.status, RunStatus.INTERRUPTED)
        self.assertFalse(
            recovered_run.extra["recovered_from_durable_result"]
        )
        errors = recovered_run.extra[
            "recovery_document_validation_errors"
        ]
        self.assertIn("request.contest_id_mismatch", errors)
        self.assertIn("request.schema_version_mismatch", errors)
        self.assertIn("request.base_revision_mismatch", errors)
        self.assertIn("result.contest_id_mismatch", errors)
        self.assertIn("result.schema_version_mismatch", errors)
        self.assertIn("result.base_revision_mismatch", errors)
        self.assertIn("validation.base_revision_mismatch", errors)

    def test_reconcile_quarantines_missing_request_and_corrupt_provider(self):
        engine = self.engine(ProbeRoleExecutor())
        self.add_v2(engine)
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        state, session_id = orchestrator._reserve_session(
            self.identity,
            None,
        )
        state, cycle = orchestrator._reserve_cycle(
            self.identity,
            session_id,
        )
        assert cycle.captain_run_id is not None
        invocation = engine._make_invocation(
            state,
            Role.CAPTAIN,
            prefix="captain",
            instruction="return one contract-valid managed result",
            deadline_monotonic_seconds=time.monotonic() + 60,
            deadline_epoch_seconds=time.time() + 60,
            run_id=cycle.captain_run_id,
            managed_workspace=True,
        )
        result = engine.batch_runner.run(
            invocation,
            before_provider_start=lambda: engine._mark_reserved_run_running(
                self.identity,
                cycle.captain_run_id,
            ),
        )
        with (
            mock.patch.object(
                engine.store,
                "update",
                side_effect=RevisionConflict(1, 2),
            ),
            self.assertRaises(RevisionConflict),
        ):
            engine._persist_reserved_run_terminal(self.identity, result)

        paths = engine.store.run_paths(
            self.identity,
            run_id=cycle.captain_run_id,
        )
        paths.request.unlink()
        provider_path = paths.root / "provider.json"
        provider = read_json(provider_path)
        provider["status"] = True
        provider["provider_started"] = True
        provider["started_at"] = None
        provider["attempt_count"] += 999
        atomic_write_json(provider_path, provider)

        recovered = orchestrator.reconcile(self.identity)
        recovered_run = next(
            item
            for item in recovered.runs
            if item.id == cycle.captain_run_id
        )
        self.assertIs(recovered_run.status, RunStatus.INTERRUPTED)
        self.assertFalse(
            recovered_run.extra["recovered_from_durable_result"]
        )
        errors = recovered_run.extra[
            "recovery_document_validation_errors"
        ]
        self.assertIn("request.missing", errors)
        self.assertIn("provider.status_invalid", errors)
        self.assertIn("provider.start_binding_invalid", errors)
        self.assertIn(
            "provider.result_attempt_count_mismatch",
            errors,
        )
        self.assertNotIn("attempt_count", recovered_run.extra)
        recovered_provider = read_json(provider_path)
        self.assertEqual(recovered_provider["status"], "interrupted")
        self.assertFalse(recovered_provider["provider_started"])
        self.assertIsNone(recovered_provider["started_at"])
        self.assertIsNone(recovered_provider["attempt_count"])

    def test_reconcile_rejects_result_validation_status_mismatch(self):
        engine = self.engine(ProbeRoleExecutor())
        self.add_v2(engine)
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        state, session_id = orchestrator._reserve_session(
            self.identity,
            None,
        )
        state, cycle = orchestrator._reserve_cycle(
            self.identity,
            session_id,
        )
        assert cycle.captain_run_id is not None
        run = next(
            item
            for item in state.runs
            if item.id == cycle.captain_run_id
        )
        paths = engine.store.run_paths(self.identity, run_id=run.id)
        atomic_write_json(
            paths.request,
            {
                "schema_version": RUN_ENVELOPE_SCHEMA_VERSION,
                "contest_id": self.identity.contest_id,
                "category": self.identity.category,
                "challenge_id": self.identity.challenge_id,
                "run_id": run.id,
                "base_revision": run.base_revision,
                "configuration_epoch": run.configuration_epoch,
                "kind": "model",
                "role": run.role,
                "model": run.model,
                "state_revision": run.base_revision,
                "contract_version": run.extra["contract_version"],
                "thread_continuity_v1": copy.deepcopy(
                    run.extra["thread_continuity_v1"]
                ),
            },
        )
        engine.store.write_run_result(
            self.identity,
            run.id,
            {
                "base_revision": run.base_revision,
                "status": RunStatus.COMPLETED.value,
                "provisional_managed_result": True,
                "artifacts": [],
            },
        )
        engine.store.write_run_validation(
            self.identity,
            run.id,
            {
                "run_id": run.id,
                "base_revision": run.base_revision,
                "ok": False,
                "provisional_managed_result": True,
            },
        )

        recovered = orchestrator.reconcile(self.identity)
        recovered_run = next(
            item for item in recovered.runs if item.id == run.id
        )
        self.assertIs(recovered_run.status, RunStatus.INTERRUPTED)
        self.assertFalse(
            recovered_run.extra["recovered_from_durable_result"]
        )
        self.assertIn(
            "validation.result_status_mismatch",
            recovered_run.extra[
                "recovery_document_validation_errors"
            ],
        )

    def test_reconciler_recovers_two_terminal_and_one_durable_created_run(
        self,
    ):
        engine = self.engine(ProbeRoleExecutor())
        self.add_v2(engine)
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        _state, session_id = orchestrator._reserve_session(
            self.identity,
            None,
        )
        _state, cycle = orchestrator._reserve_cycle(
            self.identity,
            session_id,
        )
        prepared_paths = {}

        def persist_run(run_id: str, *, commit_state: bool) -> None:
            snapshot = engine.store.load(self.identity)
            run = next(item for item in snapshot.runs if item.id == run_id)
            paths = prepared_paths.get(run_id)
            if paths is None:
                paths = engine.store.create_run(
                    self.identity,
                    run_id=run_id,
                    request={
                        "kind": "model",
                        "role": run.role,
                        "model": run.model,
                        "state_revision": run.base_revision,
                        "configuration_epoch": run.configuration_epoch,
                        "contract_version": run.extra[
                            "contract_version"
                        ],
                        "thread_continuity_v1": copy.deepcopy(
                            run.extra["thread_continuity_v1"]
                        ),
                    },
                    base_revision=run.base_revision,
                )
                prepared_paths[run_id] = paths
                engine.store.write_run_result(
                    self.identity,
                    run_id,
                    {
                        "base_revision": run.base_revision,
                        "status": RunStatus.COMPLETED.value,
                        "provisional_managed_result": True,
                        "artifacts": [],
                    },
                )
                engine.store.write_run_validation(
                    self.identity,
                    run_id,
                    {
                        "ok": True,
                        "base_revision": run.base_revision,
                        "provisional_managed_result": True,
                    },
                )
            if not commit_state:
                return
            challenge_root = engine.store.challenge_paths(
                self.identity
            ).root
            current = engine.store.load(self.identity)

            def apply(state):
                target = next(
                    item for item in state.runs if item.id == run_id
                )
                target.status = RunStatus.COMPLETED
                target.request_path = paths.request.relative_to(
                    challenge_root
                ).as_posix()
                target.result_path = paths.result.relative_to(
                    challenge_root
                ).as_posix()
                target.validation_path = paths.validation.relative_to(
                    challenge_root
                ).as_posix()
                target.extra["provisional_managed_terminal"] = True
                target.extra["semantic_merge"] = False

            engine.store.update(
                self.identity,
                apply,
                expected_revision=current.revision,
            )

        assert cycle.captain_run_id is not None
        persist_run(cycle.captain_run_id, commit_state=True)
        _state, wave, role_runs = orchestrator._reserve_wave(
            self.identity,
            session_id,
            cycle.id,
            "discovery",
        )
        ordered_run_ids = list(role_runs.values())
        for run_id in ordered_run_ids:
            persist_run(run_id, commit_state=False)
        persist_run(ordered_run_ids[0], commit_state=True)
        persist_run(ordered_run_ids[1], commit_state=True)

        recovered = orchestrator.reconcile(self.identity)
        recovered_runs = {run.id: run for run in recovered.runs}
        self.assertTrue(
            all(
                recovered_runs[run_id].status is RunStatus.COMPLETED
                for run_id in ordered_run_ids
            )
        )
        self.assertTrue(
            recovered_runs[ordered_run_ids[2]].extra[
                "recovered_from_durable_result"
            ]
        )
        recovered_wave = next(
            item for item in recovered.waves if item.id == wave.id
        )
        self.assertEqual(recovered_wave.status, "interrupted")
        self.assertEqual(recovered.status, ChallengeStatus.PAUSED)
        self.assertEqual(recovered.facts, [])

    def test_failed_managed_tool_stages_are_quarantined(self):
        engine = self.engine(
            ProbeRoleExecutor(),
            sandbox_factory=lambda state, work, policy: FailingSandbox(work),
        )
        self.add_v2(engine)
        state = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        ).run_cycle(self.identity)
        self.assertEqual(engine._managed_storage_admissions, {})
        selected = set(state.cycles[0].selected_action_ids)
        failed = {
            item.id
            for item in state.experiments
            if item.id in selected
            and item.status is ExperimentStatus.FAILED
        }
        self.assertEqual(failed, selected)
        paths = engine.store.challenge_paths(self.identity)
        manifests = list(
            (paths.runtime / "quarantine" / "stages").rglob(
                "quarantine.json"
            )
        )
        self.assertEqual(len(manifests), len(selected))
        self.assertTrue(
            all(
                read_json(path).get("automatic_restore") is False
                for path in manifests
            )
        )
        self.assertFalse(
            any(
                (
                    paths.runtime
                    / "staging"
                    / state.sessions[0].id
                    / state.cycles[0].id
                    / experiment_id
                ).exists()
                for experiment_id in selected
            )
        )

    def test_target_lifecycle_requires_explicit_primary_selection(self):
        engine = self.engine(ProbeRoleExecutor())
        state = self.add_v2(engine)
        epoch = state.configuration_epoch
        state = engine.add_network_target(
            self.identity,
            "example.test:31337",
        )
        self.assertIsNone(state.primary_target_id)
        self.assertGreater(state.configuration_epoch, epoch)
        target = state.targets[-1]
        state = engine.select_network_target(self.identity, target.id)
        self.assertEqual(state.primary_target_id, target.id)
        state = engine.replace_network_target(
            self.identity,
            target.id,
            "replacement.test:31337",
            reason="challenge instance rotated",
        )
        self.assertIsNone(state.primary_target_id)
        self.assertEqual(state.targets[0].status.value, "revoked")
        replacement = state.targets[-1]
        state = engine.select_network_target(
            self.identity,
            replacement.id,
        )
        state = engine.revoke_network_target(
            self.identity,
            replacement.id,
            reason="operator ended remote access",
        )
        self.assertIsNone(state.primary_target_id)
        with self.assertRaisesRegex(EngineError, "not active"):
            engine.select_network_target(
                self.identity,
                replacement.id,
            )

    def test_remote_experiment_generation_pin_fails_closed_when_stale(self):
        engine = self.engine(ProbeRoleExecutor())
        self.add_v2(engine)
        endpoint = "https://challenge.example:443"
        state = engine.add_network_target(
            self.identity,
            endpoint,
            docker_network="ctfos-proxy",
            enforcement="proxy",
        )
        target = state.targets[-1]
        engine.select_network_target(self.identity, target.id)
        _state, experiment_id = engine.register_experiment(
            self.identity,
            command=("python3", "-c", "print('never runs')"),
            expected_observation="remote response",
            keep_if="response is useful",
            drop_if="response is not useful",
            network_target=endpoint,
        )
        engine.add_network_target(
            self.identity,
            "https://other.example:443",
            docker_network="ctfos-proxy",
            enforcement="proxy",
        )
        with self.assertRaisesRegex(EngineError, "stale"):
            engine.execute_registered_experiments(
                self.identity,
                experiment_ids=(experiment_id,),
            )
        state = engine.store.load(self.identity)
        experiment = next(
            item
            for item in state.experiments
            if item.id == experiment_id
        )
        self.assertEqual(experiment.status, ExperimentStatus.REGISTERED)

    def test_cycle_retires_stale_managed_remote_before_preflight(self):
        executor = ProbeRoleExecutor()
        engine = self.engine(executor)
        self.add_v2(engine)
        _target_id, experiment_id = self.seed_managed_remote_action(
            engine,
            "https://stale-managed.example:443",
        )
        engine.add_network_target(
            self.identity,
            "https://epoch-bump.example:443",
            docker_network="ctfos-proxy",
            enforcement="proxy",
        )

        state = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        ).run_cycle(self.identity)

        retired = next(
            item
            for item in state.experiments
            if item.id == experiment_id
        )
        self.assertIs(retired.status, ExperimentStatus.CANCELLED)
        self.assertEqual(
            retired.extra["cancelled_reason"],
            "stale_managed_remote_binding_retired",
        )
        self.assertIn("cancelled_at", retired.extra)
        self.assertIn(Role.CAPTAIN, executor.roles)

    def test_operator_cancels_only_exact_stale_registered_remote(self):
        executor = ProbeRoleExecutor()
        engine = self.engine(executor)
        self.add_v2(engine)
        endpoint = "https://operator-cancel.example:443"
        _target_id, stale_id = self.seed_managed_remote_action(
            engine,
            endpoint,
        )
        _state, local_id = engine.register_experiment(
            self.identity,
            command=("python3", "-c", "print('local')"),
            expected_observation="local output",
            keep_if="output exists",
            drop_if="output is absent",
        )
        engine.add_network_target(
            self.identity,
            "https://epoch-bump.example:443",
            docker_network="ctfos-proxy",
            enforcement="proxy",
        )
        _state, current_id = engine.register_experiment(
            self.identity,
            command=("python3", "-c", "print('current remote')"),
            expected_observation="remote output",
            keep_if="output exists",
            drop_if="output is absent",
            network_target=endpoint,
        )
        before = engine.store.load(self.identity)

        def stall(state):
            state.status = ChallengeStatus.STALLED
            state.resume_status = None

        before = engine.store.update(
            self.identity,
            stall,
            expected_revision=before.revision,
        )
        run_ids = [run.id for run in before.runs]

        state, cancelled_ids = engine.cancel_stale_registered_experiments(
            self.identity,
            (stale_id,),
            reason="configuration epoch changed after operator recovery",
        )

        self.assertEqual(cancelled_ids, (stale_id,))
        self.assertIs(state.status, ChallengeStatus.STALLED)
        self.assertEqual([run.id for run in state.runs], run_ids)
        self.assertEqual(executor.roles, [])
        by_id = {item.id: item for item in state.experiments}
        self.assertIs(
            by_id[stale_id].status,
            ExperimentStatus.CANCELLED,
        )
        self.assertIs(
            by_id[local_id].status,
            ExperimentStatus.REGISTERED,
        )
        self.assertIs(
            by_id[current_id].status,
            ExperimentStatus.REGISTERED,
        )
        cancellation = by_id[stale_id].extra["operator_cancellation"]
        self.assertEqual(cancellation["kind"], "stale_remote_binding")
        self.assertEqual(
            cancellation["reason"],
            "configuration epoch changed after operator recovery",
        )
        self.assertEqual(
            cancellation["source_state_revision"],
            before.revision,
        )
        self.assertNotEqual(
            cancellation["stale_binding"],
            cancellation["selected_binding"],
        )
        self.assertEqual(state.candidates, before.candidates)
        self.assertEqual(state.submissions, before.submissions)

    def test_operator_stale_cancellation_rejects_mixed_set_atomically(self):
        engine = self.engine(ProbeRoleExecutor())
        self.add_v2(engine)
        _target_id, stale_id = self.seed_managed_remote_action(
            engine,
            "https://atomic-cancel.example:443",
        )
        _state, local_id = engine.register_experiment(
            self.identity,
            command=("true",),
            expected_observation="success",
            keep_if="success",
            drop_if="failure",
        )
        engine.add_network_target(
            self.identity,
            "https://atomic-epoch-bump.example:443",
            docker_network="ctfos-proxy",
            enforcement="proxy",
        )
        before = engine.store.load(self.identity)

        with self.assertRaisesRegex(EngineError, "not remote-bound"):
            engine.cancel_stale_registered_experiments(
                self.identity,
                (stale_id, local_id),
                reason="must reject the complete mixed set",
            )

        after = engine.store.load(self.identity)
        self.assertEqual(after.revision, before.revision)
        selected = {
            item.id: item.status
            for item in after.experiments
            if item.id in {stale_id, local_id}
        }
        self.assertEqual(
            selected,
            {
                stale_id: ExperimentStatus.REGISTERED,
                local_id: ExperimentStatus.REGISTERED,
            },
        )

    def test_cycle_does_not_retire_stale_operator_remote(self):
        executor = ProbeRoleExecutor()
        engine = self.engine(executor)
        self.add_v2(engine)
        endpoint = "https://operator-stale.example:443"
        state = engine.add_network_target(
            self.identity,
            endpoint,
            docker_network="ctfos-proxy",
            enforcement="proxy",
        )
        target = state.targets[-1]
        engine.select_network_target(self.identity, target.id)
        _state, experiment_id = engine.register_experiment(
            self.identity,
            command=("python3", "-c", "print('operator remote')"),
            expected_observation="remote output",
            keep_if="output exists",
            drop_if="output is absent",
            network_target=endpoint,
        )
        engine.add_network_target(
            self.identity,
            "https://operator-epoch-bump.example:443",
            docker_network="ctfos-proxy",
            enforcement="proxy",
        )

        with self.assertRaisesRegex(
            ManagedError,
            f"remote experiment {experiment_id} has a stale",
        ):
            ManagedOrchestrator(
                engine,
                capability_probe=self.capability,
            ).run_cycle(self.identity)

        state = engine.store.load(self.identity)
        operator_action = next(
            item
            for item in state.experiments
            if item.id == experiment_id
        )
        self.assertIs(
            operator_action.status,
            ExperimentStatus.REGISTERED,
        )
        self.assertEqual(executor.roles, [])

    def test_reconcile_preserves_current_managed_remote(self):
        engine = self.engine(ProbeRoleExecutor())
        self.add_v2(engine)
        _target_id, experiment_id = self.seed_managed_remote_action(
            engine,
            "https://current-managed.example:443",
        )
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        before = engine.store.load(self.identity)

        after = (
            orchestrator
            ._retire_stale_registered_managed_remote_actions(self.identity)
        )

        self.assertEqual(after.revision, before.revision)
        current = next(
            item
            for item in after.experiments
            if item.id == experiment_id
        )
        self.assertIs(current.status, ExperimentStatus.REGISTERED)
        self.assertTrue(orchestrator.preflight(self.identity).ok)

    def test_cycle_retires_managed_remote_when_no_primary_target(self):
        executor = ProbeRoleExecutor()
        sandboxes: list[FakeSandbox] = []

        def sandbox_factory(state, work, policy):
            del state, policy
            sandbox = FakeSandbox(work)
            sandboxes.append(sandbox)
            return sandbox

        engine = self.engine(
            executor,
            sandbox_factory=sandbox_factory,
        )
        self.add_v2(engine)
        target_id, experiment_id = self.seed_managed_remote_action(
            engine,
            "https://revoked-managed.example:443",
        )
        engine.revoke_network_target(
            self.identity,
            target_id,
            reason="operator ended the target",
        )

        state = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        ).run_cycle(self.identity)

        retired = next(
            item
            for item in state.experiments
            if item.id == experiment_id
        )
        self.assertIs(retired.status, ExperimentStatus.CANCELLED)
        self.assertEqual(
            retired.extra["cancelled_reason"],
            "stale_managed_remote_binding_retired",
        )
        self.assertIn(Role.CAPTAIN, executor.roles)
        self.assertTrue(
            all(
                spec.network_target is None
                for sandbox in sandboxes
                for spec in sandbox.specs
            )
        )

    def test_managed_model_remote_actions_resolve_only_selected_proxy_pin(
        self,
    ):
        executor = ProbeRoleExecutor()
        engine = self.engine(executor)
        self.add_v2(engine)
        endpoint = "https://managed.example:443"
        state = engine.add_network_target(
            self.identity,
            endpoint,
            docker_network="ctfos-proxy",
            enforcement="proxy",
        )
        target = state.targets[-1]
        state = engine.select_network_target(
            self.identity,
            target.id,
        )
        executor.network_target = (target.id, target.generation)

        state = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        ).run_cycle(self.identity)

        managed_remote = [
            item
            for item in state.experiments
            if item.extra.get("managed_contract_version") == 2
            and item.extra.get("network_target") is not None
        ]
        self.assertEqual(len(managed_remote), 4)
        self.assertTrue(
            all(
                item.extra["network_target"] == endpoint
                and item.extra["network_target_id"] == target.id
                and item.extra["network_target_generation"]
                == target.generation
                and item.extra["configuration_epoch"]
                == state.configuration_epoch
                and item.extra["managed_command_protocol"]
                == "posix_sh_lc_v1"
                and tuple(shlex.split(item.command)[:2])
                == ("/bin/sh", "-lc")
                for item in managed_remote
            )
        )
        self.assertEqual(
            {
                item.status for item in managed_remote
            },
            {
                ExperimentStatus.AWAITING_EVALUATION,
                ExperimentStatus.COMPLETED,
                ExperimentStatus.REGISTERED,
            },
        )
        self.assertEqual(
            len(
                [
                    item
                    for item in managed_remote
                    if item.status
                    in {
                        ExperimentStatus.AWAITING_EVALUATION,
                        ExperimentStatus.COMPLETED,
                    }
                ]
            ),
            3,
        )

    def test_managed_model_stale_target_generation_never_registers_action(
        self,
    ):
        executor = ProbeRoleExecutor()
        engine = self.engine(executor)
        self.add_v2(engine)
        state = engine.add_network_target(
            self.identity,
            "https://stale.example:443",
            docker_network="ctfos-proxy",
            enforcement="proxy",
        )
        target = state.targets[-1]
        engine.select_network_target(self.identity, target.id)
        executor.network_target = (target.id, target.generation + 1)

        state = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        ).run_cycle(self.identity)

        managed_experiments = [
            item
            for item in state.experiments
            if item.extra.get("managed_contract_version") == 2
        ]
        self.assertEqual(managed_experiments, [])
        managed_runs = [
            item
            for item in state.runs
            if item.origin is RunOrigin.MANAGED_MODEL
        ]
        self.assertEqual(len(managed_runs), 4)
        self.assertTrue(
            all(
                item.extra["rejected_actions"][0]["reason"].startswith(
                    "target is not the selected active proxy target"
                )
                for item in managed_runs
            )
        )

    def test_portable_closure_exists_only_after_bounded_copy(self):
        engine = self.engine(ProbeRoleExecutor())
        self.add_v2(engine)
        create_checkpoint(engine, self.identity, note="handoff")
        state = close_challenge(
            engine,
            self.identity,
            portability="portable",
        )
        self.assertEqual(state.closure.portability, "portable")
        paths = engine.store.challenge_paths(self.identity)
        package = paths.root / state.closure.extra["package_path"]
        manifest = read_json(package / "manifest.json")
        self.assertEqual(manifest["closure_id"], state.closure.id)
        self.assertEqual(
            manifest["source_manifest_sha256"],
            state.metadata["source_manifest_sha256"],
        )
        self.assertTrue(list((package / "source").glob("*.bin")))

        repeated = close_challenge(
            engine,
            self.identity,
            portability="referential",
        )
        self.assertEqual(repeated.closure.id, state.closure.id)
        self.assertEqual(repeated.closure.portability, "portable")

        other = ChallengeIdentity("Managed CTF", "rev", "large")
        other_incoming = (
            self.root
            / "incoming"
            / other.contest_id
            / other.category
            / other.challenge_id
        )
        other_incoming.mkdir(parents=True)
        (other_incoming / "large.bin").write_bytes(b"xx")
        engine.add_challenge(
            other,
            prompt="close as referential",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        create_checkpoint(engine, other, note="handoff")
        with mock.patch(
            "ctf_os.lifecycle.MAX_PORTABLE_CLOSURE_BYTES",
            1,
        ):
            state = close_challenge(
                engine,
                other,
                portability="portable",
            )
        self.assertEqual(state.closure.portability, "referential")
        self.assertTrue(state.closure.extra["portable_requested"])
        self.assertIsNone(state.closure.extra["package_path"])

    def test_close_upgrades_automatic_submission_closure(self):
        engine = self.engine(ProbeRoleExecutor())
        self.add_v2(engine)
        create_checkpoint(engine, self.identity, note="before submit")
        state = engine.record_candidate(
            self.identity,
            "KCTF{manual_accept_then_close}",
            print_immediately=False,
        )
        candidate_id = state.candidates[-1].id
        state = engine.record_manual_submission(
            self.identity,
            candidate_id,
            outcome="accepted",
            allow_unproved=True,
            override_reason="operator submitted outside CTF-OS",
        )
        automatic_id = state.closure.id
        self.assertTrue(state.closure.extra["automatic_incomplete"])

        with (
            mock.patch.object(
                engine.store,
                "update",
                side_effect=OSError("synthetic closure upgrade fault"),
            ),
            self.assertRaisesRegex(OSError, "closure upgrade"),
        ):
            close_challenge(
                engine,
                self.identity,
                portability="portable",
            )
        self.assertTrue(
            engine.store.load(self.identity).closure.extra[
                "automatic_incomplete"
            ]
        )

        closed = close_challenge(
            engine,
            self.identity,
            portability="portable",
        )

        self.assertEqual(closed.closure.id, automatic_id)
        self.assertEqual(
            closed.closure.completeness.value,
            "complete",
        )
        self.assertNotIn(
            "automatic_incomplete",
            closed.closure.extra,
        )
        self.assertIsNotNone(
            closed.closure.extra["package_path"],
        )

    def test_storage_quarantine_preserves_workspace_and_closure_reachability(
        self,
    ):
        engine = self.engine(ProbeRoleExecutor())
        self.add_v2(engine)
        create_checkpoint(engine, self.identity, note="storage")
        state = close_challenge(
            engine,
            self.identity,
            portability="portable",
        )
        paths = engine.store.challenge_paths(self.identity)
        workspace_file = paths.artifacts / "workspace" / "operator.txt"
        workspace_file.parent.mkdir(parents=True, exist_ok=True)
        workspace_file.write_text("canonical", encoding="utf-8")
        orphan = paths.artifacts / "snapshots" / "orphan.log"
        orphan.parent.mkdir(parents=True, exist_ok=True)
        orphan.write_text("orphan", encoding="utf-8")

        plan = storage_plan(engine.store, self.identity)
        candidates = {item["path"] for item in plan["candidates"]}
        self.assertIn(
            orphan.relative_to(paths.root).as_posix(),
            candidates,
        )
        self.assertNotIn(
            workspace_file.relative_to(paths.root).as_posix(),
            candidates,
        )
        package_prefix = str(state.closure.extra["package_path"]) + "/"
        self.assertFalse(
            any(path.startswith(package_prefix) for path in candidates)
        )

        quarantined = quarantine_unreachable(
            engine.store,
            self.identity,
        )
        self.assertEqual(quarantined["status"], "quarantined")
        self.assertFalse(orphan.exists())
        restored = restore_quarantine(
            engine.store,
            self.identity,
            quarantined["quarantine_id"],
        )
        self.assertIn(
            orphan.relative_to(paths.root).as_posix(),
            restored["restored"],
        )
        self.assertEqual(orphan.read_text(encoding="utf-8"), "orphan")

    def test_ready_closure_intent_finishes_after_state_commit_fault(self):
        engine = self.engine(ProbeRoleExecutor())
        self.add_v2(engine)
        create_checkpoint(engine, self.identity, note="closure recovery")
        with (
            mock.patch.object(
                engine.store,
                "update",
                side_effect=OSError("synthetic closure commit fault"),
            ),
            self.assertRaisesRegex(OSError, "synthetic closure"),
        ):
            close_challenge(
                engine,
                self.identity,
                portability="referential",
            )
        paths = engine.store.challenge_paths(self.identity)
        self.assertEqual(
            len(list((paths.runtime / "closure-intents").glob("*.json"))),
            1,
        )
        self.assertIsNone(engine.store.load(self.identity).closure)

        recovered = close_challenge(
            engine,
            self.identity,
            portability="referential",
        )
        self.assertIsNotNone(recovered.closure)
        self.assertEqual(
            list((paths.runtime / "closure-intents").glob("*.json")),
            [],
        )


class ManagedTypedGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def engine(self, executor=None) -> ChallengeEngine:
        config = load_config(self.root)
        config = replace(
            config,
            runtime=replace(
                config.runtime,
                image_digest=IMAGE_DIGEST,
            ),
        )
        return ChallengeEngine(
            self.root,
            config=config,
            batch_runner=BatchRunner(
                process_executor=executor or ProbeRoleExecutor(),
                limiter=FifoModelCallLimiter(1),
                max_schema_retries=0,
            ),
            sandbox_factory=lambda state, work, policy: FakeSandbox(work),
        )

    @staticmethod
    def capability(_digest: str):
        return {
            "ok": True,
            "schema_version": 2,
            "capabilities": {},
        }

    def fixture(
        self,
        *,
        suffix: str,
        category: str,
        action: dict[str, object],
        role: Role = Role.BUILDER,
        wave_name: str = "attack",
        report_all_paths: bool = True,
        builder_predates_preissue: bool = False,
        active_remote_target: bool = False,
    ):
        identity = ChallengeIdentity(
            "Managed Typed Gates",
            category,
            suffix,
        )
        incoming = (
            self.root
            / "incoming"
            / identity.contest_id
            / identity.category
            / identity.challenge_id
        )
        incoming.mkdir(parents=True)
        (incoming / "challenge.bin").write_bytes(b"typed-gate-fixture")
        engine = self.engine()
        engine.add_challenge(
            identity,
            prompt="exercise exactly one managed typed gate",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        if "candidate_id" in action:
            engine.record_candidate(
                identity,
                f"KCTF{{{suffix}}}",
                print_immediately=False,
            )
            action["candidate_id"] = engine.store.load(
                identity
            ).candidates[-1].id
        if "parent_experiment_id" in action:
            _state, parent_id = engine.register_experiment(
                identity,
                command=("true",),
                expected_observation="primitive exists",
                keep_if="primitive is confirmed",
                drop_if="primitive is absent",
            )
            action["parent_experiment_id"] = parent_id
        if "oracle_preissue_id" in action:
            with tempfile.TemporaryDirectory() as operator_temp:
                operator_root = Path(operator_temp)
                if category == "crypto":
                    variant = operator_root / "variant.json"
                    expected = operator_root / "expected.bin"
                    variant.write_text(
                        '{"variant":1}\n',
                        encoding="utf-8",
                    )
                    expected.write_bytes(b"operator-expected\n")
                    _state, record = (
                        engine.preissue_managed_crypto_oracle(
                            identity,
                            variant_parameters_path=variant,
                            variant_expected_output_path=expected,
                            mutation_id="operator-variant-1",
                        )
                    )
                else:
                    verifier = operator_root / "verifier.py"
                    verifier.write_text(
                        "raise SystemExit(1)\n",
                        encoding="utf-8",
                    )
                    _state, record = (
                        engine.preissue_managed_misc_oracle(
                            identity,
                            verifier_path=verifier,
                            verifier_id="operator-verifier-v1",
                            oracle_id="operator-oracle-v1",
                        )
                    )
            action["oracle_preissue_id"] = record["preissue_id"]

        if active_remote_target:
            state = engine.add_network_target(
                identity,
                "tcp://managed-pwn.example:31337",
                docker_network="ctfos-test-proxy",
                enforcement="proxy",
            )
            engine.select_network_target(identity, state.targets[-1].id)

        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        _state, session_id = orchestrator._reserve_session(identity, None)
        _state, cycle = orchestrator._reserve_cycle(identity, session_id)
        _state, wave, role_runs = orchestrator._reserve_wave(
            identity,
            session_id,
            cycle.id,
            wave_name,
        )
        run_id = (
            role_runs[role]
            if role in role_runs
            else next(iter(role_runs.values()))
        )
        path_fields = tuple(
            field
            for field in action
            if field.endswith("_artifact_path")
        )
        run_workspace = (
            engine.store.run_paths(identity, run_id=run_id).root
            / "workspace"
        )
        run_workspace.mkdir(parents=True)
        snapshots = (
            engine.store.challenge_paths(identity).artifacts / "snapshots"
        )
        snapshots.mkdir(parents=True, exist_ok=True)
        artifact_records: list[
            tuple[str, str, bytes, str]
        ] = []
        for ordinal, field in enumerate(path_fields, start=1):
            locator = str(action[field])
            payload = (
                f"{field}:{suffix}:{ordinal}\n".encode("ascii")
            )
            staged = run_workspace / locator
            staged.parent.mkdir(parents=True, exist_ok=True)
            staged.write_bytes(payload)
            artifact_id = f"A-{run_id}-typed-{ordinal}"
            snapshot_relative = (
                f"artifacts/snapshots/{artifact_id}.bin"
            )
            snapshot = (
                engine.store.challenge_paths(identity).root
                / snapshot_relative
            )
            snapshot.write_bytes(payload)
            snapshot.chmod(0o400)
            artifact_records.append(
                (artifact_id, snapshot_relative, payload, locator)
            )

        local_hypothesis_ids = list(action.get("hypothesis_ids", []))
        canonical_hypotheses = [
            f"H-{run_id}-{item}" for item in local_hypothesis_ids
        ]

        def seed(state):
            run = next(item for item in state.runs if item.id == run_id)
            if builder_predates_preissue:
                preissue_id = action.get("oracle_preissue_id")
                history = state.extra.get("managed_oracle_preissues", {})
                preissue = (
                    history.get(preissue_id)
                    if isinstance(history, dict)
                    else None
                )
                if not isinstance(preissue, dict):
                    raise AssertionError("test preissue is unavailable")
                run.base_revision = int(preissue["issue_revision"]) - 1
            run.status = RunStatus.COMPLETED
            run.result_path = f"runs/{run_id}/result.json"
            run.validation_path = f"runs/{run_id}/validation.json"
            run.extra["semantic_merge"] = True
            for hypothesis_id, local_id in zip(
                canonical_hypotheses,
                local_hypothesis_ids,
                strict=True,
            ):
                state.hypotheses.append(
                    Hypothesis(
                        id=hypothesis_id,
                        statement="the typed gate claim is testable",
                        falsifier=Falsifier(
                            "the deterministic gate rejects it"
                        ),
                        source_run_id=run_id,
                        extra={
                            "unknowns": ["deterministic verdict"],
                            "experiment": "run the typed gate",
                            "success_oracle": "engine gate passes",
                            "managed_contract_version": 2,
                        },
                    )
                )
            for ordinal, (
                artifact_id,
                snapshot_relative,
                payload,
                locator,
            ) in enumerate(artifact_records, start=1):
                if not report_all_paths and ordinal == len(
                    artifact_records
                ):
                    continue
                state.artifacts.append(
                    ArtifactReference(
                        id=artifact_id,
                        path=snapshot_relative,
                        sha256=hashlib.sha256(payload).hexdigest(),
                        source_run_id=run_id,
                        size=len(payload),
                        extra={
                            "reported_locator": locator,
                            "purpose": "managed typed gate input",
                        },
                    )
                )

        engine.store.update(identity, seed)
        result = mock.Mock(
            invocation=mock.Mock(
                role=role,
                run_id=run_id,
                contract_version=2,
            ),
            output={
                "hypotheses": [
                    {"id": item} for item in local_hypothesis_ids
                ],
                "actions": [action],
            },
            attempts=(mock.Mock(),),
        )
        publish = orchestrator._apply_builder_publishes(
            identity,
            wave,
            (result,),
        )
        registration = orchestrator._register_typed_gate_actions(
            identity,
            wave,
            (result,),
        )
        return (
            engine,
            orchestrator,
            identity,
            session_id,
            cycle,
            wave,
            result,
            publish,
            registration,
        )

    def test_remote_pwn_local_gates_fail_admission_without_losing_artifact(
        self,
    ) -> None:
        cases = (
            {
                "kind": "prove_pwn_exploit_effect",
                "description": "invalid remote use of the local effect gate",
                "parent_experiment_id": "placeholder",
                "payload_artifact_path": "pwn/remote-exploit.py",
                "timeout_seconds": 300,
            },
            {
                "kind": "prove_pwn_interaction",
                "description": "invalid remote use of the local interaction gate",
                "parent_experiment_id": "placeholder",
                "recipe_artifact_path": "pwn/remote-interaction.json",
                "timeout_seconds": 300,
            },
        )
        for ordinal, action in enumerate(cases, start=1):
            with self.subTest(kind=action["kind"]):
                (
                    engine,
                    orchestrator,
                    identity,
                    _session_id,
                    _cycle,
                    wave,
                    result,
                    publication,
                    registration,
                ) = self.fixture(
                    suffix=f"remote-local-gate-{ordinal}",
                    category="pwn",
                    action=copy.deepcopy(action),
                    active_remote_target=True,
                )
                self.assertEqual(publication.published_count, 1)
                self.assertEqual(registration.experiment_ids, ())
                self.assertEqual(
                    registration.rejection_code,
                    "typed_gate_pwn_local_only_with_remote_target",
                )

                state = engine.store.load(identity)
                self.assertEqual(
                    orchestrator._select_actions(state, wave),
                    (),
                )
                self.assertFalse(
                    any(
                        item.extra.get("engine_executor")
                        == "managed_typed_gate_v1"
                        for item in state.experiments
                    )
                )
                builder_run = next(
                    item
                    for item in state.runs
                    if item.id == result.invocation.run_id
                )
                self.assertEqual(
                    builder_run.extra["rejected_actions"],
                    [
                        {
                            "action": "1",
                            "reason": (
                                "typed_gate_pwn_local_only_with_remote_target"
                            ),
                        }
                    ],
                )
                locator = next(
                    value
                    for key, value in action.items()
                    if key.endswith("_artifact_path")
                )
                self.assertTrue(
                    any(
                        item.run_id == result.invocation.run_id
                        and item.destination == locator
                        and item.status == "published"
                        for item in state.workspace_publishes
                    )
                )
                self.assertTrue(
                    (
                        engine.store.challenge_paths(identity).artifacts
                        / "workspace"
                        / str(locator)
                    ).is_file()
                )

    def test_oracle_preissue_must_predate_builder_registration(self):
        action = {
            "kind": "prove_crypto_metamorphic",
            "description": "reject a late hidden oracle",
            "candidate_id": "placeholder",
            "solver_artifact_path": "crypto/solver.py",
            "original_parameters_artifact_path": "crypto/original.json",
            "oracle_preissue_id": "placeholder",
            "runtime": "python",
        }
        (
            _engine,
            _orchestrator,
            _identity,
            _session_id,
            _cycle,
            _wave,
            _result,
            _publish,
            registration,
        ) = self.fixture(
            suffix="late-oracle",
            category="crypto",
            action=action,
            builder_predates_preissue=True,
        )
        self.assertEqual(registration.experiment_ids, ())
        self.assertEqual(
            registration.rejection_code,
            "typed_gate_oracle_preissue_invalid",
        )

    def test_all_typed_gates_bind_current_builder_artifacts(self):
        cases = (
            (
                "pwn",
                {
                    "kind": "prove_pwn_exploit_effect",
                    "description": "prove effect",
                    "parent_experiment_id": "placeholder",
                    "payload_artifact_path": "pwn/exploit.bin",
                    "timeout_seconds": 300,
                },
            ),
            (
                "web",
                {
                    "kind": "prove_web_impact",
                    "description": "prove impact",
                    "operator_spec_artifact_path": "web/spec.json",
                    "driver_artifact_path": "web/driver.json",
                    "hypothesis_ids": ["local-web"],
                    "timeout_seconds": 900,
                },
            ),
            (
                "web",
                {
                    "kind": "prove_web_active_probe",
                    "description": "prove bounded race/OOB impact",
                    "operator_spec_artifact_path": (
                        "web/active-spec.json"
                    ),
                    "driver_artifact_path": (
                        "web/active-driver.json"
                    ),
                    "hypothesis_ids": ["local-web-active"],
                    "timeout_seconds": 900,
                },
            ),
            (
                "crypto",
                {
                    "kind": "prove_crypto_metamorphic",
                    "description": "prove metamorphic solver",
                    "candidate_id": "placeholder",
                    "solver_artifact_path": "crypto/solver.py",
                    "original_parameters_artifact_path": (
                        "crypto/original.json"
                    ),
                    "oracle_preissue_id": "placeholder",
                    "runtime": "python",
                },
            ),
            (
                "forensics",
                {
                    "kind": "prove_forensic_assertion",
                    "description": "corroborate assertion",
                    "operator_spec_artifact_path": "forensic/spec.json",
                    "hypothesis_ids": [],
                    "timeout_seconds": 900,
                },
            ),
            (
                "misc",
                {
                    "kind": "evaluate_misc_transform",
                    "description": "evaluate DAG",
                    "candidate_id": "placeholder",
                    "spec_artifact_path": "misc/spec.json",
                    "oracle_preissue_id": "placeholder",
                },
            ),
        )
        for ordinal, (category, action) in enumerate(cases, start=1):
            with self.subTest(category=category):
                (
                    engine,
                    _orchestrator,
                    identity,
                    _session_id,
                    _cycle,
                    _wave,
                    result,
                    publish,
                    registration,
                ) = self.fixture(
                    suffix=f"valid-{ordinal}",
                    category=category,
                    action=copy.deepcopy(action),
                )
                self.assertIsNone(registration.rejection_code)
                self.assertEqual(len(registration.experiment_ids), 1)
                self.assertEqual(
                    publish.published_count,
                    sum(
                        field.endswith("_artifact_path")
                        for field in result.output["actions"][0]
                    ),
                )
                state = engine.store.load(identity)
                experiment = next(
                    item
                    for item in state.experiments
                    if item.id == registration.experiment_ids[0]
                )
                request = experiment.extra[
                    "managed_typed_gate_request"
                ]
                self.assertEqual(
                    request["action_kind"],
                    action["kind"],
                )
                self.assertEqual(
                    request["source_builder_run_id"],
                    result.invocation.run_id,
                )
                self.assertEqual(
                    set(request["artifact_bindings"]),
                    {
                        field
                        for field in action
                        if field.endswith("_artifact_path")
                    },
                )
                self.assertTrue(experiment.artifact_ids)
                self.assertEqual(
                    experiment.extra["engine_executor"],
                    "managed_typed_gate_v1",
                )

    def test_crypto_and_misc_private_dispatch_rejects_raw_oracle_bypass(self):
        cases = (
            ("crypto", "prove_crypto_metamorphic_candidate"),
            ("misc", "evaluate_misc_transform_candidate"),
        )
        for ordinal, (category, method_name) in enumerate(cases, start=1):
            with self.subTest(category=category):
                identity = ChallengeIdentity(
                    "Managed Typed Gates",
                    category,
                    f"lock-owned-{ordinal}",
                )
                incoming = (
                    self.root
                    / "incoming"
                    / identity.contest_id
                    / identity.category
                    / identity.challenge_id
                )
                incoming.mkdir(parents=True)
                (incoming / "challenge.bin").write_bytes(b"lock-owned")
                engine = self.engine()
                engine.add_challenge(
                    identity,
                    prompt="test private lock reuse",
                    state_schema_version=STATE_SCHEMA_VERSION,
                )
                lock = ChallengeLock(
                    engine.store.challenge_paths(identity).runtime
                    / "session.lock",
                    timeout=0,
                ).acquire()
                try:
                    method = getattr(engine, method_name)
                    if category == "crypto":
                        kwargs = {
                            "solver_locator": "missing-solver.py",
                            "original_parameters_locator": "missing-o.json",
                            "variant_parameters_locator": "missing-v.json",
                            "variant_expected_output_locator": (
                                "missing-e.bin"
                            ),
                            "mutation_id": "variant-1",
                        }
                    else:
                        kwargs = {"spec_locator": "missing-spec.json"}
                    with self.assertRaises(SessionAlreadyRunning):
                        method(identity, "C-missing", **kwargs)
                    with self.assertRaises(EngineError) as raised:
                        method(
                            identity,
                            "C-missing",
                            _session_owned=True,
                            **kwargs,
                        )
                    self.assertNotIsInstance(
                        raised.exception,
                        SessionAlreadyRunning,
                    )
                    self.assertIn(
                        "preissue",
                        str(raised.exception).lower(),
                    )
                finally:
                    lock.release()

    def test_typed_gate_rejects_hostile_context_and_action_mutations(self):
        cases = (
            {
                "suffix": "wrong-category",
                "category": "rev",
                "action": {
                    "kind": "prove_web_impact",
                    "description": "wrong category",
                    "operator_spec_artifact_path": "spec.json",
                    "driver_artifact_path": "driver.json",
                    "hypothesis_ids": [],
                    "timeout_seconds": 10,
                },
                "reason": "typed_gate_wrong_category",
            },
            {
                "suffix": "wrong-role",
                "category": "web",
                "role": Role.FALSIFIER,
                "action": {
                    "kind": "prove_web_impact",
                    "description": "wrong role",
                    "operator_spec_artifact_path": "spec.json",
                    "driver_artifact_path": "driver.json",
                    "hypothesis_ids": [],
                    "timeout_seconds": 10,
                },
                "reason": "typed_gate_wrong_role",
            },
            {
                "suffix": "wrong-wave",
                "category": "web",
                "wave_name": "discovery",
                "role": Role.SPECIALIST,
                "action": {
                    "kind": "prove_web_impact",
                    "description": "wrong wave",
                    "operator_spec_artifact_path": "spec.json",
                    "driver_artifact_path": "driver.json",
                    "hypothesis_ids": [],
                    "timeout_seconds": 10,
                },
                "reason": "typed_gate_wrong_wave",
            },
            {
                "suffix": "unreported-path",
                "category": "web",
                "report_all_paths": False,
                "action": {
                    "kind": "prove_web_impact",
                    "description": "missing report",
                    "operator_spec_artifact_path": "spec.json",
                    "driver_artifact_path": "driver.json",
                    "hypothesis_ids": [],
                    "timeout_seconds": 10,
                },
                "reason": "typed_gate_artifact_unbound",
            },
            {
                "suffix": "bool-timeout",
                "category": "web",
                "action": {
                    "kind": "prove_web_impact",
                    "description": "bool timeout",
                    "operator_spec_artifact_path": "spec.json",
                    "driver_artifact_path": "driver.json",
                    "hypothesis_ids": [],
                    "timeout_seconds": True,
                },
                "reason": "typed_gate_timeout_invalid",
            },
            {
                "suffix": "extra-verdict",
                "category": "web",
                "action": {
                    "kind": "prove_web_impact",
                    "description": "self report",
                    "operator_spec_artifact_path": "spec.json",
                    "driver_artifact_path": "driver.json",
                    "hypothesis_ids": [],
                    "timeout_seconds": 10,
                    "verdict": "CONFIRMED",
                },
                "reason": "typed_gate_action_invalid",
            },
        )
        for case in cases:
            with self.subTest(case=case["suffix"]):
                fixture = self.fixture(
                    suffix=str(case["suffix"]),
                    category=str(case["category"]),
                    action=copy.deepcopy(case["action"]),
                    role=case.get("role", Role.BUILDER),
                    wave_name=str(case.get("wave_name", "attack")),
                    report_all_paths=bool(
                        case.get("report_all_paths", True)
                    ),
                )
                registration = fixture[-1]
                self.assertEqual(
                    registration.rejection_code,
                    case["reason"],
                )
                self.assertEqual(registration.experiment_ids, ())

    def test_deterministic_result_alone_terminalizes_and_capsules_gate(self):
        action = {
            "kind": "prove_forensic_assertion",
            "description": "corroborate assertion",
            "operator_spec_artifact_path": "forensic/spec.json",
            "hypothesis_ids": [],
            "timeout_seconds": 900,
        }
        (
            engine,
            orchestrator,
            identity,
            session_id,
            cycle,
            wave,
            _result,
            _publish,
            registration,
        ) = self.fixture(
            suffix="deterministic-nonpass",
            category="forensics",
            action=action,
        )
        experiment_id = registration.experiment_ids[0]
        orchestrator._mark_action_selection(
            identity,
            session_id,
            cycle.id,
            (experiment_id,),
        )
        evaluation = mock.Mock(
            confirmed=False,
            reason_codes=("corroboration_failed",),
            sha256="c" * 64,
        )
        with mock.patch.object(
            engine,
            "prove_forensic_assertion",
            return_value=(engine.store.load(identity), evaluation),
        ) as prove:
            state = orchestrator._execute_selected_actions(
                identity,
                (experiment_id,),
                record_stall=False,
            )
        prove.assert_called_once_with(
            identity,
            operator_spec_locator="forensic/spec.json",
            hypothesis_ids=(),
            timeout_seconds=900,
            _session_owned=True,
        )
        experiment = next(
            item
            for item in state.experiments
            if item.id == experiment_id
        )
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        self.assertFalse(experiment.result["passed"])
        self.assertEqual(
            experiment.result["authority"],
            "engine_deterministic_gate",
        )
        checkpointed = orchestrator._checkpoint_selected_actions(
            identity,
            session_id,
            cycle.id,
            wave,
            (experiment_id,),
            note=None,
        )
        capsule = checkpointed.checkpoints[-1].failure_capsule
        self.assertIsNotNone(capsule)
        self.assertEqual(
            capsule.reason_code,
            "managed_typed_gate_nonpass",
        )
        self.assertIn(experiment_id, capsule.failed_experiment_ids)

    def test_web_active_probe_dispatch_uses_engine_owned_matrix(self):
        action = {
            "kind": "prove_web_active_probe",
            "description": "prove bounded race impact",
            "operator_spec_artifact_path": "web/active-spec.json",
            "driver_artifact_path": "web/active-driver.json",
            "hypothesis_ids": [],
            "timeout_seconds": 900,
        }
        (
            engine,
            orchestrator,
            identity,
            _session_id,
            _cycle,
            _wave,
            _result,
            _publish,
            registration,
        ) = self.fixture(
            suffix="active-dispatch",
            category="web",
            action=action,
        )
        experiment_id = registration.experiment_ids[0]
        before = engine.store.load(identity)
        evaluation = {
            "authorities": {
                "candidate_authorized": False,
                "submission_authorized": False,
            },
            "confirmed": True,
            "evaluation_sha256": "a" * 64,
            "reason_codes": [],
        }
        with mock.patch.object(
            engine,
            "prove_web_active_probe",
            return_value=(before, evaluation),
        ) as prove:
            state = orchestrator._execute_typed_gate_experiment(
                identity,
                experiment_id,
            )
        prove.assert_called_once_with(
            identity,
            operator_spec_locator="web/active-spec.json",
            driver_locator="web/active-driver.json",
            hypothesis_ids=(),
            timeout_seconds=900,
            _session_owned=True,
        )
        experiment = next(
            item
            for item in state.experiments
            if item.id == experiment_id
        )
        self.assertIs(experiment.status, ExperimentStatus.COMPLETED)
        self.assertTrue(experiment.result["passed"])
        self.assertEqual(
            experiment.result["evaluation_sha256"],
            "a" * 64,
        )
        self.assertEqual(state.candidates, before.candidates)
        self.assertEqual(state.submissions, before.submissions)

    def test_gate_exception_is_bounded_and_never_uses_model_verdict(self):
        action = {
            "kind": "evaluate_misc_transform",
            "description": "evaluate DAG",
            "candidate_id": "placeholder",
            "spec_artifact_path": "misc/spec.json",
            "oracle_preissue_id": "placeholder",
        }
        (
            engine,
            orchestrator,
            identity,
            _session_id,
            _cycle,
            _wave,
            _result,
            _publish,
            registration,
        ) = self.fixture(
            suffix="execution-error",
            category="misc",
            action=action,
        )
        experiment_id = registration.experiment_ids[0]
        secret = "must-not-enter-state"
        with mock.patch.object(
            engine,
            "evaluate_misc_transform_candidate",
            side_effect=EngineError(secret),
        ):
            state = orchestrator._execute_typed_gate_experiment(
                identity,
                experiment_id,
            )
        experiment = next(
            item
            for item in state.experiments
            if item.id == experiment_id
        )
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        self.assertNotIn(secret, json.dumps(experiment.result))
        self.assertEqual(
            experiment.result["reason_codes"],
            ["typed_gate_execution_error"],
        )

    def test_post_registration_workspace_mutation_fails_into_capsule(self):
        action = {
            "kind": "prove_web_impact",
            "description": "prove impact",
            "operator_spec_artifact_path": "web/spec.json",
            "driver_artifact_path": "web/driver.json",
            "hypothesis_ids": [],
            "timeout_seconds": 60,
        }
        (
            engine,
            orchestrator,
            identity,
            session_id,
            cycle,
            wave,
            _result,
            _publish,
            registration,
        ) = self.fixture(
            suffix="workspace-mutated",
            category="web",
            action=action,
        )
        experiment_id = registration.experiment_ids[0]
        workspace = (
            engine.store.challenge_paths(identity).artifacts / "workspace"
        )
        (workspace / "web" / "driver.json").write_bytes(
            b"hostile replacement\n"
        )
        orchestrator._mark_action_selection(
            identity,
            session_id,
            cycle.id,
            (experiment_id,),
        )
        with mock.patch.object(
            engine,
            "prove_web_impact",
        ) as prove:
            state = orchestrator._execute_selected_actions(
                identity,
                (experiment_id,),
                record_stall=False,
            )
        prove.assert_not_called()
        experiment = next(
            item
            for item in state.experiments
            if item.id == experiment_id
        )
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        self.assertEqual(
            experiment.result["reason_codes"],
            ["typed_gate_dispatch_rejected"],
        )
        checkpointed = orchestrator._checkpoint_selected_actions(
            identity,
            session_id,
            cycle.id,
            wave,
            (experiment_id,),
            note=None,
        )
        self.assertEqual(
            checkpointed.checkpoints[-1].failure_capsule.reason_code,
            "managed_typed_gate_nonpass",
        )

    def test_run_cycle_dispatches_builder_gate_and_reinjects_failure(self):
        class TypedForensicExecutor:
            def __init__(self) -> None:
                self.prompts: list[tuple[Role, str]] = []

            def run(
                self,
                command,
                *,
                cwd,
                timeout,
                on_stdout_line,
            ):
                del timeout, on_stdout_line
                role = _role_for(command)
                self.prompts.append((role, command.stdin))
                payload = _payload(role)
                payload["schema_version"] = 2
                payload["hypotheses"] = []
                payload["actions"] = [
                    {
                        "kind": "none",
                        "description": "no engine action",
                        "command": None,
                        "artifact_path": None,
                        "hypothesis_ids": [],
                        "expected_observation": "",
                        "keep_if": "",
                        "drop_if": "",
                        "timeout_seconds": 1,
                        "resource_class": "light",
                        "network_target_id": None,
                        "network_target_generation": None,
                    }
                ]
                if role is Role.CAPTAIN:
                    payload["decision"] = {
                        "next_stage": "attack",
                        "reason": "exercise the typed forensic gate",
                        "selected_experiment": None,
                    }
                    payload["hypotheses"] = [
                        {
                            "id": f"hyp-{ordinal}",
                            "claim": f"forensic claim {ordinal}",
                            "evidence": ["obs-1"],
                            "unknowns": ["independent corroboration"],
                            "experiment": "run exact typed gate",
                            "success_oracle": "engine confirms",
                            "falsifier": "engine rejects",
                        }
                        for ordinal in range(1, 4)
                    ]
                elif role is Role.BUILDER:
                    spec = Path(cwd) / "forensic" / "spec.json"
                    spec.parent.mkdir(parents=True, exist_ok=True)
                    spec_payload = b'{"strict":"bounded"}\n'
                    spec.write_bytes(spec_payload)
                    payload["artifacts"] = [
                        {
                            "path": "forensic/spec.json",
                            "sha256": hashlib.sha256(
                                spec_payload
                            ).hexdigest(),
                            "purpose": "typed assertion specification",
                        }
                    ]
                    payload["actions"] = [
                        {
                            "kind": "prove_forensic_assertion",
                            "description": "run independent corroboration",
                            "operator_spec_artifact_path": (
                                "forensic/spec.json"
                            ),
                            "hypothesis_ids": [],
                            "timeout_seconds": 30,
                        }
                    ]
                _output_path(command).write_text(
                    json.dumps(payload),
                    encoding="utf-8",
                )
                return ProcessOutcome(0, "", 0.01)

        identity = ChallengeIdentity(
            "Managed Typed Gates",
            "forensics",
            "full-cycle",
        )
        incoming = (
            self.root
            / "incoming"
            / identity.contest_id
            / identity.category
            / identity.challenge_id
        )
        incoming.mkdir(parents=True)
        (incoming / "evidence.bin").write_bytes(b"forensic evidence")
        executor = TypedForensicExecutor()
        engine = self.engine(executor)
        engine.add_challenge(
            identity,
            prompt="corroborate one forensic assertion",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self.capability,
        )
        evaluation = mock.Mock(
            confirmed=False,
            reason_codes=("corroboration_failed",),
            sha256="d" * 64,
        )
        with (
            mock.patch.object(
                engine,
                "synchronize_managed_adapter_seed_plan",
                side_effect=lambda selected, session: engine.store.load(
                    selected
                ),
            ),
            mock.patch.object(
                engine,
                "prove_forensic_assertion",
                return_value=(engine.store.load(identity), evaluation),
            ) as prove,
        ):
            state = orchestrator.run_cycle(identity)
            first_capsule = state.checkpoints[-1].failure_capsule
            self.assertIsNotNone(first_capsule)
            state = orchestrator.run_cycle(identity)

        self.assertEqual(prove.call_count, 2)
        self.assertEqual(
            prove.call_args.kwargs["operator_spec_locator"],
            "forensic/spec.json",
        )
        self.assertTrue(prove.call_args.kwargs["_session_owned"])
        typed = [
            item
            for item in state.experiments
            if item.extra.get("engine_executor")
            == "managed_typed_gate_v1"
        ]
        self.assertEqual(len(typed), 2)
        self.assertTrue(
            all(
                item.status is ExperimentStatus.FAILED
                for item in typed
            )
        )
        capsule = first_capsule
        self.assertIsNotNone(capsule)
        assert capsule is not None
        self.assertEqual(
            capsule.reason_code,
            "managed_typed_gate_nonpass",
        )
        captain_prompts = [
            prompt
            for role, prompt in executor.prompts
            if role is Role.CAPTAIN
        ]
        self.assertGreaterEqual(len(captain_prompts), 2)
        self.assertIn(
            capsule.reason_code,
            captain_prompts[-1],
        )
        self.assertIn(
            capsule.fingerprint_sha256,
            captain_prompts[-1],
        )


class ProtocolAndMigrationTests(unittest.TestCase):
    def test_strict_json_and_canonical_record_boundaries(self):
        hostile = {
            "value": "line1\n```\u202e<tag>",
            "control": "\x1b[31m",
        }
        record = canonical_json_record(hostile)
        self.assertNotIn("\n", record)
        self.assertNotIn("`", record)
        self.assertNotIn("<", record)
        self.assertNotIn(">", record)
        self.assertEqual(strict_json_loads(record), hostile)

        rejected = (
            b'{"a":1,"a":2}',
            b'{"a":NaN}',
            b'{"a":Infinity}',
            b'{"a":1e9999}',
            b'{"a":"\\ud800"}',
            b'{"a":"\xff"}',
        )
        for payload in rejected:
            with self.subTest(payload=payload), self.assertRaises(
                StrictJSONError
            ):
                strict_json_loads(payload)

    def _legacy_workspace(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        identity = ChallengeIdentity("Legacy", "rev", "migrate")
        incoming = (
            root
            / "incoming"
            / identity.contest_id
            / identity.category
            / identity.challenge_id
        )
        incoming.mkdir(parents=True)
        (incoming / "input").write_bytes(b"legacy")
        engine = ChallengeEngine(
            root,
            batch_runner=BatchRunner(
                process_executor=ProbeRoleExecutor(),
                max_schema_retries=0,
            ),
            sandbox_factory=lambda state, work, policy: FakeSandbox(work),
        )
        engine.add_challenge(identity, prompt="legacy solve")
        return temporary, root, identity, engine

    def test_explicit_migration_is_stable_and_exactly_rollbackable(self):
        temporary, root, identity, engine = self._legacy_workspace()
        self.addCleanup(temporary.cleanup)
        paths = engine.store.challenge_paths(identity)
        before = paths.state.read_bytes()
        previous_before = (
            paths.previous_state.read_bytes()
            if paths.previous_state.exists()
            else None
        )
        first = plan_migration(root)
        self.assertFalse(first["zero_diff"])
        applied = apply_migration(root)
        self.assertEqual(applied["status"], "applied")
        self.assertTrue(plan_migration(root)["zero_diff"])
        self.assertEqual(
            int(read_json(paths.state)["schema_version"]),
            STATE_SCHEMA_VERSION,
        )
        rolled_back = rollback_migration(root)
        self.assertEqual(rolled_back["status"], "rolled_back")
        self.assertEqual(paths.state.read_bytes(), before)
        if previous_before is None:
            self.assertFalse(paths.previous_state.exists())
        else:
            self.assertEqual(
                paths.previous_state.read_bytes(),
                previous_before,
            )

    def test_interrupted_rollback_resumes_from_exact_v1_or_v2_bytes(self):
        temporary, root, identity, engine = self._legacy_workspace()
        self.addCleanup(temporary.cleanup)
        paths = engine.store.challenge_paths(identity)
        before = paths.state.read_bytes()
        apply_migration(root)
        real_write = migration_module.atomic_write_bytes
        calls = 0

        def interrupt_second_restore(path, payload, *args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("synthetic rollback interruption")
            return real_write(path, payload, *args, **kwargs)

        with (
            mock.patch.object(
                migration_module,
                "atomic_write_bytes",
                side_effect=interrupt_second_restore,
            ),
            self.assertRaisesRegex(OSError, "synthetic rollback"),
        ):
            rollback_migration(root)
        marker = read_json(root / ".ctfos" / "migration.json")
        self.assertEqual(marker["status"], "migrating")
        self.assertEqual(marker["operation"], "rollback")

        resumed = rollback_migration(root)
        self.assertEqual(resumed["status"], "rolled_back")
        self.assertEqual(paths.state.read_bytes(), before)
        self.assertEqual(
            read_json(root / ".ctfos" / "migration.json")["status"],
            "rolled_back",
        )

    def test_migration_install_fault_restores_original_bytes(self):
        temporary, root, identity, engine = self._legacy_workspace()
        self.addCleanup(temporary.cleanup)
        paths = engine.store.challenge_paths(identity)
        before = paths.state.read_bytes()
        real_write = migration_module.atomic_write_bytes
        failed = False

        def fail_state_install(path, payload, *args, **kwargs):
            nonlocal failed
            if (
                Path(path) == paths.state
                and b'"schema_version": 2' in payload
                and not failed
            ):
                failed = True
                raise OSError("synthetic state install fault")
            return real_write(path, payload, *args, **kwargs)

        with (
            mock.patch.object(
                migration_module,
                "atomic_write_bytes",
                side_effect=fail_state_install,
            ),
            self.assertRaisesRegex(OSError, "synthetic"),
        ):
            apply_migration(root, migration_id="fault")
        self.assertEqual(paths.state.read_bytes(), before)
        self.assertEqual(
            read_json(root / ".ctfos" / "migration.json")["status"],
            "failed_rolled_back",
        )

    def test_operational_v2_commit_forbids_downgrade(self):
        temporary, root, identity, engine = self._legacy_workspace()
        self.addCleanup(temporary.cleanup)
        apply_migration(root)
        engine.update_prompt(identity, "operational v2 commit")
        with self.assertRaisesRegex(
            migration_module.MigrationError,
            "operational commit",
        ):
            rollback_migration(root)

    def test_migration_marker_blocks_state_and_run_writes(self):
        temporary, root, identity, engine = self._legacy_workspace()
        self.addCleanup(temporary.cleanup)
        atomic_write_json(
            root / ".ctfos" / "migration.json",
            {
                "migration_id": "blocked",
                "status": "migrating",
                "active_schema": 1,
            },
        )
        with self.assertRaises(MigrationInProgress):
            engine.store.update(identity, lambda state: None)
        with self.assertRaises(MigrationInProgress):
            engine.store.create_run(identity, run_id="blocked")

    def test_commit_telemetry_contains_only_operational_shadow_fields(self):
        temporary, root, identity, engine = self._legacy_workspace()
        self.addCleanup(temporary.cleanup)
        secret = "KCTF{must_not_enter_telemetry}"
        engine.update_prompt(identity, secret)
        telemetry_path = (
            root / ".ctfos" / "runtime" / "telemetry.jsonl"
        )
        payload = telemetry_path.read_text(encoding="utf-8")
        self.assertNotIn(secret, payload)
        records = [
            strict_json_loads(line)
            for line in payload.splitlines()
            if line
        ]
        latest = records[-1]
        self.assertEqual(latest["event"], "state_commit")
        self.assertEqual(latest["delta_shadow_mismatches"], 0)
        self.assertIn("artifact_hash_bytes", latest)
        self.assertIn("lock_wait_ms", latest)
        self.assertIn("board_shadow_match", latest)


class WorkspacePublishTests(unittest.TestCase):
    def test_builder_publish_recovers_after_filesystem_state_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identity = ChallengeIdentity("Publish", "rev", "one")
            incoming = (
                root
                / "incoming"
                / identity.contest_id
                / identity.category
                / identity.challenge_id
            )
            incoming.mkdir(parents=True)
            (incoming / "input").write_bytes(b"x")
            config = load_config(root)
            config = replace(
                config,
                runtime=replace(
                    config.runtime,
                    image_digest=IMAGE_DIGEST,
                ),
            )
            engine = ChallengeEngine(root, config=config)
            engine.add_challenge(
                identity,
                prompt="publish",
                state_schema_version=STATE_SCHEMA_VERSION,
            )
            run_id = "MR-builder-publish"
            run_paths = engine.store.create_run(
                identity,
                run_id=run_id,
                request={"kind": "model", "role": "builder"},
            )
            engine.store.write_run_result(
                identity,
                run_id,
                {"status": "completed"},
            )
            engine.store.write_run_validation(
                identity,
                run_id,
                {"ok": True},
            )
            run_paths.root.joinpath("workspace").mkdir()
            run_paths.root.joinpath("workspace", "solve.py").write_text(
                "print('complete')\n",
                encoding="utf-8",
            )
            challenge_root = engine.store.challenge_paths(identity).root

            def add_run(state):
                state.runs.append(
                    RunReference(
                        id=run_id,
                        base_revision=state.revision,
                        status=RunStatus.COMPLETED,
                        request_path=run_paths.request.relative_to(
                            challenge_root
                        ).as_posix(),
                        result_path=run_paths.result.relative_to(
                            challenge_root
                        ).as_posix(),
                        validation_path=run_paths.validation.relative_to(
                            challenge_root
                        ).as_posix(),
                        role="builder",
                        origin=RunOrigin.MANAGED_MODEL,
                        configuration_epoch=state.configuration_epoch,
                    )
                )

            engine.store.update(identity, add_run)
            real_update = engine.store.update
            with (
                mock.patch.object(
                    engine.store,
                    "update",
                    side_effect=OSError("synthetic commit fault"),
                ),
                self.assertRaisesRegex(OSError, "synthetic"),
            ):
                publish_builder_file(
                    engine,
                    identity,
                    run_id=run_id,
                    staged_path="solve.py",
                    destination="solve.py",
                    base_workspace_revision=0,
                    base_sha256=None,
                )

            canonical = (
                engine.store.challenge_paths(identity).artifacts
                / "workspace"
                / "solve.py"
            )
            self.assertEqual(
                canonical.read_text(encoding="utf-8"),
                "print('complete')\n",
            )
            reconciled = reconcile_workspace_publishes(engine, identity)
            self.assertEqual(len(reconciled), 1)
            state = engine.store.load(identity)
            self.assertEqual(state.workspace_revision, 1)
            self.assertEqual(len(state.workspace_publishes), 1)


if __name__ == "__main__":
    unittest.main()
