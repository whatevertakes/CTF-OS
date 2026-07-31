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
from ctf_os.engine.context_pack import build_context_pack
from ctf_os.engine.resume_capsule import (
    ResumeCapsulePolicy,
    render_resume_capsule,
)
from ctf_os.lifecycle import close_challenge, create_checkpoint
from ctf_os.managed import ManagedError, ManagedOrchestrator
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
    Falsifier,
    Hypothesis,
    ModelValidationError,
    RunOrigin,
    RunReference,
    RunStatus,
    SessionStatus,
)
from ctf_os.sandbox import SandboxResult
from ctf_os.schema import STATE_SCHEMA_VERSION
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
                        argv and argv[0] == "objdump"
                        for argv in pre_captain_argv
                    )
                )
                self.assertTrue(
                    any(
                        argv and argv[0] == "ctfwrap"
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
        self.assertEqual(len(legacy_ids), 2)

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
        self.assertEqual(len(bound), 2)
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
            self.assertTrue(
                (paths.runs / run.id / "provider.json").is_file()
            )
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
                        "configuration_epoch": run.configuration_epoch,
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
