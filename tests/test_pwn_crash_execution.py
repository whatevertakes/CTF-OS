from __future__ import annotations

import hashlib
import json
import struct
import tempfile
import unittest
from dataclasses import replace
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ctf_os.codex import Role
from ctf_os.capabilities import REQUIRED_MANAGED_ATTESTATIONS
from ctf_os.config import load_config
from ctf_os.contracts.pwn_crash_v1 import (
    PWN_CRASH_V1_CONTRACT_FINGERPRINT,
    PWN_CRASH_V1_CONTRACT_ID,
    PWN_CRASH_V1_CONTRACT_VERSION,
    PWN_CRASH_V1_PROTOCOL,
    PWN_CRASH_V1_SCHEMA_VERSION,
    pwn_crash_v1_canonical_json_bytes,
)
from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.engine.pwn_crash import PwnCrashRecipe
from ctf_os.managed import ManagedOrchestrator
from ctf_os.models import (
    ArtifactReference,
    CandidateStatus,
    ChallengeIdentity,
    ChallengeStatus,
    ExperimentStatus,
    Falsifier,
    Hypothesis,
    HypothesisStatus,
    RunStatus,
)
from ctf_os.sandbox import ArtifactRef, SandboxResult
from ctf_os.schema import STATE_SCHEMA_VERSION


IMAGE_DIGEST = "sha256:" + ("1" * 64)


def _elf64_executable() -> bytes:
    identity = bytearray(16)
    identity[:4] = b"\x7fELF"
    identity[4] = 2
    identity[5] = 1
    identity[6] = 1
    return struct.pack(
        "<16sHHIQQQIHHHHHH",
        bytes(identity),
        2,
        62,
        1,
        0,
        64,
        0,
        0,
        64,
        56,
        0,
        0,
        0,
        0,
    )


def _argument(argv: tuple[str, ...], name: str) -> str:
    index = argv.index(name)
    return argv[index + 1]


class _PwnCrashSandbox:
    scope_fingerprint = "a" * 64

    def __init__(self, owner, work: Path, policy) -> None:
        self.owner = owner
        self.work = work
        self.policy = policy

    def initialize_workspace(self, **_kwargs):
        raise AssertionError("not used")

    def run(self, _spec):
        self.owner.generic_calls += 1
        raise AssertionError("the engine sentinel must never reach generic run")

    def start_job(self, *_args, **_kwargs):
        raise AssertionError("not used")

    def job_status(self, *_args, **_kwargs):
        raise AssertionError("not used")

    def job_log(self, *_args, **_kwargs):
        raise AssertionError("not used")

    def cancel_job(self, *_args, **_kwargs):
        raise AssertionError("not used")

    def register_artifact(self, locator, *, maximum_bytes):
        path = self.work / locator
        if path.stat().st_size > maximum_bytes:
            raise OSError("artifact exceeds requested bound")
        return ArtifactRef(
            locator=locator,
            sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            size_bytes=path.stat().st_size,
            scope_fingerprint=self.scope_fingerprint,
        )

    def run_clean_proof(
        self,
        spec,
        *,
        input_locators=(),
        proof_inputs=(),
    ):
        self.owner.clean_calls += 1
        self.owner.specs.append(spec)
        self.owner.policies.append(self.policy)
        self.owner.proof_inputs.append(tuple(proof_inputs))
        if input_locators or len(proof_inputs) != 1:
            raise AssertionError("one typed proof input is required")
        proof_input = proof_inputs[0]
        payload = (self.work / proof_input.source_locator).read_bytes()
        if (
            proof_input.destination_locator != "pwn-crash-v1/input.bin"
            or hashlib.sha256(payload).hexdigest() != proof_input.sha256
            or len(payload) != proof_input.size_bytes
        ):
            raise AssertionError("staged proof input binding changed")
        argv = spec.argv
        ordinal = int(_argument(argv, "--ordinal"))
        phase = _argument(argv, "--phase")
        termination, target_exit, signal_number = self.owner.statuses[
            ordinal - 1
        ]
        document = {
            "binding": {
                "input_sha256": _argument(argv, "--input-sha256"),
                "input_size_bytes": int(
                    _argument(argv, "--input-size-bytes")
                ),
                "ordinal": ordinal,
                "phase": phase,
                "recipe_sha256": _argument(argv, "--recipe-sha256"),
                "source_manifest_sha256": _argument(
                    argv,
                    "--source-manifest-sha256",
                ),
                "source_sha256": _argument(argv, "--source-sha256"),
                "source_size_bytes": int(
                    _argument(argv, "--source-size-bytes")
                ),
            },
            "contract": {
                "fingerprint": PWN_CRASH_V1_CONTRACT_FINGERPRINT,
                "id": PWN_CRASH_V1_CONTRACT_ID,
                "version": PWN_CRASH_V1_CONTRACT_VERSION,
            },
            "reason_code": "observation_recorded",
            "schema_version": PWN_CRASH_V1_SCHEMA_VERSION,
            "status": "ok",
            "target": {
                "exit_code": target_exit,
                "signal_number": signal_number,
                "termination": termination,
            },
        }
        stdout_payload = pwn_crash_v1_canonical_json_bytes(document)
        proof_root = self.work / "proof"
        proof_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        proof_root.chmod(0o700)
        directory = proof_root / f"clean-{ordinal:012x}"
        directory.mkdir(mode=0o700, exist_ok=True)
        directory.chmod(0o700)
        stdout = directory / "stdout.log"
        stderr = directory / "stderr.log"
        stdout.write_bytes(stdout_payload)
        stderr.write_bytes(self.owner.stderr_payload)
        stdout.chmod(0o400)
        stderr.chmod(0o400)
        if self.owner.on_attempt is not None:
            self.owner.on_attempt(ordinal)
        truncated = ordinal in self.owner.truncated_ordinals
        return SandboxResult(
            run_id=f"sandbox-{ordinal}",
            status="completed",
            exit_code=0,
            timed_out=False,
            duration_ms=5,
            stdout_summary="producer observation",
            stderr_summary="",
            stdout_bytes=len(stdout_payload),
            stderr_bytes=len(self.owner.stderr_payload),
            stdout_path=(
                f"/work/proof/clean-{ordinal:012x}/stdout.log"
            ),
            stderr_path=(
                f"/work/proof/clean-{ordinal:012x}/stderr.log"
            ),
            stdout_stored_bytes=len(stdout_payload),
            stderr_stored_bytes=len(self.owner.stderr_payload),
            stdout_limit_bytes=16 * 1024,
            stderr_limit_bytes=64 * 1024,
            stdout_truncated=truncated,
            stderr_truncated=False,
            stdout_truncation_known=True,
            stderr_truncation_known=True,
            stdout_capture_complete=not truncated,
            stderr_capture_complete=True,
            stdout_error=None,
            stderr_error=None,
            stream_capture_error=None,
            orchestration_error=None,
        )


class _SandboxCoordinator:
    def __init__(
        self,
        statuses,
        *,
        truncated_ordinals=(),
        stderr_payload=b"",
    ) -> None:
        self.statuses = tuple(statuses)
        self.truncated_ordinals = frozenset(truncated_ordinals)
        self.stderr_payload = stderr_payload
        self.clean_calls = 0
        self.generic_calls = 0
        self.specs = []
        self.policies = []
        self.proof_inputs = []
        self.on_attempt = None

    def factory(self, _state, work, policy):
        return _PwnCrashSandbox(self, work, policy)


class PwnCrashExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.identity = ChallengeIdentity(
            "Managed CTF",
            "pwn",
            "crash-gate",
        )
        incoming = (
            self.root
            / "incoming"
            / self.identity.contest_id
            / self.identity.category
            / self.identity.challenge_id
        )
        incoming.mkdir(parents=True)
        self.binary_path = incoming / "challenge"
        self.binary_path.write_bytes(_elf64_executable())
        self.binary_path.chmod(0o500)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _capability(digest):
        return {
            "ok": True,
            "schema_version": 2,
            "image_digest": digest,
            "required": ["pwn_crash_v1"],
            "available": ["pwn_crash_v1"],
            "missing": [],
            "attestations": {
                "pwn_crash_v1": dict(
                    REQUIRED_MANAGED_ATTESTATIONS["pwn_crash_v1"]
                )
            },
            "attestation_errors": {},
        }

    def _fixture(self, coordinator: _SandboxCoordinator):
        config = load_config(self.root)
        config = replace(
            config,
            runtime=replace(
                config.runtime,
                image_digest=IMAGE_DIGEST,
            ),
        )
        engine = ChallengeEngine(
            self.root,
            config=config,
            sandbox_factory=coordinator.factory,
            capability_probe=self._capability,
        )
        engine.add_challenge(
            self.identity,
            prompt="verify one exact local stdin crash",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        orchestrator = ManagedOrchestrator(
            engine,
            capability_probe=self._capability,
        )
        _state, session_id = orchestrator._reserve_session(
            self.identity,
            None,
        )
        _state, cycle = orchestrator._reserve_cycle(
            self.identity,
            session_id,
        )
        _state, wave, role_runs = orchestrator._reserve_wave(
            self.identity,
            session_id,
            cycle.id,
            "attack",
        )
        builder_run_id = role_runs[Role.BUILDER]
        hypothesis_id = f"H-{builder_run_id}-crash"
        payload = b"A" * 32
        paths = engine.store.challenge_paths(self.identity)
        artifact_path = (
            paths.artifacts
            / "snapshots"
            / f"A-{builder_run_id}-payload.bin"
        )
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_path.write_bytes(payload)
        artifact_path.chmod(0o400)
        artifact_id = f"A-{builder_run_id}-payload"

        def seed(state):
            run = next(
                item for item in state.runs if item.id == builder_run_id
            )
            run.status = RunStatus.COMPLETED
            run.result_path = f"runs/{builder_run_id}/result.json"
            run.validation_path = f"runs/{builder_run_id}/validation.json"
            run.extra["semantic_merge"] = True
            state.hypotheses.append(
                Hypothesis(
                    id=hypothesis_id,
                    statement="the exact payload faults the primary ELF",
                    falsifier=Falsifier(
                        "exact replay is signal-free or empty input faults"
                    ),
                    source_run_id=builder_run_id,
                )
            )
            state.artifacts.append(
                ArtifactReference(
                    id=artifact_id,
                    path=artifact_path.relative_to(paths.root).as_posix(),
                    sha256=hashlib.sha256(payload).hexdigest(),
                    source_run_id=builder_run_id,
                    size=len(payload),
                    extra={
                        "reported_locator": "payload.bin",
                        "purpose": "crash payload",
                    },
                )
            )

        engine.store.update(self.identity, seed)
        result = SimpleNamespace(
            invocation=SimpleNamespace(
                role=Role.BUILDER,
                run_id=builder_run_id,
                contract_version=2,
            ),
            output={
                "hypotheses": [
                    {
                        "id": "crash",
                        "claim": "the exact payload faults the target",
                    }
                ],
                "actions": [
                    {
                        "kind": "verify_pwn_crash",
                        "description": "verify the exact crash",
                        "payload_artifact_path": "payload.bin",
                        "hypothesis_id": hypothesis_id,
                    }
                ],
            },
        )
        state = orchestrator._register_pwn_crash_actions(
            self.identity,
            wave,
            (result,),
        )
        experiment = next(
            item
            for item in state.experiments
            if item.extra.get("engine_executor")
            == "pwn_crash_differential_v1"
        )

        def select(state):
            selected_cycle = next(
                item for item in state.cycles if item.id == cycle.id
            )
            selected_cycle.selected_action_ids.append(experiment.id)

        engine.store.update(self.identity, select)
        return engine, experiment.id, artifact_path, payload

    @staticmethod
    def _confirming_statuses():
        return (
            ("signaled", None, 11),
            ("signaled", None, 11),
            ("exited", 0, None),
            ("exited", 0, None),
            ("exited", 0, None),
            ("exited", 0, None),
        )

    def _execute(self, engine, experiment_id):
        return engine.execute_registered_experiments(
            self.identity,
            maximum=1,
            _session_owned=True,
            experiment_ids=(experiment_id,),
        )

    def test_confirmed_gate_uses_six_clean_networkless_fixed_calls(self):
        coordinator = _SandboxCoordinator(self._confirming_statuses())
        engine, experiment_id, _artifact_path, payload = self._fixture(
            coordinator
        )
        capability_digests = []

        def capability_probe(digest):
            capability_digests.append(digest)
            return self._capability(digest)

        engine._capability_probe = capability_probe
        acquired_leases = []
        original_acquire = engine.lease_broker.acquire

        def acquire(request, *args, **kwargs):
            lease = original_acquire(request, *args, **kwargs)
            acquired_leases.append((request, lease))
            return lease

        engine.lease_broker.acquire = acquire
        state = self._execute(engine, experiment_id)
        experiment = next(
            item for item in state.experiments if item.id == experiment_id
        )
        recipe = PwnCrashRecipe.from_dict(
            experiment.extra["pwn_crash_recipe"]
        )
        evidence = experiment.result["pwn_crash_evidence"]
        self.assertIs(experiment.status, ExperimentStatus.KEPT)
        self.assertEqual(evidence["evaluation"]["verdict"], "CONFIRMED")
        self.assertEqual(len(evidence["attempts"]), 6)
        self.assertEqual(
            len(
                {
                    item["stdout_artifact_id"]
                    for item in evidence["attempts"]
                }
            ),
            6,
        )
        self.assertEqual(coordinator.clean_calls, 6)
        self.assertEqual(coordinator.generic_calls, 0)
        self.assertEqual(len(coordinator.specs), 6)
        self.assertEqual(capability_digests, [IMAGE_DIGEST, IMAGE_DIGEST])
        self.assertEqual(len(acquired_leases), 6)
        for ordinal, (spec, inputs, policy) in enumerate(
            zip(
                coordinator.specs,
                coordinator.proof_inputs,
                coordinator.policies,
                strict=True,
            ),
            start=1,
        ):
            self.assertEqual(spec.argv, recipe.argv_for_attempt(ordinal))
            self.assertEqual(
                set(spec.environment),
                {"CTF_WRAP_FLAG_PATTERNS_JSON"},
            )
            self.assertEqual(
                tuple(
                    json.loads(
                        spec.environment[
                            "CTF_WRAP_FLAG_PATTERNS_JSON"
                        ]
                    )
                ),
                engine.config.runtime.flag_patterns,
            )
            self.assertIsNone(spec.network_target)
            self.assertEqual(spec.resource_request.network, 0)
            self.assertEqual(policy.authorize(None), "none")
            leased_request, lease = acquired_leases[ordinal - 1]
            self.assertEqual(leased_request, spec.resource_request)
            self.assertIsNotNone(lease)
            self.assertTrue(lease.released)
            staged = inputs[0]
            self.assertEqual(
                staged.size_bytes,
                len(payload) if ordinal <= 3 else 0,
            )
            self.assertEqual(
                staged.sha256,
                hashlib.sha256(
                    payload if ordinal <= 3 else b""
                ).hexdigest(),
            )
        hypothesis = next(
            item
            for item in state.hypotheses
            if item.id == experiment.hypothesis_ids[0]
        )
        self.assertIs(hypothesis.status, HypothesisStatus.SUPPORTED)
        self.assertEqual(len(hypothesis.evidence_run_ids), 6)
        self.assertEqual(len(hypothesis.evidence_receipt_ids), 6)
        self.assertEqual(len(hypothesis.evidence_artifact_ids), 6)
        self.assertEqual(state.candidates, [])
        self.assertFalse(
            any(
                marker.extra.get("primitive_verified") is True
                for marker in state.progress_markers
            )
        )

    def test_exit_139_is_not_a_signal_crash(self):
        statuses = (
            ("exited", 139, None),
            ("exited", 139, None),
            ("exited", 139, None),
            ("exited", 0, None),
            ("exited", 0, None),
            ("exited", 0, None),
        )
        coordinator = _SandboxCoordinator(statuses)
        engine, experiment_id, _artifact_path, _payload = self._fixture(
            coordinator
        )
        state = self._execute(engine, experiment_id)
        experiment = next(
            item for item in state.experiments if item.id == experiment_id
        )
        self.assertIs(experiment.status, ExperimentStatus.INCONCLUSIVE)
        self.assertEqual(
            experiment.result["pwn_crash_evidence"]["evaluation"][
                "verdict"
            ],
            "INCONCLUSIVE",
        )

    def test_control_crash_blocks_confirmation(self):
        statuses = list(self._confirming_statuses())
        statuses[4] = ("signaled", None, 11)
        coordinator = _SandboxCoordinator(statuses)
        engine, experiment_id, _artifact_path, _payload = self._fixture(
            coordinator
        )
        state = self._execute(engine, experiment_id)
        experiment = next(
            item for item in state.experiments if item.id == experiment_id
        )
        self.assertIs(experiment.status, ExperimentStatus.INCONCLUSIVE)
        self.assertEqual(
            experiment.result["pwn_crash_evidence"]["evaluation"][
                "verdict"
            ],
            "INCONCLUSIVE",
        )

    def test_stdout_transport_truncation_fails_closed(self):
        coordinator = _SandboxCoordinator(
            self._confirming_statuses(),
            truncated_ordinals=(2,),
        )
        engine, experiment_id, _artifact_path, _payload = self._fixture(
            coordinator
        )
        state = self._execute(engine, experiment_id)
        experiment = next(
            item for item in state.experiments if item.id == experiment_id
        )
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        evaluation = experiment.result["pwn_crash_evidence"][
            "evaluation"
        ]
        self.assertEqual(evaluation["verdict"], "ERROR")
        self.assertIn("transport_", evaluation["reason_code"])

    def test_keyboard_interrupt_is_propagated_without_running_wedge(self):
        coordinator = _SandboxCoordinator(self._confirming_statuses())
        engine, experiment_id, _artifact_path, _payload = self._fixture(
            coordinator
        )
        interruption = KeyboardInterrupt("synthetic ordinal-2 interrupt")

        def interrupt(ordinal):
            if ordinal == 2:
                raise interruption

        coordinator.on_attempt = interrupt
        with self.assertRaises(KeyboardInterrupt) as raised:
            self._execute(engine, experiment_id)
        self.assertIs(raised.exception, interruption)

        state = engine.store.load(self.identity, recover=False)
        experiment = next(
            item
            for item in state.experiments
            if item.id == experiment_id
        )
        if experiment.status is ExperimentStatus.RUNNING:
            state = engine._recover_session_boundary(self.identity)
            experiment = next(
                item
                for item in state.experiments
                if item.id == experiment_id
            )

        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        self.assertEqual(set(experiment.result), {"error"})
        self.assertTrue(
            experiment.result["error"].startswith(
                "Pwn crash gate failed closed: "
            )
        )
        self.assertFalse(
            any(
                item.status is ExperimentStatus.RUNNING
                for item in state.experiments
            )
        )
        state.validate()

    def test_session_recovery_removes_only_exact_hard_death_orphans(self):
        coordinator = _SandboxCoordinator(self._confirming_statuses())
        engine, experiment_id, _artifact_path, _payload = self._fixture(
            coordinator
        )
        hard_death = SystemExit("synthetic hard process death")
        capability_calls = 0

        def capability_probe(digest):
            nonlocal capability_calls
            capability_calls += 1
            if capability_calls == 2:
                raise hard_death
            return self._capability(digest)

        engine._capability_probe = capability_probe
        with (
            patch.object(
                engine,
                "_terminalize_pwn_crash_interruption",
                return_value=None,
            ),
            patch.object(
                engine,
                "_cleanup_uncommitted_artifacts",
                return_value=None,
            ),
            patch.object(
                engine,
                "_cleanup_uncommitted_pwn_crash_runs",
                return_value=None,
            ),
            self.assertRaises(SystemExit) as raised,
        ):
            self._execute(engine, experiment_id)
        self.assertIs(raised.exception, hard_death)
        self.assertEqual(capability_calls, 2)

        crashed = engine.store.load(self.identity, recover=False)
        experiment = next(
            item
            for item in crashed.experiments
            if item.id == experiment_id
        )
        self.assertIs(experiment.status, ExperimentStatus.RUNNING)
        self.assertIsNone(experiment.result)
        self.assertEqual(experiment.evidence_run_ids, [])
        self.assertFalse(
            any(
                run.extra.get("experiment_id") == experiment_id
                for run in crashed.runs
            )
        )

        paths = engine.store.challenge_paths(self.identity)
        orphan_run_roots = []
        for request_path in sorted(paths.runs.glob("*/request.json")):
            request = json.loads(request_path.read_text(encoding="utf-8"))
            if (
                request.get("kind") == "pwn_crash_gate"
                and request.get("experiment_id") == experiment_id
            ):
                orphan_run_roots.append(request_path.parent)
        self.assertEqual(len(orphan_run_roots), 6)
        for run_root in orphan_run_roots:
            self.assertEqual(
                sorted(path.name for path in run_root.iterdir()),
                ["raw", "request.json", "result.json", "validation.json"],
            )

        recipe = PwnCrashRecipe.from_dict(
            experiment.extra["pwn_crash_recipe"]
        )
        evidence_root = (
            paths.artifacts
            / "snapshots"
            / f"pwn-crash-{recipe.recipe_sha256}"
        )
        orphan_evidence_files = sorted(
            path
            for path in evidence_root.iterdir()
            if path.is_file() and not path.is_symlink()
        )
        self.assertEqual(len(orphan_evidence_files), 13)

        canonical_run = crashed.runs[0]
        canonical_run_root = paths.runs / canonical_run.id
        canonical_run_root.mkdir(exist_ok=True)
        canonical_sentinel = canonical_run_root / "canonical.keep"
        canonical_sentinel.write_bytes(b"canonical run must survive")

        unrelated_run_root = paths.runs / "unrelated-hard-death-run"
        unrelated_run_root.mkdir()
        unrelated_request = unrelated_run_root / "request.json"
        unrelated_request.write_text(
            '{"kind":"unrelated"}\n',
            encoding="utf-8",
        )
        unrelated_unknown = unrelated_run_root / "unknown.keep"
        unrelated_unknown.write_bytes(b"unrelated run must survive")

        symlink_target = self.root / "hard-death-symlink-target"
        symlink_target.mkdir()
        symlink_target_sentinel = symlink_target / "target.keep"
        symlink_target_sentinel.write_bytes(b"symlink target must survive")
        hostile_run_link = paths.runs / "pwn-crash-hostile-link"
        hostile_run_link.symlink_to(
            symlink_target,
            target_is_directory=True,
        )

        unknown_evidence = evidence_root / "unknown.keep"
        unknown_evidence.write_bytes(b"unknown evidence must survive")
        evidence_link_target = self.root / "evidence-link-target.keep"
        evidence_link_target.write_bytes(b"evidence target must survive")
        hostile_evidence_link = evidence_root / "99-hostile-stderr.log"
        hostile_evidence_link.symlink_to(evidence_link_target)

        recovered = engine._recover_session_boundary(self.identity)
        recovered_experiment = next(
            item
            for item in recovered.experiments
            if item.id == experiment_id
        )
        self.assertIs(
            recovered_experiment.status,
            ExperimentStatus.FAILED,
        )
        self.assertEqual(set(recovered_experiment.result), {"error"})
        self.assertTrue(
            recovered_experiment.result["error"].startswith(
                "Pwn crash gate failed closed: "
            )
        )
        self.assertFalse(
            any(
                item.status is ExperimentStatus.RUNNING
                for item in recovered.experiments
            )
        )
        for run_root in orphan_run_roots:
            self.assertFalse(run_root.exists())
        for evidence_file in orphan_evidence_files:
            self.assertFalse(evidence_file.exists())

        self.assertEqual(
            canonical_sentinel.read_bytes(),
            b"canonical run must survive",
        )
        self.assertEqual(
            unrelated_request.read_text(encoding="utf-8"),
            '{"kind":"unrelated"}\n',
        )
        self.assertEqual(
            unrelated_unknown.read_bytes(),
            b"unrelated run must survive",
        )
        self.assertTrue(hostile_run_link.is_symlink())
        self.assertEqual(
            symlink_target_sentinel.read_bytes(),
            b"symlink target must survive",
        )
        self.assertEqual(
            unknown_evidence.read_bytes(),
            b"unknown evidence must survive",
        )
        self.assertTrue(hostile_evidence_link.is_symlink())
        self.assertEqual(
            evidence_link_target.read_bytes(),
            b"evidence target must survive",
        )
        recovered.validate()

    def test_hard_death_recovery_never_follows_exact_symlink_swaps(self):
        coordinator = _SandboxCoordinator(self._confirming_statuses())
        engine, experiment_id, _artifact_path, _payload = self._fixture(
            coordinator
        )
        hard_death = SystemExit("synthetic symlink-swap process death")
        capability_calls = 0

        def capability_probe(digest):
            nonlocal capability_calls
            capability_calls += 1
            if capability_calls == 2:
                raise hard_death
            return self._capability(digest)

        engine._capability_probe = capability_probe
        with (
            patch.object(
                engine,
                "_terminalize_pwn_crash_interruption",
                return_value=None,
            ),
            patch.object(
                engine,
                "_cleanup_uncommitted_artifacts",
                return_value=None,
            ),
            patch.object(
                engine,
                "_cleanup_uncommitted_pwn_crash_runs",
                return_value=None,
            ),
            self.assertRaises(SystemExit),
        ):
            self._execute(engine, experiment_id)

        crashed = engine.store.load(self.identity, recover=False)
        experiment = next(
            item
            for item in crashed.experiments
            if item.id == experiment_id
        )
        self.assertIs(experiment.status, ExperimentStatus.RUNNING)
        recipe = PwnCrashRecipe.from_dict(
            experiment.extra["pwn_crash_recipe"]
        )
        paths = engine.store.challenge_paths(self.identity)
        orphan_run_ids = engine._discover_pwn_crash_orphan_runs(
            crashed,
            experiment_id,
            recipe,
        )
        self.assertEqual(len(orphan_run_ids), 6)
        engine._write_pwn_crash_recovery_journal(
            crashed,
            experiment_id,
            recipe,
            orphan_run_ids,
        )

        victim_run_root = paths.runs / orphan_run_ids[0]
        external_run_root = self.root / "external-pwn-run-target"
        victim_run_root.rename(external_run_root)
        run_payloads = {
            name: (external_run_root / name).read_bytes()
            for name in (
                "request.json",
                "result.json",
                "validation.json",
            )
        }
        raw_sentinel = external_run_root / "raw" / "raw.keep"
        raw_sentinel.write_bytes(b"external raw must survive")
        run_sentinel = external_run_root / "unknown.keep"
        run_sentinel.write_bytes(b"external run must survive")
        victim_run_root.symlink_to(
            external_run_root,
            target_is_directory=True,
        )

        evidence_root = (
            paths.artifacts
            / "snapshots"
            / f"pwn-crash-{recipe.recipe_sha256}"
        )
        external_evidence_root = self.root / "external-evidence-target"
        evidence_root.rename(external_evidence_root)
        evidence_payloads = {
            path.name: path.read_bytes()
            for path in external_evidence_root.iterdir()
            if path.is_file()
        }
        self.assertEqual(len(evidence_payloads), 13)
        evidence_sentinel = external_evidence_root / "unknown.keep"
        evidence_sentinel.write_bytes(b"external evidence must survive")
        evidence_root.symlink_to(
            external_evidence_root,
            target_is_directory=True,
        )

        with patch(
            "ctf_os.engine.challenge.sys.stderr",
            StringIO(),
        ):
            recovered = engine._recover_session_boundary(self.identity)

        recovered_experiment = next(
            item
            for item in recovered.experiments
            if item.id == experiment_id
        )
        self.assertIs(
            recovered_experiment.status,
            ExperimentStatus.FAILED,
        )
        self.assertTrue(
            recovered_experiment.result["error"].startswith(
                "Pwn crash gate failed closed: "
            )
        )
        for name, payload in run_payloads.items():
            external_file = external_run_root / name
            self.assertTrue(
                external_file.is_file(),
                f"recovery followed run-root symlink and removed {name}",
            )
            self.assertEqual(external_file.read_bytes(), payload)
        self.assertEqual(
            raw_sentinel.read_bytes(),
            b"external raw must survive",
        )
        self.assertEqual(
            run_sentinel.read_bytes(),
            b"external run must survive",
        )
        for name, payload in evidence_payloads.items():
            external_file = external_evidence_root / name
            self.assertTrue(
                external_file.is_file(),
                f"recovery followed evidence-root symlink and removed {name}",
            )
            self.assertEqual(external_file.read_bytes(), payload)
        self.assertEqual(
            evidence_sentinel.read_bytes(),
            b"external evidence must survive",
        )
        recovered.validate()

    def _assert_drift_blocks_commit(self, drift_kind: str) -> None:
        coordinator = _SandboxCoordinator(self._confirming_statuses())
        (
            engine,
            experiment_id,
            artifact_path,
            _payload,
        ) = self._fixture(coordinator)

        def drift(ordinal):
            if ordinal != 6:
                return
            if drift_kind == "source":
                self.binary_path.chmod(0o700)
                self.binary_path.write_bytes(
                    _elf64_executable() + b"changed"
                )
                self.binary_path.chmod(0o500)
            else:
                artifact_path.chmod(0o600)
                artifact_path.write_bytes(b"B" * 32)
                artifact_path.chmod(0o400)

        coordinator.on_attempt = drift
        state = self._execute(engine, experiment_id)
        experiment = next(
            item
            for item in state.experiments
            if item.id == experiment_id
        )
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        hypothesis = next(
            item
            for item in state.hypotheses
            if item.id == experiment.hypothesis_ids[0]
        )
        self.assertIs(hypothesis.status, HypothesisStatus.OPEN)
        self.assertEqual(hypothesis.evidence_run_ids, [])

    def test_source_drift_blocks_commit(self):
        self._assert_drift_blocks_commit("source")

    def test_payload_drift_blocks_commit(self):
        self._assert_drift_blocks_commit("payload")

    def test_source_drift_removes_unreferenced_pwn_run_files(self):
        coordinator = _SandboxCoordinator(self._confirming_statuses())
        engine, experiment_id, _artifact_path, _payload = self._fixture(
            coordinator
        )
        paths = engine.store.challenge_paths(self.identity)

        def drift(ordinal):
            if ordinal == 6:
                self.binary_path.chmod(0o700)
                self.binary_path.write_bytes(
                    _elf64_executable() + b"changed"
                )
                self.binary_path.chmod(0o500)

        coordinator.on_attempt = drift
        state = self._execute(engine, experiment_id)
        experiment = next(
            item
            for item in state.experiments
            if item.id == experiment_id
        )
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        self.assertEqual(experiment.evidence_run_ids, [])
        orphaned = sorted(
            path.relative_to(paths.runs).as_posix()
            for path in paths.runs.rglob("*")
            if "pwn-crash-" in path.relative_to(paths.runs).as_posix()
        )
        self.assertEqual(orphaned, [])

    def test_timeout_is_one_gate_deadline_including_lease_waits(self):
        coordinator = _SandboxCoordinator(self._confirming_statuses())
        engine, experiment_id, _artifact_path, _payload = self._fixture(
            coordinator
        )
        gate_timeout = 20

        def set_timeout(state):
            experiment = next(
                item
                for item in state.experiments
                if item.id == experiment_id
            )
            experiment.timeout_seconds = gate_timeout

        engine.store.update(self.identity, set_timeout)
        lease_timeouts = []
        original_acquire = engine.lease_broker.acquire

        def record_acquire(*args, timeout=None, **kwargs):
            lease_timeouts.append(timeout)
            return original_acquire(
                *args,
                timeout=timeout,
                **kwargs,
            )

        engine.lease_broker.acquire = record_acquire
        now = [100.0]

        def monotonic():
            return now[0]

        def advance_after_attempt(_ordinal):
            now[0] += 1.0

        coordinator.on_attempt = advance_after_attempt
        with patch(
            "ctf_os.engine.challenge.time.monotonic",
            side_effect=monotonic,
        ):
            state = self._execute(engine, experiment_id)

        experiment = next(
            item
            for item in state.experiments
            if item.id == experiment_id
        )
        self.assertIs(experiment.status, ExperimentStatus.KEPT)
        self.assertEqual(len(coordinator.specs), 6)
        deadlines = [
            spec.deadline_monotonic_seconds
            for spec in coordinator.specs
        ]
        self.assertNotIn(None, deadlines)
        self.assertEqual(deadlines, [deadlines[0]] * 6)
        self.assertEqual(len(lease_timeouts), 6)
        self.assertTrue(
            all(
                timeout is not None and 0 < timeout <= gate_timeout
                for timeout in lease_timeouts
            )
        )
        self.assertLess(lease_timeouts[-1], lease_timeouts[0])

    def test_pause_after_sixth_attempt_fails_closed_without_confirmation(
        self,
    ):
        coordinator = _SandboxCoordinator(self._confirming_statuses())
        engine, experiment_id, _artifact_path, _payload = self._fixture(
            coordinator
        )

        def pause_after_attempt(ordinal):
            if ordinal == 6:
                engine.pause(self.identity)

        coordinator.on_attempt = pause_after_attempt
        state = self._execute(engine, experiment_id)
        experiment = next(
            item
            for item in state.experiments
            if item.id == experiment_id
        )
        self.assertEqual(coordinator.clean_calls, 6)
        self.assertIs(state.status, ChallengeStatus.PAUSED)
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        self.assertEqual(set(experiment.result), {"error"})
        self.assertTrue(
            experiment.result["error"].startswith(
                "Pwn crash gate failed closed: "
            )
        )
        self.assertNotIn("pwn_crash_evidence", experiment.result)
        self.assertEqual(experiment.evidence_run_ids, [])
        state.validate()

    def test_final_capability_probe_cannot_outlive_gate_deadline(self):
        coordinator = _SandboxCoordinator(self._confirming_statuses())
        engine, experiment_id, _artifact_path, _payload = self._fixture(
            coordinator
        )
        gate_timeout = 5

        def set_timeout(state):
            experiment = next(
                item
                for item in state.experiments
                if item.id == experiment_id
            )
            experiment.timeout_seconds = gate_timeout

        engine.store.update(self.identity, set_timeout)
        now = [100.0]
        capability_calls = []

        def capability_probe(digest):
            capability_calls.append(digest)
            if len(capability_calls) == 2:
                now[0] += gate_timeout + 1
            return self._capability(digest)

        engine._capability_probe = capability_probe
        with patch(
            "ctf_os.engine.challenge.time.monotonic",
            side_effect=lambda: now[0],
        ):
            state = self._execute(engine, experiment_id)

        experiment = next(
            item
            for item in state.experiments
            if item.id == experiment_id
        )
        self.assertEqual(capability_calls, [IMAGE_DIGEST, IMAGE_DIGEST])
        self.assertEqual(coordinator.clean_calls, 6)
        self.assertEqual(
            [
                spec.deadline_monotonic_seconds
                for spec in coordinator.specs
            ],
            [100.0 + gate_timeout] * 6,
        )
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        self.assertNotIn("pwn_crash_evidence", experiment.result)
        self.assertEqual(experiment.evidence_run_ids, [])
        state.validate()

    def test_production_capability_probe_receives_gate_remaining_time(self):
        coordinator = _SandboxCoordinator(self._confirming_statuses())
        engine, experiment_id, _artifact_path, _payload = self._fixture(
            coordinator
        )
        gate_timeout = 5

        def set_timeout(state):
            experiment = next(
                item
                for item in state.experiments
                if item.id == experiment_id
            )
            experiment.timeout_seconds = gate_timeout

        engine.store.update(self.identity, set_timeout)
        observed_timeouts = []

        def timeout_aware_probe(digest, *, timeout_seconds):
            observed_timeouts.append(timeout_seconds)
            return self._capability(digest)

        engine._capability_probe = timeout_aware_probe
        engine._capability_probe_accepts_timeout = True
        state = self._execute(engine, experiment_id)
        experiment = next(
            item
            for item in state.experiments
            if item.id == experiment_id
        )

        self.assertIs(experiment.status, ExperimentStatus.KEPT)
        self.assertEqual(len(observed_timeouts), 2)
        self.assertTrue(
            all(
                0 < timeout <= gate_timeout
                for timeout in observed_timeouts
            )
        )
        self.assertLessEqual(
            observed_timeouts[-1],
            observed_timeouts[0],
        )

    def test_committed_success_survives_staging_cleanup_failure(self):
        coordinator = _SandboxCoordinator(self._confirming_statuses())
        engine, experiment_id, _artifact_path, _payload = self._fixture(
            coordinator
        )
        original_prepare = engine._prepare_pwn_crash_inputs

        class CleanupFailure:
            def __init__(self, staging):
                self.staging = staging

            def cleanup(self):
                self.staging.cleanup()
                raise OSError("synthetic committed staging cleanup failure")

        def prepare(*args, **kwargs):
            staging, *prepared = original_prepare(*args, **kwargs)
            return CleanupFailure(staging), *prepared

        stderr = StringIO()
        with (
            patch.object(
                engine,
                "_prepare_pwn_crash_inputs",
                side_effect=prepare,
            ),
            patch("ctf_os.engine.challenge.sys.stderr", stderr),
        ):
            state = self._execute(engine, experiment_id)

        experiment = next(
            item
            for item in state.experiments
            if item.id == experiment_id
        )
        canonical = engine.store.load(self.identity, recover=False)
        canonical_experiment = next(
            item
            for item in canonical.experiments
            if item.id == experiment_id
        )
        self.assertIs(experiment.status, ExperimentStatus.KEPT)
        self.assertIs(canonical_experiment.status, ExperimentStatus.KEPT)
        self.assertEqual(
            canonical_experiment.result["pwn_crash_evidence"][
                "evaluation"
            ]["verdict"],
            "CONFIRMED",
        )
        self.assertIn(
            "warning: committed Pwn crash inputs cleanup failed",
            stderr.getvalue(),
        )
        canonical.validate()

    def test_stderr_flag_is_immediate_observed_candidate_not_submission(self):
        candidate_value = "CTF{audit_candidate}"
        coordinator = _SandboxCoordinator(
            self._confirming_statuses(),
            stderr_payload=f"producer: {candidate_value}\n".encode("ascii"),
        )
        engine, experiment_id, _artifact_path, _payload = self._fixture(
            coordinator
        )
        callbacks = []

        def on_flag(identity, detected):
            current = engine.store.load(identity, recover=False)
            experiment = next(
                item
                for item in current.experiments
                if item.id == experiment_id
            )
            callbacks.append(
                (
                    detected.value,
                    detected.source,
                    coordinator.clean_calls,
                    experiment.status,
                )
            )

        engine._on_tool_flag = on_flag
        state = self._execute(engine, experiment_id)
        experiment = next(
            item
            for item in state.experiments
            if item.id == experiment_id
        )
        self.assertEqual(len(callbacks), 1)
        observed_value, observed_source, clean_calls, observed_status = (
            callbacks[0]
        )
        self.assertEqual(observed_value, candidate_value)
        self.assertTrue(
            observed_source.startswith(
                f"tool:{experiment.evidence_run_ids[0]}:"
            )
        )
        self.assertIn("stderr", observed_source)
        self.assertEqual(clean_calls, 1)
        self.assertIs(observed_status, ExperimentStatus.RUNNING)
        candidate = next(
            item
            for item in state.candidates
            if item.value == candidate_value
        )
        self.assertIs(candidate.status, CandidateStatus.OBSERVED_CANDIDATE)
        self.assertEqual(
            candidate.source_run_id,
            experiment.evidence_run_ids[0],
        )
        self.assertEqual(
            candidate.locator,
            observed_source,
        )
        self.assertEqual(state.submissions, [])
        state.validate()

    def test_truncated_stderr_flag_uses_live_full_stream_detection(self):
        candidate_value = "CTF{large_stderr_candidate}"
        stderr_payload = (
            candidate_value.encode("ascii")
            + b"\n"
            + (b"X" * (64 * 1024))
        )
        coordinator = _SandboxCoordinator(
            self._confirming_statuses(),
            stderr_payload=stderr_payload,
        )
        engine, experiment_id, _artifact_path, _payload = self._fixture(
            coordinator
        )
        callbacks = []

        def on_flag(identity, detected):
            current = engine.store.load(identity, recover=False)
            experiment = next(
                item
                for item in current.experiments
                if item.id == experiment_id
            )
            callbacks.append(
                (
                    detected,
                    coordinator.clean_calls,
                    experiment.status,
                )
            )

        engine._on_tool_flag = on_flag
        state = self._execute(engine, experiment_id)
        experiment = next(
            item
            for item in state.experiments
            if item.id == experiment_id
        )

        self.assertIs(experiment.status, ExperimentStatus.KEPT)
        self.assertEqual(len(callbacks), 1)
        detected, clean_calls, observed_status = callbacks[0]
        self.assertEqual(detected.value, candidate_value)
        self.assertEqual(clean_calls, 1)
        self.assertIs(observed_status, ExperimentStatus.RUNNING)
        self.assertTrue(
            detected.source.startswith(
                f"tool:{experiment.evidence_run_ids[0]}:"
            )
        )
        self.assertIn("stderr", detected.source)
        candidate = next(
            item
            for item in state.candidates
            if item.value == candidate_value
        )
        self.assertEqual(
            candidate.source_run_id,
            experiment.evidence_run_ids[0],
        )
        self.assertEqual(state.submissions, [])
        first_receipt = next(
            item
            for item in state.receipts
            if item.id == experiment.evidence_receipt_ids[0]
        )
        stderr_artifact = next(
            item
            for item in state.artifacts
            if item.id == first_receipt.stderr_artifact_id
        )
        self.assertTrue(
            stderr_artifact.extra["capture_placeholder"]
        )
        self.assertEqual(stderr_artifact.size, 0)
        state.validate()

    def _assert_engine_evidence_tamper_blocks_commit(
        self,
        tamper_kind: str,
    ) -> None:
        coordinator = _SandboxCoordinator(self._confirming_statuses())
        engine, experiment_id, _artifact_path, _payload = self._fixture(
            coordinator
        )
        paths = engine.store.challenge_paths(self.identity)

        def tamper(ordinal):
            if ordinal != 6:
                return
            if tamper_kind == "request":
                request_path = next(
                    path
                    for path in sorted(paths.runs.glob("*/request.json"))
                    if json.loads(path.read_text(encoding="utf-8")).get(
                        "kind"
                    )
                    == "pwn_crash_gate"
                )
                value = json.loads(request_path.read_text(encoding="utf-8"))
                value["execution_contract"]["argv"][0] = "/bin/false"
                request_path.chmod(0o600)
                request_path.write_text(
                    json.dumps(value),
                    encoding="utf-8",
                )
                request_path.chmod(0o400)
            else:
                capability_path = next(
                    paths.artifacts.glob(
                        "snapshots/pwn-crash-*/"
                        "capability-attestation.json"
                    )
                )
                capability_path.chmod(0o600)
                capability_path.write_bytes(b"{}\n")
                capability_path.chmod(0o400)

        coordinator.on_attempt = tamper
        state = self._execute(engine, experiment_id)
        experiment = next(
            item
            for item in state.experiments
            if item.id == experiment_id
        )
        self.assertEqual(coordinator.clean_calls, 6)
        self.assertIs(experiment.status, ExperimentStatus.FAILED)
        self.assertNotIn("pwn_crash_evidence", experiment.result)
        hypothesis = next(
            item
            for item in state.hypotheses
            if item.id == experiment.hypothesis_ids[0]
        )
        self.assertIs(hypothesis.status, HypothesisStatus.OPEN)
        self.assertEqual(hypothesis.evidence_run_ids, [])

    def test_durable_request_hash_tamper_blocks_commit(self):
        self._assert_engine_evidence_tamper_blocks_commit("request")

    def test_capability_attestation_hash_tamper_blocks_commit(self):
        self._assert_engine_evidence_tamper_blocks_commit("capability")


if __name__ == "__main__":
    unittest.main()
