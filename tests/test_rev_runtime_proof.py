from __future__ import annotations

import copy
import hashlib
import inspect
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from ctf_os.config import load_config
from ctf_os.contracts.rev_runtime_v1 import build_rev_runtime_v1_spec
from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.engine.rev_runtime_proof import (
    REV_RUNTIME_EXEC_ARGV,
    REV_RUNTIME_EXEC_ATTESTATION,
    REV_RUNTIME_EXEC_CAPABILITY,
    REV_RUNTIME_PROOF_RESULT_KEY,
    RevRuntimeProofError,
    _validate_private_rev_runtime_proof_evaluation,
    prove_rev_runtime_accepted_input,
    rev_runtime_proof_state_errors,
    validate_rev_runtime_proof_evaluation,
    validate_rev_runtime_proof_state_graph,
)
from ctf_os.live_broker import inspect_state
from ctf_os.models import (
    ChallengeIdentity,
    ExperimentStatus,
    ModelValidationError,
    RunOrigin,
    RunStatus,
)
from ctf_os.sandbox import ArtifactRef, SandboxResult
from ctf_os.schema import STATE_SCHEMA_VERSION
from tests.test_engine import _elf64_image


ACCEPTED_INPUT = b"RUNTIME-OPEN"
ACCEPTED_OUTPUT = b"RUNTIME_ACCEPT_62F1\n"
REJECTED_OUTPUT = b"RUNTIME_REJECT_790C\n"
IMAGE_DIGEST = "sha256:" + ("8" * 64)


def _file(path: str, payload: bytes) -> dict[str, object]:
    return {
        "path": path,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size_bytes": len(payload),
    }


def _expectation(
    *,
    exit_code: int,
    payload: bytes,
) -> dict[str, object]:
    return {
        "exit_code": exit_code,
        "stderr_sha256": hashlib.sha256(b"").hexdigest(),
        "stderr_size_bytes": 0,
        "stdout_sha256": hashlib.sha256(payload).hexdigest(),
        "stdout_size_bytes": len(payload),
    }


def _oracle() -> dict[str, object]:
    return {
        "accepted": _expectation(
            exit_code=0,
            payload=ACCEPTED_OUTPUT,
        ),
        "controls": [
            {
                "expectation": _expectation(
                    exit_code=7,
                    payload=REJECTED_OUTPUT,
                ),
                "mutation_id": mutation_id,
            }
            for mutation_id in (
                "xor-first-01",
                "xor-last-80",
                "truncate-last",
            )
        ],
    }


class _Controller:
    def __init__(self) -> None:
        self.proof_calls = 0
        self.commands = []
        self.proof_inputs = []
        self.challenge_closures = []
        self.duplicate_sandbox_identity = False
        self.mismatched_clean_stream_identity = False
        self.truncate_ordinal: int | None = None
        self.mutate_after_ordinal: int | None = None
        self.mutate_path: Path | None = None


class _RuntimeSandbox:
    def __init__(
        self,
        controller: _Controller,
        work: Path,
        challenge: Path,
        policy,
    ) -> None:
        self.controller = controller
        self.work = work
        self.challenge = challenge
        self.policy = policy
        identity = json.dumps(
            {
                "challenge": str(challenge.resolve()),
                "work": str(work.resolve()),
            },
            sort_keys=True,
        ).encode("utf-8")
        self.scope_fingerprint = hashlib.sha256(identity).hexdigest()

    def register_artifact(
        self,
        locator,
        *,
        maximum_bytes=1 << 34,
    ):
        path = self.work / locator
        payload = path.read_bytes()
        if len(payload) > maximum_bytes:
            raise ValueError("artifact exceeds test bound")
        return ArtifactRef(
            locator=locator,
            sha256=hashlib.sha256(payload).hexdigest(),
            size_bytes=len(payload),
            scope_fingerprint=self.scope_fingerprint,
        )

    def run_clean_proof(
        self,
        spec,
        *,
        input_locators=(),
        proof_inputs=(),
        proof_outputs=(),
    ):
        del input_locators, proof_outputs
        self.controller.proof_calls += 1
        ordinal = self.controller.proof_calls
        self.controller.commands.append(spec)
        if spec.argv != REV_RUNTIME_EXEC_ARGV:
            raise AssertionError("runtime command changed")
        if (
            spec.network_target is not None
            or spec.resource_request.network != 0
            or self.policy.enforcement != "deny"
        ):
            raise AssertionError("runtime proof acquired network authority")
        captured = {}
        for item in proof_inputs:
            payload = (self.work / item.source_locator).read_bytes()
            if (
                hashlib.sha256(payload).hexdigest() != item.sha256
                or len(payload) != item.size_bytes
            ):
                raise AssertionError("proof input binding changed")
            captured[item.destination_locator] = payload
        if set(captured) != {
            "oracle/runtime-spec.json",
            "oracle/accepted-input.bin",
        }:
            raise AssertionError("runtime proof input topology changed")
        self.controller.proof_inputs.append(captured)

        closure = {
            item.relative_to(self.challenge).as_posix(): (
                hashlib.sha256(item.read_bytes()).hexdigest(),
                item.stat().st_size,
            )
            for item in self.challenge.rglob("*")
            if item.is_file()
        }
        self.controller.challenge_closures.append(closure)
        runtime_spec = json.loads(
            captured["oracle/runtime-spec.json"]
        )
        expected_closure = {
            item["path"]: (item["sha256"], item["size_bytes"])
            for item in (
                runtime_spec["source"],
                *runtime_spec["dependencies"],
            )
        }
        if closure != expected_closure:
            raise AssertionError("runtime challenge closure changed")

        accepted = (
            captured["oracle/accepted-input.bin"] == ACCEPTED_INPUT
        )
        stdout_payload = (
            ACCEPTED_OUTPUT if accepted else REJECTED_OUTPUT
        )
        exit_code = 0 if accepted else 7
        clean_nonce = (
            "000000000001"
            if self.controller.duplicate_sandbox_identity
            else f"{ordinal:012x}"
        )
        stderr_nonce = (
            "ffffffffffff"
            if self.controller.mismatched_clean_stream_identity
            else clean_nonce
        )
        directory = self.work / "proof" / f"clean-{clean_nonce}"
        stderr_directory = (
            self.work / "proof" / f"clean-{stderr_nonce}"
        )
        directory.mkdir(parents=True, exist_ok=True)
        stderr_directory.mkdir(parents=True, exist_ok=True)
        stdout = directory / "stdout.log"
        stderr = stderr_directory / "stderr.log"
        stdout.write_bytes(stdout_payload)
        stderr.write_bytes(b"")
        truncated = self.controller.truncate_ordinal == ordinal
        if (
            self.controller.mutate_after_ordinal == ordinal
            and self.controller.mutate_path is not None
        ):
            self.controller.mutate_path.write_bytes(b"changed-after-run")
        return SandboxResult(
            "run-00000001",
            "completed",
            exit_code,
            False,
            5,
            "",
            "",
            len(stdout_payload),
            0,
            f"/work/proof/clean-{clean_nonce}/stdout.log",
            f"/work/proof/clean-{stderr_nonce}/stderr.log",
            stdout_stored_bytes=len(stdout_payload),
            stderr_stored_bytes=0,
            stdout_limit_bytes=16 * 1024 * 1024,
            stderr_limit_bytes=16 * 1024 * 1024,
            stdout_truncated=truncated,
            stderr_truncated=False,
            stdout_truncation_known=True,
            stderr_truncation_known=True,
            stdout_capture_complete=True,
            stderr_capture_complete=True,
            stdout_error=None,
            stderr_error=None,
            stream_capture_error=None,
            orchestration_error=None,
        )


class _RuntimeEngine(ChallengeEngine):
    def __init__(self, *args, controller: _Controller, **kwargs) -> None:
        self.runtime_controller = controller
        super().__init__(*args, **kwargs)

    def sandbox(
        self,
        state,
        *,
        workspace_override=None,
        challenge_dir_override=None,
        network_policy_override=None,
    ):
        return _RuntimeSandbox(
            self.runtime_controller,
            workspace_override or self._workspace(state),
            challenge_dir_override or self.challenge_input(state.identity),
            network_policy_override or self._network_policy(state),
        )


class RevRuntimeProofTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.operator_temporary = tempfile.TemporaryDirectory(
            prefix="ctfos-rev-operator-private-"
        )
        self.root = Path(self.temporary.name)
        self.accepted_input_path = (
            Path(self.operator_temporary.name) / "accepted-input.bin"
        )
        self.accepted_input_path.write_bytes(ACCEPTED_INPUT)
        self.accepted_input_path.chmod(0o600)
        self.identity = ChallengeIdentity(
            "Runtime Event",
            "rev",
            "multi-runtime",
        )
        self.incoming = (
            self.root
            / "incoming"
            / self.identity.contest_id
            / self.identity.category
            / self.identity.challenge_id
        )
        (self.incoming / "bin").mkdir(parents=True)
        (self.incoming / "lib").mkdir(parents=True)
        self.source = _elf64_image(2) + b"runtime-proof-source"
        self.dependency = b"runtime-proof-dependency"
        (self.incoming / "bin" / "challenge").write_bytes(
            self.source
        )
        (self.incoming / "lib" / "data.bin").write_bytes(
            self.dependency
        )
        self.mobile_sources = {
            "dex": b"dex\n035\x00mobile",
            "apk": b"PK\x03\x04mobile",
        }
        for binary_format, payload in self.mobile_sources.items():
            (self.incoming / f"app.{binary_format}").write_bytes(
                payload
            )
        runtime_sources = {
            "bin/app.exe": b"MZ" + (b"\x00" * 126),
            "java/app.jar": b"PK\x03\x04jar",
            "java/ctf/Main.class": b"\xca\xfe\xba\xbeclass",
            "wasm/module.wasm": b"\x00asm\x01\x00\x00\x00module",
        }
        for locator, payload in runtime_sources.items():
            destination = self.incoming / locator
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(payload)
        self.runtime_sources = runtime_sources
        self.controller = _Controller()
        self.probe_count = 0
        self.bad_attestation_on_call: int | None = None
        config = load_config(self.root)
        config = replace(
            config,
            runtime=replace(
                config.runtime,
                image_digest=IMAGE_DIGEST,
                command_timeout_s=30,
            ),
        )
        self.engine = _RuntimeEngine(
            self.root,
            config=config,
            controller=self.controller,
            capability_probe=self._capability_probe,
        )
        self.added = self.engine.add_challenge(
            self.identity,
            prompt="runtime proof",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        self.workspace = self.engine._workspace(self.added)
        self.spec = build_rev_runtime_v1_spec(
            format="elf",
            runtime="native",
            source=_file("bin/challenge", self.source),
            dependencies=(
                _file("lib/data.bin", self.dependency),
            ),
            argv=("--mode", "proof"),
            working_directory=".",
        )
        (self.workspace / "runtime.json").write_bytes(
            self.spec.canonical_bytes
        )

    def tearDown(self) -> None:
        self.operator_temporary.cleanup()
        self.temporary.cleanup()

    def _capability_probe(self, image_digest: str):
        self.probe_count += 1
        attestation = dict(REV_RUNTIME_EXEC_ATTESTATION)
        if self.bad_attestation_on_call == self.probe_count:
            attestation["sha256"] = "0" * 64
        return {
            "attestations": {
                REV_RUNTIME_EXEC_CAPABILITY: attestation,
            },
            "available": [REV_RUNTIME_EXEC_CAPABILITY],
            "image_digest": image_digest,
            "missing": [],
            "ok": True,
        }

    def _prove(self):
        return prove_rev_runtime_accepted_input(
            self.engine,
            self.identity,
            runtime_spec_locator="runtime.json",
            accepted_input_path=self.accepted_input_path,
            expected_oracle=_oracle(),
            timeout_seconds=10,
        )

    def _proof_experiments(self, state):
        return [
            item
            for item in state.experiments
            if isinstance(item.result, dict)
            and REV_RUNTIME_PROOF_RESULT_KEY in item.result
        ]

    def _private_evaluation(self, state):
        proof = self._proof_experiments(state)[0]
        artifact = next(
            item
            for item in state.artifacts
            if item.extra.get("experiment_id") == proof.id
            and item.extra.get("kind") == "rev_runtime_evaluation"
        )
        paths = self.engine.store.challenge_paths(self.identity)
        return json.loads((paths.root / artifact.path).read_bytes())

    def test_hash_bound_multifile_runtime_passes_candidate_free(self):
        self.assertEqual(
            tuple(
                inspect.signature(
                    prove_rev_runtime_accepted_input
                ).parameters
            ),
            (
                "engine",
                "identity",
                "runtime_spec_locator",
                "accepted_input_path",
                "expected_oracle",
                "timeout_seconds",
                "_session_owned",
            ),
        )
        state, evaluation = self._prove()
        self.assertTrue(evaluation["passed"])
        validate_rev_runtime_proof_evaluation(evaluation)
        private_evaluation = self._private_evaluation(state)
        self.assertEqual(
            {
                record["sandbox_run_id"]
                for record in private_evaluation["records"]
            },
            {"run-00000001"},
        )
        self.assertEqual(
            len(
                {
                    record["stdout_locator"].split("/")[1]
                    for record in private_evaluation["records"]
                }
            ),
            6,
        )
        self.assertFalse((self.workspace / "accepted.bin").exists())
        self.assertEqual(self.controller.proof_calls, 6)
        self.assertEqual(self.probe_count, 2)
        self.assertEqual(
            [
                item["oracle/accepted-input.bin"]
                for item in self.controller.proof_inputs[:3]
            ],
            [ACCEPTED_INPUT] * 3,
        )
        self.assertEqual(
            len(
                {
                    item.id
                    for item in state.runs
                    if item.extra.get("engine_executor")
                    == "engine.rev_runtime_proof.v1"
                }
            ),
            6,
        )

        self.assertEqual(evaluation["record_count"], 6)
        self.assertEqual(
            evaluation["expected_oracle"],
            {
                "sha256": hashlib.sha256(
                    (
                        json.dumps(
                            _oracle(),
                            allow_nan=False,
                            ensure_ascii=True,
                            separators=(",", ":"),
                            sort_keys=True,
                        )
                        + "\n"
                    ).encode("ascii")
                ).hexdigest(),
                "size_bytes": len(
                    (
                        json.dumps(
                            _oracle(),
                            allow_nan=False,
                            ensure_ascii=True,
                            separators=(",", ":"),
                            sort_keys=True,
                        )
                        + "\n"
                    ).encode("ascii")
                ),
            },
        )
        self.assertEqual(state.status, self.added.status)
        self.assertEqual(state.candidates, [])
        self.assertEqual(state.submissions, [])
        self.assertEqual(
            evaluation["authorities"],
            {
                "automatic_submission_authorized": False,
                "candidate_authorized": False,
                "challenge_status_transition_authorized": False,
                "flag_proven": False,
            },
        )
        proof = self._proof_experiments(state)
        self.assertEqual(len(proof), 1)
        self.assertEqual(proof[0].artifact_ids, [])
        self.assertEqual(proof[0].evidence_run_ids, [])
        self.assertEqual(proof[0].evidence_receipt_ids, [])
        paths = self.engine.store.challenge_paths(self.identity)
        hidden_artifacts = [
            artifact
            for artifact in state.artifacts
            if artifact.extra.get("experiment_id") == proof[0].id
            and artifact.extra.get("engine_executor")
            == "engine.rev_runtime_proof.v1"
        ]
        self.assertEqual(len(hidden_artifacts), 15)
        self.assertTrue(
            all(
                artifact.extra.get("context_visibility")
                == "engine_private"
                for artifact in hidden_artifacts
            )
        )
        for artifact in hidden_artifacts:
            self.assertTrue(
                artifact.path.startswith(
                    f"artifacts/rev-runtime-proof/{proof[0].id}/"
                )
            )
            self.assertTrue((paths.root / artifact.path).is_file())
        serialized = json.dumps(
            state.to_dict(),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        self.assertNotIn(ACCEPTED_INPUT.rstrip(), serialized)
        self.assertNotIn(ACCEPTED_OUTPUT.rstrip(), serialized)
        self.assertNotIn(REJECTED_OUTPUT.rstrip(), serialized)
        self.assertNotIn(
            str(self.accepted_input_path).encode("ascii"),
            serialized,
        )
        inspected_state = json.dumps(
            inspect_state(state, "state"),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        inspected_experiment_values = inspect_state(state, "experiments")
        self.assertIsInstance(inspected_experiment_values, list)
        inspected_proof = next(
            item
            for item in inspected_experiment_values
            if item["id"] == proof[0].id
        )
        inspected_experiments = json.dumps(
            inspected_proof,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        for inspected in (inspected_state, inspected_experiments):
            self.assertNotIn(ACCEPTED_INPUT, inspected)
            self.assertNotIn(
                str(self.accepted_input_path).encode("ascii"),
                inspected,
            )
            self.assertNotIn(b'"accepted_input_locator"', inspected)
        self.assertNotIn(b'"source_locator"', inspected_experiments)
        state.validate()
        type(state).from_dict(state.to_dict()).validate()

    def test_challenge_engine_wrapper_preserves_operator_path_boundary(
        self,
    ):
        signature = inspect.signature(
            ChallengeEngine.prove_rev_runtime_accepted_input
        )
        self.assertEqual(
            tuple(signature.parameters),
            (
                "self",
                "identity",
                "runtime_spec_locator",
                "accepted_input_path",
                "expected_oracle",
                "timeout_seconds",
                "_session_owned",
            ),
        )
        expected = (mock.sentinel.state, mock.sentinel.evaluation)
        with mock.patch(
            "ctf_os.engine.rev_runtime_proof."
            "prove_rev_runtime_accepted_input",
            return_value=expected,
        ) as delegated:
            observed = (
                ChallengeEngine.prove_rev_runtime_accepted_input(
                    self.engine,
                    self.identity,
                    runtime_spec_locator="runtime.json",
                    accepted_input_path=self.accepted_input_path,
                    expected_oracle=_oracle(),
                    timeout_seconds=10,
                    _session_owned=True,
                )
            )

        self.assertIs(observed, expected)
        delegated.assert_called_once_with(
            self.engine,
            self.identity,
            runtime_spec_locator="runtime.json",
            accepted_input_path=self.accepted_input_path,
            expected_oracle=_oracle(),
            timeout_seconds=10,
            _session_owned=True,
        )

        with self.assertRaises(RevRuntimeProofError) as raised:
            ChallengeEngine.prove_rev_runtime_accepted_input(
                self.engine,
                self.identity,
                runtime_spec_locator="runtime.json",
                accepted_input_path=str(self.accepted_input_path),
                expected_oracle=_oracle(),
                timeout_seconds=10,
            )
        self.assertEqual(
            raised.exception.code,
            "runtime_request_invalid",
        )
        self.assertEqual(self.controller.proof_calls, 0)

    def test_each_supported_runtime_selector_uses_the_same_3_plus_3_gate(self):
        cases = (
            build_rev_runtime_v1_spec(
                format="elf",
                runtime="native",
                source=_file("bin/challenge", self.source),
            ),
            build_rev_runtime_v1_spec(
                format="elf",
                runtime="qemu-user",
                source=_file("bin/challenge", self.source),
                architecture="x86_64",
            ),
            build_rev_runtime_v1_spec(
                format="pe",
                runtime="wine",
                source=_file(
                    "bin/app.exe",
                    self.runtime_sources["bin/app.exe"],
                ),
            ),
            build_rev_runtime_v1_spec(
                format="java-jar",
                runtime="java",
                source=_file(
                    "java/app.jar",
                    self.runtime_sources["java/app.jar"],
                ),
            ),
            build_rev_runtime_v1_spec(
                format="java-class",
                runtime="java",
                source=_file(
                    "java/ctf/Main.class",
                    self.runtime_sources["java/ctf/Main.class"],
                ),
                main_class="ctf.Main",
            ),
            build_rev_runtime_v1_spec(
                format="dotnet",
                runtime="dotnet",
                source=_file(
                    "bin/app.exe",
                    self.runtime_sources["bin/app.exe"],
                ),
            ),
            build_rev_runtime_v1_spec(
                format="dotnet",
                runtime="mono",
                source=_file(
                    "bin/app.exe",
                    self.runtime_sources["bin/app.exe"],
                ),
            ),
            build_rev_runtime_v1_spec(
                format="wasm",
                runtime="node-wasi",
                source=_file(
                    "wasm/module.wasm",
                    self.runtime_sources["wasm/module.wasm"],
                ),
                wasm_entrypoint="_start",
            ),
        )
        for index, runtime_spec in enumerate(cases, start=1):
            with self.subTest(
                format=runtime_spec.format,
                runtime=runtime_spec.runtime,
            ):
                locator = f"runtime-{index}.json"
                (self.workspace / locator).write_bytes(
                    runtime_spec.canonical_bytes
                )
                before_calls = self.controller.proof_calls
                _state, evaluation = (
                    prove_rev_runtime_accepted_input(
                        self.engine,
                        self.identity,
                        runtime_spec_locator=locator,
                        accepted_input_path=self.accepted_input_path,
                        expected_oracle=_oracle(),
                        timeout_seconds=10,
                    )
                )
                self.assertTrue(evaluation["passed"])
                self.assertEqual(
                    self.controller.proof_calls - before_calls,
                    6,
                )
                self.assertEqual(
                    [
                        item["oracle/accepted-input.bin"]
                        == ACCEPTED_INPUT
                        for item in self.controller.proof_inputs[
                            before_calls : before_calls + 6
                        ]
                    ],
                    [True] * 3 + [False] * 3,
                )

    def test_dex_and_apk_reject_with_stable_code_before_execution(self):
        for binary_format in ("dex", "apk"):
            with self.subTest(binary_format=binary_format):
                mobile = self.mobile_sources[binary_format]
                path = f"app.{binary_format}"
                spec = build_rev_runtime_v1_spec(
                    format=binary_format,
                    runtime="unsupported",
                    source=_file(path, mobile),
                )
                (self.workspace / "mobile.json").write_bytes(
                    spec.canonical_bytes
                )
                before = self.engine.store.load(self.identity)
                with self.assertRaises(RevRuntimeProofError) as raised:
                    prove_rev_runtime_accepted_input(
                        self.engine,
                        self.identity,
                        runtime_spec_locator="mobile.json",
                        accepted_input_path=self.accepted_input_path,
                        expected_oracle=_oracle(),
                        timeout_seconds=10,
                    )
                self.assertEqual(
                    raised.exception.code,
                    "runtime_unsupported_dex_apk",
                )
                after = self.engine.store.load(self.identity)
                self.assertEqual(after.revision, before.revision)
                self.assertEqual(self.controller.proof_calls, 0)

    def test_attestation_and_source_binding_fail_before_execution(self):
        self.bad_attestation_on_call = 1
        with self.assertRaises(RevRuntimeProofError) as raised:
            self._prove()
        self.assertEqual(
            raised.exception.code,
            "runtime_capability_attestation_invalid",
        )
        self.assertEqual(self.controller.proof_calls, 0)

        self.bad_attestation_on_call = None
        self.probe_count = 0
        changed = self.spec.to_dict()
        changed["dependencies"][0]["sha256"] = "0" * 64
        changed_spec = type(self.spec).from_mapping(changed)
        (self.workspace / "runtime.json").write_bytes(
            changed_spec.canonical_bytes
        )
        with self.assertRaises(RevRuntimeProofError) as raised:
            self._prove()
        self.assertEqual(
            raised.exception.code,
            "runtime_source_binding_changed",
        )
        self.assertEqual(self.controller.proof_calls, 0)

    def test_operator_source_changes_after_intake_do_not_change_snapshot(self):
        self.controller.mutate_after_ordinal = 1
        self.controller.mutate_path = self.accepted_input_path
        state, evaluation = self._prove()
        self.assertTrue(evaluation["passed"])
        self.assertEqual(self.controller.proof_calls, 6)
        self.assertEqual(
            [
                item["oracle/accepted-input.bin"]
                for item in self.controller.proof_inputs[:3]
            ],
            [ACCEPTED_INPUT] * 3,
        )
        self.assertNotEqual(
            self.accepted_input_path.read_bytes(),
            ACCEPTED_INPUT,
        )
        self.assertEqual(
            len(self._proof_experiments(state)),
            1,
        )

    def test_runtime_spec_drift_discards_all_uncommitted_runs(self):
        before = self.engine.store.load(self.identity)
        self.controller.mutate_after_ordinal = 1
        self.controller.mutate_path = self.workspace / "runtime.json"
        with self.assertRaises(RevRuntimeProofError) as raised:
            self._prove()
        self.assertEqual(
            raised.exception.code,
            "runtime_workspace_binding_changed",
        )
        after = self.engine.store.load(self.identity)
        self.assertEqual(after.revision, before.revision)
        self.assertEqual(self._proof_experiments(after), [])

    def test_incoming_source_drift_discards_all_uncommitted_runs(self):
        before = self.engine.store.load(self.identity)
        self.controller.mutate_after_ordinal = 1
        self.controller.mutate_path = (
            self.incoming / "lib" / "data.bin"
        )
        with self.assertRaises(RevRuntimeProofError) as raised:
            self._prove()
        self.assertEqual(
            raised.exception.code,
            "runtime_source_binding_changed",
        )
        after = self.engine.store.load(self.identity)
        self.assertEqual(after.revision, before.revision)
        self.assertEqual(self._proof_experiments(after), [])

    def test_capability_drift_after_execution_blocks_commit(self):
        before = self.engine.store.load(self.identity)
        self.bad_attestation_on_call = 2
        with self.assertRaises(RevRuntimeProofError) as raised:
            self._prove()
        self.assertEqual(
            raised.exception.code,
            "runtime_capability_attestation_invalid",
        )
        self.assertEqual(self.controller.proof_calls, 6)
        after = self.engine.store.load(self.identity)
        self.assertEqual(after.revision, before.revision)
        self.assertEqual(self._proof_experiments(after), [])

    def test_truncation_and_reused_sandbox_identity_cannot_pass(self):
        self.controller.truncate_ordinal = 2
        self.controller.duplicate_sandbox_identity = True
        state, evaluation = self._prove()
        self.assertFalse(evaluation["passed"])
        self.assertIn(
            "attempt_2_transport_incomplete",
            evaluation["reason_codes"],
        )
        self.assertIn(
            "sandbox_identity_reused",
            evaluation["reason_codes"],
        )
        self.assertEqual(state.candidates, [])
        self.assertEqual(state.submissions, [])

    def test_reused_clean_proof_nonce_alone_cannot_pass(self):
        self.controller.duplicate_sandbox_identity = True
        state, evaluation = self._prove()
        self.assertFalse(evaluation["passed"])
        self.assertEqual(
            evaluation["reason_codes"],
            ["sandbox_identity_reused"],
        )
        self.assertEqual(state.candidates, [])
        self.assertEqual(state.submissions, [])

    def test_clean_proof_streams_must_share_one_exact_promoted_nonce(self):
        before = self.engine.store.load(self.identity)
        self.controller.mismatched_clean_stream_identity = True
        with self.assertRaises(RevRuntimeProofError) as raised:
            self._prove()
        self.assertEqual(
            raised.exception.code,
            "runtime_result_locator_invalid",
        )
        after = self.engine.store.load(self.identity)
        self.assertEqual(after.revision, before.revision)
        self.assertEqual(self._proof_experiments(after), [])

    def test_legacy_false_reuse_blocker_state_remains_valid(self):
        state, _evaluation = self._prove()
        private_evaluation = self._private_evaluation(state)
        legacy_private = copy.deepcopy(private_evaluation)
        legacy_private["passed"] = False
        legacy_private["reason_codes"] = ["sandbox_identity_reused"]
        _validate_private_rev_runtime_proof_evaluation(legacy_private)

        legacy_payload = (
            json.dumps(
                legacy_private,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
        legacy_sha256 = hashlib.sha256(legacy_payload).hexdigest()
        legacy = copy.deepcopy(state)
        proof = self._proof_experiments(legacy)[0]
        public = proof.result[REV_RUNTIME_PROOF_RESULT_KEY]["evaluation"]
        public["passed"] = False
        public["reason_codes"] = ["sandbox_identity_reused"]
        public["private_evaluation"] = {
            "sha256": legacy_sha256,
            "size_bytes": len(legacy_payload),
        }
        proof.status = ExperimentStatus.FAILED
        proof.evaluation_reason = (
            "rev_runtime_proof:sandbox_identity_reused"
        )
        artifact = next(
            item
            for item in legacy.artifacts
            if item.extra.get("experiment_id") == proof.id
            and item.extra.get("kind") == "rev_runtime_evaluation"
        )
        artifact.sha256 = legacy_sha256
        artifact.size = len(legacy_payload)
        artifact.extra["evaluation_sha256"] = legacy_sha256

        validate_rev_runtime_proof_state_graph(legacy)
        legacy.validate()

    def test_accepted_input_cannot_be_smuggled_in_runtime_argv(self):
        disclosed = build_rev_runtime_v1_spec(
            format="elf",
            runtime="native",
            source=_file("bin/challenge", self.source),
            dependencies=(
                _file("lib/data.bin", self.dependency),
            ),
            argv=("RUNTIME", "-OPEN"),
        )
        (self.workspace / "runtime.json").write_bytes(
            disclosed.canonical_bytes
        )
        with self.assertRaises(RevRuntimeProofError) as raised:
            self._prove()
        self.assertEqual(
            raised.exception.code,
            "runtime_input_disclosed_in_spec",
        )
        self.assertEqual(self.controller.proof_calls, 0)

    def test_private_input_inside_workspace_is_rejected_before_execution(self):
        unsafe = self.workspace / "accepted.bin"
        unsafe.write_bytes(ACCEPTED_INPUT)
        unsafe.chmod(0o600)
        with self.assertRaises(RevRuntimeProofError) as raised:
            prove_rev_runtime_accepted_input(
                self.engine,
                self.identity,
                runtime_spec_locator="runtime.json",
                accepted_input_path=unsafe,
                expected_oracle=_oracle(),
                timeout_seconds=10,
            )
        self.assertEqual(
            raised.exception.code,
            "runtime_private_input_boundary_invalid",
        )
        self.assertEqual(self.controller.proof_calls, 0)

    def test_private_input_requires_operator_owned_private_single_link(self):
        self.accepted_input_path.chmod(0o644)
        with self.assertRaises(RevRuntimeProofError) as raised:
            self._prove()
        self.assertEqual(
            raised.exception.code,
            "runtime_private_input_metadata_invalid",
        )
        self.assertEqual(self.controller.proof_calls, 0)

        self.accepted_input_path.chmod(0o600)
        hardlink = Path(self.operator_temporary.name) / "second-link.bin"
        hardlink.hardlink_to(self.accepted_input_path)
        with self.assertRaises(RevRuntimeProofError) as raised:
            self._prove()
        self.assertEqual(
            raised.exception.code,
            "runtime_private_input_metadata_invalid",
        )
        self.assertEqual(self.controller.proof_calls, 0)

    def test_private_input_terminal_symlink_is_rejected(self):
        symlink = Path(self.operator_temporary.name) / "accepted-link.bin"
        symlink.symlink_to(self.accepted_input_path)
        with self.assertRaises(RevRuntimeProofError) as raised:
            prove_rev_runtime_accepted_input(
                self.engine,
                self.identity,
                runtime_spec_locator="runtime.json",
                accepted_input_path=symlink,
                expected_oracle=_oracle(),
                timeout_seconds=10,
            )
        self.assertEqual(
            raised.exception.code,
            "runtime_private_input_open_failed",
        )
        self.assertEqual(self.controller.proof_calls, 0)

    def test_managed_locator_fallback_is_fail_closed(self):
        with self.assertRaises(RevRuntimeProofError) as raised:
            prove_rev_runtime_accepted_input(
                self.engine,
                self.identity,
                runtime_spec_locator="runtime.json",
                accepted_input_path=self.accepted_input_path,
                expected_oracle=_oracle(),
                timeout_seconds=10,
                _session_owned=True,
            )
        self.assertEqual(
            raised.exception.code,
            "runtime_managed_private_input_preissue_required",
        )
        self.assertEqual(self.controller.proof_calls, 0)

    def test_state_graph_validator_rejects_authority_and_path_tampering(self):
        state, _evaluation = self._prove()
        self.assertEqual(rev_runtime_proof_state_errors(state), ())
        validate_rev_runtime_proof_state_graph(state)
        proof = self._proof_experiments(state)[0]

        authority = copy.deepcopy(state)
        aggregate = next(
            item for item in authority.experiments if item.id == proof.id
        )
        aggregate.result[REV_RUNTIME_PROOF_RESULT_KEY]["evaluation"][
            "authorities"
        ]["candidate_authorized"] = True
        with self.assertRaises(RevRuntimeProofError):
            validate_rev_runtime_proof_state_graph(authority)
        with self.assertRaises(ModelValidationError):
            authority.validate()

        path_changed = copy.deepcopy(state)
        artifact = next(
            item
            for item in path_changed.artifacts
            if item.extra.get("experiment_id") == proof.id
            and item.extra.get("kind") == "rev_runtime_evaluation"
        )
        artifact.path = "artifacts/relocated-evaluation.json"
        with self.assertRaises(RevRuntimeProofError):
            validate_rev_runtime_proof_state_graph(path_changed)
        with self.assertRaises(ModelValidationError):
            path_changed.validate()

    def test_state_graph_rejects_coordinated_hidden_topology_rebinding(self):
        state, _evaluation = self._prove()
        proof = self._proof_experiments(state)[0]

        for mutation in (
            "passed_status",
            "origin",
            "request_path",
            "request_hash",
            "run_extra_schema",
            "stream_extra_schema",
            "stream_source_run",
            "evaluation_source_run",
        ):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(state)
                runs = sorted(
                    (
                        item
                        for item in changed.runs
                        if item.extra.get("parent_experiment_id")
                        == proof.id
                    ),
                    key=lambda item: item.extra[
                        "rev_runtime_proof"
                    ]["ordinal"],
                )
                artifacts = [
                    item
                    for item in changed.artifacts
                    if item.extra.get("experiment_id") == proof.id
                ]
                if mutation == "passed_status":
                    runs[0].status = RunStatus.FAILED
                elif mutation == "origin":
                    runs[0].origin = RunOrigin.MANAGED_TOOL
                elif mutation == "request_path":
                    runs[0].request_path = (
                        f"runs/{runs[1].id}/request.json"
                    )
                elif mutation == "request_hash":
                    runs[0].extra["request_sha256"] = "0" * 63
                elif mutation == "run_extra_schema":
                    runs[0].extra["unexpected"] = True
                elif mutation == "stream_extra_schema":
                    stream = next(
                        item
                        for item in artifacts
                        if item.extra.get("kind")
                        == "rev_runtime_stream"
                    )
                    stream.extra["unexpected"] = True
                elif mutation == "stream_source_run":
                    stream = next(
                        item
                        for item in artifacts
                        if item.extra.get("kind")
                        == "rev_runtime_stream"
                        and item.extra.get("ordinal") == 1
                    )
                    stream.source_run_id = runs[1].id
                else:
                    evaluation_artifact = next(
                        item
                        for item in artifacts
                        if item.extra.get("kind")
                        == "rev_runtime_evaluation"
                    )
                    evaluation_artifact.source_run_id = runs[4].id

                with self.assertRaises(RevRuntimeProofError):
                    validate_rev_runtime_proof_state_graph(changed)
                with self.assertRaises(ModelValidationError):
                    changed.validate()

    def test_failed_public_projection_still_requires_terminal_runs(self):
        self.controller.truncate_ordinal = 2
        state, evaluation = self._prove()
        self.assertFalse(evaluation["passed"])
        proof = self._proof_experiments(state)[0]
        proof_runs = [
            item
            for item in state.runs
            if item.extra.get("parent_experiment_id") == proof.id
        ]
        self.assertEqual(len(proof_runs), 6)
        self.assertTrue(
            all(
                item.status
                in {
                    RunStatus.COMPLETED,
                    RunStatus.FAILED,
                    RunStatus.TIMED_OUT,
                }
                for item in proof_runs
            )
        )

        changed = copy.deepcopy(state)
        next(
            item
            for item in changed.runs
            if item.extra.get("parent_experiment_id") == proof.id
        ).status = RunStatus.RUNNING
        with self.assertRaises(RevRuntimeProofError):
            validate_rev_runtime_proof_state_graph(changed)
        with self.assertRaises(ModelValidationError):
            changed.validate()


if __name__ == "__main__":
    unittest.main()
