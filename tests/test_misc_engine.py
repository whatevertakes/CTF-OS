from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ctf_os.config import EngineConfig, RuntimeConfig
from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.engine.misc_execution import (
    MiscExecutionSpecError,
    parse_misc_execution_spec,
)
from ctf_os.engine.misc_transform import MISC_TRANSFORM_PROTOCOL
from ctf_os.models import (
    CandidateStatus,
    ChallengeIdentity,
    ChallengeStatus,
    FlagCandidate,
    ModelValidationError,
)
from ctf_os.sandbox import ArtifactRef, SandboxResult
from ctf_os.schema import STATE_SCHEMA_VERSION


CANDIDATE = "KCTF{misc-engine-candidate}"
SOURCE = b"immutable misc input"


class MiscSandbox:
    scope_fingerprint = "d" * 64

    def __init__(
        self,
        work: Path,
        *,
        wrong_transform: bool = False,
        verifier_exit_code: int = 0,
        fail_on_call: int | None = None,
    ) -> None:
        self.work = work
        self.wrong_transform = wrong_transform
        self.verifier_exit_code = verifier_exit_code
        self.fail_on_call = fail_on_call
        self.proof_calls: list[tuple[object, dict[str, bytes]]] = []

    def initialize_workspace(self, *, deadline_monotonic_seconds=None):
        del deadline_monotonic_seconds

    def register_artifact(self, locator, *, maximum_bytes=1 << 34):
        payload = (self.work / locator).read_bytes()
        if len(payload) > maximum_bytes:
            raise ValueError("test artifact exceeds bound")
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
    ):
        if input_locators:
            raise AssertionError("Misc gate must use typed proof inputs")
        copied: dict[str, bytes] = {}
        for item in proof_inputs:
            payload = (self.work / item.source_locator).read_bytes()
            if hashlib.sha256(payload).hexdigest() != item.sha256:
                raise AssertionError("proof input hash mismatch")
            if len(payload) != item.size_bytes:
                raise AssertionError("proof input size mismatch")
            copied[item.destination_locator] = payload
        self.proof_calls.append((spec, copied))
        number = len(self.proof_calls)
        if number == self.fail_on_call:
            raise RuntimeError("synthetic Misc sandbox interruption")

        transform = spec.argv[1] == "/work/tool/transform.py"
        if transform:
            output = (
                b"wrong-output"
                if self.wrong_transform
                else CANDIDATE.encode("utf-8")
            )
            exit_code = 0
        else:
            if spec.argv[1] != "/work/oracle/verifier.py":
                raise AssertionError(f"unexpected command: {spec.argv}")
            output = b""
            exit_code = self.verifier_exit_code
        relative = Path("proof") / f"misc-clean-{number}"
        directory = self.work / relative
        directory.mkdir(parents=True, exist_ok=False)
        stdout = directory / "stdout.log"
        stderr = directory / "stderr.log"
        stdout.write_bytes(output)
        stderr.write_bytes(b"")
        return SandboxResult(
            run_id=f"misc-sandbox-{number}",
            status="completed",
            exit_code=exit_code,
            timed_out=False,
            duration_ms=2,
            stdout_summary="bounded",
            stderr_summary="",
            stdout_bytes=len(output),
            stderr_bytes=0,
            stdout_path=f"/work/{relative.as_posix()}/stdout.log",
            stderr_path=f"/work/{relative.as_posix()}/stderr.log",
            stdout_stored_bytes=len(output),
            stderr_stored_bytes=0,
            stdout_limit_bytes=1 << 20,
            stderr_limit_bytes=1 << 20,
            stdout_truncated=False,
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

    def run(self, spec):
        raise AssertionError(f"normal sandbox run is unexpected: {spec}")

    def start_job(self, *args, **kwargs):
        raise AssertionError("not used")

    def job_status(self, *args, **kwargs):
        raise AssertionError("not used")

    def job_log(self, *args, **kwargs):
        raise AssertionError("not used")

    def cancel_job(self, *args, **kwargs):
        raise AssertionError("not used")


class MiscEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.identity = ChallengeIdentity("Misc CTF", "misc", "DAG")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _engine(
        self,
        *,
        wrong_transform: bool = False,
        verifier_exit_code: int = 0,
        fail_on_call: int | None = None,
    ) -> tuple[ChallengeEngine, MiscSandbox]:
        holder: dict[str, MiscSandbox] = {}

        def sandbox_factory(state, work, policy):
            del state, policy
            sandbox = holder.get("sandbox")
            if sandbox is None:
                sandbox = MiscSandbox(
                    work,
                    wrong_transform=wrong_transform,
                    verifier_exit_code=verifier_exit_code,
                    fail_on_call=fail_on_call,
                )
                holder["sandbox"] = sandbox
            return sandbox

        engine = ChallengeEngine(
            self.root,
            config=EngineConfig(
                workspace_root=self.root,
                runtime=RuntimeConfig(
                    image_digest="sha256:" + "4" * 64,
                ),
            ),
            sandbox_factory=sandbox_factory,
        )
        incoming = engine.challenge_input(self.identity)
        incoming.mkdir(parents=True)
        (incoming / "challenge.bin").write_bytes(SOURCE)
        state = engine.add_challenge(
            self.identity,
            prompt="solve",
            state_schema_version=STATE_SCHEMA_VERSION,
        )
        work = engine._workspace(state)
        sandbox = MiscSandbox(
            work,
            wrong_transform=wrong_transform,
            verifier_exit_code=verifier_exit_code,
            fail_on_call=fail_on_call,
        )
        holder["sandbox"] = sandbox
        (work / "transform.py").write_text(
            "import pathlib,sys\nsys.stdout.buffer.write(b'x')\n",
            encoding="utf-8",
        )
        (work / "verify.py").write_text(
            "import pathlib,sys\nraise SystemExit(0)\n",
            encoding="utf-8",
        )
        (work / "misc-spec.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "sources": [
                        {"id": "original", "locator": "challenge.bin"}
                    ],
                    "steps": [
                        {
                            "id": "extract",
                            "tool_locator": "transform.py",
                            "parents": ["original"],
                        }
                    ],
                    "terminal_step_id": "extract",
                    "verifier": {
                        "id": "original-condition",
                        "tool_locator": "verify.py",
                        "oracle_id": "operator-oracle-v1",
                    },
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )

        def add_candidate(current):
            current.candidates.append(
                FlagCandidate(id="C-misc", value=CANDIDATE)
            )

        engine.store.update(self.identity, add_candidate)
        return engine, sandbox

    def _evaluate(self, engine: ChallengeEngine):
        return engine.evaluate_misc_transform_candidate(
            self.identity,
            "C-misc",
            spec_locator="misc-spec.json",
        )

    def test_clean_dag_and_three_verifier_replays_remain_candidate_only(
        self,
    ) -> None:
        engine, sandbox = self._engine()

        state, evaluation = self._evaluate(engine)

        self.assertTrue(evaluation.passed)
        self.assertEqual(len(sandbox.proof_calls), 4)
        for spec, copied in sandbox.proof_calls:
            self.assertIsNone(spec.network_target)
            self.assertFalse(spec.resource_request.network)
            self.assertNotIn("misc-spec.json", copied)
        transform_spec, transform_inputs = sandbox.proof_calls[0]
        self.assertEqual(
            transform_spec.argv,
            (
                "/usr/bin/python3",
                "/work/tool/transform.py",
                "/work/inputs/001.bin",
            ),
        )
        self.assertEqual(
            set(transform_inputs),
            {"tool/transform.py", "inputs/001.bin"},
        )
        for verifier_spec, verifier_inputs in sandbox.proof_calls[1:]:
            self.assertEqual(
                verifier_spec.argv,
                (
                    "/usr/bin/python3",
                    "/work/oracle/verifier.py",
                    "/work/candidate/candidate.bin",
                    "/work/sources/001.bin",
                ),
            )
            self.assertEqual(
                set(verifier_inputs),
                {
                    "oracle/verifier.py",
                    "candidate/candidate.bin",
                    "sources/001.bin",
                },
            )
        self.assertNotEqual(state.status, ChallengeStatus.READY_TO_SUBMIT)
        candidate = next(item for item in state.candidates if item.id == "C-misc")
        self.assertEqual(
            candidate.status,
            CandidateStatus.OBSERVED_CANDIDATE,
        )
        self.assertEqual(candidate.proof_run_ids, [])
        binding = candidate.extra["misc_transform_evidence"]
        self.assertTrue(binding["passed"])
        self.assertFalse(binding["automatic_submission_authorized"])
        self.assertEqual(binding["protocol"], MISC_TRANSFORM_PROTOCOL)
        self.assertEqual(len(binding["run_ids"]), 4)
        state.validate()

    def test_passed_graph_cannot_strip_marker_or_rebind_run(self) -> None:
        engine, _sandbox = self._engine()
        state, evaluation = self._evaluate(engine)
        self.assertTrue(evaluation.passed)
        revision = state.revision

        def strip_marker(current):
            current.progress_markers.clear()

        with self.assertRaisesRegex(
            ModelValidationError,
            "exact progress marker",
        ):
            engine.store.update(self.identity, strip_marker)

        def strip_binding(current):
            candidate = next(
                item for item in current.candidates if item.id == "C-misc"
            )
            candidate.extra.pop("misc_transform_evidence")

        with self.assertRaisesRegex(
            ModelValidationError,
            "orphan Misc transform evaluation artifact",
        ):
            engine.store.update(self.identity, strip_binding)

        def rebind_run(current):
            candidate = next(
                item for item in current.candidates if item.id == "C-misc"
            )
            run_id = candidate.extra["misc_transform_evidence"]["run_ids"][0]
            run = next(item for item in current.runs if item.id == run_id)
            run.extra["plan_sha256"] = "0" * 64

        with self.assertRaisesRegex(
            ModelValidationError,
            "run record was stripped or rebound",
        ):
            engine.store.update(self.identity, rebind_run)
        self.assertEqual(engine.store.load(self.identity).revision, revision)

    def test_verifier_rejection_cannot_create_normalized_success(self) -> None:
        engine, sandbox = self._engine(verifier_exit_code=7)

        state, evaluation = self._evaluate(engine)

        self.assertFalse(evaluation.passed)
        self.assertEqual(len(sandbox.proof_calls), 2)
        self.assertFalse(
            any(
                artifact.extra.get("kind")
                == "misc_transform_normalized_result"
                for artifact in state.artifacts
            )
        )
        self.assertEqual(state.runs[-1].status.value, "failed")
        state.validate()

    def test_operator_may_record_manual_outcome_only_with_unproved_override(
        self,
    ) -> None:
        engine, _sandbox = self._engine()
        self._evaluate(engine)

        solved = engine.record_manual_submission(
            self.identity,
            "C-misc",
            outcome="accepted",
            allow_unproved=True,
            override_reason="operator submitted candidate manually",
        )

        self.assertEqual(solved.status, ChallengeStatus.SOLVED)
        self.assertEqual(
            solved.candidates[0].status,
            CandidateStatus.ACCEPTED,
        )
        self.assertTrue(
            solved.candidates[0]
            .extra["misc_transform_evidence"]["passed"]
        )

    def test_workspace_file_cannot_replace_immutable_incoming_source(
        self,
    ) -> None:
        engine, sandbox = self._engine()
        work = sandbox.work
        (work / "workspace-only.bin").write_bytes(SOURCE)
        spec_path = work / "misc-spec.json"
        spec = json.loads(spec_path.read_text(encoding="utf-8"))
        spec["sources"][0]["locator"] = "workspace-only.bin"
        spec_path.write_text(json.dumps(spec, sort_keys=True), encoding="utf-8")

        with self.assertRaisesRegex(
            RuntimeError,
            "immutable incoming file",
        ):
            self._evaluate(engine)
        self.assertEqual(sandbox.proof_calls, [])

    def test_wrong_terminal_output_persists_failed_evaluation(self) -> None:
        engine, sandbox = self._engine(wrong_transform=True)

        state, evaluation = self._evaluate(engine)

        self.assertFalse(evaluation.passed)
        self.assertEqual(len(sandbox.proof_calls), 4)
        candidate = next(item for item in state.candidates if item.id == "C-misc")
        self.assertFalse(candidate.extra["misc_transform_evidence"]["passed"])
        self.assertEqual(
            candidate.status,
            CandidateStatus.OBSERVED_CANDIDATE,
        )
        self.assertFalse(
            any(
                marker.extra.get("adapter_marker")
                == "misc_original_condition_verified"
                for marker in state.progress_markers
            )
        )
        state.validate()

    def test_interruption_terminalizes_run_and_preserves_frozen_inputs(
        self,
    ) -> None:
        engine, _sandbox = self._engine(fail_on_call=2)

        with self.assertRaisesRegex(
            RuntimeError,
            "synthetic Misc sandbox interruption",
        ):
            self._evaluate(engine)

        state = engine.store.load(self.identity)
        inputs = [
            artifact
            for artifact in state.artifacts
            if artifact.extra.get("kind")
            in {
                "misc_transform_input",
                "misc_transform_input_manifest",
            }
        ]
        self.assertEqual(len(inputs), 6)
        self.assertTrue(
            all(
                (
                    engine.store.challenge_paths(self.identity).root
                    / artifact.path
                ).is_file()
                for artifact in inputs
            )
        )
        self.assertEqual(len(state.runs), 2)
        self.assertEqual(state.runs[-1].status.value, "failed")
        self.assertTrue(state.runs[-1].extra["terminalized"])
        candidate = next(item for item in state.candidates if item.id == "C-misc")
        self.assertNotIn("misc_transform_evidence", candidate.extra)
        state.validate()

    def test_final_pre_replace_guard_rejects_incoming_toctou(self) -> None:
        engine, _sandbox = self._engine()
        original_update = engine.store.update
        changed = False

        def mutate_at_pre_replace(*args, **kwargs):
            nonlocal changed
            guard = kwargs.get("pre_replace_guard")
            if guard is not None:
                def changed_guard():
                    nonlocal changed
                    source = (
                        engine.challenge_input(self.identity)
                        / "challenge.bin"
                    )
                    source.write_bytes(b"changed after final inventory")
                    changed = True
                    return guard()

                kwargs["pre_replace_guard"] = changed_guard
            return original_update(*args, **kwargs)

        with patch.object(
            engine.store,
            "update",
            side_effect=mutate_at_pre_replace,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "immutable incoming changed before final Misc commit",
            ):
                self._evaluate(engine)

        self.assertTrue(changed)
        state = engine.store.load(self.identity)
        candidate = next(
            item for item in state.candidates if item.id == "C-misc"
        )
        self.assertNotIn("misc_transform_evidence", candidate.extra)
        self.assertFalse(
            any(
                marker.extra.get("adapter_marker")
                == "misc_original_condition_verified"
                for marker in state.progress_markers
            )
        )
        state.validate()

    def test_operator_spec_rejects_bool_schema_and_ambiguous_paths(
        self,
    ) -> None:
        base = {
            "schema_version": 1,
            "sources": [{"id": "source", "locator": "challenge.bin"}],
            "steps": [
                {
                    "id": "step",
                    "tool_locator": "transform.py",
                    "parents": ["source"],
                }
            ],
            "terminal_step_id": "step",
            "verifier": {
                "id": "verify",
                "tool_locator": "verify.py",
                "oracle_id": "operator-oracle",
            },
        }
        bool_schema = dict(base)
        bool_schema["schema_version"] = True
        with self.assertRaises(MiscExecutionSpecError):
            parse_misc_execution_spec(bool_schema)

        for locator in (
            r"nested\source.bin",
            "nested//source.bin",
            "nested/../source.bin",
            "C:/source.bin",
        ):
            with self.subTest(locator=locator):
                malformed = json.loads(json.dumps(base))
                malformed["sources"][0]["locator"] = locator
                with self.assertRaises(MiscExecutionSpecError):
                    parse_misc_execution_spec(malformed)


if __name__ == "__main__":
    unittest.main()
