from __future__ import annotations

import copy
import hashlib
import unittest
from pathlib import Path
from types import SimpleNamespace

from ctf_os.adapters import get_adapter
from ctf_os.engine import failure_capsule as failure_capsule_module
from ctf_os.engine.context_pack import build_context_pack
from ctf_os.engine.failure_capsule import build_failure_capsule
from ctf_os.engine.resume_capsule import (
    MAX_RESUME_CAPSULE_BYTES,
    ResumeCapsulePolicy,
    render_resume_capsule,
)
from ctf_os.models import (
    ArtifactReference,
    ChallengeState,
    Checkpoint,
    ExecutionReceipt,
    Experiment,
    ExperimentKind,
    ExperimentStatus,
    Fact,
    Falsifier,
    Goal,
    GoalStatus,
    Hypothesis,
    HypothesisStatus,
    ManagedCycle,
    ModelValidationError,
    Provenance,
    ReceiptOutcome,
    RunReference,
    RunStatus,
    SessionMode,
    SessionStatus,
    SolveSession,
)
from ctf_os.store.atomic import canonical_json_record, strict_json_loads


class ContextPackTests(unittest.TestCase):
    def state(self) -> ChallengeState:
        state = ChallengeState("contest", "rev", "challenge")
        state.goals.append(Goal("G-1", "locate validation", GoalStatus.ACTIVE))
        state.active_goal_id = "G-1"
        state.facts.extend(
            [
                Fact(
                    "F-1",
                    "runtime reached 0x401000",
                    Provenance.EXECUTED,
                    challenge_id="challenge",
                    locator="run.log:20",
                    source_run_id="R-1",
                    artifact_id="A-1",
                ),
                Fact(
                    "F-2",
                    "the answer may be 7",
                    Provenance.MODEL_CLAIMED,
                    challenge_id="challenge",
                ),
            ]
        )
        state.runs.append(
            RunReference(
                id="R-1",
                base_revision=0,
                status=RunStatus.COMPLETED,
            )
        )
        state.artifacts.append(
            ArtifactReference(
                id="A-1",
                path="artifacts/run.log",
                sha256="a" * 64,
                source_run_id="R-1",
            )
        )
        state.hypotheses.append(
            Hypothesis("H-1", "comparison is direct", Falsifier("change input"))
        )
        state.validate()
        return state

    def pwn_crash_state(
        self,
        statuses=None,
        *,
        truncated_ordinals=(),
    ) -> tuple[ChallengeState, str]:
        import tests.test_pwn_crash_execution as pwn_execution

        case = pwn_execution.PwnCrashExecutionTests(
            methodName=(
                "test_confirmed_gate_uses_six_clean_networkless_fixed_calls"
            )
        )
        case.setUp()
        try:
            selected_statuses = (
                tuple(statuses)
                if statuses is not None
                else case._confirming_statuses()
            )
            coordinator = pwn_execution._SandboxCoordinator(
                selected_statuses,
                truncated_ordinals=truncated_ordinals,
            )
            engine, experiment_id, _artifact_path, _payload = (
                case._fixture(coordinator)
            )
            return (
                copy.deepcopy(case._execute(engine, experiment_id)),
                experiment_id,
            )
        finally:
            case.tearDown()

    def failure_capsule_state(self) -> tuple[ChallengeState, dict[str, str]]:
        state = self.state()
        state.schema_version = 2
        state.revision = 8
        canaries = {
            "command": "CREDENTIAL_FAILURE_COMMAND_622d81",
            "contract": "CREDENTIAL_CONTRACT_ERROR_d30ca1",
            "normalization": "CREDENTIAL_NORMALIZATION_ERROR_7c43af",
            "failure": "CREDENTIAL_FAILURE_MESSAGE_a39f72",
            "checkpoint": "CREDENTIAL_CHECKPOINT_NOTE_ba4e13",
        }
        captain = RunReference(
            id="R-failure-captain",
            base_revision=4,
            status=RunStatus.COMPLETED,
            result_path="runs/R-failure-captain/result.json",
            validation_path="runs/R-failure-captain/validation.json",
            role="captain",
            session_id="S-failure",
            cycle_id="CY-failure",
            extra={
                "contract_errors": [],
                "failures": [],
            },
        )
        failed = RunReference(
            id="R-failure-falsifier",
            base_revision=5,
            status=RunStatus.INVALID,
            result_path="runs/R-failure-falsifier/result.json",
            validation_path=(
                "runs/R-failure-falsifier/validation.json"
            ),
            role="falsifier",
            session_id="S-failure",
            cycle_id="CY-failure",
            extra={
                "contract_errors": [canaries["contract"]],
                "normalization_error": canaries["normalization"],
                "failures": [
                    {
                        "kind": "contract_invalid",
                        "message": canaries["failure"],
                        "retryable": False,
                    }
                ],
            },
        )
        failed_experiment = Experiment(
            id="E-cycle-proposal",
            hypothesis_ids=["H-1"],
            command=f"probe --token {canaries['command']}",
            expected_observation="a different branch is observed",
            keep_if="the branch changes",
            drop_if="the branch remains fixed",
            timeout_seconds=10,
            kind=ExperimentKind.STRATEGIC,
            status=ExperimentStatus.REGISTERED,
            source_run_id=captain.id,
        )
        next_experiment = Experiment(
            id="E-next-safe",
            hypothesis_ids=["H-1"],
            command="probe --alternate",
            expected_observation="the alternate branch is observed",
            keep_if="the branch changes",
            drop_if="the branch remains fixed",
            timeout_seconds=10,
            kind=ExperimentKind.STRATEGIC,
            status=ExperimentStatus.REGISTERED,
        )
        state.runs.extend((captain, failed))
        state.experiments.extend(
            (failed_experiment, next_experiment)
        )
        state.sessions.append(
            SolveSession(
                id="S-failure",
                mode=SessionMode.MANAGED,
                status=SessionStatus.COMPLETED,
                configuration_epoch=0,
                start_revision=4,
                end_revision=9,
                run_ids=[captain.id, failed.id],
            )
        )
        state.cycles.append(
            ManagedCycle(
                id="CY-failure",
                session_id="S-failure",
                ordinal=1,
                phase="invalid",
                configuration_epoch=0,
                selected_action_ids=[failed_experiment.id],
            )
        )
        capsule = build_failure_capsule(
            state,
            session_id="S-failure",
            cycle_id="CY-failure",
            reason_code="analysis_wave_invalid",
            stage="attack",
            state_revision_after=state.revision + 1,
        )
        state.cycles[-1].checkpoint_id = "CP-failure"
        state.checkpoints.append(
            Checkpoint(
                id="CP-failure",
                session_id="S-failure",
                cycle_id="CY-failure",
                active_goal_id="G-1",
                open_hypothesis_ids=["H-1"],
                next_actions=[canaries["checkpoint"]],
                do_not_repeat=[canaries["checkpoint"]],
                note=canaries["checkpoint"],
                failure_capsule=capsule,
            )
        )
        state.revision += 1
        state.validate()
        return state, canaries

    def test_pack_preserves_active_goal_provenance_and_state_pointer(self) -> None:
        pack = build_context_pack(
            self.state(),
            get_adapter("rev"),
            state_path=Path("/state/state.json"),
        )
        self.assertIn("locate validation", pack.text)
        self.assertIn("[executed]", pack.text)
        self.assertIn("/state/state.json", pack.text)
        self.assertIn("Category progress and failure contract", pack.text)
        self.assertIn("failure label:", pack.text)
        self.assertIn("evidence=", pack.text)
        self.assertEqual(len(pack.sha256), 64)

    def test_pack_is_bounded_and_reports_omissions(self) -> None:
        state = self.state()
        for index in range(200):
            state.facts.append(
                Fact(
                    f"F-{index + 10}",
                    "x" * 200,
                    Provenance.MODEL_CLAIMED,
                    challenge_id="challenge",
                )
            )
        pack = build_context_pack(
            state,
            get_adapter("rev"),
            state_path=Path("/state/state.json"),
            max_chars=4096,
        )
        self.assertLessEqual(len(pack.text), 4096)
        self.assertTrue(pack.truncated)
        self.assertIn("facts", pack.omitted)

    def test_falsifier_pack_prioritizes_executed_facts(self) -> None:
        pack = build_context_pack(
            self.state(),
            get_adapter("rev"),
            state_path=Path("/state/state.json"),
            role="falsifier",
        )
        self.assertLess(
            pack.text.index("runtime reached"), pack.text.index("answer may")
        )

    def test_pack_keeps_bounded_resolved_hypothesis_history(self) -> None:
        state = self.state()
        state.hypotheses[0].status = HypothesisStatus.CONFIRMED
        state.hypotheses[0].evidence_fact_ids.append("F-1")
        state.facts[0].supports.append("H-1")
        pack = build_context_pack(
            state,
            get_adapter("rev"),
            state_path=Path("/state/state.json"),
        )
        self.assertIn('"kind":"resolved_hypothesis"', pack.text)
        self.assertIn("comparison is direct", pack.text)

    def test_supported_hypothesis_remains_on_active_frontier(self) -> None:
        state = self.state()
        state.hypotheses[0].status = HypothesisStatus.SUPPORTED
        state.hypotheses[0].evidence_fact_ids.append("F-1")
        state.facts[0].supports.append("H-1")
        state.validate()

        pack = build_context_pack(
            state,
            get_adapter("rev"),
            state_path=Path("/state/state.json"),
        )

        self.assertIn('"kind":"active_hypothesis"', pack.text)
        self.assertIn('"status":"supported"', pack.text)
        self.assertNotIn('"kind":"resolved_hypothesis"', pack.text)

    def test_active_hypothesis_exposes_typed_frontier_fields(self) -> None:
        state = self.state()
        hypothesis = state.hypotheses[0]
        hypothesis.evidence_fact_ids.append("F-1")
        hypothesis.extra.update(
            {
                "unknowns": ["whether a second comparison exists"],
                "experiment": "trace one changed input",
                "success_oracle": "the comparison branch changes",
            }
        )
        state.validate()

        pack = build_context_pack(
            state,
            get_adapter("rev"),
            state_path=Path("/state/state.json"),
        )
        records = [
            strict_json_loads(line)
            for line in pack.text.splitlines()
            if line
        ]
        record = next(
            item
            for item in records
            if item.get("kind") == "active_hypothesis"
        )

        self.assertEqual(record["claim"], "comparison is direct")
        self.assertEqual(record["evidence"], ["F-1"])
        self.assertEqual(
            record["unknowns"],
            ["whether a second comparison exists"],
        )
        self.assertEqual(
            record["experiment"],
            "trace one changed input",
        )
        self.assertEqual(
            record["success_oracle"],
            "the comparison branch changes",
        )
        self.assertEqual(record["falsifier"], "change input")

    def test_latest_checkpoint_is_mandatory_under_context_pressure(self) -> None:
        state = self.state()
        state.prompt = "operator pressure " * 2_000
        state.checkpoints.append(
            Checkpoint(
                id="CP-latest",
                session_id=None,
                cycle_id=None,
                active_goal_id="G-1",
                open_hypothesis_ids=["H-1"],
                next_actions=[
                    "run the cheapest discriminator",
                    *(["x" * 2_000] * 20),
                ],
                do_not_repeat=[
                    "avoid the stale brute-force path",
                    *(["y" * 2_000] * 20),
                ],
                note="resume from this exact checkpoint",
            )
        )
        state.validate()

        pack = build_context_pack(
            state,
            get_adapter("rev"),
            state_path=Path("/state/state.json"),
            max_chars=4096,
        )

        self.assertLessEqual(len(pack.text), 4096)
        self.assertIn('"kind":"resume_capsule"', pack.text)
        self.assertIn('"hypothesis_ids":["H-1"]', pack.text)
        self.assertIn('"next_action_count":21', pack.text)
        self.assertIn('"do_not_repeat_count":21', pack.text)
        self.assertNotIn("resume from this exact checkpoint", pack.text)
        self.assertNotIn("run the cheapest discriminator", pack.text)
        self.assertNotIn("avoid the stale brute-force path", pack.text)
        self.assertIn("operator_context", pack.omitted)

    def test_resume_capsule_is_deterministic_bounded_and_reserves_facts(
        self,
    ) -> None:
        state = self.state()
        for index in range(10):
            run_id = f"R-confirmed-{index:02d}"
            artifact_id = f"A-confirmed-{index:02d}"
            state.runs.append(
                RunReference(
                    id=run_id,
                    base_revision=0,
                    status=RunStatus.COMPLETED,
                    created_at=f"2026-01-01T00:00:{index:02d}Z",
                )
            )
            state.artifacts.append(
                ArtifactReference(
                    id=artifact_id,
                    path=f"artifacts/confirmed-{index:02d}.json",
                    sha256=f"{index + 1:064x}",
                    source_run_id=run_id,
                    size=index + 1,
                    created_at=f"2026-01-01T00:00:{index:02d}Z",
                )
            )
            state.facts.append(
                Fact(
                    id=f"F-confirmed-{index:02d}",
                    statement=f"confirmed observation {index}",
                    provenance=Provenance.EXECUTED,
                    challenge_id="challenge",
                    locator=f"artifact:{index}",
                    source_run_id=run_id,
                    artifact_id=artifact_id,
                    created_at=f"2026-01-01T00:00:{index:02d}Z",
                )
            )
        for index in range(300):
            state.experiments.append(
                Experiment(
                    id=f"E-pending-{index:03d}",
                    hypothesis_ids=["H-1"],
                    command=f"probe --case {index}",
                    expected_observation=f"observation {index}",
                    keep_if="branch changes",
                    drop_if="branch remains fixed",
                    timeout_seconds=10,
                    status=ExperimentStatus.REGISTERED,
                    created_at=f"2026-01-02T00:{index // 60:02d}:"
                    f"{index % 60:02d}Z",
                )
            )
        state.cycles.append(
            ManagedCycle(
                id="CY-latest",
                session_id="S-history",
                ordinal=1,
                phase="completed",
                configuration_epoch=0,
                selected_action_ids=["E-pending-000"],
            )
        )
        state.checkpoints.append(
            Checkpoint(
                id="CP-latest",
                session_id=None,
                cycle_id="CY-latest",
                active_goal_id="G-1",
                open_hypothesis_ids=["H-1"],
            )
        )
        state.validate()

        first = render_resume_capsule(
            state,
            state_path=Path("/state/state.json"),
        )
        second = render_resume_capsule(
            state,
            state_path=Path("/state/state.json"),
        )
        record = strict_json_loads(first.text)

        self.assertEqual(first.text, second.text)
        self.assertEqual(first.sha256, second.sha256)
        self.assertEqual(
            first.sha256,
            hashlib.sha256(first.text.encode("ascii")).hexdigest(),
        )
        self.assertLessEqual(
            len(first.text.encode("ascii")),
            MAX_RESUME_CAPSULE_BYTES,
        )
        self.assertEqual(record["counts"]["pending"]["total"], 300)
        self.assertLessEqual(record["counts"]["pending"]["included"], 6)
        self.assertEqual(
            record["counts"]["pending"]["omitted"],
            300 - record["counts"]["pending"]["included"],
        )
        self.assertLessEqual(record["counts"]["confirmed"]["included"], 6)
        self.assertGreater(record["counts"]["confirmed"]["included"], 0)
        self.assertEqual(
            record["pending"][0]["id"],
            "E-pending-000",
        )
        self.assertEqual(
            record["pending"][0]["selection_reason"],
            "checkpoint_or_cycle",
        )

        pressure = build_context_pack(
            state,
            get_adapter("rev"),
            state_path=Path("/state/state.json"),
            max_chars=4096,
        )
        pressure_record = next(
            strict_json_loads(line)
            for line in pressure.text.splitlines()
            if '"kind":"resume_capsule"' in line
        )
        self.assertGreater(
            pressure_record["counts"]["confirmed"]["included"],
            0,
        )
        self.assertNotIn("pending_strategic_evaluation", pressure.text)

    def test_resume_capsule_keeps_pointer_only_fact_under_unicode_pressure(
        self,
    ) -> None:
        state = self.state()
        fact = state.facts[0]
        fact.statement = "확인된관찰" * 80
        fact.locator = "실행위치" * 64

        wide = strict_json_loads(
            render_resume_capsule(
                state,
                state_path=Path("/state/state.json"),
            ).text
        )
        wide_fact = wide["confirmed"][0]
        self.assertLessEqual(
            len(
                canonical_json_record(wide_fact["summary"]).encode("ascii")
            ),
            240,
        )
        self.assertLessEqual(
            len(
                canonical_json_record(wide_fact["locator"]).encode("ascii")
            ),
            192,
        )

        for index in range(300):
            state.experiments.append(
                Experiment(
                    id=f"E-unicode-pressure-{index:03d}",
                    hypothesis_ids=["H-1"],
                    command=f"probe --case {index}",
                    expected_observation="one bounded observation",
                    keep_if="the branch changes",
                    drop_if="the branch remains fixed",
                    timeout_seconds=10,
                    status=ExperimentStatus.REGISTERED,
                    created_at=f"2026-01-02T00:{index // 60:02d}:"
                    f"{index % 60:02d}Z",
                )
            )
        state.validate()

        pack = build_context_pack(
            state,
            get_adapter("rev"),
            state_path=Path("/state/state.json"),
            max_chars=4096,
        )
        record = next(
            strict_json_loads(line)
            for line in pack.text.splitlines()
            if '"kind":"resume_capsule"' in line
        )

        self.assertLessEqual(len(pack.text), 4096)
        self.assertEqual(
            record["counts"]["confirmed"],
            {"included": 1, "omitted": 0, "total": 1},
        )
        self.assertEqual(record["counts"]["pending"]["total"], 300)
        self.assertEqual(
            record["counts"]["pending"]["omitted"],
            300 - record["counts"]["pending"]["included"],
        )
        compact = record["confirmed"][0]
        self.assertEqual(
            set(compact),
            {"artifact", "fact_ids", "run_id", "run_status"},
        )
        self.assertEqual(compact["fact_ids"], [fact.id])
        self.assertEqual(compact["run_id"], fact.source_run_id)
        self.assertEqual(
            compact["artifact"],
            {
                "coverage": None,
                "id": "A-1",
                "path": "artifacts/run.log",
                "sha256": "a" * 64,
                "size": None,
            },
        )

    def test_resume_capsule_omits_unverified_result_run_binding(self) -> None:
        state = self.state()
        unrelated = RunReference(
            id="R-unrelated",
            base_revision=0,
            status=RunStatus.COMPLETED,
        )
        experiment = Experiment(
            id="E-unrelated-result",
            hypothesis_ids=["H-1"],
            command="probe --bounded",
            expected_observation="one bounded observation",
            keep_if="the branch changes",
            drop_if="the branch remains fixed",
            timeout_seconds=10,
            status=ExperimentStatus.REGISTERED,
            result={"run_id": unrelated.id},
        )
        state.runs.append(unrelated)
        state.experiments.append(experiment)
        state.validate()

        capsule = strict_json_loads(
            render_resume_capsule(
                state,
                state_path=Path("/state/state.json"),
            ).text
        )
        pending = next(
            item
            for item in capsule["pending"]
            if item["id"] == experiment.id
        )

        self.assertIsNone(pending["receipt"])
        self.assertIsNone(pending["run"])
        self.assertNotIn(unrelated.id, canonical_json_record(pending))

    def test_resume_capsule_omits_raw_and_credential_bearing_fields(
        self,
    ) -> None:
        state = self.state()
        canaries = {
            "command": "CREDENTIAL_COMMAND_4cf867",
            "result": "CREDENTIAL_RESULT_9a239b",
            "provider": "CREDENTIAL_PROVIDER_7e3a19",
            "preview": "CREDENTIAL_PREVIEW_87ab1f",
            "artifact": "CREDENTIAL_ARTIFACT_BYTES_d91f00",
            "checkpoint": "CREDENTIAL_CHECKPOINT_3057aa",
        }
        run = RunReference(
            id="R-canary",
            base_revision=0,
            status=RunStatus.COMPLETED,
        )
        artifact = ArtifactReference(
            id="A-canary",
            path="artifacts/canary.stdout",
            sha256="b" * 64,
            source_run_id=run.id,
            size=32,
        )
        experiment = Experiment(
            id="E-canary",
            hypothesis_ids=["H-1"],
            command=f"probe --password {canaries['command']}",
            expected_observation="a safe expected observation",
            keep_if="a safe keep condition",
            drop_if="a safe drop condition",
            timeout_seconds=10,
            status=ExperimentStatus.AWAITING_EVALUATION,
            result={
                "run_id": run.id,
                "receipt_id": "RC-canary",
                "stdout_summary": canaries["result"],
                "provider_error": canaries["provider"],
            },
            evidence_run_ids=[run.id],
            evidence_receipt_ids=["RC-canary"],
        )
        receipt = ExecutionReceipt(
            id="RC-canary",
            experiment_id=experiment.id,
            run_id=run.id,
            outcome=ReceiptOutcome.SUCCEEDED,
            exit_code=0,
            stdout_artifact_id=artifact.id,
            stdout_bytes=32,
            preview=canaries["preview"],
            extra={
                "provider_error": canaries["provider"],
                "stream_evidence": {
                    "stdout": {
                        "artifact_id": artifact.id,
                        "coverage": "complete_stream",
                        "head": {"text": canaries["artifact"]},
                        "path": artifact.path,
                        "sha256": artifact.sha256,
                        "stored_bytes": artifact.size,
                    }
                },
            },
        )
        state.runs.append(run)
        state.artifacts.append(artifact)
        state.experiments.append(experiment)
        state.receipts.append(receipt)
        state.checkpoints.append(
            Checkpoint(
                id="CP-canary",
                session_id=None,
                cycle_id=None,
                active_goal_id="G-1",
                open_hypothesis_ids=["H-1"],
                next_actions=[canaries["checkpoint"]],
                do_not_repeat=[canaries["checkpoint"]],
                note=canaries["checkpoint"],
            )
        )
        state.validate()

        capsule = render_resume_capsule(
            state,
            state_path=Path("/state/state.json"),
        )
        pack = build_context_pack(
            state,
            get_adapter("rev"),
            state_path=Path("/state/state.json"),
        )
        for canary in canaries.values():
            self.assertNotIn(canary, capsule.text)
            self.assertNotIn(canary, pack.text)
        capsule_record = strict_json_loads(capsule.text)
        pending = next(
            item
            for item in capsule_record["pending"]
            if item["id"] == "E-canary"
        )
        self.assertEqual(
            pending["command_sha256"],
            hashlib.sha256(experiment.command.encode()).hexdigest(),
        )
        pointer = pending["receipt"]["artifacts"][0]
        self.assertEqual(pointer["artifact_id"], artifact.id)
        self.assertEqual(pointer["path"], artifact.path)
        self.assertEqual(pointer["sha256"], artifact.sha256)
        self.assertEqual(pointer["size"], artifact.size)
        self.assertEqual(pointer["coverage"], "complete_stream")
        self.assertTrue(pending["summary_available"])
        self.assertIsNone(pending["run"])
        self.assertEqual(pending["receipt"]["run_id"], run.id)

        tampered = copy.deepcopy(state)
        tampered.receipts[-1].extra["stream_evidence"]["stdout"][
            "sha256"
        ] = "c" * 64
        with self.assertRaisesRegex(
            ModelValidationError,
            "artifact evidence chain",
        ):
            render_resume_capsule(
                tampered,
                state_path=Path("/state/state.json"),
            )

    def test_resume_capsule_projects_six_typed_pwn_receipts_in_result_order(
        self,
    ) -> None:
        state, experiment_id = self.pwn_crash_state()
        experiment = next(
            item for item in state.experiments
            if item.id == experiment_id
        )
        evidence = experiment.result["pwn_crash_evidence"]
        expected_receipt_ids = [
            item["receipt_id"] for item in evidence["attempts"]
        ]
        # Canonical attempt order is result-owned, not incidental state-list
        # order.
        state.receipts.reverse()
        state.validate()

        rendered = render_resume_capsule(
            state,
            state_path=Path("/state/state.json"),
        )
        record = strict_json_loads(rendered.text)
        projection = record["pwn_crash"]

        self.assertEqual(projection["verdict"], "CONFIRMED")
        self.assertEqual(
            projection["reason_code"],
            "reproducible_input_triggered_fault_signal",
        )
        self.assertEqual(
            projection["evaluation_sha256"],
            evidence["evaluation_sha256"],
        )
        self.assertEqual(
            projection["recipe_sha256"],
            evidence["recipe_sha256"],
        )
        self.assertEqual(projection["attempt_count"], 6)
        self.assertEqual(len(projection["attempts"]), 6)
        self.assertEqual(
            [
                item["receipt_id"]
                for item in projection["attempts"]
            ],
            expected_receipt_ids,
        )
        self.assertEqual(
            [item["phase"] for item in projection["attempts"]],
            ["positive"] * 3 + ["control"] * 3,
        )
        for attempt in projection["attempts"]:
            self.assertEqual(
                set(attempt["artifacts"]),
                {"stdout", "stderr"},
            )
            self.assertEqual(
                set(attempt["run"]),
                {
                    "id",
                    "request_path",
                    "result_path",
                    "status",
                    "validation_path",
                },
            )
            for pointer in attempt["artifacts"].values():
                self.assertEqual(
                    set(pointer),
                    {
                        "capture_placeholder",
                        "id",
                        "path",
                        "sha256",
                        "size",
                    },
                )

        compact = render_resume_capsule(
            state,
            state_path=Path("/state/state.json"),
            policy=ResumeCapsulePolicy(max_bytes=1536),
        )
        compact_projection = strict_json_loads(compact.text)["pwn_crash"]
        self.assertLessEqual(len(compact.text.encode("ascii")), 1536)
        self.assertEqual(compact_projection["verdict"], "CONFIRMED")
        self.assertEqual(
            compact_projection["reason_code"],
            "reproducible_input_triggered_fault_signal",
        )
        self.assertEqual(compact_projection["attempt_count"], 6)
        self.assertEqual(len(compact_projection["attempts"]), 1)
        pointer = compact_projection["attempts"][0]
        self.assertTrue(pointer["run_id"])
        self.assertEqual(
            set(pointer["artifact"]),
            {
                "capture_placeholder",
                "id",
                "path",
                "sha256",
                "size",
            },
        )

    def test_resume_capsule_pwn_pointer_tamper_fails_closed(self) -> None:
        state, experiment_id = self.pwn_crash_state()
        experiment = next(
            item for item in state.experiments
            if item.id == experiment_id
        )
        stdout_id = experiment.result["pwn_crash_evidence"][
            "attempts"
        ][0]["stdout_artifact_id"]
        stdout = next(
            item for item in state.artifacts if item.id == stdout_id
        )
        stdout.path = "artifacts/tampered.stdout"

        with self.assertRaisesRegex(
            ModelValidationError,
            "invalid stdout artifact pointer",
        ):
            render_resume_capsule(
                state,
                state_path=Path("/state/state.json"),
            )

        stderr_tampered, experiment_id = self.pwn_crash_state()
        experiment = next(
            item for item in stderr_tampered.experiments
            if item.id == experiment_id
        )
        first_attempt = experiment.result["pwn_crash_evidence"][
            "attempts"
        ][0]
        receipt = next(
            item
            for item in stderr_tampered.receipts
            if item.id == first_attempt["receipt_id"]
        )
        stderr = next(
            item
            for item in stderr_tampered.artifacts
            if item.id == receipt.stderr_artifact_id
        )
        stderr.sha256 = "f" * 64
        with self.assertRaisesRegex(
            ModelValidationError,
            "Pwn crash",
        ):
            render_resume_capsule(
                stderr_tampered,
                state_path=Path("/state/state.json"),
            )

    def test_pwn_failure_capsule_verdict_and_reason_mismatch_fail_closed(
        self,
    ) -> None:
        no_fault_statuses = (
            ("exited", 139, None),
            ("exited", 139, None),
            ("exited", 139, None),
            ("exited", 0, None),
            ("exited", 0, None),
            ("exited", 0, None),
        )
        cases = (
            (
                "confirmed",
                None,
                ExperimentStatus.KEPT,
                "CONFIRMED",
            ),
            (
                "inconclusive_reason_mismatch",
                no_fault_statuses,
                ExperimentStatus.INCONCLUSIVE,
                "INCONCLUSIVE",
            ),
        )
        for (
            label,
            statuses,
            expected_status,
            expected_verdict,
        ) in cases:
            with self.subTest(case=label):
                state, experiment_id = self.pwn_crash_state(statuses)
                experiment = next(
                    item
                    for item in state.experiments
                    if item.id == experiment_id
                )
                evaluation = experiment.result[
                    "pwn_crash_evidence"
                ]["evaluation"]
                self.assertIs(experiment.status, expected_status)
                self.assertEqual(
                    evaluation["verdict"],
                    expected_verdict,
                )

                session = state.sessions[0]
                cycle = state.cycles[0]
                with self.assertRaisesRegex(
                    ModelValidationError,
                    "(?i)(pwn crash|failure capsule|verdict|reason)",
                ):
                    build_failure_capsule(
                        state,
                        session_id=session.id,
                        cycle_id=cycle.id,
                        reason_code="pwn_crash_setup_failed",
                        stage="attack",
                        state_revision_after=state.revision + 1,
                    )
                if expected_status is ExperimentStatus.KEPT:
                    with self.assertRaisesRegex(
                        ModelValidationError,
                        "(?i)(only successful|non-pwn failure)",
                    ):
                        build_failure_capsule(
                            state,
                            session_id=session.id,
                            cycle_id=cycle.id,
                            reason_code="analysis_wave_invalid",
                            stage="attack",
                            state_revision_after=state.revision + 1,
                        )
                valid_reason = (
                    "pwn_crash_no_positive_fault_observed"
                    if expected_status is ExperimentStatus.INCONCLUSIVE
                    else "analysis_wave_invalid"
                )
                if expected_status is ExperimentStatus.KEPT:
                    generic_failure = Experiment(
                        id="E-selected-generic-failure",
                        hypothesis_ids=[],
                        command="false",
                        expected_observation="the probe succeeds",
                        keep_if="the probe succeeds",
                        drop_if="the probe fails",
                        timeout_seconds=1,
                        kind=ExperimentKind.PROBE,
                        status=ExperimentStatus.FAILED,
                    )
                    state.experiments.append(generic_failure)
                    cycle.selected_action_ids.append(
                        generic_failure.id
                    )
                failure = build_failure_capsule(
                    state,
                    session_id=session.id,
                    cycle_id=cycle.id,
                    reason_code=valid_reason,
                    stage="attack",
                    state_revision_after=state.revision + 1,
                )
                failure.reason_code = "pwn_crash_setup_failed"
                failure.content_sha256 = (
                    failure.computed_content_sha256()
                )
                checkpoint_id = f"CP-pwn-mismatch-{label}"
                cycle.checkpoint_id = checkpoint_id
                state.checkpoints.append(
                    Checkpoint(
                        id=checkpoint_id,
                        session_id=session.id,
                        cycle_id=cycle.id,
                        active_goal_id=state.active_goal_id,
                        failure_capsule=failure,
                    )
                )
                state.revision += 1

                entrypoints = (
                    ("state.validate", state.validate),
                    (
                        "render_resume_capsule",
                        lambda: render_resume_capsule(
                            state,
                            state_path=Path("/state/state.json"),
                        ),
                    ),
                )
                for entrypoint, action in entrypoints:
                    with self.subTest(
                        case=label,
                        entrypoint=entrypoint,
                    ):
                        with self.assertRaisesRegex(
                            ModelValidationError,
                            (
                                "(?i)(pwn crash|failure capsule|"
                                "verdict|reason|non-pass)"
                            ),
                        ):
                            action()

    def test_pwn_compact_transport_error_points_to_failing_ordinal(
        self,
    ) -> None:
        state, experiment_id = self.pwn_crash_state(
            truncated_ordinals=(2,),
        )
        experiment = next(
            item
            for item in state.experiments
            if item.id == experiment_id
        )
        evidence = experiment.result["pwn_crash_evidence"]
        transport_error = evidence["evaluation"]["transport_error"]
        self.assertEqual(transport_error["ordinal"], 2)
        failing_attempt = next(
            item
            for item in evidence["attempts"]
            if item["ordinal"] == transport_error["ordinal"]
        )

        compact = render_resume_capsule(
            state,
            state_path=Path("/state/state.json"),
            policy=ResumeCapsulePolicy(max_bytes=1536),
        )
        record = strict_json_loads(compact.text)
        pointer = record["pwn_crash"]["attempts"][0]
        self.assertLessEqual(len(compact.text.encode("ascii")), 1536)
        self.assertEqual(
            record["pwn_crash"]["reason_code"],
            "transport_stdout_capture_incomplete",
        )
        self.assertEqual(pointer["run_id"], failing_attempt["run_id"])
        self.assertEqual(
            pointer["artifact"]["id"],
            failing_attempt["stdout_artifact_id"],
        )

    def test_resume_capsule_rejects_typed_pwn_on_legacy_schema(self) -> None:
        state, _experiment_id = self.pwn_crash_state()
        state.schema_version = 1

        with self.assertRaisesRegex(
            ModelValidationError,
            "current state schema",
        ):
            render_resume_capsule(
                state,
                state_path=Path("/state/state.json"),
            )

    def test_resume_capsule_still_rejects_generic_multi_receipt(
        self,
    ) -> None:
        state = self.state()
        experiment = Experiment(
            id="E-generic-multi-receipt",
            hypothesis_ids=["H-1"],
            command="probe --generic",
            expected_observation="one observation",
            keep_if="the branch changes",
            drop_if="the branch remains fixed",
            timeout_seconds=10,
            status=ExperimentStatus.AWAITING_EVALUATION,
        )
        state.experiments.append(experiment)
        for ordinal in (1, 2):
            run = RunReference(
                id=f"R-generic-receipt-{ordinal}",
                base_revision=state.revision,
                status=RunStatus.COMPLETED,
            )
            state.runs.append(run)
            state.receipts.append(
                ExecutionReceipt(
                    id=f"RC-generic-receipt-{ordinal}",
                    experiment_id=experiment.id,
                    run_id=run.id,
                    outcome=ReceiptOutcome.SUCCEEDED,
                    exit_code=0,
                )
            )

        with self.assertRaisesRegex(
            ModelValidationError,
            "more than one receipt",
        ):
            render_resume_capsule(
                state,
                state_path=Path("/state/state.json"),
            )

    def test_pwn_failure_capsule_prefers_gate_and_compacts_to_1536(
        self,
    ) -> None:
        no_fault_statuses = (
            ("exited", 139, None),
            ("exited", 139, None),
            ("exited", 139, None),
            ("exited", 0, None),
            ("exited", 0, None),
            ("exited", 0, None),
        )
        state, _experiment_id = self.pwn_crash_state(
            no_fault_statuses
        )
        captain = next(
            item for item in state.runs if item.role == "captain"
        )
        captain.status = RunStatus.COMPLETED
        captain.result_path = f"runs/{captain.id}/result.json"
        captain.validation_path = (
            f"runs/{captain.id}/validation.json"
        )
        session = state.sessions[0]
        cycle = state.cycles[0]
        failure = build_failure_capsule(
            state,
            session_id=session.id,
            cycle_id=cycle.id,
            reason_code="pwn_crash_no_positive_fault_observed",
            stage="attack",
            state_revision_after=state.revision + 1,
        )
        cycle.checkpoint_id = "CP-pwn-crash"
        state.checkpoints.append(
            Checkpoint(
                id="CP-pwn-crash",
                session_id=session.id,
                cycle_id=cycle.id,
                active_goal_id=state.active_goal_id,
                failure_capsule=failure,
            )
        )
        state.revision += 1
        state.validate()

        wide = strict_json_loads(
            render_resume_capsule(
                state,
                state_path=Path("/state/state.json"),
            ).text
        )
        failure_projection = wide["checkpoint"]["failure_capsule"]
        self.assertEqual(
            failure_projection["runs"][0]["role"],
            "pwn_crash_gate",
        )
        self.assertNotEqual(
            failure_projection["runs"][0]["id"],
            captain.id,
        )

        compact = render_resume_capsule(
            state,
            state_path=Path("/state/state.json"),
            policy=ResumeCapsulePolicy(max_bytes=1536),
        )
        compact_record = strict_json_loads(compact.text)
        self.assertLessEqual(len(compact.text.encode("ascii")), 1536)
        self.assertEqual(
            compact_record["pwn_crash"]["verdict"],
            "INCONCLUSIVE",
        )
        self.assertEqual(
            compact_record["pwn_crash"]["reason_code"],
            "no_positive_fault_observed",
        )
        self.assertTrue(
            compact_record["checkpoint"]["failure_capsule"][
                "pwn_crash_pointer"
            ],
        )
        self.assertEqual(
            compact_record["checkpoint"]["failure_capsule"][
                "pwn_crash_pointer"
            ],
            compact_record["pwn_crash"]["experiment_id"],
        )
        self.assertTrue(
            compact_record["pwn_crash"]["attempts"][0]["run_id"]
        )
        self.assertTrue(
            compact_record["pwn_crash"]["attempts"][0]["artifact"][
                "path"
            ]
        )

    def test_pwn_failure_capsule_preserves_selected_typed_experiment(
        self,
    ) -> None:
        no_fault_statuses = (
            ("exited", 139, None),
            ("exited", 139, None),
            ("exited", 139, None),
            ("exited", 0, None),
            ("exited", 0, None),
            ("exited", 0, None),
        )
        state, experiment_id = self.pwn_crash_state(
            no_fault_statuses
        )
        session = state.sessions[0]
        cycle = state.cycles[0]
        self.assertIn(experiment_id, cycle.selected_action_ids)
        self.assertIsNotNone(cycle.captain_run_id)

        for ordinal in range(16):
            state.experiments.append(
                Experiment(
                    id=f"E-earlier-generic-{ordinal:02d}",
                    hypothesis_ids=[],
                    command=f"probe --earlier-generic {ordinal}",
                    expected_observation="one bounded observation",
                    keep_if="the observation changes",
                    drop_if="the observation remains unchanged",
                    timeout_seconds=1,
                    resource_class="light",
                    kind=ExperimentKind.PROBE,
                    status=ExperimentStatus.REGISTERED,
                    source_run_id=cycle.captain_run_id,
                    created_at=(
                        f"2000-01-01T00:00:{ordinal:02d}Z"
                    ),
                )
            )
        state.validate()

        failure = build_failure_capsule(
            state,
            session_id=session.id,
            cycle_id=cycle.id,
            reason_code="pwn_crash_no_positive_fault_observed",
            stage="attack",
            state_revision_after=state.revision + 1,
        )
        self.assertIn(
            experiment_id,
            failure.failed_experiment_ids,
        )

        cycle.checkpoint_id = "CP-pwn-selected-typed"
        state.checkpoints.append(
            Checkpoint(
                id=cycle.checkpoint_id,
                session_id=session.id,
                cycle_id=cycle.id,
                active_goal_id=state.active_goal_id,
                failure_capsule=failure,
            )
        )
        state.revision += 1
        state.validate()

        compact = render_resume_capsule(
            state,
            state_path=Path("/state/state.json"),
            policy=ResumeCapsulePolicy(max_bytes=2304),
        )
        record = strict_json_loads(compact.text)
        failure_projection = record["checkpoint"]["failure_capsule"]
        self.assertLessEqual(len(compact.text.encode("ascii")), 2304)
        self.assertEqual(
            record["pwn_crash"]["experiment_id"],
            experiment_id,
        )
        self.assertEqual(
            failure_projection["pwn_crash_pointer"],
            experiment_id,
        )

    def test_pwn_failure_capsule_rejects_unselected_causal_binding(
        self,
    ) -> None:
        no_fault_statuses = (
            ("exited", 139, None),
            ("exited", 139, None),
            ("exited", 139, None),
            ("exited", 0, None),
            ("exited", 0, None),
            ("exited", 0, None),
        )
        state, experiment_id = self.pwn_crash_state(
            no_fault_statuses
        )
        session = state.sessions[0]
        cycle = state.cycles[0]
        failure = build_failure_capsule(
            state,
            session_id=session.id,
            cycle_id=cycle.id,
            reason_code="pwn_crash_no_positive_fault_observed",
            stage="attack",
            state_revision_after=state.revision + 1,
        )
        cycle.checkpoint_id = "CP-pwn-unselected"
        state.checkpoints.append(
            Checkpoint(
                id=cycle.checkpoint_id,
                session_id=session.id,
                cycle_id=cycle.id,
                active_goal_id=state.active_goal_id,
                failure_capsule=failure,
            )
        )
        state.revision += 1
        state.validate()

        cycle.selected_action_ids.remove(experiment_id)
        entrypoints = (
            ("state.validate", state.validate),
            (
                "render_resume_capsule",
                lambda: render_resume_capsule(
                    state,
                    state_path=Path("/state/state.json"),
                ),
            ),
        )
        for entrypoint, action in entrypoints:
            with self.subTest(entrypoint=entrypoint):
                with self.assertRaisesRegex(
                    ModelValidationError,
                    "(?i)(selected cycle action|failure capsule|pwn)",
                ):
                    action()

    def test_pwn_compaction_preserves_selected_negative_non_pwn_run(
        self,
    ) -> None:
        no_fault_statuses = (
            ("exited", 139, None),
            ("exited", 139, None),
            ("exited", 139, None),
            ("exited", 0, None),
            ("exited", 0, None),
            ("exited", 0, None),
        )
        state, _experiment_id = self.pwn_crash_state(
            no_fault_statuses
        )
        session = state.sessions[0]
        cycle = state.cycles[0]
        negative_run = RunReference(
            id="R-negative-falsifier",
            base_revision=state.revision,
            status=RunStatus.INVALID,
            result_path="runs/R-negative-falsifier/result.json",
            validation_path=(
                "runs/R-negative-falsifier/validation.json"
            ),
            role="falsifier",
            session_id=session.id,
            cycle_id=cycle.id,
        )
        state.runs.append(negative_run)
        failure = build_failure_capsule(
            state,
            session_id=session.id,
            cycle_id=cycle.id,
            reason_code="pwn_crash_no_positive_fault_observed",
            stage="attack",
            state_revision_after=state.revision + 1,
        )
        cycle.checkpoint_id = "CP-pwn-negative"
        state.checkpoints.append(
            Checkpoint(
                id="CP-pwn-negative",
                session_id=session.id,
                cycle_id=cycle.id,
                active_goal_id=state.active_goal_id,
                failure_capsule=failure,
            )
        )
        state.revision += 1
        state.validate()

        compact = render_resume_capsule(
            state,
            state_path=Path("/state/state.json"),
            policy=ResumeCapsulePolicy(max_bytes=1536),
        )
        record = strict_json_loads(compact.text)
        failure_projection = record["checkpoint"]["failure_capsule"]

        self.assertLessEqual(len(compact.text.encode("ascii")), 1536)
        self.assertNotIn("pwn_crash_pointer", failure_projection)
        self.assertEqual(
            failure_projection["runs"][0]["id"],
            negative_run.id,
        )
        self.assertEqual(
            failure_projection["runs"][0]["status"],
            "invalid",
        )

    def test_failure_capsule_rendering_is_deterministic_and_structured(
        self,
    ) -> None:
        state, _canaries = self.failure_capsule_state()

        first = render_resume_capsule(
            state,
            state_path=Path("/state/state.json"),
        )
        second = render_resume_capsule(
            state,
            state_path=Path("/state/state.json"),
        )
        record = strict_json_loads(first.text)
        failure = record["checkpoint"]["failure_capsule"]

        self.assertEqual(first.text, second.text)
        self.assertEqual(first.sha256, second.sha256)
        self.assertEqual(failure["reason_code"], "analysis_wave_invalid")
        self.assertEqual(failure["stage"], "attack")
        self.assertEqual(failure["occurrence_count"], 1)
        self.assertEqual(failure["state_revision_before"], 4)
        self.assertEqual(failure["state_revision_after"], 9)
        self.assertEqual(failure["run_count"], 2)
        failed_run = next(
            item
            for item in failure["runs"]
            if item["id"] == "R-failure-falsifier"
        )
        self.assertEqual(
            failed_run["validation_path"],
            "runs/R-failure-falsifier/validation.json",
        )
        self.assertEqual(
            failed_run["result_path"],
            "runs/R-failure-falsifier/result.json",
        )
        self.assertEqual(
            failed_run["diagnostics"]["contract_error_count"],
            1,
        )
        self.assertTrue(
            failed_run["diagnostics"][
                "normalization_error_present"
            ]
        )
        self.assertEqual(
            failed_run["diagnostics"]["machine_failure_kinds"],
            [
                {
                    "kind": "contract_invalid",
                    "non_retryable_count": 1,
                    "retryable_count": 0,
                    "total_count": 1,
                }
            ],
        )
        self.assertEqual(
            failure["failed_experiments"][0]["id"],
            "E-cycle-proposal",
        )
        self.assertEqual(
            failure["next_experiments"][0]["id"],
            "E-next-safe",
        )
        self.assertNotIn(
            "command",
            failure["next_experiments"][0],
        )

    def test_failure_capsule_counts_repeated_fingerprint(self) -> None:
        state, _canaries = self.failure_capsule_state()
        original_captain = next(
            item for item in state.runs
            if item.id == "R-failure-captain"
        )
        original_failed = next(
            item for item in state.runs
            if item.id == "R-failure-falsifier"
        )
        repeated_captain = copy.deepcopy(original_captain)
        repeated_captain.id = "R-failure-captain-repeat"
        repeated_captain.cycle_id = "CY-failure-repeat"
        repeated_captain.result_path = (
            "runs/R-failure-captain-repeat/result.json"
        )
        repeated_captain.validation_path = (
            "runs/R-failure-captain-repeat/validation.json"
        )
        repeated_failed = copy.deepcopy(original_failed)
        repeated_failed.id = "R-failure-falsifier-repeat"
        repeated_failed.cycle_id = "CY-failure-repeat"
        repeated_failed.result_path = (
            "runs/R-failure-falsifier-repeat/result.json"
        )
        repeated_failed.validation_path = (
            "runs/R-failure-falsifier-repeat/validation.json"
        )
        repeated_experiment = copy.deepcopy(
            next(
                item for item in state.experiments
                if item.id == "E-cycle-proposal"
            )
        )
        repeated_experiment.id = "E-cycle-proposal-repeat"
        repeated_experiment.source_run_id = repeated_captain.id
        state.runs.extend((repeated_captain, repeated_failed))
        state.experiments.append(repeated_experiment)
        state.sessions[0].run_ids.extend(
            (repeated_captain.id, repeated_failed.id)
        )
        state.sessions[0].end_revision = 10
        state.cycles.append(
            ManagedCycle(
                id="CY-failure-repeat",
                session_id="S-failure",
                ordinal=2,
                phase="invalid",
                configuration_epoch=0,
                selected_action_ids=[repeated_experiment.id],
            )
        )
        repeated_capsule = build_failure_capsule(
            state,
            session_id="S-failure",
            cycle_id="CY-failure-repeat",
            reason_code="analysis_wave_invalid",
            stage="attack",
            state_revision_after=state.revision + 1,
        )
        state.cycles[-1].checkpoint_id = "CP-failure-repeat"
        state.checkpoints.append(
            Checkpoint(
                id="CP-failure-repeat",
                session_id="S-failure",
                cycle_id="CY-failure-repeat",
                active_goal_id="G-1",
                failure_capsule=repeated_capsule,
            )
        )
        state.revision += 1
        state.validate()

        record = strict_json_loads(
            render_resume_capsule(
                state,
                state_path=Path("/state/state.json"),
            ).text
        )

        self.assertEqual(
            record["checkpoint"]["failure_capsule"][
                "occurrence_count"
            ],
            2,
        )

    def test_failure_capsule_is_mandatory_bounded_and_omits_canaries(
        self,
    ) -> None:
        state, canaries = self.failure_capsule_state()

        capsule = render_resume_capsule(
            state,
            state_path=Path("/state/state.json"),
            policy=ResumeCapsulePolicy(max_bytes=1536),
        )
        pack = build_context_pack(
            state,
            get_adapter("rev"),
            state_path=Path("/state/state.json"),
            max_chars=4096,
        )

        self.assertLessEqual(len(capsule.text.encode("ascii")), 1536)
        self.assertIn('"failure_capsule":', capsule.text)
        self.assertIn('"failure_capsule":', pack.text)
        for canary in canaries.values():
            self.assertNotIn(canary, capsule.text)
            self.assertNotIn(canary, pack.text)

    def test_failure_capsule_fingerprint_tamper_fails_closed(self) -> None:
        state, _canaries = self.failure_capsule_state()
        tampered = copy.deepcopy(state)
        capsule = tampered.checkpoints[-1].failure_capsule
        assert capsule is not None
        capsule.fingerprint_sha256 = "0" * 64

        with self.assertRaisesRegex(
            ModelValidationError,
            "content_sha256|content hash|fingerprint does not match",
        ):
            render_resume_capsule(
                tampered,
                state_path=Path("/state/state.json"),
            )

    def test_failure_capsule_builder_requires_next_state_revision(
        self,
    ) -> None:
        state, _canaries = self.failure_capsule_state()

        with self.assertRaisesRegex(
            ModelValidationError,
            "must be the next revision",
        ):
            build_failure_capsule(
                state,
                session_id="S-failure",
                cycle_id="CY-failure",
                reason_code="analysis_wave_invalid",
                stage="attack",
                state_revision_after=state.revision + 2,
            )

    def test_failure_fingerprint_ignores_raw_messages_but_not_approach(
        self,
    ) -> None:
        state, _canaries = self.failure_capsule_state()
        original = build_failure_capsule(
            state,
            session_id="S-failure",
            cycle_id="CY-failure",
            reason_code="analysis_wave_invalid",
            stage="attack",
            state_revision_after=state.revision + 1,
        )
        failed_run = next(
            run for run in state.runs if run.id == "R-failure-falsifier"
        )
        failed_run.extra["contract_errors"] = ["different raw detail"]
        failed_run.extra["normalization_error"] = "different raw detail"
        failed_run.extra["failures"][0]["message"] = "different raw detail"
        redacted_variation = build_failure_capsule(
            state,
            session_id="S-failure",
            cycle_id="CY-failure",
            reason_code="analysis_wave_invalid",
            stage="attack",
            state_revision_after=state.revision + 1,
        )
        self.assertEqual(
            original.fingerprint_sha256,
            redacted_variation.fingerprint_sha256,
        )

        failed_experiment = next(
            item for item in state.experiments if item.id == "E-cycle-proposal"
        )
        failed_experiment.command = "probe --different-approach"
        changed_approach = build_failure_capsule(
            state,
            session_id="S-failure",
            cycle_id="CY-failure",
            reason_code="analysis_wave_invalid",
            stage="attack",
            state_revision_after=state.revision + 1,
        )
        self.assertNotEqual(
            original.fingerprint_sha256,
            changed_approach.fingerprint_sha256,
        )

    def test_proof_failure_fingerprint_includes_recipe_hash(self) -> None:
        experiment = Experiment(
            id="E-proof-fingerprint",
            hypothesis_ids=[],
            command="./target",
            expected_observation="the oracle accepts",
            keep_if="exit status is zero",
            drop_if="exit status is non-zero",
            timeout_seconds=10,
            kind=ExperimentKind.PROOF,
        )
        experiment.proof_recipe = SimpleNamespace(
            recipe_sha256="a" * 64
        )
        first = failure_capsule_module._experiment_fingerprint_digest(
            experiment
        )
        experiment.proof_recipe = SimpleNamespace(
            recipe_sha256="b" * 64
        )
        second = failure_capsule_module._experiment_fingerprint_digest(
            experiment
        )

        self.assertEqual(first["proof_recipe_sha256"], "a" * 64)
        self.assertNotEqual(first, second)

    def test_failure_capsule_survives_later_experiment_status_change(
        self,
    ) -> None:
        state, _canaries = self.failure_capsule_state()
        failed_experiment = next(
            item for item in state.experiments if item.id == "E-cycle-proposal"
        )
        failed_experiment.status = ExperimentStatus.COMPLETED
        state.validate()

        rendered = render_resume_capsule(
            state,
            state_path=Path("/state/state.json"),
        )

        self.assertIn('"reason_code":"analysis_wave_invalid"', rendered.text)

    def test_failure_capsule_marks_stale_frontier_records(self) -> None:
        state, _canaries = self.failure_capsule_state()
        next_experiment = next(
            item for item in state.experiments
            if item.id == "E-next-safe"
        )
        next_experiment.status = ExperimentStatus.COMPLETED
        resolved = state.hypotheses[0]
        resolved.status = HypothesisStatus.CONFIRMED
        resolved.evidence_fact_ids = ["F-1"]
        resolved.evidence_artifact_ids = ["A-1"]
        resolved.evidence_run_ids = ["R-1"]
        state.revision += 1
        state.sessions[0].end_revision = state.revision
        state.validate()

        record = strict_json_loads(
            render_resume_capsule(
                state,
                state_path=Path("/state/state.json"),
            ).text
        )
        failure = record["checkpoint"]["failure_capsule"]

        self.assertEqual(failure["next_experiments"], [])
        self.assertEqual(failure["next_experiments_stale"], 1)
        self.assertEqual(failure["unresolved_hypotheses"]["ids"], [])
        self.assertEqual(failure["unresolved_hypotheses_stale"], 1)

    def test_failure_capsule_omits_mutated_next_experiment_text(
        self,
    ) -> None:
        state, _canaries = self.failure_capsule_state()
        canary = "sk-live-CREDENTIAL-MUTATION-CANARY-9817"
        next_experiment = next(
            item for item in state.experiments
            if item.id == "E-next-safe"
        )
        next_experiment.expected_observation = canary
        next_experiment.keep_if = canary
        next_experiment.drop_if = canary
        state.validate()

        rendered = render_resume_capsule(
            state,
            state_path=Path("/state/state.json"),
        )
        record = strict_json_loads(rendered.text)
        next_record = record["checkpoint"]["failure_capsule"][
            "next_experiments"
        ][0]

        self.assertNotIn(canary, rendered.text)
        self.assertEqual(next_record["id"], "E-next-safe")
        self.assertEqual(
            set(next_record),
            {"command_sha256", "id", "kind"},
        )

    def test_failure_capsule_accepts_result_only_run_pointer(self) -> None:
        state, _canaries = self.failure_capsule_state()
        failed_run = next(
            item for item in state.runs
            if item.id == "R-failure-falsifier"
        )
        failed_run.validation_path = None
        state.validate()

        record = strict_json_loads(
            render_resume_capsule(
                state,
                state_path=Path("/state/state.json"),
            ).text
        )
        rendered_run = record["checkpoint"]["failure_capsule"]["runs"][0]
        self.assertEqual(
            rendered_run["result_path"],
            "runs/R-failure-falsifier/result.json",
        )
        self.assertNotIn("validation_path", rendered_run)

    def test_failure_capsule_bounds_provider_failure_burst(self) -> None:
        state, _canaries = self.failure_capsule_state()
        canary = "sk_live_credential_canary_2af9"
        failed_run = next(
            item for item in state.runs
            if item.id == "R-failure-falsifier"
        )
        failed_run.extra["failures"] = [
            {
                "kind": f"{canary}_{index % 40:02d}",
                "message": f"raw-{index}",
                "retryable": True,
            }
            for index in range(200)
        ]
        capsule = build_failure_capsule(
            state,
            session_id="S-failure",
            cycle_id="CY-failure",
            reason_code="analysis_wave_invalid",
            stage="attack",
            state_revision_after=state.revision + 1,
        )
        state.checkpoints[-1].failure_capsule = capsule
        state.revision += 1
        state.sessions[0].end_revision = state.revision

        rendered = render_resume_capsule(
            state,
            state_path=Path("/state/state.json"),
        )
        record = strict_json_loads(rendered.text)
        diagnostics = record["checkpoint"]["failure_capsule"]["runs"][0][
            "diagnostics"
        ]

        self.assertNotIn(canary, rendered.text)
        self.assertEqual(diagnostics["machine_failure_count"], 200)
        self.assertEqual(
            diagnostics["machine_failure_records_over_soft_limit"],
            72,
        )
        self.assertEqual(
            diagnostics["machine_failure_kinds_omitted"],
            8,
        )
        self.assertRegex(
            diagnostics["machine_failure_kinds"][0]["kind"],
            r"^external_[0-9a-f]{16}$",
        )

        compact = render_resume_capsule(
            state,
            state_path=Path("/state/state.json"),
            policy=ResumeCapsulePolicy(max_bytes=1536),
        )
        compact_record = strict_json_loads(compact.text)
        compact_diagnostics = compact_record["checkpoint"][
            "failure_capsule"
        ]["runs"][0]["diagnostics"]
        self.assertLessEqual(len(compact.text.encode("ascii")), 1536)
        self.assertEqual(len(compact_diagnostics["failure_kinds"]), 2)
        self.assertEqual(
            compact_diagnostics["failure_kinds_omitted"],
            38,
        )
        self.assertEqual(
            compact_diagnostics["failure_records_over_soft_limit"],
            72,
        )

    def test_failure_capsule_projects_oversized_cycle_sources(self) -> None:
        state, _canaries = self.failure_capsule_state()
        session = state.sessions[0]
        cycle_id = "CY-oversized"
        run_ids = []
        selected_ids = []
        for index in range(20):
            run_id = f"R-oversized-{index:02d}"
            experiment_id = f"E-oversized-{index:02d}"
            run_ids.append(run_id)
            selected_ids.append(experiment_id)
            state.runs.append(
                RunReference(
                    id=run_id,
                    base_revision=state.revision,
                    status=RunStatus.FAILED,
                    role="builder",
                    session_id=session.id,
                    cycle_id=cycle_id,
                )
            )
            state.experiments.append(
                Experiment(
                    id=experiment_id,
                    hypothesis_ids=[],
                    command=f"probe-{index}",
                    expected_observation="observable branch change",
                    keep_if="branch changes",
                    drop_if="branch does not change",
                    timeout_seconds=10,
                    kind=ExperimentKind.PROBE,
                    status=ExperimentStatus.FAILED,
                    source_run_id=run_id,
                )
            )
        session.run_ids.extend(run_ids)
        state.cycles.append(
            ManagedCycle(
                id=cycle_id,
                session_id=session.id,
                ordinal=2,
                phase="invalid",
                configuration_epoch=0,
                selected_action_ids=selected_ids,
            )
        )
        for index in range(40):
            artifact_id = f"A-oversized-{index:02d}"
            run_id = run_ids[index % len(run_ids)]
            state.artifacts.append(
                ArtifactReference(
                    id=artifact_id,
                    path=f"artifacts/oversized-{index:02d}.log",
                    sha256=f"{index:064x}",
                    source_run_id=run_id,
                )
            )
            state.facts.append(
                Fact(
                    id=f"F-oversized-{index:02d}",
                    challenge_id=state.challenge_id,
                    statement=f"bounded evidence {index}",
                    provenance=Provenance.EXECUTED,
                    source_run_id=run_id,
                    artifact_id=artifact_id,
                    locator=f"artifacts/oversized-{index:02d}.log:1",
                )
            )
            state.hypotheses.append(
                Hypothesis(
                    id=f"H-oversized-{index:02d}",
                    statement=f"hypothesis {index}",
                    falsifier=Falsifier(f"counterexample {index}"),
                )
            )

        capsule = build_failure_capsule(
            state,
            session_id=session.id,
            cycle_id=cycle_id,
            reason_code="analysis_wave_invalid",
            stage="attack",
            state_revision_after=state.revision + 1,
        )

        self.assertEqual(len(capsule.run_ids), 16)
        self.assertEqual(capsule.omitted_counts["run_ids"], 4)
        self.assertEqual(len(capsule.failed_experiment_ids), 16)
        self.assertEqual(
            capsule.omitted_counts["failed_experiment_ids"],
            4,
        )
        self.assertEqual(len(capsule.artifact_ids), 32)
        self.assertEqual(capsule.omitted_counts["artifact_ids"], 8)
        self.assertEqual(len(capsule.fact_ids), 32)
        self.assertEqual(capsule.omitted_counts["fact_ids"], 8)
        self.assertEqual(len(capsule.unresolved_hypothesis_ids), 32)
        self.assertGreater(
            capsule.omitted_counts["unresolved_hypothesis_ids"],
            0,
        )

    def test_failure_capsule_omits_oversized_next_experiment_id(
        self,
    ) -> None:
        state, _canaries = self.failure_capsule_state()
        oversized_id = "E-" + "x" * 400
        state.experiments.append(
            Experiment(
                id=oversized_id,
                hypothesis_ids=["H-1"],
                command="probe --oversized-id",
                expected_observation="the alternate branch is observed",
                keep_if="the branch changes",
                drop_if="the branch remains fixed",
                timeout_seconds=10,
                kind=ExperimentKind.STRATEGIC,
            )
        )
        capsule = build_failure_capsule(
            state,
            session_id="S-failure",
            cycle_id="CY-failure",
            reason_code="analysis_wave_invalid",
            stage="attack",
            state_revision_after=state.revision + 1,
        )
        state.checkpoints[-1].failure_capsule = capsule
        state.revision += 1
        state.sessions[0].end_revision = state.revision

        rendered = render_resume_capsule(
            state,
            state_path=Path("/state/state.json"),
            policy=ResumeCapsulePolicy(max_bytes=1536),
        )
        record = strict_json_loads(rendered.text)
        failure = record["checkpoint"]["failure_capsule"]

        self.assertLessEqual(len(rendered.text.encode("ascii")), 1536)
        self.assertNotIn(oversized_id, rendered.text)
        self.assertGreaterEqual(
            failure["next_experiments_omitted"],
            1,
        )

    def test_long_operator_prompt_has_explicit_pointer_and_truncation(self) -> None:
        state = self.state()
        state.prompt = "A" * 16_000 + "TAIL_SENTINEL"
        state_path = Path("/state/state.json")
        pack = build_context_pack(
            state,
            get_adapter("rev"),
            state_path=state_path,
        )
        self.assertNotIn("TAIL_SENTINEL", pack.text)
        self.assertIn("complete operator prompt", pack.text)
        self.assertIn(str(state_path), pack.text)
        self.assertTrue(pack.truncated)
        self.assertEqual(pack.omitted["prompt_chars"], len("TAIL_SENTINEL"))

    def test_small_pack_omits_hostile_operator_text_without_partial_json(
        self,
    ) -> None:
        state = self.state()
        state.prompt = ("line\n```\u202e<tag>\x1b" * 2_000)
        pack = build_context_pack(
            state,
            get_adapter("rev"),
            state_path=Path("/state/state.json"),
            max_chars=4096,
        )
        self.assertLessEqual(len(pack.text), 4096)
        self.assertIn("operator_context", pack.omitted)
        for line in pack.text.splitlines():
            strict_json_loads(line.encode("utf-8"))


if __name__ == "__main__":
    unittest.main()
