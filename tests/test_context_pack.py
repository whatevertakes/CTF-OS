from __future__ import annotations

import copy
import hashlib
import unittest
from pathlib import Path

from ctf_os.adapters import get_adapter
from ctf_os.engine.context_pack import build_context_pack
from ctf_os.engine.resume_capsule import (
    MAX_RESUME_CAPSULE_BYTES,
    render_resume_capsule,
)
from ctf_os.models import (
    ArtifactReference,
    ChallengeState,
    Checkpoint,
    ExecutionReceipt,
    Experiment,
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
