from __future__ import annotations

import copy
import hashlib
import json
import unittest
from unittest import mock

import ctf_os.models as models_module
from ctf_os.contracts.rev_inventory_v2 import (
    REV_INVENTORY_V2_MAX_SOURCE_BYTES,
    REV_INVENTORY_V2_CONTRACT_FINGERPRINT,
    REV_INVENTORY_V2_CONTRACT_ID,
    REV_INVENTORY_V2_CONTRACT_VERSION,
    REV_INVENTORY_V2_SEED_DROP_CONDITION,
    REV_INVENTORY_V2_SEED_EXPECTED_OBSERVATION,
    REV_INVENTORY_V2_SEED_KEEP_CONDITION,
    REV_INVENTORY_V2_SEED_TIMEOUT_SECONDS,
    RevInventoryV2ContractError,
    build_rev_inventory_v2_seed_extra,
    build_rev_inventory_v2_source_binding,
    build_rev_inventory_v2_source_snapshot,
    evaluate_rev_inventory_v2,
    rev_inventory_v2_seed_command,
)
from ctf_os.models import (
    MAX_RECORDS_PER_COLLECTION,
    MAX_REPEATED_FIELD_ITEMS,
    ArtifactReference,
    CandidateStatus,
    Checkpoint,
    ChallengeIdentity,
    ChallengeStatus,
    Experiment,
    ExperimentKind,
    ExperimentStatus,
    ExecutionReceipt,
    Fact,
    FailureCapsule,
    Falsifier,
    FlagCandidate,
    Goal,
    GoalStatus,
    Hypothesis,
    HypothesisStatus,
    ManagedCycle,
    MAX_EXPERIMENT_TIMEOUT_SECONDS,
    ModelValidationError,
    ProofPolicySnapshot,
    ProofRecipe,
    ProofRecipeInput,
    Provenance,
    ReceiptOutcome,
    RevStdinOracleBinding,
    RunReference,
    RunOrigin,
    RunStatus,
    SessionMode,
    SessionStatus,
    SolveSession,
    SubmissionReference,
    SubmissionStatus,
    new_challenge_state,
)
from ctf_os.engine.rev_proof import (
    parse_rev_proof_evaluation_evidence,
)
from ctf_os.store.upgrades import upgrade_state


def _canonical_rev_inventory_error_records(
    index: int,
) -> tuple[
    Experiment,
    RunReference,
    ExecutionReceipt,
    ArtifactReference,
]:
    source_binding = build_rev_inventory_v2_source_binding(
        manifest_generation=1,
        manifest_sha256="a" * 64,
        path="chall",
        source_sha256="b" * 64,
        source_size_bytes=83,
    )
    source_snapshot = build_rev_inventory_v2_source_snapshot(
        source_binding
    )
    seed_extra = build_rev_inventory_v2_seed_extra(
        source_binding,
        source_snapshot,
    )
    experiment_id = f"E-rev-error-{index}"
    run_id = f"R-rev-error-{index}"
    receipt_id = f"RCPT-rev-error-{index}"
    artifact_id = f"A-rev-error-{index}-stdout"
    artifact_path = f"artifacts/{artifact_id}.log"
    request_path = f"runs/{run_id}/request.json"
    request_sha256 = f"{index:064x}"
    artifact_sha256 = f"{index + 256:064x}"
    evaluated_at = "2026-01-01T00:00:00Z"
    snapshot_execution = {
        "enforced": False,
        "mode": "trusted_injected_sandbox",
        "scope_fingerprint": "c" * 64,
        "snapshot_id": source_snapshot["id"],
    }
    semantic_result = evaluate_rev_inventory_v2(
        b"{",
        expected_source_sha256=source_binding["sha256"],
        expected_source_size_bytes=source_binding["size_bytes"],
    ).to_dict()
    execution_binding = {
        "schema_version": 2,
        "argv": [
            "python3",
            "/opt/ctf-templates/rev/inventory_v2.py",
            "/challenge/chall",
        ],
        "base_revision": 0,
        "configuration_epoch": 0,
        "experiment": {
            "adapter_name": seed_extra["adapter_name"],
            "adapter_seed": seed_extra["adapter_seed"],
            "adapter_seed_contract_version": seed_extra[
                "adapter_seed_contract_version"
            ],
            "adapter_seed_order": seed_extra["adapter_seed_order"],
            "adapter_spec_id": seed_extra["adapter_spec_id"],
            "adapter_spec_sha256": seed_extra[
                "adapter_spec_sha256"
            ],
            "adapter_spec_template_id": seed_extra[
                "adapter_spec_template_id"
            ],
            "id": experiment_id,
            "requires_explicit_execution": seed_extra[
                "requires_explicit_execution"
            ],
            "resource_class": "light",
        },
        "image": {
            "digest": "sha256:" + ("1" * 64),
            "name": "ctf-os:core",
            "reference": "sha256:" + ("1" * 64),
        },
        "network": {
            "target": None,
            "target_generation": None,
            "target_id": None,
        },
        "oracle": seed_extra["partial_oracle"],
        "request": {
            "path": request_path,
            "sha256": request_sha256,
        },
        "resource_request": {
            "cpu": 1,
            "gpu": 0,
            "kvm": 0,
            "memory_mib": 2048,
            "network": 0,
        },
        "source_binding": source_binding,
        "source_snapshot": source_snapshot,
        "source_snapshot_execution_binding": snapshot_execution,
        "stdout_artifact": {
            "id": artifact_id,
            "path": artifact_path,
            "sha256": artifact_sha256,
            "size": 1,
        },
    }
    outcome = {
        "schema_version": 2,
        "transport_succeeded": True,
        "evaluation_status": "evaluated",
        "rejection_code": None,
        "result": semantic_result,
        "request_sha256": request_sha256,
        "image_reference": "sha256:" + ("1" * 64),
        "stdout_artifact_id": artifact_id,
        "source_binding": source_binding,
        "execution_binding": execution_binding,
        "evaluated_at": evaluated_at,
    }
    experiment = Experiment(
        id=experiment_id,
        hypothesis_ids=[],
        command=rev_inventory_v2_seed_command("chall"),
        expected_observation=(
            REV_INVENTORY_V2_SEED_EXPECTED_OBSERVATION
        ),
        keep_if=REV_INVENTORY_V2_SEED_KEEP_CONDITION,
        drop_if=REV_INVENTORY_V2_SEED_DROP_CONDITION,
        timeout_seconds=REV_INVENTORY_V2_SEED_TIMEOUT_SECONDS,
        kind=ExperimentKind.PROBE,
        status=ExperimentStatus.FAILED,
        result={
            "exit_code": 0,
            "partial_oracle": outcome,
            "receipt_id": receipt_id,
            "run_id": run_id,
            "timed_out": False,
        },
        artifact_ids=[artifact_id],
        evidence_run_ids=[run_id],
        evidence_receipt_ids=[receipt_id],
        evaluation_reason="rev_inventory:evaluated:ERROR/invalid_json",
        evaluated_at=evaluated_at,
        extra=seed_extra,
    )
    run = RunReference(
        id=run_id,
        base_revision=0,
        status=RunStatus.COMPLETED,
        request_path=request_path,
        configuration_epoch=0,
        extra={
            **seed_extra,
            "experiment_id": experiment_id,
            "partial_oracle_result": outcome,
            "source_snapshot_execution_binding": snapshot_execution,
        },
    )
    receipt = ExecutionReceipt(
        id=receipt_id,
        experiment_id=experiment_id,
        run_id=run_id,
        outcome=ReceiptOutcome.SUCCEEDED,
        exit_code=0,
        stdout_artifact_id=artifact_id,
        extra={"partial_oracle_result": outcome},
    )
    artifact = ArtifactReference(
        id=artifact_id,
        path=artifact_path,
        sha256=artifact_sha256,
        source_run_id=run_id,
        size=1,
    )
    return experiment, run, receipt, artifact


def _managed_rev_proof_state(
    *,
    negative_emits_flag: bool = False,
):
    """Return a detached real managed-proof state for model tamper tests."""

    from tests.test_managed import ManagedV2Tests

    fixture = ManagedV2Tests(
        "test_rev_managed_stdin_proof_passes_six_clean_runs"
    )
    fixture.setUp()
    try:
        state, _experiment, _candidate, _sandbox, _accepted = (
            fixture.run_managed_rev_proof_fixture(
                negative_emits_flag=negative_emits_flag,
            )
        )
        return copy.deepcopy(state)
    finally:
        fixture.tearDown()


def _duplicate_passing_rev_candidate(state):
    """Add a second independently linked copy of a passing Rev proof."""

    original_experiment = next(
        item
        for item in state.experiments
        if item.kind is ExperimentKind.PROOF
        and item.result["rev_proof_evidence"]["evaluation"]["passed"]
    )
    original_recipe = original_experiment.proof_recipe
    assert original_recipe is not None
    original_candidate = next(
        item
        for item in state.candidates
        if item.id == original_recipe.candidate_id
    )
    second_candidate = copy.deepcopy(original_candidate)
    second_candidate.id = f"{original_candidate.id}-second"
    second_candidate.proof_run_ids = []

    second_experiment_id = f"{original_experiment.id}-second"
    second_recipe = ProofRecipe.create(
        candidate_id=second_candidate.id,
        source_experiment_id=original_recipe.source_experiment_id,
        source_run_id=original_recipe.source_run_id,
        argv=original_recipe.argv,
        inputs=original_recipe.inputs,
        network_target_id=original_recipe.network_target_id,
        network_target_generation=(
            original_recipe.network_target_generation
        ),
        network_endpoint=original_recipe.network_endpoint,
        configuration_epoch=original_recipe.configuration_epoch,
        source_manifest_sha256=(
            original_recipe.source_manifest_sha256
        ),
        source_request_sha256=original_recipe.source_request_sha256,
        image_reference=original_recipe.image_reference,
        policy=original_recipe.policy,
        oracle_binding=original_recipe.oracle_binding,
    )

    original_envelope = original_experiment.result[
        "rev_proof_evidence"
    ]
    evaluation_mapping = copy.deepcopy(
        original_envelope["evaluation"]
    )
    run_id_map: dict[str, str] = {}
    artifact_id_map: dict[str, str] = {}
    for observation in evaluation_mapping["observations"]:
        original_run_id = observation["run_id"]
        second_run_id = f"{original_run_id}-second"
        run_id_map[original_run_id] = second_run_id
        observation["run_id"] = second_run_id
        for stream_name in ("stdout", "stderr"):
            stream = observation[stream_name]
            original_artifact_id = stream["artifact_id"]
            second_artifact_id = f"{original_artifact_id}-second"
            artifact_id_map[original_artifact_id] = second_artifact_id
            stream["artifact_id"] = second_artifact_id
    parsed_evaluation = parse_rev_proof_evaluation_evidence(
        evaluation_mapping
    )
    second_run_ids = [
        observation.run_id
        for observation in parsed_evaluation.observations
    ]
    second_candidate.proof_run_ids = list(second_run_ids)

    original_runs = {
        item.id: item
        for item in state.runs
        if item.id in run_id_map
    }
    second_runs = []
    for observation in parsed_evaluation.observations:
        original_run_id = next(
            old_id
            for old_id, new_id in run_id_map.items()
            if new_id == observation.run_id
        )
        second_run = copy.deepcopy(original_runs[original_run_id])
        second_run.id = observation.run_id
        second_run.request_path = (
            f"runs/{observation.run_id}/request.json"
        )
        second_run.result_path = (
            f"runs/{observation.run_id}/result.json"
        )
        second_run.validation_path = (
            f"runs/{observation.run_id}/validation.json"
        )
        second_run.extra["experiment_id"] = second_experiment_id
        second_run.extra["rev_proof_recipe_sha256"] = (
            second_recipe.recipe_sha256
        )
        second_run.extra["rev_proof_observation"] = (
            observation.to_dict()
        )
        second_runs.append(second_run)

    original_artifacts = {
        item.id: item
        for item in state.artifacts
        if item.id in artifact_id_map
    }
    second_stream_artifacts = []
    for original_id, second_id in artifact_id_map.items():
        artifact = copy.deepcopy(original_artifacts[original_id])
        artifact.id = second_id
        artifact.path = f"{artifact.path}.second"
        assert artifact.source_run_id is not None
        artifact.source_run_id = run_id_map[artifact.source_run_id]
        artifact.extra["experiment_id"] = second_experiment_id
        second_stream_artifacts.append(artifact)

    second_evaluation_artifact_id = (
        f"{original_envelope['evaluation_artifact_id']}-second"
    )
    original_evaluation_artifact = next(
        item
        for item in state.artifacts
        if item.id == original_envelope["evaluation_artifact_id"]
    )
    second_evaluation_artifact = copy.deepcopy(
        original_evaluation_artifact
    )
    second_evaluation_artifact.id = second_evaluation_artifact_id
    second_evaluation_artifact.path = (
        f"{original_evaluation_artifact.path}.second"
    )
    second_evaluation_artifact.sha256 = (
        parsed_evaluation.evidence_sha256
    )
    second_evaluation_artifact.size = len(
        parsed_evaluation.canonical_bytes()
    )
    second_evaluation_artifact.extra = {
        "kind": "rev_proof_evaluation",
        "experiment_id": second_experiment_id,
        "candidate_id": second_candidate.id,
        "recipe_sha256": second_recipe.recipe_sha256,
        "policy_sha256": second_recipe.policy.policy_sha256,
        "protocol": parsed_evaluation.protocol,
    }

    second_envelope = copy.deepcopy(original_envelope)
    second_envelope["candidate_id"] = second_candidate.id
    second_envelope["recipe_sha256"] = second_recipe.recipe_sha256
    second_envelope["evaluation"] = parsed_evaluation.to_dict()
    second_envelope["evaluation_sha256"] = (
        parsed_evaluation.evidence_sha256
    )
    second_envelope["evaluation_artifact_id"] = (
        second_evaluation_artifact_id
    )
    second_proof_result = copy.deepcopy(
        original_experiment.result["proof_result"]
    )
    second_proof_result["run_ids"] = list(second_run_ids)

    second_experiment = copy.deepcopy(original_experiment)
    second_experiment.id = second_experiment_id
    second_experiment.proof_recipe = second_recipe
    second_experiment.evidence_run_ids = list(second_run_ids)
    ordered_stream_ids: list[str] = []
    for observation in parsed_evaluation.observations:
        assert observation.stdout.artifact_id is not None
        assert observation.stderr.artifact_id is not None
        ordered_stream_ids.extend(
            (
                observation.stdout.artifact_id,
                observation.stderr.artifact_id,
            )
        )
    second_experiment.artifact_ids = [
        second_recipe.inputs[0].artifact_id,
        *ordered_stream_ids,
        second_evaluation_artifact_id,
    ]
    second_experiment.result = {
        "proof_result": second_proof_result,
        "rev_proof_evidence": second_envelope,
    }

    state.candidates.append(second_candidate)
    state.experiments.append(second_experiment)
    state.runs.extend(second_runs)
    state.artifacts.extend(second_stream_artifacts)
    state.artifacts.append(second_evaluation_artifact)
    return original_candidate, second_candidate


def _failure_capsule_state():
    state = new_challenge_state(
        ChallengeIdentity("Demo", "misc", "FailureCapsule"),
        schema_version=2,
    )
    state.revision = 5
    state.sessions.append(
        SolveSession(
            id="S-failed",
            mode=SessionMode.MANAGED,
            status=SessionStatus.COMPLETED,
            configuration_epoch=0,
            start_revision=3,
            end_revision=5,
            run_ids=["R-failed", "R-evidence"],
        )
    )
    state.cycles.append(
        ManagedCycle(
            id="C-failed",
            session_id="S-failed",
            ordinal=1,
            phase="failed",
            configuration_epoch=0,
            checkpoint_id="CP-failed",
        )
    )
    state.runs.extend(
        (
            RunReference(
                id="R-failed",
                base_revision=4,
                status=RunStatus.FAILED,
                session_id="S-failed",
                cycle_id="C-failed",
            ),
            RunReference(
                id="R-evidence",
                base_revision=3,
                status=RunStatus.COMPLETED,
                session_id="S-failed",
                cycle_id="C-failed",
            ),
        )
    )
    state.artifacts.append(
        ArtifactReference(
            id="A-evidence",
            path="artifacts/evidence.log",
            sha256="a" * 64,
            source_run_id="R-evidence",
        )
    )
    state.facts.append(
        Fact(
            id="F-evidence",
            challenge_id="FailureCapsule",
            statement="the original oracle accepted the control input",
            provenance=Provenance.EXECUTED,
            source_run_id="R-evidence",
            artifact_id="A-evidence",
            locator="artifacts/evidence.log:1",
        )
    )
    state.hypotheses.append(
        Hypothesis(
            id="H-resolved",
            statement="the control path is reachable",
            falsifier=Falsifier("the original oracle rejects the input"),
            status=HypothesisStatus.CONFIRMED,
            evidence_fact_ids=["F-evidence"],
            evidence_artifact_ids=["A-evidence"],
            evidence_run_ids=["R-evidence"],
        )
    )
    state.experiments.extend(
        (
            Experiment(
                id="E-failed",
                hypothesis_ids=[],
                command="false",
                expected_observation="the probe exits successfully",
                keep_if="exit status is zero",
                drop_if="exit status is non-zero",
                timeout_seconds=10,
                kind=ExperimentKind.PROBE,
                status=ExperimentStatus.FAILED,
            ),
            Experiment(
                id="E-next",
                hypothesis_ids=[],
                command="true",
                expected_observation="the alternate probe exits successfully",
                keep_if="exit status is zero",
                drop_if="exit status is non-zero",
                timeout_seconds=10,
                kind=ExperimentKind.PROBE,
            ),
        )
    )
    state.receipts.append(
        ExecutionReceipt(
            id="RC-failed",
            experiment_id="E-failed",
            run_id="R-failed",
            outcome=ReceiptOutcome.FAILED,
            exit_code=1,
        )
    )
    failure_capsule = FailureCapsule(
        reason_code="contract_invalid",
        stage="exploration",
        state_revision_before=4,
        state_revision_after=5,
        fingerprint_sha256="f" * 64,
        content_sha256="0" * 64,
        run_ids=["R-failed"],
        failed_experiment_ids=["E-failed"],
        fact_ids=["F-evidence"],
        artifact_ids=["A-evidence"],
        receipt_ids=["RC-failed"],
        unresolved_hypothesis_ids=["H-resolved"],
        next_experiment_ids=["E-next"],
    )
    failure_capsule.content_sha256 = (
        failure_capsule.computed_content_sha256()
    )
    state.checkpoints.append(
        Checkpoint(
            id="CP-failed",
            session_id="S-failed",
            cycle_id="C-failed",
            active_goal_id=None,
            created_at="2026-01-01T00:00:00Z",
            failure_capsule=failure_capsule,
        )
    )
    state.validate()
    return state


class ModelTests(unittest.TestCase):
    def test_failure_capsule_round_trips_with_committed_revision(
        self,
    ) -> None:
        state = _failure_capsule_state()

        payload = state.to_dict()
        capsule_payload = payload["checkpoints"][0]["failure_capsule"]
        self.assertEqual(
            set(capsule_payload),
            {
                "schema_version",
                "reason_code",
                "stage",
                "state_revision_before",
                "state_revision_after",
                "fingerprint_sha256",
                "content_sha256",
                "run_ids",
                "failed_experiment_ids",
                "fact_ids",
                "artifact_ids",
                "receipt_ids",
                "unresolved_hypothesis_ids",
                "next_experiment_ids",
                "omitted_counts",
            },
        )
        self.assertEqual(capsule_payload["state_revision_after"], 5)
        self.assertEqual(
            capsule_payload["omitted_counts"],
            {
                "run_ids": 0,
                "failed_experiment_ids": 0,
                "fact_ids": 0,
                "artifact_ids": 0,
                "receipt_ids": 0,
                "unresolved_hypothesis_ids": 0,
                "next_experiment_ids": 0,
            },
        )

        restored = type(state).from_dict(payload)
        restored.validate()
        self.assertEqual(restored.to_dict(), payload)
        self.assertIs(
            restored.hypotheses[0].status,
            HypothesisStatus.CONFIRMED,
        )

    def test_failure_capsule_future_revision_is_precommit_only(
        self,
    ) -> None:
        state = _failure_capsule_state()
        state.revision = 4

        with self.assertRaisesRegex(
            ModelValidationError,
            "invalid revision range",
        ):
            state.validate()

        state.validate(_allow_precommit_failure_capsules=True)

    def test_failure_capsule_content_tamper_fails_state_validation(
        self,
    ) -> None:
        state = _failure_capsule_state()
        capsule = state.checkpoints[0].failure_capsule
        assert capsule is not None
        capsule.next_experiment_ids.clear()

        with self.assertRaisesRegex(
            ModelValidationError,
            "content_sha256 does not match its capture",
        ):
            state.validate()

    def test_failure_capsule_requires_canonical_cycle_binding(
        self,
    ) -> None:
        cases = (
            (
                "missing session",
                lambda state: setattr(
                    state.checkpoints[0], "session_id", None
                ),
                "requires session_id and cycle_id",
            ),
            (
                "missing cycle",
                lambda state: setattr(
                    state.checkpoints[0], "cycle_id", None
                ),
                "requires session_id and cycle_id",
            ),
            (
                "unknown session",
                lambda state: setattr(
                    state.checkpoints[0], "session_id", "S-missing"
                ),
                "references unknown session",
            ),
            (
                "unknown cycle",
                lambda state: setattr(
                    state.checkpoints[0], "cycle_id", "C-missing"
                ),
                "references unknown cycle",
            ),
            (
                "cycle session mismatch",
                lambda state: setattr(
                    state.cycles[0], "session_id", "S-missing"
                ),
                "cycle does not bind its session",
            ),
            (
                "cycle checkpoint mismatch",
                lambda state: setattr(
                    state.cycles[0], "checkpoint_id", None
                ),
                "is not the cycle checkpoint",
            ),
        )
        for label, mutate, error in cases:
            state = _failure_capsule_state()
            mutate(state)
            with self.subTest(case=label):
                with self.assertRaisesRegex(ModelValidationError, error):
                    state.validate()

    def test_failure_capsules_cannot_share_cycle_binding(self) -> None:
        state = _failure_capsule_state()
        duplicate = copy.deepcopy(state.checkpoints[0])
        duplicate.id = "CP-duplicate"
        state.checkpoints.append(duplicate)

        with self.assertRaisesRegex(
            ModelValidationError,
            "share a session/cycle binding",
        ):
            state.validate()

    def test_checkpoint_preserves_legacy_failure_capsule_extension(
        self,
    ) -> None:
        checkpoint = Checkpoint(
            id="CP-legacy",
            session_id=None,
            cycle_id=None,
            active_goal_id=None,
            note="legacy note",
            created_at="2026-01-01T00:00:00Z",
            extra={"failure_capsule": {"legacy": "shadow"}},
        )
        payload = checkpoint.to_dict()
        self.assertEqual(
            payload["failure_capsule"],
            {"legacy": "shadow"},
        )
        encoded = json.dumps(
            payload,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )

        restored = Checkpoint.from_dict(json.loads(encoded))
        self.assertIsNone(restored.failure_capsule)
        self.assertEqual(
            restored.extra["failure_capsule"],
            {"legacy": "shadow"},
        )
        self.assertEqual(
            json.dumps(
                restored.to_dict(),
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ),
            encoded,
        )

        explicit_null = dict(payload, failure_capsule=None)
        restored_null = Checkpoint.from_dict(explicit_null)
        self.assertIsNone(restored_null.failure_capsule)
        self.assertNotIn("failure_capsule", restored_null.to_dict())

    def test_failure_capsule_from_dict_rejects_noncanonical_shape(
        self,
    ) -> None:
        canonical = (
            _failure_capsule_state()
            .checkpoints[0]
            .failure_capsule.to_dict()
        )
        malformed = []
        missing = dict(canonical)
        missing.pop("stage")
        malformed.append(missing)
        extra = dict(canonical, extension=True)
        malformed.append(extra)
        wrong_array = dict(canonical, run_ids=("R-failed",))
        malformed.append(wrong_array)
        wrong_item = dict(canonical, run_ids=[1])
        malformed.append(wrong_item)
        wrong_revision = dict(canonical, state_revision_before=True)
        malformed.append(wrong_revision)
        missing_omitted_count = copy.deepcopy(canonical)
        missing_omitted_count["omitted_counts"].pop("run_ids")
        malformed.append(missing_omitted_count)
        extra_omitted_count = copy.deepcopy(canonical)
        extra_omitted_count["omitted_counts"]["unexpected_ids"] = 0
        malformed.append(extra_omitted_count)
        negative_omitted_count = copy.deepcopy(canonical)
        negative_omitted_count["omitted_counts"]["run_ids"] = -1
        malformed.append(negative_omitted_count)
        boolean_omitted_count = copy.deepcopy(canonical)
        boolean_omitted_count["omitted_counts"]["run_ids"] = True
        malformed.append(boolean_omitted_count)

        for payload in malformed:
            with self.subTest(payload=payload):
                with self.assertRaises(ModelValidationError):
                    FailureCapsule.from_dict(payload)

        checkpoint_payload = (
            _failure_capsule_state().checkpoints[0].to_dict()
        )
        checkpoint_payload["failure_capsule"] = []
        with self.assertRaisesRegex(
            ModelValidationError,
            "canonical object or null",
        ):
            Checkpoint.from_dict(checkpoint_payload)

        stripped_typed = (
            _failure_capsule_state().checkpoints[0].to_dict()
        )
        stripped_payload = stripped_typed["failure_capsule"]
        for key in (
            "schema_version",
            "fingerprint_sha256",
            "content_sha256",
        ):
            stripped_payload.pop(key)
        with self.assertRaisesRegex(
            ModelValidationError,
            "non-canonical schema",
        ):
            Checkpoint.from_dict(stripped_typed)

    def test_failure_capsule_rejects_invalid_values_and_bounds(
        self,
    ) -> None:
        cases = (
            (
                "schema",
                lambda capsule: setattr(capsule, "schema_version", 2),
                "schema_version",
            ),
            (
                "reason",
                lambda capsule: setattr(
                    capsule, "reason_code", "Contract-Invalid"
                ),
                "machine token",
            ),
            (
                "stage",
                lambda capsule: setattr(capsule, "stage", "_exploration"),
                "machine token",
            ),
            (
                "fingerprint",
                lambda capsule: setattr(
                    capsule, "fingerprint_sha256", "F" * 64
                ),
                "fingerprint_sha256",
            ),
            (
                "content hash",
                lambda capsule: setattr(
                    capsule, "content_sha256", "E" * 64
                ),
                "content_sha256",
            ),
            (
                "boolean revision",
                lambda capsule: setattr(
                    capsule, "state_revision_before", True
                ),
                "non-boolean integers",
            ),
            (
                "reverse revision",
                lambda capsule: setattr(
                    capsule, "state_revision_before", 6
                ),
                "revision range",
            ),
            (
                "future revision",
                lambda capsule: setattr(
                    capsule, "state_revision_after", 6
                ),
                "revision range",
            ),
            (
                "empty id",
                lambda capsule: capsule.run_ids.append(""),
                "empty or non-string",
            ),
            (
                "duplicate id",
                lambda capsule: capsule.run_ids.append("R-failed"),
                "duplicate id",
            ),
            (
                "omitted count fields",
                lambda capsule: capsule.omitted_counts.pop("run_ids"),
                "omitted_counts",
            ),
            (
                "negative omitted count",
                lambda capsule: capsule.omitted_counts.__setitem__(
                    "run_ids", -1
                ),
                "omitted_counts",
            ),
            (
                "boolean omitted count",
                lambda capsule: capsule.omitted_counts.__setitem__(
                    "run_ids", True
                ),
                "omitted_counts",
            ),
        )
        for label, mutate, error in cases:
            state = _failure_capsule_state()
            capsule = state.checkpoints[0].failure_capsule
            assert capsule is not None
            mutate(capsule)
            with self.subTest(case=label):
                with self.assertRaisesRegex(ModelValidationError, error):
                    state.validate()

        for field_name, limit in (
            ("run_ids", 16),
            ("failed_experiment_ids", 16),
            ("fact_ids", 32),
            ("artifact_ids", 32),
            ("receipt_ids", 32),
            ("unresolved_hypothesis_ids", 32),
            ("next_experiment_ids", 3),
        ):
            state = _failure_capsule_state()
            capsule = state.checkpoints[0].failure_capsule
            assert capsule is not None
            setattr(
                capsule,
                field_name,
                [f"missing-{index}" for index in range(limit + 1)],
            )
            with self.subTest(field=field_name):
                with self.assertRaisesRegex(
                    ModelValidationError,
                    rf"{field_name} exceeds {limit} items",
                ):
                    state.validate()

    def test_failure_capsule_rejects_invalid_crosslinks(self) -> None:
        cases = (
            ("run_ids", "R-missing", "unknown run"),
            (
                "failed_experiment_ids",
                "E-missing-failed",
                "unknown experiment",
            ),
            ("fact_ids", "F-missing", "unknown fact"),
            ("artifact_ids", "A-missing", "unknown artifact"),
            ("receipt_ids", "RC-missing", "unknown receipt"),
            (
                "unresolved_hypothesis_ids",
                "H-missing",
                "unknown hypothesis",
            ),
            (
                "next_experiment_ids",
                "E-missing-next",
                "unknown experiment",
            ),
        )
        for field_name, missing_id, error in cases:
            state = _failure_capsule_state()
            capsule = state.checkpoints[0].failure_capsule
            assert capsule is not None
            getattr(capsule, field_name).append(missing_id)
            with self.subTest(field=field_name):
                with self.assertRaisesRegex(ModelValidationError, error):
                    state.validate()

        state = _failure_capsule_state()
        state.runs[0].session_id = "S-other"
        with self.assertRaisesRegex(
            ModelValidationError,
            "does not bind its session and cycle",
        ):
            state.validate()

    def test_persisted_rev_proof_rejects_hash_and_run_slice_tamper(
        self,
    ) -> None:
        state = _managed_rev_proof_state()
        state.validate()

        hash_tampered = copy.deepcopy(state)
        proof = next(
            item
            for item in hash_tampered.experiments
            if item.kind is ExperimentKind.PROOF
        )
        proof.result["rev_proof_evidence"][
            "evaluation_sha256"
        ] = "0" * 64
        with self.assertRaisesRegex(
            ModelValidationError,
            "proof evaluation",
        ):
            hash_tampered.validate()

        slice_tampered = copy.deepcopy(state)
        candidate = next(
            item
            for item in slice_tampered.candidates
            if item.status is CandidateStatus.READY_TO_SUBMIT
        )
        candidate.proof_run_ids[-6], candidate.proof_run_ids[-5] = (
            candidate.proof_run_ids[-5],
            candidate.proof_run_ids[-6],
        )
        with self.assertRaisesRegex(
            ModelValidationError,
            "contiguous evaluation",
        ):
            slice_tampered.validate()

    def test_latest_failed_rev_evaluation_cannot_promote_ready(
        self,
    ) -> None:
        state = _managed_rev_proof_state(
            negative_emits_flag=True,
        )
        candidate = next(
            item
            for item in state.candidates
            if item.proof_run_ids
        )
        self.assertIs(
            candidate.status,
            CandidateStatus.OBSERVED_CANDIDATE,
        )
        candidate.status = CandidateStatus.READY_TO_SUBMIT
        state.status = ChallengeStatus.READY_TO_SUBMIT

        with self.assertRaisesRegex(
            ModelValidationError,
            "latest passing evaluation",
        ):
            state.validate()

    def test_solved_candidate_can_coexist_with_other_ready_rev_candidate(
        self,
    ) -> None:
        state = _managed_rev_proof_state()
        accepted_candidate, ready_candidate = (
            _duplicate_passing_rev_candidate(state)
        )
        state.validate()
        self.assertIs(
            ready_candidate.status,
            CandidateStatus.READY_TO_SUBMIT,
        )

        accepted_candidate.status = CandidateStatus.ACCEPTED
        state.status = ChallengeStatus.SOLVED
        if state.active_goal_id is not None:
            active_goal = next(
                item
                for item in state.goals
                if item.id == state.active_goal_id
            )
            active_goal.status = GoalStatus.DONE
            state.active_goal_id = None
        state.submissions.append(
            SubmissionReference(
                id="SUB-manual-accepted",
                candidate_id=accepted_candidate.id,
                status=SubmissionStatus.ACCEPTED,
                submitted_at="2026-07-30T00:00:00Z",
                response="accepted",
                proof_passed=True,
                format_ok=True,
            )
        )

        state.validate()
        self.assertIs(
            ready_candidate.status,
            CandidateStatus.READY_TO_SUBMIT,
        )

    def test_rev_stdin_oracle_binding_is_exact_and_immutable(
        self,
    ) -> None:
        source_binding = build_rev_inventory_v2_source_binding(
            manifest_generation=1,
            manifest_sha256="a" * 64,
            path="chall",
            source_sha256="b" * 64,
            source_size_bytes=83,
        )
        source_snapshot = build_rev_inventory_v2_source_snapshot(
            source_binding
        )
        binding = RevStdinOracleBinding.create(
            protocol="rev_original_binary_stdin_candidate_v1",
            inventory_contract_id=REV_INVENTORY_V2_CONTRACT_ID,
            inventory_contract_version=REV_INVENTORY_V2_CONTRACT_VERSION,
            inventory_contract_fingerprint=(
                REV_INVENTORY_V2_CONTRACT_FINGERPRINT
            ),
            inventory_experiment_id="E-inventory",
            inventory_run_id="R-inventory",
            inventory_stdout_artifact_id="A-inventory-stdout",
            inventory_stdout_sha256="c" * 64,
            inventory_stdout_size_bytes=128,
            source_binding=source_binding,
            source_snapshot=source_snapshot,
            budget_deadline_utc="2026-01-01T00:00:00Z",
        )
        self.assertEqual(
            RevStdinOracleBinding.from_dict(binding.to_dict()),
            binding,
        )
        cloned_binding = copy.deepcopy(binding)
        self.assertIs(cloned_binding, binding)
        with self.assertRaises(TypeError):
            binding.source_binding["path"] = "other"  # type: ignore[index]
        policy = ProofPolicySnapshot.create(
            mode="deterministic",
            oracle_protocol="rev_original_binary_stdin_candidate_v1",
            clean_repetitions=3,
            remote_repetitions=0,
            trial_count=0,
            negative_control_repetitions=3,
            negative_control_timeout_seconds=30,
            minimum_success_rate=None,
            notes="Rev original-binary stdin oracle",
        )
        recipe = ProofRecipe.create(
            candidate_id="C-1",
            source_experiment_id="E-source",
            source_run_id="R-source",
            argv=(
                "/usr/bin/python3",
                "/opt/ctf-templates/rev/stdin_exec.py",
                "--binary",
                "/challenge/chall",
                "--input",
                "/work/oracle/accepted-input.bin",
            ),
            inputs=(),
            network_target_id=None,
            network_target_generation=None,
            network_endpoint=None,
            configuration_epoch=0,
            source_manifest_sha256="a" * 64,
            source_request_sha256="d" * 64,
            image_reference="sha256:" + "e" * 64,
            policy=policy,
            oracle_binding=binding,
        )
        state = new_challenge_state(
            ChallengeIdentity("Demo", "misc", "Deepcopy")
        )
        state.extra["detached_recipe"] = recipe
        cloned_state = copy.deepcopy(state)
        self.assertIs(
            cloned_state.extra["detached_recipe"].oracle_binding,
            binding,
        )
        with self.assertRaises(TypeError):
            cloned_state.extra["detached_recipe"].oracle_binding.source_snapshot[
                "id"
            ] = "other"

        for field, value in (
            ("schema_version", True),
            ("kind", "other"),
            ("protocol", "other"),
            ("inventory_contract_version", True),
            ("inventory_contract_fingerprint", "0" * 64),
            ("inventory_stdout_size_bytes", True),
            ("budget_deadline_utc", "2026-01-01T00:00:00"),
        ):
            payload = binding.to_dict()
            payload[field] = value
            with (
                self.subTest(field=field),
                self.assertRaises(ModelValidationError),
            ):
                RevStdinOracleBinding.from_dict(payload)
        payload = binding.to_dict()
        payload["source_binding"] = dict(source_binding)
        payload["source_binding"]["path"] = "alternate"
        with self.assertRaises(ModelValidationError):
            RevStdinOracleBinding.from_dict(payload)

    def test_legacy_pwn_recipe_omits_binding_and_keeps_its_hash(
        self,
    ) -> None:
        policy = ProofPolicySnapshot.create(
            mode="success_distribution",
            oracle_protocol="remote_pwn_replay_negative_control_v1",
            clean_repetitions=0,
            remote_repetitions=0,
            trial_count=10,
            negative_control_repetitions=1,
            negative_control_timeout_seconds=30,
            minimum_success_rate=0.7,
            notes="remote pwn replay",
        )
        recipe = ProofRecipe.create(
            candidate_id="C-1",
            source_experiment_id="E-source",
            source_run_id="R-source",
            argv=("python3", "solver.py"),
            inputs=(),
            network_target_id="T-1",
            network_target_generation=1,
            network_endpoint="https://pwn.example:443",
            configuration_epoch=1,
            source_manifest_sha256="b" * 64,
            source_request_sha256="c" * 64,
            image_reference="sha256:" + "d" * 64,
            policy=policy,
        )
        payload = recipe.to_dict()
        self.assertNotIn("oracle_binding", payload)
        unsigned = dict(payload)
        unsigned.pop("recipe_sha256")
        expected_hash = hashlib.sha256(
            json.dumps(
                unsigned,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(recipe.recipe_sha256, expected_hash)
        self.assertEqual(
            ProofRecipe.from_dict(payload).to_dict(),
            payload,
        )
        payload["oracle_binding"] = None
        with self.assertRaisesRegex(
            ModelValidationError,
            "oracle_binding must be a canonical object",
        ):
            ProofRecipe.from_dict(payload)

    def test_rev_inventory_source_binding_enforces_oracle_source_limit(
        self,
    ) -> None:
        common = {
            "manifest_generation": 1,
            "manifest_sha256": "a" * 64,
            "path": "chall",
            "source_sha256": "b" * 64,
        }
        binding = build_rev_inventory_v2_source_binding(
            **common,
            source_size_bytes=REV_INVENTORY_V2_MAX_SOURCE_BYTES,
        )
        self.assertEqual(
            binding["size_bytes"],
            REV_INVENTORY_V2_MAX_SOURCE_BYTES,
        )
        with self.assertRaisesRegex(
            RevInventoryV2ContractError,
            "outside the v2 source-size contract",
        ):
            build_rev_inventory_v2_source_binding(
                **common,
                source_size_bytes=(
                    REV_INVENTORY_V2_MAX_SOURCE_BYTES + 1
                ),
            )

    def test_rev_inventory_link_discovery_is_one_pass_per_collection(
        self,
    ) -> None:
        class CountingList(list):
            def __init__(self, values=()):
                super().__init__(values)
                self.iterations = 0

            def __iter__(self):
                self.iterations += 1
                return super().__iter__()

        state = new_challenge_state(
            ChallengeIdentity("Demo", "rev", "Linear links")
        )
        rev_records = [
            _canonical_rev_inventory_error_records(index)
            for index in range(32)
        ]
        state.experiments = [
            record[0] for record in rev_records
        ] + [
            Experiment(
                id=f"E-generic-{index}",
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
        ]
        raw_runs = [
            record[1] for record in rev_records
        ] + [
            RunReference(
                id=f"R-generic-{index}",
                base_revision=0,
                status=RunStatus.FAILED,
                extra={"experiment_id": f"E-generic-{index}"},
            )
            for index in range(256)
        ]
        raw_receipts = [record[2] for record in rev_records]
        raw_artifacts = [record[3] for record in rev_records]
        state.runs = CountingList(raw_runs)
        state.receipts = CountingList(raw_receipts)
        state.facts = CountingList()

        errors = models_module._rev_inventory_state_errors(
            state,
            runs={run.id: run for run in raw_runs},
            receipts={
                receipt.id: receipt for receipt in raw_receipts
            },
            artifacts={
                artifact.id: artifact for artifact in raw_artifacts
            },
            facts={},
        )

        self.assertEqual(errors, [])
        self.assertEqual(state.runs.iterations, 1)
        self.assertEqual(state.receipts.iterations, 1)
        self.assertEqual(state.facts.iterations, 1)

    def test_experiment_rejects_non_object_non_null_proof_recipe(self) -> None:
        payload = Experiment(
            id="E-probe",
            hypothesis_ids=[],
            command="true",
            expected_observation="bounded output",
            keep_if="the output appears",
            drop_if="the output does not appear",
            timeout_seconds=1,
            kind=ExperimentKind.PROBE,
        ).to_dict(v2=True)
        for malformed in (True, 1, "recipe", [], [("candidate_id", "C-1")]):
            malformed_payload = dict(payload)
            malformed_payload["proof_recipe"] = malformed
            with (
                self.subTest(malformed=malformed),
                self.assertRaisesRegex(
                    ModelValidationError,
                    "proof_recipe must be a canonical object or null",
                ),
            ):
                Experiment.from_dict(malformed_payload)

    def test_proof_recipe_rejects_nested_type_traps(self) -> None:
        policy = ProofPolicySnapshot.create(
            mode="success_distribution",
            oracle_protocol="remote_pwn_replay_negative_control_v1",
            clean_repetitions=0,
            remote_repetitions=0,
            trial_count=10,
            negative_control_repetitions=1,
            negative_control_timeout_seconds=30,
            minimum_success_rate=0.7,
            notes="remote pwn replay",
        )
        recipe = ProofRecipe.create(
            candidate_id="C-1",
            source_experiment_id="E-source",
            source_run_id="R-source",
            argv=("python3", "solver.py"),
            inputs=(
                ProofRecipeInput(
                    artifact_id="A-solver",
                    destination="solver.py",
                    purpose="reproducer",
                    sha256="a" * 64,
                    size=12,
                    source_run_id="R-builder",
                ),
            ),
            network_target_id="T-1",
            network_target_generation=1,
            network_endpoint="https://pwn.example:443",
            configuration_epoch=1,
            source_manifest_sha256="b" * 64,
            source_request_sha256="c" * 64,
            image_reference="sha256:" + "d" * 64,
            policy=policy,
        )
        self.assertEqual(
            recipe.recipe_sha256,
            "190dddfcf1a4c08ee300503731a3601d683706ac7e0697c01d4e71a45c908686",
        )
        mutations = (
            ("candidate id bool", ("candidate_id",), True),
            ("argv bool", ("argv", 0), True),
            ("configuration bool", ("configuration_epoch",), True),
            (
                "target generation bool",
                ("network_target_generation",),
                True,
            ),
            ("policy notes bool", ("policy", "notes"), True),
            ("policy repetition bool", ("policy", "trial_count"), True),
            ("input artifact bool", ("inputs", 0, "artifact_id"), True),
            ("input size bool", ("inputs", 0, "size"), True),
        )
        for label, path, value in mutations:
            payload = copy.deepcopy(recipe.to_dict())
            current = payload
            for segment in path[:-1]:
                current = current[segment]  # type: ignore[index]
            current[path[-1]] = value  # type: ignore[index]
            with (
                self.subTest(label=label),
                self.assertRaises(ModelValidationError),
            ):
                ProofRecipe.from_dict(payload)

    def test_experiment_timeout_requires_a_positive_integer(self) -> None:
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
            state = new_challenge_state(
                ChallengeIdentity("Demo", "rev", "Timeout")
            )
            state.experiments.append(
                Experiment(
                    id="E-timeout",
                    hypothesis_ids=[],
                    command="true",
                    expected_observation="bounded output",
                    keep_if="the output appears",
                    drop_if="the output does not appear",
                    timeout_seconds=timeout,  # type: ignore[arg-type]
                )
            )
            with (
                self.subTest(timeout=timeout),
                self.assertRaisesRegex(
                    ModelValidationError,
                    "not fully pre-registered",
                ),
            ):
                state.validate()
            serialized = state.to_dict()
            restored = type(state).from_dict(serialized)
            with (
                self.subTest(serialized_timeout=timeout),
                self.assertRaisesRegex(
                    ModelValidationError,
                    "not fully pre-registered",
                ),
            ):
                restored.validate()

        for timeout in (1, MAX_EXPERIMENT_TIMEOUT_SECONDS):
            state = new_challenge_state(
                ChallengeIdentity(
                    "Demo",
                    "rev",
                    f"Valid timeout {timeout}",
                )
            )
            state.experiments.append(
                Experiment(
                    id="E-timeout",
                    hypothesis_ids=[],
                    command="true",
                    expected_observation="bounded output",
                    keep_if="the output appears",
                    drop_if="the output does not appear",
                    timeout_seconds=timeout,
                )
            )
            with self.subTest(valid_timeout=timeout):
                state.validate()

    def test_repeated_record_and_typed_fields_are_bounded_before_copy(
        self,
    ) -> None:
        self.assertEqual(MAX_RECORDS_PER_COLLECTION, 16_384)
        self.assertEqual(MAX_REPEATED_FIELD_ITEMS, 16_384)
        identity = ChallengeIdentity("Demo", "web", "Bounded")
        payload = new_challenge_state(identity).to_dict()
        valid_facts = [
            {
                "id": f"F-{index}",
                "statement": "bounded",
                "provenance": "model_claimed",
            }
            for index in range(2)
        ]
        with mock.patch(
            "ctf_os.models.MAX_RECORDS_PER_COLLECTION",
            2,
        ):
            payload["facts"] = valid_facts
            state = new_challenge_state(identity).from_dict(payload)
            self.assertEqual(len(state.facts), 2)
            payload["facts"] = [*valid_facts, valid_facts[0]]
            with self.assertRaisesRegex(
                ModelValidationError,
                "record collection exceeds 2",
            ):
                new_challenge_state(identity).from_dict(payload)
            payload["facts"] = {
                f"F-{index}": {
                    "statement": "bounded",
                    "provenance": "model_claimed",
                }
                for index in range(3)
            }
            with self.assertRaisesRegex(
                ModelValidationError,
                "record collection exceeds 2",
            ):
                new_challenge_state(identity).from_dict(payload)

        with mock.patch(
            "ctf_os.models.MAX_REPEATED_FIELD_ITEMS",
            2,
        ):
            with self.assertRaisesRegex(
                ModelValidationError,
                "fact supports exceeds 2",
            ):
                Fact.from_dict(
                    {
                        "id": "F-over",
                        "statement": "bounded",
                        "provenance": "model_claimed",
                        "supports": ["H-1", "H-1", "H-1"],
                    }
                )
            with self.assertRaisesRegex(
                ModelValidationError,
                "fact supports must be an array",
            ):
                Fact.from_dict(
                    {
                        "id": "F-string",
                        "statement": "bounded",
                        "provenance": "model_claimed",
                        "supports": "H-1",
                    }
                )
            with self.assertRaisesRegex(
                ModelValidationError,
                "goal artifact_ids exceeds 2",
            ):
                Goal.from_dict(
                    {
                        "id": "G-over",
                        "description": "bounded",
                        "artifact_ids": ["A-1", "A-2"],
                        "artifact": "A-3",
                    }
                )
            state = new_challenge_state(identity)
            state.facts.append(
                Fact(
                    id="F-memory",
                    statement="bounded",
                    provenance=Provenance.MODEL_CLAIMED,
                    supports=["H-1", "H-1", "H-1"],
                )
            )
            with self.assertRaisesRegex(
                ModelValidationError,
                "fact F-memory supports exceeds 2",
            ):
                state.validate()

    def test_provenance_uses_canonical_09_values_and_reads_legacy_values(
        self,
    ) -> None:
        fact = Fact.from_dict(
            {
                "id": "F-1",
                "claim": "decompiler reconstructed a branch",
                "confidence": "tool-inferred",
            },
            default_challenge_id="warmup",
        )

        self.assertIs(fact.provenance, Provenance.TOOL_INFERRED)
        self.assertEqual(fact.to_dict()["provenance"], "tool_inferred")
        self.assertEqual(
            {item.value for item in Provenance},
            {
                "executed",
                "tool_inferred",
                "model_claimed",
                "external_doc",
                "operator",
            },
        )

    def test_legacy_state_is_upgraded_without_losing_unknown_fields(self) -> None:
        upgraded = upgrade_state(
            {
                "identity": {
                    "contest_id": "Demo",
                    "category": "rev",
                    "challenge_id": "Warmup",
                },
                "revision": 2,
                "facts": [
                    {
                        "id": "F-1",
                        "claim": "claim",
                        "confidence": "model-claimed",
                    }
                ],
                "vendor_extension": {"kept": True},
            }
        )

        state = new_challenge_state(
            ChallengeIdentity("unused", "unused", "unused")
        ).from_dict(upgraded)
        round_trip = state.to_dict()
        self.assertEqual(round_trip["schema_version"], 1)
        self.assertEqual(round_trip["contest_id"], "Demo")
        self.assertEqual(
            round_trip["facts"][0]["provenance"], "model_claimed"
        )
        self.assertEqual(round_trip["vendor_extension"], {"kept": True})

    def test_legacy_paused_alias_preserves_exact_resume_target(self) -> None:
        identity = ChallengeIdentity("Demo", "misc", "Paused")
        payload = new_challenge_state(identity).to_dict()
        payload.update(
            {
                "schema_version": 0,
                "status": "PAUSED",
                "paused_from_status": "NEW",
            }
        )
        payload.pop("resume_status", None)

        state = new_challenge_state(identity).from_dict(
            upgrade_state(payload)
        )

        self.assertIs(state.status, ChallengeStatus.PAUSED)
        self.assertIs(state.resume_status, ChallengeStatus.NEW)

    def test_candidate_values_use_the_canonical_printable_bounds(self) -> None:
        identity = ChallengeIdentity("Demo", "misc", "Candidate bounds")
        invalid_values = (
            "KCTF{line\nbreak}",
            "KCTF{zero\u200bwidth}",
            "K" * 1025,
        )

        for value in invalid_values:
            with self.subTest(value=ascii(value[:32])):
                state = new_challenge_state(identity)
                state.candidates.append(
                    FlagCandidate(id="C-invalid", value=value)
                )
                with self.assertRaises(ModelValidationError):
                    state.validate()

    def test_legacy_candidate_alias_cannot_bypass_canonical_validation(
        self,
    ) -> None:
        identity = ChallengeIdentity("Demo", "misc", "Legacy candidate")
        payload = new_challenge_state(identity).to_dict()
        payload["schema_version"] = 0
        payload["flag_candidates"] = [
            {
                "id": "C-legacy-invalid",
                "flag": "KCTF{legacy\ncontext-injection}",
            }
        ]
        payload.pop("candidates", None)

        state = new_challenge_state(identity).from_dict(
            upgrade_state(payload)
        )
        with self.assertRaises(ModelValidationError):
            state.validate()

    def test_model_claim_alone_cannot_confirm_hypothesis(self) -> None:
        state = new_challenge_state(
            ChallengeIdentity("Demo", "crypto", "Oracle")
        )
        state.facts.append(
            Fact(
                id="F-1",
                challenge_id="Oracle",
                statement="the model guessed AES",
                provenance=Provenance.MODEL_CLAIMED,
            )
        )
        state.hypotheses.append(
            Hypothesis(
                id="H-1",
                statement="the primitive is AES",
                falsifier=Falsifier("known-answer test differs"),
                status=HypothesisStatus.CONFIRMED,
                evidence_fact_ids=["F-1"],
            )
        )

        with self.assertRaisesRegex(
            ModelValidationError, "cannot be confirmed"
        ):
            state.validate()

        state.facts.append(
            Fact(
                id="F-2",
                challenge_id="Oracle",
                statement="known-answer test matches",
                provenance=Provenance.EXECUTED,
                source_run_id="R-1",
                artifact_id="A-1",
            )
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
                path="artifacts/known-answer.txt",
                sha256="a" * 64,
                source_run_id="R-1",
            )
        )
        state.hypotheses[0].evidence_fact_ids.append("F-2")
        state.hypotheses[0].evidence_artifact_ids.append("A-1")
        state.hypotheses[0].evidence_run_ids.append("R-1")
        state.validate()

    def test_evaluated_experiment_requires_its_own_result_run_chain(
        self,
    ) -> None:
        state = new_challenge_state(
            ChallengeIdentity("Demo", "rev", "OwnRun")
        )
        for run_id in ("R-old", "R-target"):
            state.runs.append(
                RunReference(
                    id=run_id,
                    base_revision=0,
                    status=RunStatus.COMPLETED,
                )
            )
        state.artifacts.append(
            ArtifactReference(
                id="A-old",
                path="artifacts/old.log",
                sha256="a" * 64,
                source_run_id="R-old",
            )
        )
        state.facts.append(
            Fact(
                id="F-old",
                statement="unrelated executed result",
                provenance=Provenance.EXECUTED,
                source_run_id="R-old",
                artifact_id="A-old",
            )
        )
        state.experiments.append(
            Experiment(
                id="E-target",
                hypothesis_ids=[],
                command="true",
                expected_observation="target output",
                keep_if="target succeeds",
                drop_if="target fails",
                timeout_seconds=10,
                status=ExperimentStatus.KEPT,
                result={"run_id": "R-target"},
                artifact_ids=["A-old"],
                evidence_fact_ids=["F-old"],
                evidence_run_ids=["R-old"],
                evaluation_reason="incorrect cross-run evidence",
                evaluated_at="2026-01-01T00:00:00Z",
            )
        )

        with self.assertRaisesRegex(
            ModelValidationError,
            "own result run",
        ):
            state.validate()

    def test_executed_fact_requires_terminal_same_run_artifact(
        self,
    ) -> None:
        identity = ChallengeIdentity("Demo", "rev", "Executed evidence")
        state = new_challenge_state(identity)
        state.runs.extend(
            (
                RunReference(
                    id="R-source",
                    base_revision=0,
                    status=RunStatus.COMPLETED,
                ),
                RunReference(
                    id="R-other",
                    base_revision=0,
                    status=RunStatus.COMPLETED,
                ),
            )
        )
        state.artifacts.append(
            ArtifactReference(
                id="A-other",
                path="artifacts/other.log",
                sha256="a" * 64,
                source_run_id="R-other",
            )
        )
        state.facts.append(
            Fact(
                id="F-executed",
                statement="claimed executed evidence",
                provenance=Provenance.EXECUTED,
                source_run_id="R-source",
            )
        )
        with self.assertRaisesRegex(
            ModelValidationError,
            "requires an artifact",
        ):
            state.validate()

        state.facts[0].artifact_id = "A-other"
        with self.assertRaisesRegex(
            ModelValidationError,
            "artifact/run mismatch",
        ):
            state.validate()

        state.artifacts[0].source_run_id = "R-source"
        state.runs[0].status = RunStatus.RUNNING
        with self.assertRaisesRegex(
            ModelValidationError,
            "requires a terminal run",
        ):
            state.validate()

    def test_identity_includes_category(self) -> None:
        web = ChallengeIdentity("Demo", "web", "Warmup")
        rev = ChallengeIdentity("Demo", "rev", "Warmup")
        self.assertNotEqual(web, rev)
        self.assertEqual(web.key, "web/Warmup")

    def test_paused_state_preserves_an_explicit_resume_target(self) -> None:
        state = new_challenge_state(
            ChallengeIdentity("Demo", "web", "Warmup")
        )
        state.resume_status = state.status
        state.status = ChallengeStatus.PAUSED
        state.validate()

        loaded = state.from_dict(state.to_dict())
        self.assertEqual(loaded.resume_status, ChallengeStatus.NEW)

        loaded.resume_status = None
        with self.assertRaisesRegex(
            ModelValidationError, "requires resume_status"
        ):
            loaded.validate()

        for terminal in (
            ChallengeStatus.SOLVED,
            ChallengeStatus.ABANDONED,
        ):
            with self.subTest(terminal=terminal.value):
                loaded.resume_status = terminal
                with self.assertRaisesRegex(
                    ModelValidationError,
                    "terminal status",
                ):
                    loaded.validate()


if __name__ == "__main__":
    unittest.main()
