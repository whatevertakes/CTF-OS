from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import replace

from ctf_os.engine.misc_transform import (
    MISC_TRANSFORM_MAX_EVIDENCE_BYTES,
    MISC_TRANSFORM_MAX_OUTPUT_BYTES,
    MISC_TRANSFORM_MAX_SOURCE_BYTES,
    MISC_TRANSFORM_MAX_STREAM_BYTES,
    MISC_TRANSFORM_PROTOCOL,
    MISC_TRANSFORM_VERIFICATION_REPEATS,
    MiscArtifactRef,
    MiscReverseVerificationObservation,
    MiscStreamEvidence,
    MiscTransformObservation,
    MiscTransformPreflightError,
    MiscTransformStepSpec,
    MiscVerifierSpec,
    build_misc_transform_plan,
    evaluate_misc_transform_receipts,
    expected_misc_reverse_result_artifact,
    misc_transform_node_commitment_sha256,
    verify_misc_transform_evidence,
)


CANDIDATE = "KCTF{misc-transform-candidate}"
MANIFEST = "a" * 64


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


SOURCES = (
    MiscArtifactRef(
        artifact_id="source.image",
        sha256=sha256(b"immutable image bytes"),
        size_bytes=len(b"immutable image bytes"),
    ),
    MiscArtifactRef(
        artifact_id="source.key",
        sha256=sha256(b"immutable key bytes"),
        size_bytes=len(b"immutable key bytes"),
    ),
)

STEPS = (
    MiscTransformStepSpec(
        ordinal=1,
        step_id="decode-image",
        parent_ids=("source.image",),
        tool_id="image-decoder",
        tool_artifact_sha256="b" * 64,
        argv_contract_sha256="c" * 64,
        execution_contract_sha256="d" * 64,
    ),
    MiscTransformStepSpec(
        ordinal=2,
        step_id="normalize-key",
        parent_ids=("source.key",),
        tool_id="key-normalizer",
        tool_artifact_sha256="e" * 64,
        argv_contract_sha256="f" * 64,
        execution_contract_sha256="1" * 64,
    ),
    MiscTransformStepSpec(
        ordinal=3,
        step_id="extract-candidate",
        parent_ids=("decode-image", "normalize-key"),
        tool_id="candidate-extractor",
        tool_artifact_sha256="2" * 64,
        argv_contract_sha256="3" * 64,
        execution_contract_sha256="4" * 64,
    ),
)

VERIFIER = MiscVerifierSpec(
    verifier_id="original-condition-oracle",
    tool_artifact_sha256="5" * 64,
    argv_contract_sha256="6" * 64,
    execution_contract_sha256="7" * 64,
    oracle_contract_sha256="8" * 64,
)


def artifact(
    artifact_id: str,
    payload: bytes,
) -> MiscArtifactRef:
    return MiscArtifactRef(
        artifact_id=artifact_id,
        sha256=sha256(payload),
        size_bytes=len(payload),
    )


def stream(run_id: str, name: str) -> MiscStreamEvidence:
    payload = f"{run_id}:{name}".encode("ascii")
    return MiscStreamEvidence(
        artifact_id=f"stream.{run_id}.{name}",
        artifact_sha256=sha256(payload),
        artifact_size_bytes=len(payload),
        capture_complete=True,
        truncation_known=True,
        truncated=False,
        capture_error=None,
        durable_artifact_complete=True,
    )


def transform_observation(
    plan,
    spec: MiscTransformStepSpec,
    *,
    parents: tuple[tuple[MiscArtifactRef, str], ...],
    output: MiscArtifactRef,
) -> MiscTransformObservation:
    run_id = f"misc-step-{spec.ordinal}"
    return MiscTransformObservation(
        run_id=run_id,
        ordinal=spec.ordinal,
        step_id=spec.step_id,
        plan_sha256=plan.sha256,
        source_manifest_sha256=MANIFEST,
        parent_node_sha256s=tuple(item[1] for item in parents),
        input_artifacts=tuple(item[0] for item in parents),
        tool_id=spec.tool_id,
        tool_artifact_sha256=spec.tool_artifact_sha256,
        argv_contract_sha256=spec.argv_contract_sha256,
        execution_contract_sha256=spec.execution_contract_sha256,
        clean_workspace=True,
        network_denied=True,
        target_exit_code=0,
        runner_exit_code=0,
        ctfwrap_exit_code=0,
        timed_out=False,
        orchestration_status="completed",
        output_artifact=output,
        stdout=stream(run_id, "stdout"),
        stderr=stream(run_id, "stderr"),
    )


def valid_receipts():
    plan = build_misc_transform_plan(
        CANDIDATE,
        MANIFEST,
        SOURCES,
        STEPS,
        terminal_step_id="extract-candidate",
        verifier=VERIFIER,
    )
    image_output = artifact("output.image", b"decoded pixels")
    key_output = artifact("output.key", b"normalized key")
    candidate_output = artifact(
        "output.candidate",
        CANDIDATE.encode("utf-8"),
    )

    first = transform_observation(
        plan,
        STEPS[0],
        parents=((SOURCES[0], SOURCES[0].commitment_sha256),),
        output=image_output,
    )
    first_sha = misc_transform_node_commitment_sha256(first)
    second = transform_observation(
        plan,
        STEPS[1],
        parents=((SOURCES[1], SOURCES[1].commitment_sha256),),
        output=key_output,
    )
    second_sha = misc_transform_node_commitment_sha256(second)
    third = transform_observation(
        plan,
        STEPS[2],
        parents=(
            (image_output, first_sha),
            (key_output, second_sha),
        ),
        output=candidate_output,
    )
    terminal_sha = misc_transform_node_commitment_sha256(third)

    reverse = []
    for ordinal in range(1, MISC_TRANSFORM_VERIFICATION_REPEATS + 1):
        run_id = f"misc-reverse-{ordinal}"
        reverse.append(
            MiscReverseVerificationObservation(
                run_id=run_id,
                ordinal=ordinal,
                plan_sha256=plan.sha256,
                source_manifest_sha256=MANIFEST,
                terminal_node_sha256=terminal_sha,
                candidate_artifact=candidate_output,
                source_artifacts=SOURCES,
                verifier_id=VERIFIER.verifier_id,
                tool_artifact_sha256=(
                    VERIFIER.tool_artifact_sha256
                ),
                argv_contract_sha256=(
                    VERIFIER.argv_contract_sha256
                ),
                execution_contract_sha256=(
                    VERIFIER.execution_contract_sha256
                ),
                oracle_contract_sha256=(
                    VERIFIER.oracle_contract_sha256
                ),
                clean_workspace=True,
                network_denied=True,
                target_exit_code=0,
                runner_exit_code=0,
                ctfwrap_exit_code=0,
                timed_out=False,
                orchestration_status="completed",
                result_artifact=expected_misc_reverse_result_artifact(
                    plan,
                    terminal_sha,
                    ordinal,
                    artifact_id=f"result.reverse.{ordinal}",
                ),
                stdout=stream(run_id, "stdout"),
                stderr=stream(run_id, "stderr"),
            )
        )
    return plan, (first, second, third), tuple(reverse)


def evaluate(transforms=None, reverse=None):
    _plan, valid_transforms, valid_reverse = valid_receipts()
    return evaluate_misc_transform_receipts(
        CANDIDATE,
        MANIFEST,
        SOURCES,
        STEPS,
        terminal_step_id="extract-candidate",
        verifier=VERIFIER,
        transform_observations=(
            valid_transforms if transforms is None else transforms
        ),
        reverse_observations=(
            valid_reverse if reverse is None else reverse
        ),
    )


class MiscTransformPlanTests(unittest.TestCase):
    def test_plan_is_canonical_topological_and_raw_free(self) -> None:
        first = build_misc_transform_plan(
            CANDIDATE,
            MANIFEST,
            SOURCES,
            STEPS,
            terminal_step_id="extract-candidate",
            verifier=VERIFIER,
        )
        second = build_misc_transform_plan(
            CANDIDATE,
            MANIFEST,
            SOURCES,
            STEPS,
            terminal_step_id="extract-candidate",
            verifier=VERIFIER,
        )

        self.assertEqual(first, second)
        self.assertEqual(first.sha256, second.sha256)
        self.assertEqual(
            tuple(step.ordinal for step in first.steps),
            (1, 2, 3),
        )
        encoded = json.dumps(
            first.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
        )
        self.assertNotIn(CANDIDATE, encoded)
        self.assertEqual(
            first.candidate_sha256,
            sha256(CANDIDATE.encode("utf-8")),
        )
        self.assertIn(MISC_TRANSFORM_PROTOCOL, encoded)

    def test_cycle_is_rejected_before_topological_order(self) -> None:
        cyclic = (
            replace(STEPS[0], parent_ids=("normalize-key",)),
            replace(STEPS[1], parent_ids=("decode-image",)),
            STEPS[2],
        )
        with self.assertRaisesRegex(
            MiscTransformPreflightError,
            "dag_cycle",
        ):
            build_misc_transform_plan(
                CANDIDATE,
                MANIFEST,
                SOURCES,
                cyclic,
                terminal_step_id="extract-candidate",
                verifier=VERIFIER,
            )

    def test_back_reference_without_cycle_is_rejected(self) -> None:
        out_of_order = (
            replace(STEPS[0], parent_ids=("normalize-key",)),
            replace(STEPS[1], parent_ids=("source.key",)),
            replace(
                STEPS[2],
                parent_ids=("decode-image",),
            ),
        )
        with self.assertRaisesRegex(
            MiscTransformPreflightError,
            "dag_order_invalid",
        ):
            build_misc_transform_plan(
                CANDIDATE,
                MANIFEST,
                SOURCES,
                out_of_order,
                terminal_step_id="extract-candidate",
                verifier=VERIFIER,
            )

    def test_missing_parent_and_unused_source_fail_closed(self) -> None:
        missing = (replace(STEPS[0], parent_ids=("not-present",)),)
        with self.assertRaisesRegex(
            MiscTransformPreflightError,
            "graph_parent_invalid",
        ):
            build_misc_transform_plan(
                CANDIDATE,
                MANIFEST,
                SOURCES[:1],
                missing,
                terminal_step_id="decode-image",
                verifier=VERIFIER,
            )

        single_step = (
            replace(
                STEPS[0],
                parent_ids=("source.image",),
            ),
        )
        with self.assertRaisesRegex(
            MiscTransformPreflightError,
            "dag_disconnected",
        ):
            build_misc_transform_plan(
                CANDIDATE,
                MANIFEST,
                SOURCES,
                single_step,
                terminal_step_id="decode-image",
                verifier=VERIFIER,
            )

    def test_source_size_and_verifier_independence_are_bounded(self) -> None:
        oversized = replace(
            SOURCES[0],
            size_bytes=MISC_TRANSFORM_MAX_SOURCE_BYTES + 1,
        )
        with self.assertRaisesRegex(
            MiscTransformPreflightError,
            "source_artifact_too_large",
        ):
            build_misc_transform_plan(
                CANDIDATE,
                MANIFEST,
                (oversized, SOURCES[1]),
                STEPS,
                terminal_step_id="extract-candidate",
                verifier=VERIFIER,
            )

        dependent = replace(
            VERIFIER,
            tool_artifact_sha256=STEPS[-1].tool_artifact_sha256,
        )
        with self.assertRaisesRegex(
            MiscTransformPreflightError,
            "verifier_not_independent",
        ):
            build_misc_transform_plan(
                CANDIDATE,
                MANIFEST,
                SOURCES,
                STEPS,
                terminal_step_id="extract-candidate",
                verifier=dependent,
            )


class MiscTransformEvaluationTests(unittest.TestCase):
    def test_exact_dag_and_three_reverse_replays_pass(self) -> None:
        result = evaluate()

        self.assertTrue(result.passed)
        self.assertEqual(result.failure_codes, ())
        self.assertEqual(len(result.transform_nodes), 3)
        self.assertTrue(
            all(item.accepted for item in result.transform_nodes)
        )
        self.assertEqual(
            len(result.reverse_verifications),
            MISC_TRANSFORM_VERIFICATION_REPEATS,
        )
        self.assertTrue(
            all(
                item.accepted
                for item in result.reverse_verifications
            )
        )
        self.assertEqual(
            result.transform_nodes[2].parent_node_sha256s,
            (
                result.transform_nodes[0].node_sha256,
                result.transform_nodes[1].node_sha256,
            ),
        )
        self.assertTrue(
            result.to_dict()["authorities"][
                "candidate_original_condition_verified"
            ]
        )
        self.assertFalse(
            result.to_dict()["authorities"][
                "automatic_submission_authorized"
            ]
        )

    def test_evidence_is_bounded_canonical_and_raw_free(self) -> None:
        result = evaluate()
        payload = result.canonical_bytes

        self.assertLessEqual(
            len(payload),
            MISC_TRANSFORM_MAX_EVIDENCE_BYTES,
        )
        self.assertEqual(payload, result.canonical_bytes)
        self.assertTrue(verify_misc_transform_evidence(result, payload))
        self.assertFalse(
            verify_misc_transform_evidence(
                result,
                payload.replace(b'"passed":true', b'"passed":false'),
            )
        )
        text = payload.decode("ascii")
        self.assertNotIn(CANDIDATE, text)
        self.assertNotIn("immutable image bytes", text)
        self.assertNotIn("decoded pixels", text)
        self.assertNotIn("normalized key", text)
        self.assertIn(sha256(CANDIDATE.encode()), text)
        self.assertTrue(payload.endswith(b"\n"))

    def test_parent_or_input_tamper_invalidates_descendants(self) -> None:
        _plan, transforms, reverse = valid_receipts()
        bad_parent = list(transforms)
        bad_parent[2] = replace(
            bad_parent[2],
            parent_node_sha256s=("9" * 64,) * 2,
        )
        result = evaluate(tuple(bad_parent), reverse)
        self.assertFalse(result.passed)
        self.assertIn(
            "step-3:parent_commitment_mismatch",
            result.failure_codes,
        )

        bad_input = list(transforms)
        bad_input[2] = replace(
            bad_input[2],
            input_artifacts=(
                replace(
                    bad_input[2].input_artifacts[0],
                    sha256="9" * 64,
                ),
                bad_input[2].input_artifacts[1],
            ),
        )
        result = evaluate(tuple(bad_input), reverse)
        self.assertFalse(result.passed)
        self.assertIn(
            "step-3:input_binding_mismatch",
            result.failure_codes,
        )

    def test_tool_plan_and_source_tamper_fail_closed(self) -> None:
        _plan, transforms, reverse = valid_receipts()
        mutations = (
            (
                replace(transforms[0], plan_sha256="9" * 64),
                "step-1:plan_binding_mismatch",
            ),
            (
                replace(
                    transforms[0],
                    source_manifest_sha256="9" * 64,
                ),
                "step-1:source_manifest_mismatch",
            ),
            (
                replace(
                    transforms[0],
                    argv_contract_sha256="9" * 64,
                ),
                "step-1:tool_contract_mismatch",
            ),
            (
                replace(
                    transforms[0],
                    execution_contract_sha256="9" * 64,
                ),
                "step-1:execution_contract_mismatch",
            ),
        )
        for replacement, code in mutations:
            with self.subTest(code=code):
                changed = (replacement,) + transforms[1:]
                result = evaluate(changed, reverse)
                self.assertFalse(result.passed)
                self.assertIn(code, result.failure_codes)

    def test_terminal_candidate_and_reverse_result_are_exact(self) -> None:
        _plan, transforms, reverse = valid_receipts()
        bad_terminal = list(transforms)
        bad_terminal[2] = replace(
            bad_terminal[2],
            output_artifact=artifact(
                "output.other-candidate",
                b"KCTF{different}",
            ),
        )
        result = evaluate(tuple(bad_terminal), reverse)
        self.assertFalse(result.passed)
        self.assertIn(
            "step-3:candidate_output_mismatch",
            result.failure_codes,
        )

        bad_reverse = list(reverse)
        bad_reverse[1] = replace(
            bad_reverse[1],
            result_artifact=replace(
                bad_reverse[1].result_artifact,
                sha256="9" * 64,
            ),
        )
        result = evaluate(transforms, tuple(bad_reverse))
        self.assertFalse(result.passed)
        self.assertIn(
            "reverse-2:reverse_result_mismatch",
            result.failure_codes,
        )

    def test_reverse_must_bind_original_sources_and_independent_contract(
        self,
    ) -> None:
        _plan, transforms, reverse = valid_receipts()
        bad_sources = list(reverse)
        bad_sources[0] = replace(
            bad_sources[0],
            source_artifacts=(SOURCES[0],),
        )
        result = evaluate(transforms, tuple(bad_sources))
        self.assertFalse(result.passed)
        self.assertIn(
            "reverse-1:reverse_candidate_binding_mismatch",
            result.failure_codes,
        )

        bad_verifier = list(reverse)
        bad_verifier[0] = replace(
            bad_verifier[0],
            oracle_contract_sha256="9" * 64,
        )
        result = evaluate(transforms, tuple(bad_verifier))
        self.assertFalse(result.passed)
        self.assertIn(
            "reverse-1:verifier_contract_mismatch",
            result.failure_codes,
        )

    def test_clean_network_denied_execution_is_mandatory(self) -> None:
        _plan, transforms, reverse = valid_receipts()
        changes = (
            (
                replace(transforms[0], clean_workspace=False),
                "step-1:workspace_not_clean",
            ),
            (
                replace(transforms[0], network_denied=False),
                "step-1:network_not_denied",
            ),
            (
                replace(transforms[0], timed_out=True),
                "step-1:timed_out",
            ),
            (
                replace(transforms[0], runner_exit_code=1),
                "step-1:exit_status_mismatch",
            ),
        )
        for replacement, code in changes:
            with self.subTest(code=code):
                result = evaluate(
                    (replacement,) + transforms[1:],
                    reverse,
                )
                self.assertFalse(result.passed)
                self.assertIn(code, result.failure_codes)

    def test_stream_and_output_sizes_fail_closed_without_raw_error(self) -> None:
        _plan, transforms, reverse = valid_receipts()
        oversized_stream = replace(
            transforms[0].stdout,
            artifact_size_bytes=MISC_TRANSFORM_MAX_STREAM_BYTES + 1,
            capture_error="secret-model-controlled-error",
        )
        changed = (
            replace(transforms[0], stdout=oversized_stream),
        ) + transforms[1:]
        result = evaluate(changed, reverse)
        self.assertFalse(result.passed)
        self.assertIn(
            "step-1:stdout:stream_artifact_too_large",
            result.failure_codes,
        )
        self.assertIn(
            "step-1:stdout:stream_capture_incomplete",
            result.failure_codes,
        )
        self.assertNotIn(
            "secret-model-controlled-error",
            result.canonical_bytes.decode("ascii"),
        )

        oversized_output = replace(
            transforms[0].output_artifact,
            size_bytes=MISC_TRANSFORM_MAX_OUTPUT_BYTES + 1,
        )
        result = evaluate(
            (replace(transforms[0], output_artifact=oversized_output),)
            + transforms[1:],
            reverse,
        )
        self.assertFalse(result.passed)
        self.assertIn(
            "step-1:output_artifact_too_large",
            result.failure_codes,
        )

    def test_order_count_run_and_artifact_reuse_fail_closed(self) -> None:
        _plan, transforms, reverse = valid_receipts()
        result = evaluate(transforms[:2], reverse)
        self.assertFalse(result.passed)
        self.assertIn(
            "observation_count_mismatch",
            result.failure_codes,
        )

        duplicate_run = list(transforms)
        duplicate_run[1] = replace(
            duplicate_run[1],
            run_id=duplicate_run[0].run_id,
        )
        result = evaluate(tuple(duplicate_run), reverse)
        self.assertFalse(result.passed)
        self.assertIn(
            "step-2:duplicate_run_id",
            result.failure_codes,
        )

        reused_artifact = list(transforms)
        reused_artifact[1] = replace(
            reused_artifact[1],
            stderr=replace(
                reused_artifact[1].stderr,
                artifact_id=transforms[0].stdout.artifact_id,
            ),
        )
        result = evaluate(tuple(reused_artifact), reverse)
        self.assertFalse(result.passed)
        self.assertIn(
            "step-2:stderr:artifact_id_reused",
            result.failure_codes,
        )


if __name__ == "__main__":
    unittest.main()
