from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import replace

from ctf_os.engine.rev_proof import (
    REV_STDIN_PROOF_EMPTY_NEGATIVE_MUTATION_IDS,
    REV_STDIN_PROOF_FLAG_SCANNER_CONTRACT,
    REV_STDIN_PROOF_MAX_ACCEPTED_INPUT_BYTES,
    REV_STDIN_PROOF_MAX_EVIDENCE_BYTES,
    REV_STDIN_PROOF_NONEMPTY_NEGATIVE_MUTATION_IDS,
    REV_STDIN_PROOF_POSITIVE_MUTATION_IDS,
    REV_STDIN_PROOF_PROTOCOL,
    RevProofObservation,
    RevProofEvaluationRecord,
    RevProofStreamEvidence,
    build_rev_stdin_proof_plan,
    evaluate_rev_stdin_proof,
    parse_rev_proof_evaluation_evidence,
    verify_rev_proof_evaluation,
)


CANDIDATE = "KCTF{rev-proof-candidate}"
MANIFEST = "a" * 64
ACCEPTED_INPUT = b"\x00open-sesame\xff\n"


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def stream_evidence(
    run_id: str,
    stream: str,
    *,
    capture_complete: bool = True,
    truncation_known: bool = True,
    truncated: bool | None = False,
    capture_error: str | None = None,
    durable_artifact_complete: bool = True,
) -> RevProofStreamEvidence:
    payload = f"{run_id}:{stream}".encode("ascii")
    return RevProofStreamEvidence(
        artifact_id=f"artifact-{run_id}-{stream}",
        artifact_sha256=sha256(payload),
        artifact_size_bytes=len(payload),
        capture_complete=capture_complete,
        truncation_known=truncation_known,
        truncated=truncated,
        capture_error=capture_error,
        durable_artifact_complete=durable_artifact_complete,
    )


def valid_observations(
    accepted_input: bytes = ACCEPTED_INPUT,
    *,
    target_exit_code: int = 0,
) -> tuple[RevProofObservation, ...]:
    observations: list[RevProofObservation] = []
    for planned in build_rev_stdin_proof_plan(CANDIDATE, accepted_input):
        run_id = f"rev-proof-{planned.ordinal}"
        positive = planned.phase == "positive"
        observations.append(
            RevProofObservation(
                run_id=run_id,
                phase=planned.phase,
                mutation_id=planned.mutation_id,
                input_sha256=planned.sha256,
                input_size_bytes=planned.size_bytes,
                source_manifest_sha256=MANIFEST,
                clean_workspace=True,
                target_exit_code=target_exit_code,
                runner_exit_code=target_exit_code,
                ctfwrap_exit_code=target_exit_code,
                timed_out=False,
                orchestration_status="completed",
                orchestration_error=None,
                stream_capture_error=None,
                stdout=stream_evidence(run_id, "stdout"),
                stderr=stream_evidence(run_id, "stderr"),
                flag_scanner_contract=(
                    REV_STDIN_PROOF_FLAG_SCANNER_CONTRACT
                ),
                flag_scan_complete=True,
                flag_scan_error=None,
                flag_values_overflow=False,
                flag_values=(CANDIDATE,) if positive else (),
                selected_candidate_direct_output=positive,
            )
        )
    return tuple(observations)


def failure_codes(evaluation) -> set[str]:
    return set(evaluation.failure_codes)


class RevProofPlanTests(unittest.TestCase):
    def test_nonempty_binary_plan_has_exact_order_mutations_and_hashes(
        self,
    ) -> None:
        accepted = b"\x00\x10\xff"
        first = build_rev_stdin_proof_plan(CANDIDATE, accepted)
        second = build_rev_stdin_proof_plan(CANDIDATE, accepted)

        self.assertEqual(first, second)
        self.assertEqual(len(first), 6)
        self.assertEqual(
            tuple(item.ordinal for item in first),
            (1, 2, 3, 4, 5, 6),
        )
        self.assertEqual(
            tuple(item.phase for item in first),
            ("positive",) * 3 + ("negative",) * 3,
        )
        self.assertEqual(
            tuple(item.mutation_id for item in first[:3]),
            REV_STDIN_PROOF_POSITIVE_MUTATION_IDS,
        )
        self.assertEqual(
            tuple(item.mutation_id for item in first[3:]),
            REV_STDIN_PROOF_NONEMPTY_NEGATIVE_MUTATION_IDS,
        )
        self.assertEqual(
            tuple(item.payload for item in first),
            (
                accepted,
                accepted,
                accepted,
                b"\x01\x10\xff",
                b"\x00\x10\x7f",
                b"\x00\x10",
            ),
        )
        for item in first:
            self.assertEqual(item.sha256, sha256(item.payload))
            self.assertEqual(item.size_bytes, len(item.payload))
            self.assertNotIn("payload", item.to_dict())

    def test_empty_input_uses_three_exact_append_mutations(self) -> None:
        plan = build_rev_stdin_proof_plan(CANDIDATE, b"")
        self.assertEqual(
            tuple(item.mutation_id for item in plan[3:]),
            REV_STDIN_PROOF_EMPTY_NEGATIVE_MUTATION_IDS,
        )
        self.assertEqual(
            tuple(item.payload for item in plan[3:]),
            (b"\x00", b"\x0a", b"\xff"),
        )
        self.assertEqual(
            tuple(item.size_bytes for item in plan),
            (0, 0, 0, 1, 1, 1),
        )
        self.assertEqual(
            tuple(item.sha256 for item in plan),
            (
                sha256(b""),
                sha256(b""),
                sha256(b""),
                sha256(b"\x00"),
                sha256(b"\x0a"),
                sha256(b"\xff"),
            ),
        )

    def test_input_size_limit_is_exact(self) -> None:
        maximum = b"x" * REV_STDIN_PROOF_MAX_ACCEPTED_INPUT_BYTES
        self.assertEqual(
            build_rev_stdin_proof_plan(CANDIDATE, maximum)[0].size_bytes,
            REV_STDIN_PROOF_MAX_ACCEPTED_INPUT_BYTES,
        )
        result, evaluation = evaluate_rev_stdin_proof(
            CANDIDATE,
            maximum + b"x",
            MANIFEST,
            (),
        )
        self.assertFalse(result.passed)
        self.assertEqual(
            evaluation.failure_codes,
            ("accepted_input_too_large",),
        )

    def test_mutations_may_not_derive_the_candidate_literal(self) -> None:
        result, evaluation = evaluate_rev_stdin_proof(
            "A",
            b"@",
            MANIFEST,
            (),
        )
        self.assertFalse(result.passed)
        self.assertEqual(
            evaluation.failure_codes,
            ("derived_input_contains_candidate",),
        )
        self.assertEqual(evaluation.plan, ())


class RevProofEvaluationTests(unittest.TestCase):
    def test_three_positive_and_three_negative_runs_pass_with_nonzero_target(
        self,
    ) -> None:
        observations = valid_observations(target_exit_code=7)
        result, evaluation = evaluate_rev_stdin_proof(
            CANDIDATE,
            ACCEPTED_INPUT,
            MANIFEST,
            observations,
        )

        self.assertTrue(result.passed)
        self.assertTrue(evaluation.passed)
        self.assertEqual(result.policy_mode, REV_STDIN_PROOF_PROTOCOL)
        self.assertEqual(result.successful_attempts, 3)
        self.assertEqual(result.required_attempts, 3)
        self.assertEqual(result.total_attempts, 6)
        self.assertEqual(evaluation.positive_successes, 3)
        self.assertEqual(evaluation.failures, ())
        self.assertEqual(
            result.run_ids,
            tuple(item.run_id for item in observations),
        )

    def test_any_flag_looking_value_in_a_negative_run_fails(self) -> None:
        observations = list(valid_observations())
        observations[4] = replace(
            observations[4],
            flag_values=("OTHER{negative-output}",),
        )
        result, evaluation = evaluate_rev_stdin_proof(
            CANDIDATE,
            ACCEPTED_INPUT,
            MANIFEST,
            observations,
        )
        self.assertFalse(result.passed)
        self.assertIn(
            "negative_flag_candidate_observed",
            failure_codes(evaluation),
        )

    def test_positive_requires_direct_selected_candidate_output(self) -> None:
        observations = list(valid_observations())
        observations[1] = replace(
            observations[1],
            selected_candidate_direct_output=False,
        )
        result, evaluation = evaluate_rev_stdin_proof(
            CANDIDATE,
            ACCEPTED_INPUT,
            MANIFEST,
            observations,
        )
        self.assertFalse(result.passed)
        self.assertIn(
            "selected_candidate_not_direct",
            failure_codes(evaluation),
        )

    def test_timeout_orchestration_capture_and_artifact_fail_closed(
        self,
    ) -> None:
        base = valid_observations()
        cases = {
            "timeout": (
                replace(base[0], timed_out=True),
                "timed_out",
            ),
            "orchestration-status": (
                replace(base[0], orchestration_status="failed"),
                "orchestration_incomplete",
            ),
            "workspace-not-clean": (
                replace(base[0], clean_workspace=False),
                "workspace_not_clean",
            ),
            "orchestration-error": (
                replace(
                    base[0],
                    orchestration_error="bounded synthetic error",
                ),
                "orchestration_error",
            ),
            "stream-error": (
                replace(
                    base[0],
                    stream_capture_error="capture transport failed",
                ),
                "capture_error",
            ),
            "capture-incomplete": (
                replace(
                    base[0],
                    stdout=replace(
                        base[0].stdout,
                        capture_complete=False,
                    ),
                ),
                "capture_incomplete",
            ),
            "truncation-unknown": (
                replace(
                    base[0],
                    stdout=replace(
                        base[0].stdout,
                        truncation_known=False,
                    ),
                ),
                "capture_truncation_unknown",
            ),
            "truncated": (
                replace(
                    base[0],
                    stderr=replace(base[0].stderr, truncated=True),
                ),
                "capture_truncated",
            ),
            "capture-error": (
                replace(
                    base[0],
                    stderr=replace(
                        base[0].stderr,
                        capture_error="read failed",
                    ),
                ),
                "capture_error",
            ),
            "missing-artifact": (
                replace(
                    base[0],
                    stdout=replace(
                        base[0].stdout,
                        artifact_id=None,
                    ),
                ),
                "durable_artifact_incomplete",
            ),
            "incomplete-artifact": (
                replace(
                    base[0],
                    stdout=replace(
                        base[0].stdout,
                        durable_artifact_complete=False,
                    ),
                ),
                "durable_artifact_incomplete",
            ),
            "target-exit-unavailable": (
                replace(base[0], target_exit_code=None),
                "target_exit_unavailable",
            ),
            "target-125": (
                replace(
                    base[0],
                    target_exit_code=125,
                    runner_exit_code=125,
                    ctfwrap_exit_code=125,
                ),
                "target_transport_exit_125",
            ),
            "runner-exit-unavailable": (
                replace(base[0], runner_exit_code=None),
                "runner_exit_unavailable",
            ),
            "runner-bool-is-not-an-exit": (
                replace(base[0], runner_exit_code=True),
                "runner_exit_unavailable",
            ),
            "ctfwrap-exit-unavailable": (
                replace(base[0], ctfwrap_exit_code=None),
                "ctfwrap_exit_unavailable",
            ),
            "ctfwrap-bool-is-not-an-exit": (
                replace(base[0], ctfwrap_exit_code=False),
                "ctfwrap_exit_unavailable",
            ),
            "runner-125": (
                replace(base[0], runner_exit_code=125),
                "runner_transport_exit_125",
            ),
            "ctfwrap-125": (
                replace(base[0], ctfwrap_exit_code=125),
                "ctfwrap_transport_exit_125",
            ),
            "exit-status-mismatch": (
                replace(base[0], runner_exit_code=7),
                "exit_status_mismatch",
            ),
            "flag-scanner-contract": (
                replace(base[0], flag_scanner_contract="other"),
                "flag_scanner_contract_mismatch",
            ),
            "flag-scan-incomplete": (
                replace(base[0], flag_scan_complete=False),
                "flag_scan_incomplete",
            ),
            "flag-scan-error": (
                replace(base[0], flag_scan_error="scanner failed"),
                "flag_scan_error",
            ),
            "flag-values-overflow": (
                replace(base[0], flag_values_overflow=True),
                "flag_values_overflow",
            ),
            "flag-values-control-character": (
                replace(base[0], flag_values=(CANDIDATE, "X{\n}")),
                "flag_evidence_invalid",
            ),
        }
        for name, (changed, expected_code) in cases.items():
            observations = list(base)
            observations[0] = changed
            with self.subTest(name=name):
                result, evaluation = evaluate_rev_stdin_proof(
                    CANDIDATE,
                    ACCEPTED_INPUT,
                    MANIFEST,
                    observations,
                )
                self.assertFalse(result.passed)
                self.assertIn(
                    expected_code,
                    failure_codes(evaluation),
                )
                if expected_code.endswith("transport_exit_125"):
                    self.assertTrue(evaluation.transport_inconclusive)

    def test_wrong_order_hash_duplicate_and_missing_attempts_fail(self) -> None:
        base = valid_observations()
        swapped = list(base)
        swapped[0], swapped[3] = swapped[3], swapped[0]
        wrong_hash = list(base)
        wrong_hash[2] = replace(
            wrong_hash[2],
            input_sha256="0" * 64,
        )
        duplicate = list(base)
        duplicate[5] = replace(
            duplicate[5],
            run_id=duplicate[0].run_id,
        )
        cases = (
            ("wrong-order", swapped, "attempt_order_mismatch"),
            ("wrong-hash", wrong_hash, "input_binding_mismatch"),
            ("duplicate", duplicate, "duplicate_run_id"),
            ("missing", base[:-1], "attempt_count_mismatch"),
            ("extra", base + (base[-1],), "attempt_count_mismatch"),
        )
        for name, observations, expected in cases:
            with self.subTest(name=name):
                result, evaluation = evaluate_rev_stdin_proof(
                    CANDIDATE,
                    ACCEPTED_INPUT,
                    MANIFEST,
                    observations,
                )
                self.assertFalse(result.passed)
                self.assertIn(expected, failure_codes(evaluation))
                self.assertLessEqual(len(evaluation.observations), 6)

    def test_runtime_type_tricks_cannot_confirm_blank_bindings(self) -> None:
        class EqualString(str):
            def __eq__(self, _other):
                return True

            __hash__ = str.__hash__

        observations = list(valid_observations())
        observations[0] = replace(
            observations[0],
            phase=EqualString("wrong-phase"),
            mutation_id=EqualString("wrong-mutation"),
            input_sha256=EqualString("wrong-hash"),
            source_manifest_sha256=EqualString("wrong-manifest"),
            orchestration_status=EqualString("wrong-status"),
        )
        result, evaluation = evaluate_rev_stdin_proof(
            CANDIDATE,
            ACCEPTED_INPUT,
            MANIFEST,
            observations,
        )
        self.assertFalse(result.passed)
        self.assertTrue(
            {
                "attempt_order_mismatch",
                "input_binding_mismatch",
                "source_manifest_mismatch",
                "orchestration_incomplete",
            }
            <= failure_codes(evaluation)
        )
        retained = evaluation.observations[0]
        self.assertEqual(retained.phase, "")
        self.assertEqual(retained.mutation_id, "")
        self.assertEqual(retained.input_sha256, "")
        self.assertEqual(retained.source_manifest_sha256, "")
        self.assertEqual(retained.orchestration_status, "")

    def test_huge_numeric_evidence_fails_before_normalized_persistence(
        self,
    ) -> None:
        huge = 10**100
        observations = list(valid_observations())
        observations[0] = replace(
            observations[0],
            target_exit_code=huge,
            runner_exit_code=huge,
            ctfwrap_exit_code=huge,
            stdout=replace(
                observations[0].stdout,
                artifact_size_bytes=huge,
            ),
        )
        result, evaluation = evaluate_rev_stdin_proof(
            CANDIDATE,
            ACCEPTED_INPUT,
            MANIFEST,
            observations,
        )
        self.assertFalse(result.passed)
        self.assertTrue(
            {
                "target_exit_unavailable",
                "runner_exit_unavailable",
                "ctfwrap_exit_unavailable",
                "durable_artifact_incomplete",
            }
            <= failure_codes(evaluation)
        )
        retained = evaluation.observations[0]
        self.assertIsNone(retained.target_exit_code)
        self.assertIsNone(retained.runner_exit_code)
        self.assertIsNone(retained.ctfwrap_exit_code)
        self.assertIsNone(retained.stdout.artifact_size_bytes)

    def test_every_stdout_and_stderr_artifact_id_must_be_globally_unique(
        self,
    ) -> None:
        observations = list(valid_observations())
        observations[5] = replace(
            observations[5],
            stderr=replace(
                observations[5].stderr,
                artifact_id=observations[0].stdout.artifact_id,
            ),
        )
        result, evaluation = evaluate_rev_stdin_proof(
            CANDIDATE,
            ACCEPTED_INPUT,
            MANIFEST,
            observations,
        )
        self.assertFalse(result.passed)
        reused = [
            item
            for item in evaluation.failures
            if item.code == "durable_artifact_reused"
        ]
        self.assertEqual(len(reused), 1)
        self.assertEqual(reused[0].attempt_ordinal, 6)
        self.assertEqual(reused[0].stream, "stderr")

    def test_stale_source_manifest_fails_every_affected_observation(
        self,
    ) -> None:
        observations = list(valid_observations())
        observations[0] = replace(
            observations[0],
            source_manifest_sha256="b" * 64,
        )
        result, evaluation = evaluate_rev_stdin_proof(
            CANDIDATE,
            ACCEPTED_INPUT,
            MANIFEST,
            observations,
        )
        self.assertFalse(result.passed)
        failures = [
            item
            for item in evaluation.failures
            if item.code == "source_manifest_mismatch"
        ]
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0].attempt_ordinal, 1)

    def test_candidate_embedded_in_input_is_rejected_before_consuming_runs(
        self,
    ) -> None:
        consumed = False

        def observations():
            nonlocal consumed
            consumed = True
            yield from valid_observations()

        accepted_input = b"\x00prefix" + CANDIDATE.encode() + b"\xff"
        result, evaluation = evaluate_rev_stdin_proof(
            CANDIDATE,
            accepted_input,
            MANIFEST,
            observations(),
        )
        self.assertFalse(result.passed)
        self.assertFalse(consumed)
        self.assertEqual(
            evaluation.failure_codes,
            ("accepted_input_contains_candidate",),
        )
        self.assertEqual(evaluation.plan, ())
        self.assertEqual(evaluation.observations, ())
        self.assertEqual(result.run_ids, ())

    def test_non_iterable_observations_fail_with_bounded_code(self) -> None:
        result, evaluation = evaluate_rev_stdin_proof(
            CANDIDATE,
            ACCEPTED_INPUT,
            MANIFEST,
            None,  # type: ignore[arg-type]
        )
        self.assertFalse(result.passed)
        self.assertEqual(
            evaluation.failure_codes,
            ("observations_not_iterable",),
        )
        self.assertEqual(evaluation.observations, ())

    def test_observation_iteration_errors_are_redacted(self) -> None:
        marker = "RAW-ITERATOR-ERROR-MUST-NOT-PERSIST"

        class BrokenIter:
            def __iter__(self):
                raise ValueError(marker)

        class BrokenNext:
            def __iter__(self):
                return self

            def __next__(self):
                raise RuntimeError(marker)

        cases = (
            (BrokenIter(), "observations_not_iterable"),
            (BrokenNext(), "observation_iteration_failed"),
        )
        for observations, expected in cases:
            with self.subTest(expected=expected):
                result, evaluation = evaluate_rev_stdin_proof(
                    CANDIDATE,
                    ACCEPTED_INPUT,
                    MANIFEST,
                    observations,
                )
                self.assertFalse(result.passed)
                self.assertEqual(evaluation.failure_codes, (expected,))
                self.assertNotIn(
                    marker.encode(),
                    evaluation.canonical_bytes(),
                )

    def test_invalid_large_text_is_not_retained_in_evaluation_evidence(
        self,
    ) -> None:
        marker = "UNBOUNDED-SENTINEL-" + ("x" * 20_000)
        observations = list(valid_observations())
        observations[0] = replace(
            observations[0],
            run_id=marker,
            source_manifest_sha256=marker,
            orchestration_error=marker,
            stdout=replace(
                observations[0].stdout,
                artifact_id=marker,
                capture_error=marker,
            ),
            flag_values=(marker,),
        )
        result, evaluation = evaluate_rev_stdin_proof(
            CANDIDATE,
            ACCEPTED_INPUT,
            MANIFEST,
            observations,
        )
        serialized = evaluation.canonical_bytes()
        self.assertFalse(result.passed)
        self.assertNotIn(marker.encode(), serialized)
        self.assertLess(len(serialized), 64 * 1024)
        self.assertNotIn(
            marker,
            json.dumps(observations[0].to_dict()),
        )
        self.assertNotIn(
            marker,
            json.dumps(observations[0].stdout.to_dict()),
        )
        retained = evaluation.observations[0]
        self.assertEqual(retained.run_id, "")
        self.assertEqual(retained.source_manifest_sha256, "")
        self.assertEqual(retained.orchestration_error, "<present>")
        self.assertEqual(retained.stdout.artifact_id, None)
        self.assertEqual(retained.stdout.capture_error, "<present>")
        self.assertEqual(retained.flag_values, ())

        huge_candidate_result, huge_candidate_evaluation = (
            evaluate_rev_stdin_proof(
                marker,
                ACCEPTED_INPUT,
                MANIFEST,
                None,  # type: ignore[arg-type]
            )
        )
        self.assertFalse(huge_candidate_result.passed)
        self.assertEqual(huge_candidate_evaluation.candidate, "")
        self.assertNotIn(
            marker.encode(),
            huge_candidate_evaluation.canonical_bytes(),
        )

        _, bad_manifest_evaluation = evaluate_rev_stdin_proof(
            CANDIDATE,
            ACCEPTED_INPUT,
            marker,
            None,  # type: ignore[arg-type]
        )
        self.assertEqual(bad_manifest_evaluation.source_manifest_sha256, "")
        self.assertNotIn(
            marker.encode(),
            bad_manifest_evaluation.canonical_bytes(),
        )

    def test_evidence_serialization_and_digest_are_deterministic(self) -> None:
        first_result, first = evaluate_rev_stdin_proof(
            CANDIDATE,
            ACCEPTED_INPUT,
            MANIFEST,
            valid_observations(),
        )
        second_result, second = evaluate_rev_stdin_proof(
            CANDIDATE,
            ACCEPTED_INPUT,
            MANIFEST,
            valid_observations(),
        )

        self.assertEqual(first_result.to_dict(), second_result.to_dict())
        self.assertEqual(first, second)
        self.assertEqual(first.canonical_bytes(), second.canonical_bytes())
        self.assertEqual(first.evidence_sha256, second.evidence_sha256)
        self.assertTrue(first.canonical_bytes().endswith(b"\n"))
        decoded = json.loads(first.canonical_bytes())
        self.assertEqual(decoded["protocol"], REV_STDIN_PROOF_PROTOCOL)
        self.assertEqual(decoded["schema_version"], 1)
        self.assertEqual(decoded["verdict"], "CONFIRMED")
        self.assertEqual(
            decoded["accepted_input_sha256"],
            sha256(ACCEPTED_INPUT),
        )
        self.assertNotIn(
            ACCEPTED_INPUT.hex(),
            first.canonical_bytes().decode("ascii"),
        )

    def test_maximal_valid_flag_evidence_stays_bounded(self) -> None:
        values = (
            CANDIDATE,
            *(
                f"F{i:03d}{{" + ("x" * 110) + "}"
                for i in range(127)
            ),
        )
        observations = list(valid_observations())
        for index in range(3):
            observations[index] = replace(
                observations[index],
                flag_values=values,
            )
        result, evaluation = evaluate_rev_stdin_proof(
            CANDIDATE,
            ACCEPTED_INPUT,
            MANIFEST,
            observations,
        )
        self.assertTrue(result.passed)
        self.assertLessEqual(
            len(evaluation.canonical_bytes()),
            REV_STDIN_PROOF_MAX_EVIDENCE_BYTES,
        )


class RevProofPersistedEvidenceTests(unittest.TestCase):
    def confirmed_mapping(self) -> dict[str, object]:
        _, evaluation = evaluate_rev_stdin_proof(
            CANDIDATE,
            ACCEPTED_INPUT,
            MANIFEST,
            valid_observations(),
        )
        return json.loads(evaluation.canonical_bytes())

    def test_exact_mapping_round_trips_and_replays_original_input(
        self,
    ) -> None:
        mapping = self.confirmed_mapping()
        record = parse_rev_proof_evaluation_evidence(mapping)

        self.assertIsInstance(record, RevProofEvaluationRecord)
        self.assertEqual(record.to_dict(), mapping)
        self.assertEqual(
            json.loads(record.canonical_bytes()),
            mapping,
        )
        self.assertEqual(
            verify_rev_proof_evaluation(
                mapping,
                accepted_input=ACCEPTED_INPUT,
            ),
            record,
        )
        self.assertNotIn(
            ACCEPTED_INPUT.hex(),
            record.canonical_bytes().decode("ascii"),
        )

    def test_replay_rejects_wrong_input_and_hash_only_plan_tampering(
        self,
    ) -> None:
        mapping = self.confirmed_mapping()
        with self.assertRaisesRegex(
            ValueError,
            "invalid persisted Rev proof evidence",
        ):
            verify_rev_proof_evaluation(
                mapping,
                accepted_input=ACCEPTED_INPUT + b"x",
            )

        tampered = json.loads(json.dumps(mapping))
        tampered["plan"][3]["input_sha256"] = "0" * 64
        tampered["observations"][3]["input_sha256"] = "0" * 64
        parsed = parse_rev_proof_evaluation_evidence(tampered)
        self.assertEqual(parsed.plan[3].input_sha256, "0" * 64)
        with self.assertRaises(ValueError):
            verify_rev_proof_evaluation(
                tampered,
                accepted_input=ACCEPTED_INPUT,
            )

    def test_derived_fields_and_fixed_plan_order_are_exact(self) -> None:
        base = self.confirmed_mapping()
        mutations = {
            "failure-codes": lambda value: value.__setitem__(
                "failure_codes",
                ["timed_out"],
            ),
            "positive-successes": lambda value: value.__setitem__(
                "positive_successes",
                2,
            ),
            "total-attempts": lambda value: value.__setitem__(
                "total_attempts",
                5,
            ),
            "transport": lambda value: value.__setitem__(
                "transport_inconclusive",
                True,
            ),
            "verdict": lambda value: value.__setitem__(
                "verdict",
                "INCONCLUSIVE",
            ),
            "required-count": lambda value: value.__setitem__(
                "required_positive_attempts",
                2,
            ),
            "plan-order": lambda value: value["plan"].__setitem__(
                slice(0, 2),
                list(reversed(value["plan"][0:2])),
            ),
        }
        for name, mutate in mutations.items():
            mapping = json.loads(json.dumps(base))
            mutate(mapping)
            with self.subTest(name=name), self.assertRaises(ValueError):
                parse_rev_proof_evaluation_evidence(mapping)

    def test_exact_builtin_types_keys_and_cardinality_are_required(
        self,
    ) -> None:
        class EqualString(str):
            def __eq__(self, _other):
                return True

            __hash__ = str.__hash__

        class ExplodingIterable:
            consumed = False

            def __iter__(self):
                self.consumed = True
                raise AssertionError("must not consume")

        class ExplodingList(list):
            def __len__(self):
                raise AssertionError("must not inspect subclass")

            def __iter__(self):
                raise AssertionError("must not consume subclass")

        base = self.confirmed_mapping()
        cases: list[tuple[str, object]] = []

        extra = json.loads(json.dumps(base))
        extra["extra"] = None
        cases.append(("extra-key", extra))

        missing = json.loads(json.dumps(base))
        del missing["verdict"]
        cases.append(("missing-key", missing))

        tuple_plan = json.loads(json.dumps(base))
        tuple_plan["plan"] = tuple(tuple_plan["plan"])
        cases.append(("tuple-plan", tuple_plan))

        subclass_list = json.loads(json.dumps(base))
        explosive = ExplodingList(subclass_list["observations"])
        subclass_list["observations"] = explosive
        cases.append(("list-subclass", subclass_list))

        subclass_text = json.loads(json.dumps(base))
        subclass_text["candidate"] = EqualString(CANDIDATE)
        cases.append(("str-subclass", subclass_text))

        bool_integer = json.loads(json.dumps(base))
        bool_integer["schema_version"] = True
        cases.append(("bool-int", bool_integer))

        oversized_list = json.loads(json.dumps(base))
        oversized_list["observations"].append(
            oversized_list["observations"][-1]
        )
        cases.append(("oversized-observations", oversized_list))

        non_mapping = ExplodingIterable()
        cases.append(("arbitrary-iterator", non_mapping))

        for name, value in cases:
            with self.subTest(name=name), self.assertRaises(ValueError):
                parse_rev_proof_evaluation_evidence(value)
        self.assertFalse(non_mapping.consumed)

    def test_huge_values_are_rejected_without_entering_canonical_record(
        self,
    ) -> None:
        marker = "PERSISTED-EVIDENCE-HUGE-" + (
            "x" * (REV_STDIN_PROOF_MAX_EVIDENCE_BYTES + 1)
        )
        cases = []
        huge_candidate = self.confirmed_mapping()
        huge_candidate["candidate"] = marker
        cases.append(huge_candidate)

        huge_flag = self.confirmed_mapping()
        huge_flag["observations"][0]["flag_values"] = [marker]
        cases.append(huge_flag)

        huge_integer = self.confirmed_mapping()
        huge_integer["observations"][0]["input_size_bytes"] = 10**1000
        cases.append(huge_integer)

        for mapping in cases:
            with self.assertRaises(ValueError) as caught:
                parse_rev_proof_evaluation_evidence(mapping)
            self.assertNotIn(marker, str(caught.exception))

    def test_run_artifact_and_failure_identifiers_are_unique_and_known(
        self,
    ) -> None:
        base = self.confirmed_mapping()
        duplicate_run = json.loads(json.dumps(base))
        duplicate_run["observations"][5]["run_id"] = (
            duplicate_run["observations"][0]["run_id"]
        )
        duplicate_artifact = json.loads(json.dumps(base))
        duplicate_artifact["observations"][5]["stderr"]["artifact_id"] = (
            duplicate_artifact["observations"][0]["stdout"][
                "artifact_id"
            ]
        )

        _, failed_evaluation = evaluate_rev_stdin_proof(
            CANDIDATE,
            ACCEPTED_INPUT,
            MANIFEST,
            (
                replace(
                    valid_observations()[0],
                    target_exit_code=125,
                    runner_exit_code=125,
                    ctfwrap_exit_code=125,
                ),
                *valid_observations()[1:],
            ),
        )
        unknown_failure = json.loads(
            failed_evaluation.canonical_bytes()
        )
        unknown_failure["failures"][0]["code"] = "unknown"
        unknown_failure["failure_codes"][0] = "unknown"

        for mapping in (
            duplicate_run,
            duplicate_artifact,
            unknown_failure,
        ):
            with self.assertRaises(ValueError):
                parse_rev_proof_evaluation_evidence(mapping)

        failed_mapping = json.loads(
            failed_evaluation.canonical_bytes()
        )
        failed_record = verify_rev_proof_evaluation(
            failed_mapping,
            accepted_input=ACCEPTED_INPUT,
        )
        self.assertFalse(failed_record.passed)
        self.assertTrue(failed_record.transport_inconclusive)

    def test_canonical_duplicate_run_and_artifact_failures_round_trip(
        self,
    ) -> None:
        base = valid_observations()
        duplicate_run_observations = list(base)
        duplicate_run_observations[5] = replace(
            duplicate_run_observations[5],
            run_id=duplicate_run_observations[0].run_id,
        )
        duplicate_artifact_observations = list(base)
        duplicate_artifact_observations[5] = replace(
            duplicate_artifact_observations[5],
            stderr=replace(
                duplicate_artifact_observations[5].stderr,
                artifact_id=(
                    duplicate_artifact_observations[0]
                    .stdout.artifact_id
                ),
            ),
        )

        for expected_code, observations in (
            ("duplicate_run_id", duplicate_run_observations),
            (
                "durable_artifact_reused",
                duplicate_artifact_observations,
            ),
        ):
            with self.subTest(expected_code=expected_code):
                _, evaluation = evaluate_rev_stdin_proof(
                    CANDIDATE,
                    ACCEPTED_INPUT,
                    MANIFEST,
                    observations,
                )
                mapping = json.loads(evaluation.canonical_bytes())
                record = parse_rev_proof_evaluation_evidence(mapping)
                self.assertIn(expected_code, record.failure_codes)
                self.assertEqual(
                    verify_rev_proof_evaluation(
                        mapping,
                        accepted_input=ACCEPTED_INPUT,
                    ),
                    record,
                )

    def test_noncanonical_nested_shape_and_observation_binding_fail(
        self,
    ) -> None:
        base = self.confirmed_mapping()
        extra_stream_key = json.loads(json.dumps(base))
        extra_stream_key["observations"][0]["stdout"]["raw"] = "forbidden"

        wrong_phase = json.loads(json.dumps(base))
        wrong_phase["observations"][0]["phase"] = "other"

        wrong_binding = json.loads(json.dumps(base))
        wrong_binding["observations"][0]["input_sha256"] = "0" * 64

        for name, mapping, parser_only in (
            ("extra-stream-key", extra_stream_key, True),
            ("phase-vocabulary", wrong_phase, True),
            ("observation-binding", wrong_binding, False),
        ):
            with self.subTest(name=name), self.assertRaises(ValueError):
                if parser_only:
                    parse_rev_proof_evaluation_evidence(mapping)
                else:
                    verify_rev_proof_evaluation(
                        mapping,
                        accepted_input=ACCEPTED_INPUT,
                    )


if __name__ == "__main__":
    unittest.main()
