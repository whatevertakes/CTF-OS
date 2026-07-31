from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import replace

from ctf_os.engine.forensic_assertion_graph import (
    FORENSIC_ASSERTION_MIN_COVERAGE_PPM,
    ForensicAssertionNode,
    ForensicAssertionPreflightError,
    ForensicAssertionState,
    ForensicAssertionVerdict,
    ForensicCorroborationObservation,
    ForensicFileRangePointer,
    ForensicInodePointer,
    ForensicNormalizedTimestamp,
    ForensicObservationArtifact,
    ForensicPcapFramePointer,
    ForensicProcessPointer,
    ForensicTimestampPointer,
    ForensicToolBinding,
    build_forensic_assertion_graph_plan,
    evaluate_forensic_assertion_graph,
    forensic_corroboration_execution_contract_sha256,
)
from ctf_os.engine.forensic_index import (
    ForensicIndexEvaluation,
    ForensicIndexVerdict,
    ForensicSourceExpectation,
)
from ctf_os.engine.forensic_index_execution import (
    ForensicIndexExecutionEnvelope,
    ForensicIndexExecutionEvaluation,
    ForensicIndexExecutionVerdict,
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


class ForensicAssertionGraphTests(unittest.TestCase):
    def setUp(self) -> None:
        source_specs = (
            ("archive.bin", 10_000),
            ("capture.pcap", 12_000),
            ("disk.img", 30_000),
            ("events.log", 8_000),
            ("memory.raw", 20_000),
        )
        self.sources = tuple(
            ForensicSourceExpectation(
                path=path,
                sha256=_digest("source:" + path),
                size_bytes=size,
                prefix_sha256=_digest("prefix:" + path),
                prefix_size_bytes=min(size, 4096),
            )
            for path, size in source_specs
        )
        self.index_execution = self._index_execution(self.sources)
        self.timestamp_packet = self._timestamp(
            "packet_capture",
            local_seconds=1_700_000_000,
            offset_minutes=540,
        )
        self.timestamp_process = self._timestamp(
            "process_start",
            local_seconds=1_700_000_100,
            offset_minutes=0,
        )
        self.timestamp_event = self._timestamp(
            "event_created",
            local_seconds=1_700_000_200,
            offset_minutes=-300,
        )
        self.pointers = (
            ForensicFileRangePointer(
                pointer_id="PTR-file",
                source_path="archive.bin",
                source_sha256=_digest("source:archive.bin"),
                offset_bytes=100,
                length_bytes=32,
            ),
            ForensicInodePointer(
                pointer_id="PTR-inode",
                source_path="disk.img",
                source_sha256=_digest("source:disk.img"),
                partition_offset_bytes=0,
                inode_number=128,
                metadata_offset_bytes=400,
                metadata_length_bytes=64,
                metadata_sha256=_digest("inode:128"),
            ),
            ForensicPcapFramePointer(
                pointer_id="PTR-pcap",
                source_path="capture.pcap",
                source_sha256=_digest("source:capture.pcap"),
                frame_number=7,
                packet_offset_bytes=200,
                captured_length_bytes=96,
                original_length_bytes=128,
                packet_sha256=_digest("pcap:frame:7"),
                timestamp=self.timestamp_packet,
            ),
            ForensicProcessPointer(
                pointer_id="PTR-process",
                source_path="memory.raw",
                source_sha256=_digest("source:memory.raw"),
                pid=4242,
                virtual_address=0x7F001000,
                object_offset_bytes=300,
                object_length_bytes=128,
                object_sha256=_digest("process:4242"),
                process_start=self.timestamp_process,
            ),
            ForensicTimestampPointer(
                pointer_id="PTR-time",
                source_path="events.log",
                source_sha256=_digest("source:events.log"),
                field_offset_bytes=500,
                field_length_bytes=24,
                field_sha256=_digest("event:timestamp"),
                timestamp=self.timestamp_event,
            ),
        )
        self.tools = (
            ForensicToolBinding(
                tool_id="tool-alpha",
                independence_family="parser-alpha",
                tool_version_sha256=_digest("tool-alpha-version"),
                runtime_image_digest="sha256:" + "a" * 64,
                supported_pointer_kinds=(
                    "file_range",
                    "inode",
                    "pcap_frame",
                    "process",
                    "timestamp",
                ),
            ),
            ForensicToolBinding(
                tool_id="tool-beta",
                independence_family="parser-beta",
                tool_version_sha256=_digest("tool-beta-version"),
                runtime_image_digest="sha256:" + "b" * 64,
                supported_pointer_kinds=(
                    "file_range",
                    "inode",
                    "pcap_frame",
                    "process",
                    "timestamp",
                ),
            ),
        )
        pointer_ids = tuple(sorted(item.pointer_id for item in self.pointers))
        self.assertions = (
            ForensicAssertionNode(
                assertion_id="A-confirmed",
                state=ForensicAssertionState.CONFIRMED,
                claim_kind="timeline_event",
                claim_sha256=_digest("confirmed-claim"),
                depends_on=(),
                evidence_pointer_ids=pointer_ids,
            ),
            ForensicAssertionNode(
                assertion_id="A-hypothesis",
                state=ForensicAssertionState.HYPOTHESIS,
                claim_kind="causal_link",
                claim_sha256=_digest("hypothesis-claim"),
                depends_on=("A-confirmed",),
                evidence_pointer_ids=("PTR-file",),
            ),
        )
        self.plan = self._plan()

    @staticmethod
    def _timestamp(
        kind: str,
        *,
        local_seconds: int,
        offset_minutes: int,
    ) -> ForensicNormalizedTimestamp:
        local_ns = local_seconds * 1_000_000_000
        normalized_ns = (
            local_ns - offset_minutes * 60 * 1_000_000_000
        )
        return ForensicNormalizedTimestamp(
            timestamp_kind=kind,
            source_local_epoch_ns=local_ns,
            source_utc_offset_minutes=offset_minutes,
            normalized_utc_epoch_ns=normalized_ns,
            precision_ns=1_000_000_000,
        )

    @staticmethod
    def _index_execution(
        sources: tuple[ForensicSourceExpectation, ...],
    ) -> ForensicIndexExecutionEvaluation:
        inventory_sha256 = hashlib.sha256(
            _canonical([item.commitment() for item in sources])
        ).hexdigest()
        total_bytes = sum(item.size_bytes for item in sources)
        semantic = ForensicIndexEvaluation(
            verdict=ForensicIndexVerdict.CONFIRMED,
            reason_code="complete_hash_bound_index",
            source_inventory_sha256=inventory_sha256,
            tree_sha256=_digest("tree"),
            index_sha256=_digest("index"),
            indexed_files=len(sources),
            indexed_bytes=total_bytes,
            pointer_coverage_ppm=1_000_000,
            modality_counts=(("disk", 1), ("log", 1)),
        )
        envelope = ForensicIndexExecutionEnvelope(
            category="forensics",
            contest_id="contest",
            challenge_id="challenge",
            configuration_epoch=3,
            experiment_id="EXP-index",
            run_id="RUN-index",
            run_origin="managed_tool",
            request_path="runs/RUN-index/request.json",
            request_sha256=_digest("index-request"),
            request_size_bytes=1000,
            result_path="runs/RUN-index/result.json",
            validation_path="runs/RUN-index/validation.json",
            receipt_id="RCPT-index",
            image_name="ctf-forensics",
            image_digest="sha256:" + "9" * 64,
            source_manifest_sha256=_digest("source-manifest"),
            source_inventory_sha256=inventory_sha256,
            source_file_count=len(sources),
            source_total_bytes=total_bytes,
            prefix_coverage_ppm=1_000_000,
            stdout_artifact_id="ART-index",
            stdout_artifact_path="artifacts/index.json",
            stdout_artifact_sha256=_digest("index-artifact"),
            stdout_artifact_size_bytes=4096,
        )
        return ForensicIndexExecutionEvaluation(
            verdict=ForensicIndexExecutionVerdict.CONFIRMED,
            reason_code="complete_executed_evidence_index",
            envelope=envelope,
            semantic_evaluation=semantic,
        )

    def _plan(
        self,
        *,
        index_execution=None,
        sources=None,
        tools=None,
        pointers=None,
        assertions=None,
        threshold=FORENSIC_ASSERTION_MIN_COVERAGE_PPM,
    ):
        return build_forensic_assertion_graph_plan(
            index_execution=(
                self.index_execution
                if index_execution is None
                else index_execution
            ),
            expected_sources=self.sources if sources is None else sources,
            tools=self.tools if tools is None else tools,
            pointers=self.pointers if pointers is None else pointers,
            assertions=(
                self.assertions if assertions is None else assertions
            ),
            coverage_threshold_ppm=threshold,
        )

    def _observation(
        self,
        plan,
        pointer_id: str,
        tool_id: str,
        *,
        suffix: str = "",
    ) -> ForensicCorroborationObservation:
        tool = next(item for item in plan.tools if item.tool_id == tool_id)
        label = f"{pointer_id}:{tool_id}:{suffix}"
        nonce = _digest("nonce:" + label)
        return ForensicCorroborationObservation(
            observation_id=f"OBS-{pointer_id}-{tool_id}{suffix}",
            pointer_id=pointer_id,
            tool_id=tool_id,
            run_id=f"RUN-{pointer_id}-{tool_id}{suffix}",
            receipt_id=f"RCPT-{pointer_id}-{tool_id}{suffix}",
            receipt_sha256=_digest("receipt:" + label),
            execution_nonce_sha256=nonce,
            execution_contract_sha256=(
                forensic_corroboration_execution_contract_sha256(
                    plan,
                    pointer_id=pointer_id,
                    tool_id=tool_id,
                    execution_nonce_sha256=nonce,
                )
            ),
            plan_sha256=plan.plan_sha256,
            source_manifest_sha256=(
                plan.inventory_root.source_manifest_sha256
            ),
            source_inventory_sha256=(
                plan.inventory_root.source_inventory_sha256
            ),
            runtime_image_digest=tool.runtime_image_digest,
            clean_workspace=True,
            network_disabled=True,
            orchestration_status="completed",
            exit_code=0,
            timed_out=False,
            capture_complete=True,
            truncation_known=True,
            truncated=False,
            capture_error=None,
            observation_artifact=ForensicObservationArtifact(
                artifact_id=f"ART-{pointer_id}-{tool_id}{suffix}",
                sha256=_digest("artifact:" + label),
                size_bytes=1024,
            ),
        )

    def _observations(
        self,
        plan=None,
        *,
        pointer_ids=None,
        tool_ids=None,
    ):
        selected = self.plan if plan is None else plan
        selected_pointers = (
            tuple(item.pointer_id for item in selected.pointers)
            if pointer_ids is None
            else tuple(pointer_ids)
        )
        selected_tools = (
            tuple(item.tool_id for item in selected.tools)
            if tool_ids is None
            else tuple(tool_ids)
        )
        return tuple(
            self._observation(selected, pointer_id, tool_id)
            for pointer_id in selected_pointers
            for tool_id in selected_tools
        )

    def test_confirmed_graph_authorizes_only_executed_fact_progress(
        self,
    ) -> None:
        evaluation = evaluate_forensic_assertion_graph(
            self.plan,
            self._observations(),
        )

        self.assertIs(
            evaluation.verdict,
            ForensicAssertionVerdict.CONFIRMED,
        )
        self.assertTrue(evaluation.passed)
        self.assertEqual(len(evaluation.corroboration_records), 10)
        confirmed, hypothesis = evaluation.coverage_records
        self.assertEqual(confirmed.coverage_ppm, 1_000_000)
        self.assertTrue(confirmed.confirmed_requirement_met)
        self.assertFalse(hypothesis.confirmed_requirement_met)
        authorities = evaluation.to_dict()["authorities"]
        self.assertTrue(
            authorities["executed_forensic_assertion_fact_authorized"]
        )
        for key in (
            "automatic_submission_authorized",
            "candidate_authorized",
            "challenge_proof_satisfied",
            "flag_proven",
            "impact_proven",
            "self_report_accepted",
            "status_transition_authorized",
        ):
            self.assertFalse(authorities[key])
        reduction = evaluation.reduction_projection()
        self.assertEqual(
            reduction["executed_fact"]["provenance"],
            "executed",
        )
        self.assertIsNone(reduction["candidate"])
        self.assertIsNone(reduction["impact"])
        self.assertIsNone(reduction["proof"])
        self.assertFalse(reduction["automatic_submission"])

    def test_threshold_allows_exact_four_of_five_covered(self) -> None:
        pointer_ids = tuple(
            item.pointer_id for item in self.plan.pointers[:4]
        )
        evaluation = evaluate_forensic_assertion_graph(
            self.plan,
            self._observations(pointer_ids=pointer_ids),
        )

        self.assertTrue(evaluation.passed)
        self.assertEqual(
            evaluation.coverage_records[0].coverage_ppm,
            800_000,
        )

    def test_threshold_rejects_three_of_five_covered(self) -> None:
        pointer_ids = tuple(
            item.pointer_id for item in self.plan.pointers[:3]
        )
        evaluation = evaluate_forensic_assertion_graph(
            self.plan,
            self._observations(pointer_ids=pointer_ids),
        )

        self.assertFalse(evaluation.passed)
        self.assertEqual(
            evaluation.coverage_records[0].coverage_ppm,
            600_000,
        )
        self.assertTrue(
            any(
                "coverage_or_corroboration_insufficient" in item
                for item in evaluation.failure_codes
            )
        )

    def test_two_independent_families_required_when_available(self) -> None:
        only_alpha = self._observations(tool_ids=("tool-alpha",))
        evaluation = evaluate_forensic_assertion_graph(
            self.plan,
            only_alpha,
        )

        self.assertFalse(evaluation.passed)
        self.assertEqual(
            evaluation.coverage_records[0].coverage_ppm,
            0,
        )

    def test_single_family_is_retained_but_never_confirms(self) -> None:
        plan = self._plan(tools=(self.tools[0],))
        evaluation = evaluate_forensic_assertion_graph(
            plan,
            self._observations(plan),
        )

        self.assertFalse(evaluation.passed)
        self.assertEqual(
            evaluation.coverage_records[0].coverage_ppm,
            0,
        )
        self.assertEqual(
            len(evaluation.corroboration_records),
            len(plan.pointers),
        )

    def test_distinct_families_cannot_share_one_tool_version(self) -> None:
        duplicate_version = replace(
            self.tools[1],
            tool_version_sha256=self.tools[0].tool_version_sha256,
        )
        plan = self._plan(
            tools=(self.tools[0], duplicate_version)
        )
        evaluation = evaluate_forensic_assertion_graph(
            plan,
            self._observations(plan),
        )

        self.assertFalse(evaluation.passed)
        self.assertTrue(
            any(
                "pointer_tool_version_reused" in item
                for item in evaluation.failure_codes
            )
        )

    def test_same_family_is_not_independent_corroboration(self) -> None:
        same_family = replace(
            self.tools[1],
            independence_family=self.tools[0].independence_family,
        )
        plan = self._plan(tools=(self.tools[0], same_family))
        observations = self._observations(plan)
        evaluation = evaluate_forensic_assertion_graph(
            plan,
            observations,
        )

        self.assertFalse(evaluation.passed)
        self.assertTrue(
            any(
                "pointer_tool_family_reused" in item
                for item in evaluation.failure_codes
            )
        )

    def test_each_typed_pointer_is_source_and_bounds_checked(self) -> None:
        invalid_values = (
            replace(
                self.pointers[0],
                offset_bytes=9_990,
                length_bytes=20,
            ),
            replace(
                self.pointers[1],
                metadata_offset_bytes=29_990,
                metadata_length_bytes=20,
            ),
            replace(
                self.pointers[2],
                packet_offset_bytes=11_990,
                captured_length_bytes=20,
            ),
            replace(
                self.pointers[3],
                object_offset_bytes=19_990,
                object_length_bytes=20,
            ),
            replace(
                self.pointers[4],
                field_offset_bytes=7_990,
                field_length_bytes=20,
            ),
        )
        for invalid in invalid_values:
            pointers = tuple(
                invalid if item.kind == invalid.kind else item
                for item in self.pointers
            )
            with self.subTest(kind=invalid.kind):
                with self.assertRaisesRegex(
                    ForensicAssertionPreflightError,
                    "pointer_schema_invalid",
                ):
                    self._plan(pointers=pointers)

    def test_overlapping_pointer_ranges_are_rejected(self) -> None:
        overlap = replace(
            self.pointers[0],
            pointer_id="PTR-file-overlap",
            offset_bytes=120,
            length_bytes=20,
        )
        with self.assertRaisesRegex(
            ForensicAssertionPreflightError,
            "pointer_overlap",
        ):
            self._plan(pointers=(*self.pointers, overlap))

    def test_timestamp_must_be_exactly_utc_normalized(self) -> None:
        bad_time = replace(
            self.timestamp_event,
            normalized_utc_epoch_ns=(
                self.timestamp_event.normalized_utc_epoch_ns + 1
            ),
        )
        bad_pointer = replace(self.pointers[4], timestamp=bad_time)
        pointers = (*self.pointers[:4], bad_pointer)

        with self.assertRaisesRegex(
            ForensicAssertionPreflightError,
            "pointer_schema_invalid",
        ):
            self._plan(pointers=pointers)

    def test_unknown_dependency_pointer_and_cycle_rejected(self) -> None:
        unknown_dependency = replace(
            self.assertions[1],
            depends_on=("A-missing",),
        )
        unknown_pointer = replace(
            self.assertions[1],
            evidence_pointer_ids=("PTR-missing",),
        )
        cycle_a = replace(
            self.assertions[0],
            state=ForensicAssertionState.HYPOTHESIS,
            depends_on=("A-hypothesis",),
        )
        cycle_b = replace(
            self.assertions[1],
            depends_on=("A-confirmed",),
        )
        cases = (
            (
                (self.assertions[0], unknown_dependency),
                "assertion_dependency_unknown",
            ),
            (
                (self.assertions[0], unknown_pointer),
                "assertion_pointer_unknown",
            ),
            ((cycle_a, cycle_b), "assertion_cycle"),
        )
        for assertions, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(
                    ForensicAssertionPreflightError,
                    reason,
                ):
                    self._plan(assertions=assertions)

    def test_confirmed_cannot_depend_on_hypothesis(self) -> None:
        hypothesis = replace(
            self.assertions[1],
            assertion_id="A-first-hypothesis",
            depends_on=(),
        )
        confirmed = replace(
            self.assertions[0],
            depends_on=(hypothesis.assertion_id,),
        )
        with self.assertRaisesRegex(
            ForensicAssertionPreflightError,
            "confirmed_depends_on_hypothesis",
        ):
            self._plan(assertions=(hypothesis, confirmed))

    def test_inventory_must_match_confirmed_index_execution(self) -> None:
        changed = replace(
            self.sources[0],
            prefix_sha256=_digest("changed-prefix"),
        )
        sources = (changed, *self.sources[1:])

        with self.assertRaisesRegex(
            ForensicAssertionPreflightError,
            "index_execution_inventory_mismatch",
        ):
            self._plan(sources=sources)

        rejected = replace(
            self.index_execution,
            verdict=ForensicIndexExecutionVerdict.REJECTED,
        )
        with self.assertRaisesRegex(
            ForensicAssertionPreflightError,
            "index_execution_not_confirmed",
        ):
            self._plan(index_execution=rejected)

    def test_execution_binding_and_transport_fail_closed(self) -> None:
        baseline = list(self._observations())
        mutations = (
            {"plan_sha256": _digest("foreign-plan")},
            {"source_manifest_sha256": _digest("stale-manifest")},
            {"source_inventory_sha256": _digest("stale-inventory")},
            {"runtime_image_digest": "sha256:" + "f" * 64},
            {"clean_workspace": False},
            {"network_disabled": False},
            {"truncated": True},
        )
        for mutation in mutations:
            observations = list(baseline)
            observations[0] = replace(observations[0], **mutation)
            evaluation = evaluate_forensic_assertion_graph(
                self.plan,
                observations,
            )
            with self.subTest(mutation=tuple(mutation)):
                self.assertFalse(evaluation.passed)
                self.assertTrue(
                    any(
                        "execution_binding_mismatch" in item
                        or "transport_invalid" in item
                        for item in evaluation.failure_codes
                    )
                )

    def test_receipts_nonces_runs_and_artifacts_must_be_unique(
        self,
    ) -> None:
        base = list(self._observations())
        mutations = (
            {"run_id": base[0].run_id},
            {"receipt_id": base[0].receipt_id},
            {"receipt_sha256": base[0].receipt_sha256},
            {"execution_nonce_sha256": base[0].execution_nonce_sha256},
            {"observation_artifact": base[0].observation_artifact},
        )
        for mutation in mutations:
            observations = list(base)
            observations[1] = replace(observations[1], **mutation)
            evaluation = evaluate_forensic_assertion_graph(
                self.plan,
                observations,
            )
            with self.subTest(mutation=tuple(mutation)):
                self.assertFalse(evaluation.passed)

    def test_raw_model_claim_is_rejected_and_never_echoed(self) -> None:
        observations = list(self._observations())
        observations[0] = {
            "status": "confirmed",
            "flag": "KCTF{not-evidence}",
            "self_reported_success": True,
        }
        evaluation = evaluate_forensic_assertion_graph(
            self.plan,
            observations,
        )

        self.assertFalse(evaluation.passed)
        encoded = json.dumps(
            evaluation.to_dict(),
            ensure_ascii=True,
            sort_keys=True,
        )
        self.assertNotIn("KCTF{not-evidence}", encoded)
        self.assertTrue(
            any(
                "observation_type_invalid" in item
                for item in evaluation.failure_codes
            )
        )

    def test_canonical_result_is_bounded_and_contains_no_raw_values(
        self,
    ) -> None:
        evaluation = evaluate_forensic_assertion_graph(
            self.plan,
            self._observations(),
        )
        encoded = evaluation.canonical_bytes.decode("ascii")

        self.assertLess(len(evaluation.canonical_bytes), 2 * 1024 * 1024)
        self.assertEqual(
            evaluation.sha256,
            hashlib.sha256(evaluation.canonical_bytes).hexdigest(),
        )
        for forbidden in (
            "Bearer secret-token",
            "session=administrator",
            "KCTF{candidate}",
            "raw packet payload",
        ):
            self.assertNotIn(forbidden, encoded)
        self.assertNotIn("claim_text", encoded)
        self.assertIn(_digest("confirmed-claim"), encoded)

    def test_manually_incomplete_coverage_projection_cannot_pass(self) -> None:
        evaluation = evaluate_forensic_assertion_graph(
            self.plan,
            self._observations(),
        )
        forged = replace(
            evaluation,
            coverage_records=evaluation.coverage_records[:1],
        )

        self.assertFalse(forged.passed)
        self.assertIsNone(
            forged.reduction_projection()["executed_fact"]
        )

    def test_bool_is_not_accepted_as_integer_pointer_offset(self) -> None:
        invalid = replace(self.pointers[0], offset_bytes=True)
        pointers = (invalid, *self.pointers[1:])
        with self.assertRaisesRegex(
            ForensicAssertionPreflightError,
            "pointer_schema_invalid",
        ):
            self._plan(pointers=pointers)

    def test_unhashable_schema_values_fail_closed_without_exception(
        self,
    ) -> None:
        invalid_assertion = replace(
            self.assertions[0],
            claim_sha256=[],
        )
        invalid_claim_kind = replace(
            self.assertions[0],
            claim_kind=[],
        )
        for invalid_node in (invalid_assertion, invalid_claim_kind):
            with self.assertRaisesRegex(
                ForensicAssertionPreflightError,
                "assertion_schema_invalid",
            ):
                self._plan(
                    assertions=(invalid_node, self.assertions[1])
                )

        invalid_tool = replace(self.tools[0], tool_id=[])
        invalid_kinds = replace(
            self.tools[0],
            supported_pointer_kinds=([],),
        )
        for invalid_binding in (invalid_tool, invalid_kinds):
            with self.assertRaisesRegex(
                ForensicAssertionPreflightError,
                "tool_registry_invalid",
            ):
                self._plan(tools=(invalid_binding, self.tools[1]))

        invalid_timestamp = replace(
            self.timestamp_event,
            timestamp_kind=[],
        )
        invalid_pointer = replace(
            self.pointers[4],
            timestamp=invalid_timestamp,
        )
        with self.assertRaisesRegex(
            ForensicAssertionPreflightError,
            "pointer_schema_invalid",
        ):
            self._plan(pointers=(*self.pointers[:4], invalid_pointer))

        observations = list(self._observations())
        observations[0] = replace(observations[0], pointer_id=[])
        evaluation = evaluate_forensic_assertion_graph(
            self.plan,
            observations,
        )
        self.assertFalse(evaluation.passed)
        self.assertTrue(
            any(
                "pointer_unknown" in item
                for item in evaluation.failure_codes
            )
        )


if __name__ == "__main__":
    unittest.main()
