from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import replace

from ctf_os.engine.forensic_assertion_execution import (
    FORENSIC_ASSERTION_EXECUTION_PROTOCOL,
    FORENSIC_ASSERTION_OPERATOR_SPEC_PROTOCOL,
    ForensicAssertionExecutionPreflightError,
    ForensicCapturedArtifact,
    ForensicObservationIssue,
    ForensicToolObservationDocument,
    ForensicToolObservationTransport,
    ForensicToolReadiness,
    build_forensic_tool_observation_document,
    evaluate_forensic_assertion_execution,
    forensic_assertion_execution_plan_is_canonical,
    forensic_tool_readiness_registry_sha256,
    parse_forensic_assertion_operator_spec,
    plan_forensic_assertion_execution,
)
from ctf_os.engine.forensic_assertion_graph import (
    FORENSIC_ASSERTION_MIN_COVERAGE_PPM,
    ForensicAssertionNode,
    ForensicAssertionState,
    ForensicFileRangePointer,
    ForensicInodePointer,
    ForensicNormalizedTimestamp,
    ForensicPcapFramePointer,
    ForensicProcessPointer,
    ForensicTimestampPointer,
    build_forensic_assertion_graph_plan,
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


class ForensicAssertionExecutionTests(unittest.TestCase):
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
        packet_time = self._timestamp(
            "packet_capture",
            local_seconds=1_700_000_000,
            offset_minutes=540,
        )
        process_time = self._timestamp(
            "process_start",
            local_seconds=1_700_000_100,
            offset_minutes=0,
        )
        event_time = self._timestamp(
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
                timestamp=packet_time,
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
                process_start=process_time,
            ),
            ForensicTimestampPointer(
                pointer_id="PTR-time",
                source_path="events.log",
                source_sha256=_digest("source:events.log"),
                field_offset_bytes=500,
                field_length_bytes=24,
                field_sha256=_digest("event:timestamp"),
                timestamp=event_time,
            ),
        )
        pointer_ids = tuple(item.pointer_id for item in self.pointers)
        self.assertions = (
            ForensicAssertionNode(
                assertion_id="A-confirmed",
                state=ForensicAssertionState.CONFIRMED,
                claim_kind="timeline_event",
                claim_sha256=_digest("claim:confirmed"),
                depends_on=(),
                evidence_pointer_ids=tuple(sorted(pointer_ids)),
            ),
        )
        self.readiness = (
            self._readiness("alpha", "family-alpha", "a"),
            self._readiness("beta", "family-beta", "b"),
            self._readiness("gamma", "family-gamma", "c"),
        )
        self.graph_plan = build_forensic_assertion_graph_plan(
            index_execution=self.index_execution,
            expected_sources=self.sources,
            tools=tuple(item.tool_binding for item in self.readiness),
            pointers=self.pointers,
            assertions=self.assertions,
        )
        self.operator_document = {
            "assertions": [
                item.to_dict() for item in self.graph_plan.assertions
            ],
            "coverage_threshold_ppm": (
                FORENSIC_ASSERTION_MIN_COVERAGE_PPM
            ),
            "index_root": self.graph_plan.inventory_root.to_dict(),
            "pointers": [
                item.to_dict() for item in self.graph_plan.pointers
            ],
            "protocol": FORENSIC_ASSERTION_OPERATOR_SPEC_PROTOCOL,
            "readiness_registry_sha256": (
                forensic_tool_readiness_registry_sha256(self.readiness)
            ),
            "schema_version": 1,
            "source_catalog_sha256": (
                self.graph_plan.source_catalog_sha256
            ),
            "tools": [item.to_dict() for item in self.readiness],
        }
        self.operator_payload = _canonical(self.operator_document)
        self.specification = self._parse(self.operator_payload)
        request_count = len(self.pointers) * 2
        self.issues = tuple(
            ForensicObservationIssue(
                request_id=f"REQ-{ordinal}",
                run_id=f"RUN-{ordinal}",
                observation_id=f"OBS-{ordinal}",
                receipt_id=f"RCPT-{ordinal}",
                artifact_id=f"ART-{ordinal}",
                execution_nonce=bytes([ordinal]) * 32,
            )
            for ordinal in range(1, request_count + 1)
        )
        self.execution_plan = plan_forensic_assertion_execution(
            self.specification,
            self.issues,
        )
        self.transports = self._transports()

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

    @staticmethod
    def _readiness(
        tool_id: str,
        family: str,
        image_label: str,
    ) -> ForensicToolReadiness:
        return ForensicToolReadiness(
            tool_id=f"tool-{tool_id}",
            independence_family=family,
            tool_version_sha256=_digest(f"version:{tool_id}"),
            runtime_image_digest="sha256:" + image_label * 64,
            supported_pointer_kinds=(
                "file_range",
                "inode",
                "pcap_frame",
                "process",
                "timestamp",
            ),
            command_template=(
                f"/opt/ctf-tools/{tool_id}",
                "--request",
                "{request_path}",
                "--observation",
                "{observation_path}",
                "--artifact",
                "{artifact_path}",
            ),
            readiness_generation=7,
            readiness_artifact_id=f"READY-{tool_id}",
            readiness_artifact_sha256=_digest(
                f"readiness:{tool_id}"
            ),
            readiness_artifact_size_bytes=512,
        )

    def _parse(
        self,
        payload: bytes,
        *,
        index_execution=None,
        sources=None,
        readiness=None,
    ):
        return parse_forensic_assertion_operator_spec(
            payload,
            current_index_execution=(
                self.index_execution
                if index_execution is None
                else index_execution
            ),
            current_sources=self.sources if sources is None else sources,
            current_readiness=(
                self.readiness if readiness is None else readiness
            ),
        )

    def _transports(self, *, payload_prefix: bytes = b"observed"):
        result = []
        for position, request in enumerate(
            self.execution_plan.requests,
            start=1,
        ):
            artifact_payload = (
                payload_prefix
                + b":"
                + str(position).encode("ascii")
                + b":"
                + request.pointer_id.encode("ascii")
            )
            document = build_forensic_tool_observation_document(
                request,
                artifact_payload,
            )
            result.append(
                ForensicToolObservationTransport(
                    request_path=request.request_path,
                    request_payload=request.canonical_bytes,
                    observation_path=request.observation_path,
                    observation_payload=document.canonical_bytes,
                    artifact=ForensicCapturedArtifact(
                        artifact_id=request.artifact_id,
                        path=request.artifact_path,
                        payload=artifact_payload,
                    ),
                )
            )
        return tuple(result)

    def _evaluate(self, transports=None, **bindings):
        return evaluate_forensic_assertion_execution(
            self.execution_plan,
            self.transports if transports is None else transports,
            operator_spec_payload=bindings.get(
                "operator_spec_payload",
                self.operator_payload,
            ),
            current_index_execution=bindings.get(
                "current_index_execution",
                self.index_execution,
            ),
            current_sources=bindings.get(
                "current_sources",
                self.sources,
            ),
            current_readiness=bindings.get(
                "current_readiness",
                self.readiness,
            ),
        )

    def _mutated_operator(self, mutate) -> bytes:
        document = json.loads(self.operator_payload)
        mutate(document)
        return _canonical(document)

    @staticmethod
    def _mutated_observation(transport, mutate):
        document = json.loads(transport.observation_payload)
        mutate(document)
        return replace(
            transport,
            observation_payload=_canonical(document),
        )

    def test_clean_preissued_wave_confirms_only_fact_and_progress(
        self,
    ) -> None:
        evaluation = self._evaluate()

        self.assertTrue(evaluation.confirmed)
        self.assertEqual(len(evaluation.records), 10)
        self.assertEqual(
            len(evaluation.semantic_evaluation.corroboration_records),
            10,
        )
        self.assertEqual(
            evaluation.to_dict()["protocol"],
            FORENSIC_ASSERTION_EXECUTION_PROTOCOL,
        )
        authorities = evaluation.to_dict()["authorities"]
        self.assertTrue(
            authorities["executed_forensic_assertion_fact_authorized"]
        )
        self.assertTrue(authorities["progress_marker_authorized"])
        self.assertFalse(authorities["candidate_authorized"])
        self.assertFalse(authorities["flag_proven"])
        self.assertFalse(authorities["impact_proven"])
        projection = evaluation.reduction_projection()
        self.assertIsNotNone(projection["executed_fact"])
        self.assertIsNotNone(projection["progress"])
        self.assertIsNone(projection["candidate"])
        self.assertIsNone(projection["proof"])
        self.assertFalse(projection["automatic_submission"])

    def test_plan_uses_exactly_two_of_three_ready_families_per_pointer(
        self,
    ) -> None:
        requests = self.execution_plan.requests
        by_pointer: dict[str, set[str]] = {}
        for request in requests:
            by_pointer.setdefault(request.pointer_id, set()).add(
                request.independence_family
            )
            pointer_document = request.to_dict()["pointer"]
            self.assertEqual(
                pointer_document["source_path"],
                request.pointer.source_path,
            )
            self.assertEqual(
                pointer_document["source_sha256"],
                request.pointer.source_sha256,
            )
            self.assertIn("read_only", request.canonical_bytes.decode())
            self.assertIn('"network":"none"', request.canonical_bytes.decode())
        self.assertEqual(set(by_pointer), {
            item.pointer_id for item in self.pointers
        })
        self.assertTrue(
            all(
                families == {"family-alpha", "family-beta"}
                for families in by_pointer.values()
            )
        )

    def test_raw_output_is_hashed_but_never_serialized_or_authoritative(
        self,
    ) -> None:
        marker = b"FLAG{raw-tool-output-is-not-proof}"
        transports = self._transports(payload_prefix=marker)
        evaluation = self._evaluate(transports)

        self.assertTrue(evaluation.confirmed)
        self.assertNotIn(marker, evaluation.canonical_bytes)
        self.assertNotIn(marker, self.execution_plan.canonical_bytes)
        self.assertNotIn(marker, transports[0].observation_payload)

    def test_operator_spec_rejects_raw_claim_or_output_injection(
        self,
    ) -> None:
        for key in ("claim", "raw_output", "flag_candidate"):
            with self.subTest(key=key):
                payload = self._mutated_operator(
                    lambda doc, selected=key: doc.__setitem__(
                        selected,
                        "FLAG{not-authority}",
                    )
                )
                with self.assertRaises(
                    ForensicAssertionExecutionPreflightError
                ):
                    self._parse(payload)

    def test_operator_spec_requires_canonical_unique_json(self) -> None:
        noncanonical = json.dumps(
            self.operator_document,
            indent=2,
            sort_keys=False,
        ).encode("ascii")
        with self.assertRaises(ForensicAssertionExecutionPreflightError):
            self._parse(noncanonical)
        duplicate = (
            b'{"protocol":"a","protocol":"b","schema_version":1}'
        )
        with self.assertRaises(ForensicAssertionExecutionPreflightError):
            self._parse(duplicate)

    def test_bool_is_not_an_integer_in_pointer_or_policy(self) -> None:
        payloads = (
            self._mutated_operator(
                lambda doc: doc.__setitem__(
                    "coverage_threshold_ppm",
                    True,
                )
            ),
            self._mutated_operator(
                lambda doc: doc["pointers"][0].__setitem__(
                    "offset_bytes",
                    True,
                )
            ),
        )
        for payload in payloads:
            with self.subTest(payload=payload[:60]):
                with self.assertRaises(
                    ForensicAssertionExecutionPreflightError
                ):
                    self._parse(payload)

    def test_duplicate_or_orphan_assertion_graph_entries_fail_closed(
        self,
    ) -> None:
        duplicate = self._mutated_operator(
            lambda doc: doc["assertions"].append(
                dict(doc["assertions"][0])
            )
        )
        orphan = self._mutated_operator(
            lambda doc: doc["assertions"][0].__setitem__(
                "depends_on",
                ["A-missing"],
            )
        )
        duplicate_pointer = self._mutated_operator(
            lambda doc: doc["pointers"][1].__setitem__(
                "pointer_id",
                doc["pointers"][0]["pointer_id"],
            )
        )
        for payload in (duplicate, orphan, duplicate_pointer):
            with self.subTest(payload=payload[:80]):
                with self.assertRaises(
                    ForensicAssertionExecutionPreflightError
                ):
                    self._parse(payload)

    def test_all_typed_pointer_boundaries_and_timezone_are_enforced(
        self,
    ) -> None:
        mutations = (
            lambda doc: doc["pointers"][0].__setitem__(
                "source_path",
                "missing.bin",
            ),
            lambda doc: doc["pointers"][0].__setitem__(
                "length_bytes",
                99_999,
            ),
            lambda doc: doc["pointers"][1].__setitem__(
                "inode_number",
                0,
            ),
            lambda doc: doc["pointers"][2].__setitem__(
                "frame_number",
                0,
            ),
            lambda doc: doc["pointers"][3].__setitem__("pid", 0),
            lambda doc: doc["pointers"][4]["timestamp"].__setitem__(
                "normalized_timezone",
                "Asia/Seoul",
            ),
            lambda doc: doc["pointers"][4]["timestamp"].__setitem__(
                "normalized_utc_epoch_ns",
                1,
            ),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaises(
                    ForensicAssertionExecutionPreflightError
                ):
                    self._parse(self._mutated_operator(mutation))

    def test_operator_cannot_omit_or_spoof_ready_tool_family(
        self,
    ) -> None:
        omit = self._mutated_operator(lambda doc: doc["tools"].pop())
        spoof = self._mutated_operator(
            lambda doc: doc["tools"][0].__setitem__(
                "independence_family",
                "forged-family",
            )
        )
        command_rebind = self._mutated_operator(
            lambda doc: doc["tools"][0]["command_template"].__setitem__(
                0,
                "/opt/ctf-tools/evil",
            )
        )
        for payload in (omit, spoof, command_rebind):
            with self.subTest(payload=payload[-100:]):
                with self.assertRaises(
                    ForensicAssertionExecutionPreflightError
                ):
                    self._parse(payload)

    def test_engine_readiness_rejects_shell_or_missing_placeholders(
        self,
    ) -> None:
        bad_values = (
            replace(
                self.readiness[0],
                command_template=(
                    "/bin/sh",
                    "-c",
                    "id;uname",
                    "{request_path}",
                    "{observation_path}",
                    "{artifact_path}",
                ),
            ),
            replace(
                self.readiness[0],
                command_template=(
                    "/usr/bin/python3",
                    "-c",
                    "print",
                    "{request_path}",
                    "{observation_path}",
                    "{artifact_path}",
                ),
            ),
            replace(
                self.readiness[0],
                command_template=(
                    "/opt/ctf-tools/alpha",
                    "--request",
                    "{request_path}",
                    "--artifact",
                    "{artifact_path}",
                ),
            ),
        )
        for bad in bad_values:
            with self.subTest(template=bad.command_template):
                with self.assertRaises(
                    ForensicAssertionExecutionPreflightError
                ):
                    forensic_tool_readiness_registry_sha256(
                        (bad, *self.readiness[1:])
                    )

    def test_preissue_rejects_nonce_and_identifier_collisions(
        self,
    ) -> None:
        duplicate_artifact = list(self.issues)
        duplicate_artifact[1] = replace(
            duplicate_artifact[1],
            artifact_id=duplicate_artifact[0].artifact_id,
        )
        duplicate_nonce = list(self.issues)
        duplicate_nonce[1] = replace(
            duplicate_nonce[1],
            execution_nonce=duplicate_nonce[0].execution_nonce,
        )
        index_collision = list(self.issues)
        index_collision[0] = replace(
            index_collision[0],
            artifact_id="ART-index",
        )
        for issues in (
            tuple(duplicate_artifact),
            tuple(duplicate_nonce),
            tuple(index_collision),
        ):
            with self.subTest(first=issues[0]):
                with self.assertRaises(
                    ForensicAssertionExecutionPreflightError
                ):
                    plan_forensic_assertion_execution(
                        self.specification,
                        issues,
                    )

    def test_preissued_plan_tamper_is_detected(self) -> None:
        requests = list(self.execution_plan.requests)
        requests[0] = replace(
            requests[0],
            pointer_id=requests[2].pointer_id,
        )
        forged = replace(
            self.execution_plan,
            requests=tuple(requests),
        )
        self.assertFalse(
            forensic_assertion_execution_plan_is_canonical(forged)
        )
        evaluation = evaluate_forensic_assertion_execution(
            forged,
            self.transports,
            operator_spec_payload=self.operator_payload,
            current_index_execution=self.index_execution,
            current_sources=self.sources,
            current_readiness=self.readiness,
        )
        self.assertFalse(evaluation.confirmed)
        self.assertEqual(evaluation.reason_codes, ("execution_plan_invalid",))

    def test_subset_reordering_and_posthoc_request_rebind_fail(
        self,
    ) -> None:
        subset = self.transports[:-1]
        reordered = (
            self.transports[1],
            self.transports[0],
            *self.transports[2:],
        )
        rebound = list(self.transports)
        rebound[0] = replace(
            rebound[0],
            request_payload=self.execution_plan.requests[
                1
            ].canonical_bytes,
        )
        for transports in (subset, reordered, tuple(rebound)):
            with self.subTest(count=len(transports)):
                self.assertFalse(self._evaluate(transports).confirmed)

    def test_observation_path_document_and_artifact_hash_are_exact(
        self,
    ) -> None:
        bad_path = list(self.transports)
        bad_path[0] = replace(
            bad_path[0],
            observation_path="artifacts/other.json",
        )
        bad_artifact_path = list(self.transports)
        bad_artifact_path[0] = replace(
            bad_artifact_path[0],
            artifact=replace(
                bad_artifact_path[0].artifact,
                path="artifacts/other.bin",
            ),
        )
        bad_artifact_bytes = list(self.transports)
        bad_artifact_bytes[0] = replace(
            bad_artifact_bytes[0],
            artifact=replace(
                bad_artifact_bytes[0].artifact,
                payload=b"changed-after-receipt",
            ),
        )
        for transports in (
            tuple(bad_path),
            tuple(bad_artifact_path),
            tuple(bad_artifact_bytes),
        ):
            with self.subTest(first=transports[0]):
                self.assertFalse(self._evaluate(transports).confirmed)

    def test_observation_document_rejects_raw_claim_injection(
        self,
    ) -> None:
        transports = list(self.transports)
        transports[0] = self._mutated_observation(
            transports[0],
            lambda doc: doc.__setitem__(
                "raw_claim",
                "the suspect executed malware",
            ),
        )
        evaluation = self._evaluate(tuple(transports))
        self.assertFalse(evaluation.confirmed)
        self.assertIn(
            "observation_document_invalid",
            evaluation.reason_codes[0],
        )

    def test_observation_tool_family_and_request_rebinding_fail(
        self,
    ) -> None:
        family = list(self.transports)
        family[0] = self._mutated_observation(
            family[0],
            lambda doc: doc.__setitem__(
                "independence_family",
                "forged-family",
            ),
        )
        request = list(self.transports)
        request[0] = self._mutated_observation(
            request[0],
            lambda doc: doc.__setitem__("request_id", "REQ-forged"),
        )
        for transports in (tuple(family), tuple(request)):
            with self.subTest(first=transports[0]):
                evaluation = self._evaluate(transports)
                self.assertFalse(evaluation.confirmed)
                self.assertIn(
                    "observation_request_binding_mismatch",
                    evaluation.reason_codes[0],
                )

    def test_observation_bool_int_and_unsafe_transport_fail_closed(
        self,
    ) -> None:
        bool_int = list(self.transports)
        bool_int[0] = self._mutated_observation(
            bool_int[0],
            lambda doc: doc["transport"].__setitem__(
                "network_disabled",
                1,
            ),
        )
        unsafe = list(self.transports)
        request = self.execution_plan.requests[0]
        payload = unsafe[0].artifact.payload
        document = build_forensic_tool_observation_document(
            request,
            payload,
            evidence_read_only=False,
        )
        unsafe[0] = replace(
            unsafe[0],
            observation_payload=document.canonical_bytes,
        )
        for transports in (tuple(bool_int), tuple(unsafe)):
            with self.subTest(first=transports[0]):
                self.assertFalse(self._evaluate(transports).confirmed)

    def test_current_index_readiness_or_operator_rebind_fails(
        self,
    ) -> None:
        assert self.index_execution.envelope is not None
        changed_index = replace(
            self.index_execution,
            envelope=replace(
                self.index_execution.envelope,
                source_manifest_sha256=_digest("new-source-manifest"),
            ),
        )
        changed_readiness = (
            replace(
                self.readiness[0],
                readiness_generation=8,
            ),
            *self.readiness[1:],
        )
        changed_operator = self._mutated_operator(
            lambda doc: doc["assertions"][0].__setitem__(
                "claim_sha256",
                _digest("different-claim"),
            )
        )
        evaluations = (
            self._evaluate(current_index_execution=changed_index),
            self._evaluate(current_readiness=changed_readiness),
            self._evaluate(operator_spec_payload=changed_operator),
        )
        for evaluation in evaluations:
            with self.subTest(reason=evaluation.reason_codes):
                self.assertFalse(evaluation.confirmed)
                self.assertIn(
                    evaluation.reason_codes[0],
                    {
                        (
                            "current_binding_or_operator_spec_"
                            "revalidation_failed"
                        ),
                        "operator_spec_or_current_binding_rebound",
                    },
                )

    def test_one_family_fallback_is_explicitly_allowed_only_when_current(
        self,
    ) -> None:
        readiness = self.readiness[:1]
        graph_plan = build_forensic_assertion_graph_plan(
            index_execution=self.index_execution,
            expected_sources=self.sources,
            tools=(readiness[0].tool_binding,),
            pointers=self.pointers,
            assertions=self.assertions,
        )
        document = {
            **self.operator_document,
            "index_root": graph_plan.inventory_root.to_dict(),
            "readiness_registry_sha256": (
                forensic_tool_readiness_registry_sha256(readiness)
            ),
            "source_catalog_sha256": graph_plan.source_catalog_sha256,
            "tools": [readiness[0].to_dict()],
        }
        specification = self._parse(
            _canonical(document),
            readiness=readiness,
        )
        issues = self.issues[: len(self.pointers)]
        plan = plan_forensic_assertion_execution(specification, issues)
        self.assertEqual(len(plan.requests), len(self.pointers))
        self.assertTrue(
            all(
                request.independence_family == "family-alpha"
                for request in plan.requests
            )
        )

    def test_observation_document_round_trip_is_strict_and_value_free(
        self,
    ) -> None:
        request = self.execution_plan.requests[0]
        payload = b"\x00binary\xffoutput"
        document = build_forensic_tool_observation_document(
            request,
            payload,
        )
        parsed = ForensicToolObservationDocument.from_payload(
            document.canonical_bytes
        )
        self.assertEqual(parsed, document)
        self.assertEqual(parsed.sha256, _digest_bytes(document.canonical_bytes))
        self.assertNotIn(payload, document.canonical_bytes)


def _digest_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


if __name__ == "__main__":
    unittest.main()
