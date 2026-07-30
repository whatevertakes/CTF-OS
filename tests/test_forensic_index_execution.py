from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from ctf_os.engine.forensic_index_execution import (
    FORENSIC_INDEX_EXPECTED_ARGV,
    ForensicIndexExecutionVerdict,
    evaluate_forensic_index_execution,
)
from ctf_os.models import (
    ArtifactReference,
    ChallengeIdentity,
    ExecutionReceipt,
    ReceiptOutcome,
    RunOrigin,
    RunReference,
    RunStatus,
    SourceFile,
)
from ctf_os.store.atomic import canonical_json_bytes


REPOSITORY = Path(__file__).resolve().parent.parent
PRODUCER_PATH = (
    REPOSITORY / "ctf-os-image/templates/forensic/evidence_index.py"
)
SPEC = importlib.util.spec_from_file_location(
    "forensic_index_producer_for_execution_test",
    PRODUCER_PATH,
)
assert SPEC is not None and SPEC.loader is not None
PRODUCER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PRODUCER
SPEC.loader.exec_module(PRODUCER)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _write_provenance(
    root: Path,
    metadata_path: Path,
    tree_path: Path,
) -> None:
    tree = bytearray()
    file_count = 0
    total_bytes = 0
    for path in sorted(
        root.rglob("*"),
        key=lambda item: os.fsencode(item.relative_to(root).as_posix()),
    ):
        relative = path.relative_to(root).as_posix().encode()
        mode = f"{stat.S_IMODE(path.stat().st_mode):o}".encode()
        if path.is_dir():
            tree.extend(b"D\0" + mode + b"\0" + relative + b"\0")
            continue
        payload = path.read_bytes()
        tree.extend(
            b"F\0"
            + mode
            + b"\0"
            + relative
            + b"\0"
            + _sha256(payload).encode()
            + b"\0"
        )
        file_count += 1
        total_bytes += len(payload)
    tree_path.parent.mkdir(parents=True, exist_ok=True)
    tree_path.write_bytes(tree)
    metadata_path.write_text(
        json.dumps(
            {
                "inventory": {
                    "algorithm": "sha256",
                    "file_count": file_count,
                    "total_bytes": total_bytes,
                },
                "schema_version": 1,
                "source": {
                    "mount_read_only": True,
                    "path": str(root),
                    "present": True,
                    "read_only_expected": True,
                    "writable_override_used": False,
                },
                "status": "initialized",
                "tree": {
                    "digest": _sha256(bytes(tree)),
                    "format": "ctf-tree-v1-nul",
                    "path": str(tree_path),
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )


class ForensicIndexExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        root = self.base / "challenge"
        root.mkdir()
        (root / "traffic.pcapng").write_bytes(
            b"\x0a\x0d\x0d\x0a" + b"packet"
        )
        nested = root / "nested"
        nested.mkdir()
        (nested / "case.evtx").write_bytes(b"ElfFile\0event")
        metadata = self.base / "work/.ctf/challenge.json"
        tree = self.base / "work/.ctf/challenge.tree"
        _write_provenance(root, metadata, tree)
        document = PRODUCER.build_evidence_index(root, tree, metadata)
        # Production invokes the producer through its /challenge mount.
        document["source"]["path"] = "/challenge"
        for record in document["records"]:
            relative = Path(record["pointer"]["path"]).relative_to(root)
            record["pointer"]["path"] = (
                "/challenge/" + relative.as_posix()
            )
        record_chain = hashlib.sha256()
        for record in document["records"]:
            record_chain.update(PRODUCER._canonical_json(record))
            record_chain.update(b"\n")
        document["index_sha256"] = record_chain.hexdigest()
        stdout = PRODUCER._canonical_json(document) + b"\n"

        sources = [
            SourceFile(
                path=path.relative_to(root).as_posix(),
                sha256=_sha256(path.read_bytes()),
                size=path.stat().st_size,
                kind="file",
            )
            for path in sorted(
                (item for item in root.rglob("*") if item.is_file()),
                key=lambda item: item.relative_to(root).as_posix().encode(),
            )
        ]
        prefixes = {
            item.path: (
                root / item.path
            ).read_bytes()[:4096]
            for item in sources
        }
        identity = ChallengeIdentity(
            contest_id="contest",
            category="forensics",
            challenge_id="case",
        )
        run_id = "RUN-forensic-index"
        experiment_id = "E-forensic-index"
        artifact = ArtifactReference(
            id="A-forensic-index-stdout",
            path="artifacts/snapshots/A-forensic-index-stdout.log",
            sha256=_sha256(stdout),
            source_run_id=run_id,
            media_type="application/json",
            size=len(stdout),
            extra={"stream": "stdout"},
        )
        source_binding = {
            "adapter_plan_sha256": "b" * 64,
            "manifest_sha256": "c" * 64,
            "path": sources[1].path,
            "schema_version": 1,
            "sha256": sources[1].sha256,
            "size_bytes": sources[1].size,
        }
        seed = {
            "adapter_name": "forensics",
            "adapter_seed": True,
            "adapter_seed_contract_version": 1,
            "adapter_seed_order": 0,
            "adapter_spec_id": "file_inventory@" + "a" * 64,
            "adapter_spec_sha256": "a" * 64,
            "adapter_spec_template_id": "file_inventory",
            "partial_oracle": None,
            "requires_explicit_execution": True,
            "source_binding": source_binding,
            "source_snapshot": None,
        }
        run = RunReference(
            id=run_id,
            base_revision=7,
            status=RunStatus.COMPLETED,
            request_path=f"runs/{run_id}/request.json",
            result_path=f"runs/{run_id}/result.json",
            validation_path=f"runs/{run_id}/validation.json",
            role="tool",
            origin=RunOrigin.MANAGED_TOOL,
            configuration_epoch=3,
            extra={
                "experiment_id": experiment_id,
                **copy.deepcopy(seed),
            },
        )
        stream_evidence = {
            "artifact_id": artifact.id,
            "binary_sample_omitted": False,
            "capture_complete": True,
            "capture_error_present": False,
            "coverage": "complete_stream",
            "drained_bytes": len(stdout),
            "head": {
                "byte_end": 0,
                "byte_start": 0,
                "encoding": "utf-8",
                "text": "",
                "text_truncated": False,
            },
            "limit_bytes": 16 * 1024 * 1024,
            "omitted_stored_bytes": len(stdout),
            "path": artifact.path,
            "redaction_count": 0,
            "sample_policy": "immutable_snapshot_head_tail",
            "schema_version": 1,
            "sha256": artifact.sha256,
            "stored_bytes": len(stdout),
            "stream": "stdout",
            "stream_error_present": False,
            "tail": None,
            "transport_summary_truncated": False,
            "truncated": False,
            "truncation_known": True,
        }
        receipt = ExecutionReceipt(
            id="RCPT-forensic-index",
            experiment_id=experiment_id,
            run_id=run_id,
            outcome=ReceiptOutcome.SUCCEEDED,
            exit_code=0,
            stdout_artifact_id=artifact.id,
            stdout_bytes=len(stdout),
            extra={
                "line_count_basis": "transport_summary_tail",
                "stream_evidence": {"stdout": stream_evidence},
            },
        )
        request = {
            **copy.deepcopy(seed),
            "argv": list(FORENSIC_INDEX_EXPECTED_ARGV),
            "base_revision": 7,
            "category": "forensics",
            "challenge_id": "case",
            "configuration_epoch": 3,
            "contest_id": "contest",
            "created_at": "2026-07-31T00:00:00Z",
            "experiment_id": experiment_id,
            "image": "ctf-os:local",
            "image_digest": "sha256:" + "d" * 64,
            "image_reference": "sha256:" + "d" * 64,
            "kind": "tool",
            "lease_id": "lease-forensic",
            "network_target": None,
            "network_target_generation": None,
            "network_target_id": None,
            "resource_class": "light",
            "resource_request": {
                "cpu": 1,
                "gpu": 0,
                "kvm": 0,
                "memory_mib": 512,
                "network": 0,
            },
            "run_id": run_id,
            "schema_version": 1,
        }
        self.document = document
        self.inputs = {
            "identity": identity,
            "configuration_epoch": 3,
            "expected_source_manifest_sha256": "c" * 64,
            "current_source_manifest_sha256": "c" * 64,
            "expected_source_inventory": sources,
            "current_source_inventory": copy.deepcopy(sources),
            "current_prefix_payloads": prefixes,
            "expected_image_name": "ctf-os:local",
            "expected_image_digest": "sha256:" + "d" * 64,
            "issued_request": request,
            "request_payload": canonical_json_bytes(request),
            "run": run,
            "receipt": receipt,
            "stdout_artifact": artifact,
            "stdout_payload": stdout,
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _evaluate(self, **changes: object):
        values = dict(self.inputs)
        values.update(changes)
        return evaluate_forensic_index_execution(**values)

    def test_complete_transport_authorizes_only_fact_and_progress(self) -> None:
        result = self._evaluate()

        self.assertIs(
            result.verdict,
            ForensicIndexExecutionVerdict.CONFIRMED,
        )
        self.assertTrue(result.confirmed)
        encoded = result.canonical_bytes.decode("ascii")
        self.assertNotIn("traffic.pcapng", encoded)
        self.assertNotIn("ElfFile", encoded)
        authorities = result.to_dict()["authorities"]
        self.assertTrue(
            authorities["executed_evidence_index_fact_authorized"]
        )
        self.assertTrue(authorities["progress_marker_authorized"])
        self.assertFalse(authorities["candidate_authorized"])
        self.assertFalse(authorities["challenge_proof_satisfied"])
        self.assertFalse(authorities["impact_proven"])
        self.assertFalse(authorities["automatic_submission_authorized"])

        reduction = result.reduction_projection()
        self.assertEqual(
            reduction["executed_fact"]["provenance"],
            "executed",
        )
        self.assertEqual(
            reduction["executed_fact"]["artifact_id"],
            self.inputs["stdout_artifact"].id,
        )
        self.assertIsNone(reduction["candidate"])
        self.assertIsNone(reduction["proof"])
        self.assertIsNone(reduction["impact"])
        self.assertFalse(reduction["automatic_submission"])

    def test_category_and_manifest_mismatches_fail_closed(self) -> None:
        wrong_identity = replace(
            self.inputs["identity"],
            category="pwn",
        )
        cases = (
            (
                {"identity": wrong_identity},
                "category_mismatch",
            ),
            (
                {"current_source_manifest_sha256": "e" * 64},
                "source_manifest_mismatch",
            ),
            (
                {"expected_source_manifest_sha256": "not-a-hash"},
                "source_manifest_mismatch",
            ),
        )
        for changes, reason in cases:
            with self.subTest(reason=reason):
                result = self._evaluate(**changes)
                self.assertFalse(result.confirmed)
                self.assertEqual(result.reason_code, reason)
                self.assertIsNone(
                    result.reduction_projection()["executed_fact"]
                )

    def test_current_inventory_and_independent_prefixes_are_exact(self) -> None:
        changed_inventory = copy.deepcopy(
            self.inputs["current_source_inventory"]
        )
        changed_inventory[0].sha256 = "f" * 64
        short_prefixes = dict(self.inputs["current_prefix_payloads"])
        first = next(iter(short_prefixes))
        short_prefixes[first] = short_prefixes[first][:-1]
        changed_prefixes = dict(self.inputs["current_prefix_payloads"])
        changed_prefixes[first] = b"X" * len(changed_prefixes[first])
        extra_prefixes = dict(self.inputs["current_prefix_payloads"])
        extra_prefixes["unindexed"] = b""
        for value in (
            {"current_source_inventory": changed_inventory},
            {"current_prefix_payloads": short_prefixes},
            {"current_prefix_payloads": changed_prefixes},
            {"current_prefix_payloads": extra_prefixes},
        ):
            with self.subTest(value=tuple(value)):
                result = self._evaluate(**value)
                self.assertEqual(
                    result.reason_code,
                    "source_inventory_or_prefix_mismatch",
                )

    def test_image_must_be_digest_pinned_and_request_bound(self) -> None:
        mutable = self._evaluate(expected_image_digest="ctf-os:latest")
        self.assertEqual(mutable.reason_code, "image_digest_invalid")

        request = copy.deepcopy(self.inputs["issued_request"])
        request["image_digest"] = "sha256:" + "e" * 64
        request["image_reference"] = request["image_digest"]
        result = self._evaluate(
            issued_request=request,
            request_payload=canonical_json_bytes(request),
        )
        self.assertEqual(result.reason_code, "image_digest_mismatch")

    def test_network_or_resource_request_cannot_be_enabled(self) -> None:
        for mutation in ("network", "target"):
            request = copy.deepcopy(self.inputs["issued_request"])
            if mutation == "network":
                request["resource_request"]["network"] = 1
            else:
                request["network_target"] = "https://example.invalid"
            with self.subTest(mutation=mutation):
                result = self._evaluate(
                    issued_request=request,
                    request_payload=canonical_json_bytes(request),
                )
                self.assertEqual(
                    result.reason_code,
                    "network_or_resource_binding_mismatch",
                )

    def test_durable_request_must_match_engine_issued_canonical_copy(self) -> None:
        request = copy.deepcopy(self.inputs["issued_request"])
        request["lease_id"] = "lease-other"
        mismatched = self._evaluate(
            request_payload=canonical_json_bytes(request),
        )
        self.assertEqual(
            mismatched.reason_code,
            "request_artifact_mismatch",
        )

        noncanonical = json.dumps(
            self.inputs["issued_request"],
            sort_keys=True,
        ).encode()
        self.assertEqual(
            self._evaluate(request_payload=noncanonical).reason_code,
            "request_artifact_mismatch",
        )

        duplicate = self.inputs["request_payload"].replace(
            b'{\n  "adapter_name":',
            b'{\n  "adapter_name":"forensics",\n  "adapter_name":',
            1,
        )
        self.assertEqual(
            self._evaluate(request_payload=duplicate).reason_code,
            "request_artifact_mismatch",
        )

    def test_run_receipt_and_artifact_chain_is_exact(self) -> None:
        run = self.inputs["run"]
        receipt = self.inputs["receipt"]
        artifact = self.inputs["stdout_artifact"]
        cases = (
            (
                {"run": replace(run, status=RunStatus.FAILED)},
                "run_binding_mismatch",
            ),
            (
                {"run": replace(run, configuration_epoch=2)},
                "run_binding_mismatch",
            ),
            (
                {"run": replace(run, request_path="../request.json")},
                "run_binding_mismatch",
            ),
            (
                {
                    "receipt": replace(
                        receipt,
                        outcome=ReceiptOutcome.FAILED,
                    )
                },
                "receipt_binding_mismatch",
            ),
            (
                {
                    "artifact": replace(
                        artifact,
                        source_run_id="RUN-foreign",
                    )
                },
                "stdout_artifact_binding_mismatch",
            ),
        )
        for changes, reason in cases:
            if "artifact" in changes:
                changes["stdout_artifact"] = changes.pop("artifact")
            with self.subTest(reason=reason):
                self.assertEqual(
                    self._evaluate(**changes).reason_code,
                    reason,
                )

    def test_capture_must_be_complete_known_and_untruncated(self) -> None:
        for field, value in (
            ("capture_complete", False),
            ("truncation_known", False),
            ("truncated", True),
            ("coverage", "retained_prefix_only"),
            ("stream_error_present", True),
            ("capture_error_present", True),
        ):
            receipt = copy.deepcopy(self.inputs["receipt"])
            receipt.extra["stream_evidence"]["stdout"][field] = value
            with self.subTest(field=field):
                result = self._evaluate(receipt=receipt)
                self.assertEqual(
                    result.reason_code,
                    "stdout_capture_incomplete",
                )

    def test_stdout_payload_is_bound_to_artifact_hash_and_size(self) -> None:
        result = self._evaluate(
            stdout_payload=self.inputs["stdout_payload"] + b"x",
        )
        self.assertEqual(
            result.reason_code,
            "stdout_artifact_content_mismatch",
        )

        artifact = replace(
            self.inputs["stdout_artifact"],
            sha256="f" * 64,
        )
        result = self._evaluate(stdout_artifact=artifact)
        self.assertEqual(
            result.reason_code,
            "stdout_capture_incomplete",
        )

    def test_semantic_pointer_and_coverage_tampering_cannot_authorize_fact(
        self,
    ) -> None:
        pointer = copy.deepcopy(self.document)
        pointer["records"][0]["pointer"]["sha256"] = "e" * 64
        partial = copy.deepcopy(self.document)
        partial["records"] = partial["records"][:1]
        partial["coverage"]["pointer_records_emitted"] = 1
        partial["coverage"]["projection"] = "partial"
        partial["coverage"]["records_truncated"] = True
        for document, semantic_reason in (
            (pointer, "semantic_record_binding_invalid"),
            (partial, "semantic_coverage_incomplete"),
        ):
            stdout = PRODUCER._canonical_json(document) + b"\n"
            artifact = replace(
                self.inputs["stdout_artifact"],
                sha256=_sha256(stdout),
                size=len(stdout),
            )
            receipt = copy.deepcopy(self.inputs["receipt"])
            receipt.stdout_bytes = len(stdout)
            evidence = receipt.extra["stream_evidence"]["stdout"]
            evidence["sha256"] = artifact.sha256
            evidence["drained_bytes"] = len(stdout)
            evidence["stored_bytes"] = len(stdout)
            evidence["omitted_stored_bytes"] = len(stdout)
            with self.subTest(reason=semantic_reason):
                result = self._evaluate(
                    stdout_payload=stdout,
                    stdout_artifact=artifact,
                    receipt=receipt,
                )
                self.assertEqual(result.reason_code, semantic_reason)
                self.assertFalse(result.confirmed)
                self.assertIsNone(
                    result.reduction_projection()["executed_fact"]
                )

    def test_evaluator_hash_binds_envelope_and_semantic_result(self) -> None:
        result = self._evaluate()
        persisted = result.to_dict()

        self.assertEqual(
            persisted["envelope_sha256"],
            result.envelope.sha256,
        )
        self.assertEqual(
            persisted["semantic_evaluation_sha256"],
            result.semantic_evaluation.sha256,
        )
        self.assertEqual(len(result.sha256), 64)
        self.assertEqual(
            persisted["envelope"]["stdout_artifact"]["path"],
            self.inputs["stdout_artifact"].path,
        )


if __name__ == "__main__":
    unittest.main()
