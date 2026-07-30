from __future__ import annotations

import copy
import hashlib
import sys
import unittest
from dataclasses import replace
from unittest.mock import patch

import ctf_os.engine.pwn_disclosure as disclosure

from ctf_os.contracts.pwn_crash_v1 import (
    PWN_CRASH_V1_CONTRACT_FINGERPRINT,
    PWN_CRASH_V1_CONTRACT_ID,
    PWN_CRASH_V1_CONTRACT_VERSION,
    PWN_CRASH_V1_SCHEMA_VERSION,
    PwnCrashV1Verdict,
    pwn_crash_v1_canonical_json_bytes,
)
from ctf_os.contracts.pwn_runtime_snapshot_v1 import (
    PWN_RUNTIME_SNAPSHOT_V1_REGISTER_NAMES,
    PwnRuntimeSnapshotV1Maps,
    PwnRuntimeSnapshotV1Registers,
    build_pwn_runtime_snapshot_v1_failure,
    build_pwn_runtime_snapshot_v1_result,
)
from ctf_os.engine.pwn_crash import (
    PWN_CRASH_NETWORK_POLICY,
    PWN_CRASH_ONE_SHOT,
    PWN_CRASH_PRODUCER_CAPABILITY_NAME,
    PWN_CRASH_PRODUCER_FILE_SHA256,
    PWN_CRASH_SANDBOX_METHOD,
    PwnCrashCapabilityAttestation,
    PwnCrashGateEvaluation,
    PwnCrashReceiptMetadata,
    PwnCrashRecipe,
    evaluate_pwn_crash_gate,
)
from ctf_os.engine.pwn_disclosure import (
    PWN_DISCLOSURE_MAX_CANDIDATES,
    PwnDisclosureError,
    PwnDisclosureStatus,
    build_pwn_disclosure_trusted_receipt_expectation,
    evaluate_pwn_disclosure,
    parse_pwn_disclosure_maps,
    parse_pwn_disclosure_result,
    pwn_disclosure_result_sha256,
    validate_pwn_disclosure_result,
)
from ctf_os.engine.pwn_runtime_snapshot import (
    PWN_RUNTIME_SNAPSHOT_NETWORK_POLICY,
    PWN_RUNTIME_SNAPSHOT_ONE_SHOT,
    PWN_RUNTIME_SNAPSHOT_PRODUCER_CAPABILITY_NAME,
    PWN_RUNTIME_SNAPSHOT_PRODUCER_FILE_SHA256,
    PWN_RUNTIME_SNAPSHOT_SANDBOX_METHOD,
    PwnRuntimeSnapshotCapabilityAttestation,
    PwnRuntimeSnapshotReceiptMetadata,
    PwnRuntimeSnapshotRecipe,
    evaluate_pwn_runtime_snapshot_gate,
    pwn_runtime_snapshot_child_experiment_id,
)


PAYLOAD = b"A" * 64
SOURCE_SHA256 = hashlib.sha256(b"\x7fELF-disclosure").hexdigest()
MANIFEST_SHA256 = hashlib.sha256(b"manifest").hexdigest()
IMAGE_DIGEST = "sha256:" + ("1" * 64)
MAPS = (
    b"0000000000400000-0000000000500000 r-xp "
    b"0000000000000000 00:00 0 /challenge/bin\n"
    b"00007f0000000000-0000800000000000 rw-p "
    b"0000000000000000 00:00 0 [heap]\n"
)


def crash_recipe() -> PwnCrashRecipe:
    return PwnCrashRecipe(
        configuration_epoch=7,
        experiment_id="E-pwn-crash",
        hypothesis_id="H-pwn-crash",
        primary_elf_locator="bin/challenge",
        source_manifest_sha256=MANIFEST_SHA256,
        source_sha256=SOURCE_SHA256,
        source_size_bytes=4096,
        payload_artifact_id="A-payload",
        payload_source_run_id="R-builder",
        payload_artifact_locator="artifacts/payload.bin",
        payload_sha256=hashlib.sha256(PAYLOAD).hexdigest(),
        payload_size_bytes=len(PAYLOAD),
        image_reference="ctf-os:test",
        image_digest=IMAGE_DIGEST,
        producer_file_sha256=PWN_CRASH_PRODUCER_FILE_SHA256,
    )


def crash_observation(
    recipe: PwnCrashRecipe,
    ordinal: int,
    *,
    confirmed: bool,
) -> bytes:
    binding = recipe.attempt_input_binding(ordinal)
    signaled = ordinal <= 3 and (confirmed or ordinal == 1)
    return pwn_crash_v1_canonical_json_bytes(
        {
            "binding": {
                "input_sha256": binding["input_sha256"],
                "input_size_bytes": binding["input_size_bytes"],
                "ordinal": ordinal,
                "phase": binding["phase"],
                "recipe_sha256": recipe.recipe_sha256,
                "source_manifest_sha256": (
                    recipe.source_manifest_sha256
                ),
                "source_sha256": recipe.source_sha256,
                "source_size_bytes": recipe.source_size_bytes,
            },
            "contract": {
                "fingerprint": PWN_CRASH_V1_CONTRACT_FINGERPRINT,
                "id": PWN_CRASH_V1_CONTRACT_ID,
                "version": PWN_CRASH_V1_CONTRACT_VERSION,
            },
            "reason_code": "observation_recorded",
            "schema_version": PWN_CRASH_V1_SCHEMA_VERSION,
            "status": "ok",
            "target": {
                "exit_code": None if signaled else 0,
                "signal_number": 11 if signaled else None,
                "termination": "signaled" if signaled else "exited",
            },
        }
    )


def crash_receipt(
    recipe: PwnCrashRecipe,
    ordinal: int,
    stdout: bytes,
    stderr: bytes,
) -> PwnCrashReceiptMetadata:
    attestation = PwnCrashCapabilityAttestation(
        image_digest=recipe.image_digest,
        recipe_sha256=recipe.recipe_sha256,
    )
    return PwnCrashReceiptMetadata(
        ordinal=ordinal,
        receipt_id=f"receipt-crash-{ordinal}",
        run_id=f"run-crash-{ordinal}",
        outcome="succeeded",
        exit_code=0,
        timed_out=False,
        clean_workspace=True,
        one_shot=PWN_CRASH_ONE_SHOT,
        sandbox_method=PWN_CRASH_SANDBOX_METHOD,
        network=PWN_CRASH_NETWORK_POLICY,
        configuration_epoch=recipe.configuration_epoch,
        image_digest=recipe.image_digest,
        recipe_sha256=recipe.recipe_sha256,
        request_sha256=hashlib.sha256(
            f"request-crash-{ordinal}".encode()
        ).hexdigest(),
        execution_contract_sha256=hashlib.sha256(
            f"execution-crash-{ordinal}".encode()
        ).hexdigest(),
        capability_attestation_artifact_id="A-crash-capability",
        capability_attestation_sha256=attestation.evidence_sha256,
        producer_capability_name=PWN_CRASH_PRODUCER_CAPABILITY_NAME,
        producer_file_sha256=recipe.producer_file_sha256,
        stdout_artifact_id=f"A-crash-stdout-{ordinal}",
        stdout_artifact_sha256=hashlib.sha256(stdout).hexdigest(),
        stdout_artifact_size_bytes=len(stdout),
        stdout_artifact_capture_placeholder=False,
        stderr_artifact_id=f"A-crash-stderr-{ordinal}",
        stderr_artifact_sha256=hashlib.sha256(stderr).hexdigest(),
        stderr_artifact_size_bytes=len(stderr),
        stderr_artifact_capture_placeholder=False,
        stdout_drained_bytes=len(stdout),
        stdout_stored_bytes=len(stdout),
        stdout_capture_complete=True,
        stdout_truncation_known=True,
        stdout_truncated=False,
        stdout_error=None,
        stream_capture_error=None,
        orchestration_error=None,
        durable_stdout_artifact_complete=True,
    )


def snapshot_recipe(
    parent: PwnCrashRecipe,
    evaluation: PwnCrashGateEvaluation,
    *,
    parent_evaluation_sha256: str | None = None,
) -> PwnRuntimeSnapshotRecipe:
    return PwnRuntimeSnapshotRecipe(
        configuration_epoch=parent.configuration_epoch,
        child_experiment_id=pwn_runtime_snapshot_child_experiment_id(
            parent.experiment_id
        ),
        parent_experiment_id=parent.experiment_id,
        primary_elf_locator=parent.primary_elf_locator,
        source_manifest_sha256=parent.source_manifest_sha256,
        source_sha256=parent.source_sha256,
        source_size_bytes=parent.source_size_bytes,
        payload_artifact_id=parent.payload_artifact_id,
        payload_source_run_id=parent.payload_source_run_id,
        payload_artifact_locator=parent.payload_artifact_locator,
        payload_sha256=parent.payload_sha256,
        payload_size_bytes=parent.payload_size_bytes,
        parent_crash_recipe_sha256=parent.recipe_sha256,
        parent_crash_evaluation_sha256=(
            evaluation.evidence_sha256
            if parent_evaluation_sha256 is None
            else parent_evaluation_sha256
        ),
        expected_signal_number=11,
        image_reference=parent.image_reference,
        image_digest=parent.image_digest,
        producer_file_sha256=(
            PWN_RUNTIME_SNAPSHOT_PRODUCER_FILE_SHA256
        ),
    )


def snapshot_document(
    recipe: PwnRuntimeSnapshotRecipe,
    *,
    captured: bool,
    maps_data: bytes,
) -> bytes:
    bindings = {
        "expected_source_manifest_sha256": (
            recipe.source_manifest_sha256
        ),
        "expected_source_sha256": recipe.source_sha256,
        "expected_source_size_bytes": recipe.source_size_bytes,
        "expected_payload_sha256": recipe.payload_sha256,
        "expected_payload_size_bytes": recipe.payload_size_bytes,
        "expected_parent_crash_recipe_sha256": (
            recipe.parent_crash_recipe_sha256
        ),
        "expected_parent_crash_evaluation_sha256": (
            recipe.parent_crash_evaluation_sha256
        ),
        "expected_signal_number": recipe.expected_signal_number,
        "expected_snapshot_recipe_sha256": recipe.recipe_sha256,
    }
    if not captured:
        return build_pwn_runtime_snapshot_v1_failure(
            reason_code="target_exited_before_expected_signal",
            **bindings,
        ).canonical_bytes()
    registers = PwnRuntimeSnapshotV1Registers(
        tuple(
            (name, f"{index:016x}")
            for index, name in enumerate(
                PWN_RUNTIME_SNAPSHOT_V1_REGISTER_NAMES
            )
        )
    )
    return build_pwn_runtime_snapshot_v1_result(
        registers=registers,
        maps=PwnRuntimeSnapshotV1Maps(maps_data),
        **bindings,
    ).canonical_bytes()


def snapshot_receipt(
    recipe: PwnRuntimeSnapshotRecipe,
    stdout: bytes,
    stderr: bytes,
) -> PwnRuntimeSnapshotReceiptMetadata:
    attestation = PwnRuntimeSnapshotCapabilityAttestation(
        image_digest=recipe.image_digest,
        recipe_sha256=recipe.recipe_sha256,
    )
    return PwnRuntimeSnapshotReceiptMetadata(
        receipt_id="receipt-snapshot",
        run_id="run-snapshot",
        outcome="succeeded",
        exit_code=0,
        timed_out=False,
        clean_workspace=True,
        one_shot=PWN_RUNTIME_SNAPSHOT_ONE_SHOT,
        sandbox_method=PWN_RUNTIME_SNAPSHOT_SANDBOX_METHOD,
        network=PWN_RUNTIME_SNAPSHOT_NETWORK_POLICY,
        configuration_epoch=recipe.configuration_epoch,
        image_digest=recipe.image_digest,
        recipe_sha256=recipe.recipe_sha256,
        request_sha256=hashlib.sha256(b"request-snapshot").hexdigest(),
        execution_contract_sha256=hashlib.sha256(
            b"execution-snapshot"
        ).hexdigest(),
        capability_attestation_artifact_id="A-snapshot-capability",
        capability_attestation_sha256=attestation.evidence_sha256,
        producer_capability_name=(
            PWN_RUNTIME_SNAPSHOT_PRODUCER_CAPABILITY_NAME
        ),
        producer_file_sha256=recipe.producer_file_sha256,
        stdout_artifact_id="A-snapshot-stdout",
        stdout_artifact_sha256=hashlib.sha256(stdout).hexdigest(),
        stdout_artifact_size_bytes=len(stdout),
        stderr_artifact_id="A-snapshot-stderr",
        stderr_artifact_sha256=hashlib.sha256(stderr).hexdigest(),
        stderr_artifact_size_bytes=len(stderr),
        stderr_capture_placeholder=False,
        stdout_drained_bytes=len(stdout),
        stdout_stored_bytes=len(stdout),
        stdout_capture_complete=True,
        stdout_truncation_known=True,
        stdout_truncated=False,
        stdout_error=None,
        stream_capture_error=None,
        orchestration_error=None,
        durable_stdout_artifact_complete=True,
    )


def fixture(
    streams: tuple[bytes, bytes, bytes, bytes],
    *,
    payload: bytes = PAYLOAD,
    maps_data: bytes = MAPS,
    crash_confirmed: bool = True,
    snapshot_captured: bool = True,
    mismatched_parent_evaluation: bool = False,
) -> dict[str, object]:
    crash = crash_recipe()
    if payload != PAYLOAD:
        crash = replace(
            crash,
            payload_sha256=hashlib.sha256(payload).hexdigest(),
            payload_size_bytes=len(payload),
        )
    observations = tuple(
        crash_observation(
            crash,
            ordinal,
            confirmed=crash_confirmed,
        )
        for ordinal in range(1, 7)
    )
    stderrs = (*streams[:3], b"", b"", b"")
    receipts = tuple(
        crash_receipt(
            crash,
            ordinal,
            observations[ordinal - 1],
            stderrs[ordinal - 1],
        )
        for ordinal in range(1, 7)
    )
    crash_gate = evaluate_pwn_crash_gate(
        crash,
        poc_input=payload,
        stdout_payloads=observations,
        receipts=receipts,
    )
    snap = snapshot_recipe(
        crash,
        crash_gate,
        parent_evaluation_sha256=(
            "e" * 64 if mismatched_parent_evaluation else None
        ),
    )
    snap_doc = snapshot_document(
        snap,
        captured=snapshot_captured,
        maps_data=maps_data,
    )
    snap_receipt = snapshot_receipt(snap, snap_doc, streams[3])
    snap_gate = evaluate_pwn_runtime_snapshot_gate(
        snap,
        stdout_payload=snap_doc,
        receipt=snap_receipt,
    )
    trusted_receipts = (
        build_pwn_disclosure_trusted_receipt_expectation(
            positive_crash_receipts=receipts[:3],
            snapshot_receipt=snap_receipt,
        )
    )
    return {
        "crash_recipe": crash,
        "crash_evaluation": crash_gate,
        "positive_crash_receipts": receipts[:3],
        "snapshot_recipe": snap,
        "snapshot_evaluation": snap_gate,
        "snapshot_receipt": snap_receipt,
        "trusted_receipt_expectation": trusted_receipts,
        "payload": payload,
        "positive_crash_stderr": streams[:3],
        "runtime_stderr": streams[3],
    }


class PwnDisclosureTests(unittest.TestCase):
    def test_dynamic_pointer_is_bound_to_both_typed_gates(self) -> None:
        streams = (
            b"leak=0x7f1000001000\n",
            b"leak=0x7f2000002000\n",
            b"leak=0x7f3000003000\n",
            b"leak=0x7f4000004000\n",
        )
        result = evaluate_pwn_disclosure(**fixture(streams))

        self.assertIs(
            result.status,
            PwnDisclosureStatus.DYNAMIC_POINTER_OBSERVED,
        )
        self.assertEqual(result.candidates[0].distinct_value_count, 4)
        upstream = result.binding.upstream
        self.assertEqual(
            upstream.parent_crash_recipe_sha256,
            upstream.crash_recipe_sha256,
        )
        self.assertEqual(
            upstream.parent_crash_evaluation_sha256,
            upstream.crash_evaluation_sha256,
        )
        self.assertEqual(
            tuple(item.ordinal for item in upstream.positive_receipts),
            (1, 2, 3),
        )
        self.assertEqual(
            result.binding.crash_stderr,
            tuple(item.stderr for item in upstream.positive_receipts),
        )
        self.assertEqual(
            result.binding.runtime_stderr,
            upstream.runtime_snapshot_receipt.stderr,
        )
        self.assertEqual(
            result.binding.maps,
            upstream.runtime_snapshot_receipt.stdout,
        )
        persisted = result.canonical_bytes()
        self.assertNotIn(b"0x7f", persisted)
        self.assertNotIn(b"/challenge", persisted)
        self.assertNotIn(b"r-xp", persisted)
        self.assertTrue(
            all(value is False for value in result.to_dict()["authorities"].values())
        )
        self.assertEqual(
            parse_pwn_disclosure_result(
                persisted,
                expected_result=result,
            ),
            result,
        )
        self.assertEqual(
            pwn_disclosure_result_sha256(result),
            hashlib.sha256(persisted).hexdigest(),
        )

    def test_non_pie_uppercase_prefix_and_minimal_ascii_echo(self) -> None:
        upper = b"ptr=0X401234\n"
        result = evaluate_pwn_disclosure(
            **fixture((upper, upper, upper, upper))
        )
        self.assertIs(
            result.status,
            PwnDisclosureStatus.MAPPED_POINTER_OBSERVED,
        )
        self.assertEqual(result.candidates[0].hex_width, 6)

        padded = b"ptr=0x000000401234\n"
        echoed = evaluate_pwn_disclosure(
            **fixture(
                (padded, padded, padded, padded),
                payload=b"AAAA0x401234BBBB",
            )
        )
        self.assertIs(echoed.status, PwnDisclosureStatus.UNRESOLVED)
        self.assertEqual(echoed.reason_code, "payload_echo_only")

    def test_payload_endian_echo_is_rejected(self) -> None:
        stream = b"ptr=0x000000401234\n"
        value = 0x401234
        for width in (4, 5, 6, 7, 8):
            for byte_order in ("little", "big"):
                payload = (
                    b"A"
                    + value.to_bytes(width, byte_order)
                    + b"B"
                )
                with self.subTest(
                    width=width,
                    byte_order=byte_order,
                ):
                    result = evaluate_pwn_disclosure(
                        **fixture(
                            (stream, stream, stream, stream),
                            payload=payload,
                        )
                    )
                    self.assertEqual(
                        result.reason_code,
                        "payload_echo_only",
                    )

        six_byte_value = 0x7F1000001000
        six_byte_stream = b"ptr=0x7f1000001000\n"
        for byte_order in ("little", "big"):
            with self.subTest(minimal_six_byte_order=byte_order):
                result = evaluate_pwn_disclosure(
                    **fixture(
                        (
                            six_byte_stream,
                            six_byte_stream,
                            six_byte_stream,
                            six_byte_stream,
                        ),
                        payload=six_byte_value.to_bytes(
                            6,
                            byte_order,
                        ),
                    )
                )
                self.assertEqual(
                    result.reason_code,
                    "payload_echo_only",
                )

    def test_nonconfirmed_and_noncaptured_gates_fail_closed(self) -> None:
        stream = b"ptr=0x000000401234\n"
        result = evaluate_pwn_disclosure(
            **fixture(
                (stream, stream, stream, stream),
                crash_confirmed=False,
            )
        )
        self.assertIs(result.status, PwnDisclosureStatus.UNVERIFIABLE)
        self.assertEqual(result.reason_code, "crash_gate_not_confirmed")

        result = evaluate_pwn_disclosure(
            **fixture(
                (stream, stream, stream, stream),
                snapshot_captured=False,
            )
        )
        self.assertIs(result.status, PwnDisclosureStatus.UNVERIFIABLE)
        self.assertEqual(result.reason_code, "snapshot_gate_not_captured")

    def test_parent_and_receipt_binding_mismatches_fail_closed(self) -> None:
        stream = b"ptr=0x000000401234\n"
        result = evaluate_pwn_disclosure(
            **fixture(
                (stream, stream, stream, stream),
                mismatched_parent_evaluation=True,
            )
        )
        self.assertIs(result.status, PwnDisclosureStatus.UNVERIFIABLE)
        self.assertEqual(
            result.reason_code,
            "provenance_binding_mismatch",
        )

        values = fixture((stream, stream, stream, stream))
        receipts = values["positive_crash_receipts"]
        assert isinstance(receipts, tuple)
        values["positive_crash_receipts"] = (
            replace(
                receipts[0],
                receipt_id="receipt-crash-substitute",
                stderr_artifact_id="A-crash-stderr-substitute",
            ),
            receipts[1],
            receipts[2],
        )
        result = evaluate_pwn_disclosure(**values)
        self.assertEqual(result.reason_code, "receipt_binding_mismatch")

        values = fixture((stream, stream, stream, stream))
        receipts = values["positive_crash_receipts"]
        assert isinstance(receipts, tuple)
        values["positive_crash_receipts"] = (
            replace(
                receipts[0],
                stderr_artifact_id=None,
                stderr_artifact_sha256=None,
                stderr_artifact_size_bytes=None,
            ),
            receipts[1],
            receipts[2],
        )
        result = evaluate_pwn_disclosure(**values)
        self.assertIs(result.status, PwnDisclosureStatus.UNVERIFIABLE)
        self.assertEqual(result.reason_code, "receipt_binding_mismatch")

        values = fixture((stream, stream, stream, stream))
        receipts = values["positive_crash_receipts"]
        assert isinstance(receipts, tuple)
        values["positive_crash_receipts"] = (
            receipts[0],
            replace(receipts[1], ordinal=1),
            receipts[2],
        )
        result = evaluate_pwn_disclosure(**values)
        self.assertEqual(result.reason_code, "receipt_binding_mismatch")

        values = fixture((stream, stream, stream, stream))
        receipt = values["snapshot_receipt"]
        assert isinstance(
            receipt,
            PwnRuntimeSnapshotReceiptMetadata,
        )
        values["snapshot_receipt"] = replace(
            receipt,
            receipt_id="receipt-snapshot-substitute",
            stderr_artifact_id="A-snapshot-stderr-substitute",
        )
        result = evaluate_pwn_disclosure(**values)
        self.assertEqual(result.reason_code, "receipt_binding_mismatch")

    def test_fingerprint_binds_every_upstream_acceptance_constant(
        self,
    ) -> None:
        baseline = hashlib.sha256(
            disclosure.pwn_disclosure_canonical_json_bytes(
                disclosure.pwn_disclosure_contract_descriptor()
            )
        ).hexdigest()
        self.assertEqual(
            baseline,
            disclosure.PWN_DISCLOSURE_CONTRACT_FINGERPRINT,
        )
        replacements = {
            "PWN_CRASH_V1_CONTRACT_FINGERPRINT": "a" * 64,
            "PWN_CRASH_V1_POSITIVE_ATTEMPTS": 4,
            "PWN_CRASH_CAPABILITY_PROBE_CONTRACT": "changed.crash",
            "PWN_CRASH_NETWORK_POLICY": "changed",
            "PWN_CRASH_ONE_SHOT": False,
            "PWN_CRASH_PRODUCER_CAPABILITY_NAME": "changed-crash",
            "PWN_CRASH_PRODUCER_FILE_SHA256": "b" * 64,
            "PWN_CRASH_PRODUCER_INTERPRETER_PATH": "/changed/python",
            "PWN_CRASH_PRODUCER_PATH": "/changed/crash",
            "PWN_CRASH_SANDBOX_METHOD": "changed_crash",
            "PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_FINGERPRINT": "c" * 64,
            "PWN_RUNTIME_SNAPSHOT_CAPABILITY_PROBE_CONTRACT": (
                "changed.snapshot"
            ),
            "PWN_RUNTIME_SNAPSHOT_NETWORK_POLICY": "changed",
            "PWN_RUNTIME_SNAPSHOT_ONE_SHOT": False,
            "PWN_RUNTIME_SNAPSHOT_V1_MAX_MAPS_BYTES": 131073,
            "PWN_RUNTIME_SNAPSHOT_PRODUCER_CAPABILITY_NAME": (
                "changed-snapshot"
            ),
            "PWN_RUNTIME_SNAPSHOT_PRODUCER_FILE_SHA256": "d" * 64,
            "PWN_RUNTIME_SNAPSHOT_PRODUCER_INTERPRETER_PATH": (
                "/changed/python"
            ),
            "PWN_RUNTIME_SNAPSHOT_PRODUCER_PATH": "/changed/snapshot",
            "PWN_RUNTIME_SNAPSHOT_SANDBOX_METHOD": "changed_snapshot",
        }
        for name, changed in replacements.items():
            with self.subTest(name=name), patch.object(
                disclosure,
                name,
                changed,
            ):
                observed = hashlib.sha256(
                    disclosure.pwn_disclosure_canonical_json_bytes(
                        disclosure.pwn_disclosure_contract_descriptor()
                    )
                ).hexdigest()
                self.assertNotEqual(observed, baseline)
        stream = b"ptr=0x000000401234\n"
        values = fixture((stream, stream, stream, stream))
        with patch.object(
            disclosure,
            "PWN_CRASH_NETWORK_POLICY",
            "changed",
        ), self.assertRaisesRegex(
            PwnDisclosureError,
            "contract_dependency_drift",
        ):
            evaluate_pwn_disclosure(**values)

    def test_forged_typed_gate_is_rejected_before_classification(self) -> None:
        stream = b"ptr=0x000000401234\n"
        values = fixture((stream, stream, stream, stream))
        forged = object.__new__(PwnCrashGateEvaluation)
        object.__setattr__(forged, "verdict", PwnCrashV1Verdict.CONFIRMED)
        object.__setattr__(forged, "reason_code", "confirmed")
        object.__setattr__(forged, "failures", ())
        object.__setattr__(forged, "semantic_evaluation", None)
        object.__setattr__(forged, "transport_error", None)
        values["crash_evaluation"] = forged
        with self.assertRaisesRegex(
            PwnDisclosureError,
            "typed_provenance_invalid",
        ):
            evaluate_pwn_disclosure(**values)

    def test_persisted_result_requires_exact_recomputation(self) -> None:
        stream = b"ptr=0x000000401234\n"
        result = evaluate_pwn_disclosure(
            **fixture((stream, stream, stream, stream))
        )
        with self.assertRaises(TypeError):
            validate_pwn_disclosure_result(result.to_dict())
        changed = copy.deepcopy(result.to_dict())
        first = changed["candidates"][0]
        first["replay_value_sha256"][0] = "f" * 64
        first["distinct_value_count"] = 2
        changed["status"] = "DYNAMIC_POINTER_OBSERVED"
        changed["reason_code"] = "dynamic_pointer_observed"
        with self.assertRaisesRegex(
            PwnDisclosureError,
            "result_binding_mismatch",
        ):
            validate_pwn_disclosure_result(
                changed,
                expected_result=result,
            )

    def test_json_value_and_recursion_bombs_are_stable_invalid_json(
        self,
    ) -> None:
        stream = b"ptr=0x000000401234\n"
        result = evaluate_pwn_disclosure(
            **fixture((stream, stream, stream, stream))
        )
        bombs = (
            b'{"x":' + (b"9" * 5000) + b"}\n",
            (b"[" * 10000) + b"0" + (b"]" * 10000),
        )
        previous_limit = sys.get_int_max_str_digits()
        try:
            sys.set_int_max_str_digits(0)
            for bomb in bombs:
                with self.subTest(length=len(bomb)):
                    with self.assertRaisesRegex(
                        PwnDisclosureError,
                        "invalid_json",
                    ):
                        parse_pwn_disclosure_result(
                            bomb,
                            expected_result=result,
                        )
        finally:
            sys.set_int_max_str_digits(previous_limit)
        disclosure._precheck_json_resource_limits(
            b'{"brackets":"[[[{{{]]]}}}"}'
        )

    def test_malformed_maps_and_offset_canary_are_not_disclosures(
        self,
    ) -> None:
        malformed = (
            b"0000000000400000-0000000000500000 r-qq "
            b"0000000000000000 00:00 0 /challenge/bin\n"
        )
        stream = b"ptr=0x000000401234\n"
        result = evaluate_pwn_disclosure(
            **fixture(
                (stream, stream, stream, stream),
                maps_data=malformed,
            )
        )
        self.assertIs(result.status, PwnDisclosureStatus.UNVERIFIABLE)
        self.assertEqual(result.reason_code, "malformed_maps")

        result = evaluate_pwn_disclosure(
            **fixture(
                (
                    b"x=0x7f1000001000\n",
                    b"xx=0x7f2000002000\n",
                    b"xxx=0x7f3000003000\n",
                    b"xxxx=0x7f4000004000\n",
                )
            )
        )
        self.assertIs(result.status, PwnDisclosureStatus.UNRESOLVED)
        self.assertEqual(result.reason_code, "no_common_pointer_shape")

    def test_upstream_accepted_4097_line_maps_is_stable_unverifiable(
        self,
    ) -> None:
        stream = b"ptr=0x000000401234\n"
        maps_data = b"x\n" * 4097
        result = evaluate_pwn_disclosure(
            **fixture(
                (stream, stream, stream, stream),
                maps_data=maps_data,
            )
        )
        self.assertIs(result.status, PwnDisclosureStatus.UNVERIFIABLE)
        self.assertEqual(result.reason_code, "maps_limit_exceeded")
        self.assertEqual(
            result.binding.upstream.expected_maps_line_count,
            4097,
        )
        persisted = result.canonical_bytes()
        self.assertNotIn(maps_data, persisted)
        self.assertEqual(
            parse_pwn_disclosure_result(
                persisted,
                expected_result=result,
            ),
            result,
        )

    def test_candidates_are_ordered_and_bounded(self) -> None:
        def stream(count: int) -> bytes:
            return b"|".join(
                f"0x{0x401000 + index:06x}".encode("ascii")
                for index in range(count)
            ) + b"\n"

        bounded = stream(PWN_DISCLOSURE_MAX_CANDIDATES)
        result = evaluate_pwn_disclosure(
            **fixture((bounded, bounded, bounded, bounded))
        )
        self.assertEqual(
            len(result.candidates),
            PWN_DISCLOSURE_MAX_CANDIDATES,
        )
        order = [
            (item.byte_offset, item.hex_width)
            for item in result.candidates
        ]
        self.assertEqual(order, sorted(order))

        overflow = stream(PWN_DISCLOSURE_MAX_CANDIDATES + 1)
        result = evaluate_pwn_disclosure(
            **fixture((overflow, overflow, overflow, overflow))
        )
        self.assertIs(result.status, PwnDisclosureStatus.UNVERIFIABLE)
        self.assertEqual(result.reason_code, "candidate_limit_exceeded")

    def test_strict_maps_overflow_and_overlap(self) -> None:
        cases = (
            (
                b"00001000-00003000 r-xp 00000000 00:00 0 /a\n"
                b"00002000-00004000 rw-p 00000000 00:00 0 /b\n"
            ),
            (
                b"00001000-00003000 r-xp 00000000 00:00 "
                b"18446744073709551616 /a\n"
            ),
        )
        for value in cases:
            with self.assertRaisesRegex(
                PwnDisclosureError,
                "malformed_maps",
            ):
                parse_pwn_disclosure_maps(value)


if __name__ == "__main__":
    unittest.main()
