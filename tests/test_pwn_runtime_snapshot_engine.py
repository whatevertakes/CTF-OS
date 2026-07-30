from __future__ import annotations

import copy
import hashlib
import unittest
from dataclasses import replace

from ctf_os.contracts.pwn_runtime_snapshot_v1 import (
    PWN_RUNTIME_SNAPSHOT_V1_REGISTER_NAMES,
    PwnRuntimeSnapshotV1Maps,
    PwnRuntimeSnapshotV1Registers,
    PwnRuntimeSnapshotV1Status,
    build_pwn_runtime_snapshot_v1_failure,
    build_pwn_runtime_snapshot_v1_result,
)
from ctf_os.engine.pwn_runtime_snapshot import (
    PWN_RUNTIME_SNAPSHOT_INPUT_ARGUMENT,
    PWN_RUNTIME_SNAPSHOT_NETWORK_POLICY,
    PWN_RUNTIME_SNAPSHOT_ONE_SHOT,
    PWN_RUNTIME_SNAPSHOT_PRODUCER_CAPABILITY_NAME,
    PWN_RUNTIME_SNAPSHOT_PRODUCER_FILE_SHA256,
    PWN_RUNTIME_SNAPSHOT_PRODUCER_INTERPRETER_PATH,
    PWN_RUNTIME_SNAPSHOT_PRODUCER_PATH,
    PWN_RUNTIME_SNAPSHOT_SANDBOX_METHOD,
    PwnRuntimeSnapshotCapabilityAttestation,
    PwnRuntimeSnapshotCapabilityAttestationError,
    PwnRuntimeSnapshotGateEvaluation,
    PwnRuntimeSnapshotReceiptMetadata,
    PwnRuntimeSnapshotRecipe,
    PwnRuntimeSnapshotRecipeError,
    evaluate_pwn_runtime_snapshot_gate,
    normalize_pwn_runtime_snapshot_capability_attestation,
    pwn_runtime_snapshot_child_experiment_id,
)


SOURCE_MANIFEST = "1" * 64
SOURCE_SHA = "2" * 64
PAYLOAD_SHA = "3" * 64
PARENT_RECIPE_SHA = "4" * 64
PARENT_EVALUATION_SHA = "5" * 64
IMAGE_DIGEST = "sha256:" + ("6" * 64)
REQUEST_SHA = "7" * 64
EXECUTION_SHA = "8" * 64


def recipe() -> PwnRuntimeSnapshotRecipe:
    parent = "E-parent-crash"
    return PwnRuntimeSnapshotRecipe(
        configuration_epoch=3,
        child_experiment_id=(
            pwn_runtime_snapshot_child_experiment_id(parent)
        ),
        parent_experiment_id=parent,
        primary_elf_locator="bin/challenge",
        source_manifest_sha256=SOURCE_MANIFEST,
        source_sha256=SOURCE_SHA,
        source_size_bytes=4096,
        payload_artifact_id="A-builder-payload",
        payload_source_run_id="R-builder",
        payload_artifact_locator="artifacts/payload.bin",
        payload_sha256=PAYLOAD_SHA,
        payload_size_bytes=32,
        parent_crash_recipe_sha256=PARENT_RECIPE_SHA,
        parent_crash_evaluation_sha256=PARENT_EVALUATION_SHA,
        expected_signal_number=11,
        image_reference="ctf-os:core",
        image_digest=IMAGE_DIGEST,
        producer_file_sha256=(
            PWN_RUNTIME_SNAPSHOT_PRODUCER_FILE_SHA256
        ),
    )


def receipt(
    selected: PwnRuntimeSnapshotRecipe,
    payload: bytes,
) -> PwnRuntimeSnapshotReceiptMetadata:
    return PwnRuntimeSnapshotReceiptMetadata(
        receipt_id="RCPT-snapshot",
        run_id="R-snapshot",
        outcome="succeeded",
        exit_code=0,
        timed_out=False,
        clean_workspace=True,
        one_shot=PWN_RUNTIME_SNAPSHOT_ONE_SHOT,
        sandbox_method=PWN_RUNTIME_SNAPSHOT_SANDBOX_METHOD,
        network=PWN_RUNTIME_SNAPSHOT_NETWORK_POLICY,
        configuration_epoch=selected.configuration_epoch,
        image_digest=selected.image_digest,
        recipe_sha256=selected.recipe_sha256,
        request_sha256=REQUEST_SHA,
        execution_contract_sha256=EXECUTION_SHA,
        capability_attestation_artifact_id="A-snapshot-capability",
        capability_attestation_sha256="9" * 64,
        producer_capability_name=(
            PWN_RUNTIME_SNAPSHOT_PRODUCER_CAPABILITY_NAME
        ),
        producer_file_sha256=selected.producer_file_sha256,
        stdout_artifact_id="A-snapshot-stdout",
        stdout_artifact_sha256=hashlib.sha256(payload).hexdigest(),
        stdout_artifact_size_bytes=len(payload),
        stderr_artifact_id="A-snapshot-stderr",
        stderr_artifact_sha256=hashlib.sha256(b"").hexdigest(),
        stderr_artifact_size_bytes=0,
        stderr_capture_placeholder=False,
        stdout_drained_bytes=len(payload),
        stdout_stored_bytes=len(payload),
        stdout_capture_complete=True,
        stdout_truncation_known=True,
        stdout_truncated=False,
        stdout_error=None,
        stream_capture_error=None,
        orchestration_error=None,
        durable_stdout_artifact_complete=True,
    )


def bindings(
    selected: PwnRuntimeSnapshotRecipe,
) -> dict[str, object]:
    return {
        "expected_source_manifest_sha256": (
            selected.source_manifest_sha256
        ),
        "expected_source_sha256": selected.source_sha256,
        "expected_source_size_bytes": selected.source_size_bytes,
        "expected_payload_sha256": selected.payload_sha256,
        "expected_payload_size_bytes": selected.payload_size_bytes,
        "expected_parent_crash_recipe_sha256": (
            selected.parent_crash_recipe_sha256
        ),
        "expected_parent_crash_evaluation_sha256": (
            selected.parent_crash_evaluation_sha256
        ),
        "expected_signal_number": selected.expected_signal_number,
        "expected_snapshot_recipe_sha256": selected.recipe_sha256,
    }


def captured_payload(
    selected: PwnRuntimeSnapshotRecipe,
) -> bytes:
    registers = PwnRuntimeSnapshotV1Registers(
        tuple(
            (name, f"{index:016x}")
            for index, name in enumerate(
                PWN_RUNTIME_SNAPSHOT_V1_REGISTER_NAMES
            )
        )
    )
    maps = PwnRuntimeSnapshotV1Maps(
        b"00400000-00401000 r-xp 00000000 00:00 0 /challenge/bin\n"
    )
    return build_pwn_runtime_snapshot_v1_result(
        registers=registers,
        maps=maps,
        **bindings(selected),
    ).canonical_bytes()


class PwnRuntimeSnapshotEngineTests(unittest.TestCase):
    def test_recipe_round_trip_child_identity_and_fixed_argv(self) -> None:
        selected = recipe()
        self.assertEqual(
            PwnRuntimeSnapshotRecipe.from_dict(selected.to_dict()),
            selected,
        )
        self.assertEqual(
            selected.child_experiment_id,
            pwn_runtime_snapshot_child_experiment_id(
                selected.parent_experiment_id
            ),
        )
        argv = selected.argv()
        self.assertEqual(
            argv[:6],
            (
                PWN_RUNTIME_SNAPSHOT_PRODUCER_INTERPRETER_PATH,
                PWN_RUNTIME_SNAPSHOT_PRODUCER_PATH,
                "--binary",
                "/challenge/bin/challenge",
                "--payload",
                PWN_RUNTIME_SNAPSHOT_INPUT_ARGUMENT,
            ),
        )
        self.assertEqual(
            argv[-4:],
            (
                "--expected-signal-number",
                "11",
                "--snapshot-recipe-sha256",
                selected.recipe_sha256,
            ),
        )
        self.assertNotIn(selected.parent_experiment_id, argv)
        self.assertNotIn(selected.child_experiment_id, argv)

    def test_recipe_rejects_substitution_and_unknown_fields(self) -> None:
        selected = recipe()
        changed = copy.deepcopy(selected.to_dict())
        changed["parent"]["crash_evaluation_sha256"] = "a" * 64
        with self.assertRaises(PwnRuntimeSnapshotRecipeError):
            PwnRuntimeSnapshotRecipe.from_dict(changed)

        changed = copy.deepcopy(selected.to_dict())
        changed["runtime"]["network"] = "bridge"
        changed["recipe_sha256"] = hashlib.sha256(
            b"attacker-chosen"
        ).hexdigest()
        with self.assertRaises(PwnRuntimeSnapshotRecipeError):
            PwnRuntimeSnapshotRecipe.from_dict(changed)

        with self.assertRaisesRegex(
            PwnRuntimeSnapshotRecipeError,
            "child_experiment_id_mismatch",
        ):
            replace(selected, child_experiment_id="E-other")

    def test_capability_attestation_is_exact_and_source_bound(self) -> None:
        selected = recipe()
        expected = PwnRuntimeSnapshotCapabilityAttestation(
            image_digest=selected.image_digest,
            recipe_sha256=selected.recipe_sha256,
        )
        report = {
            "ok": True,
            "image_digest": selected.image_digest,
            "available": [
                PWN_RUNTIME_SNAPSHOT_PRODUCER_CAPABILITY_NAME
            ],
            "attestations": {
                PWN_RUNTIME_SNAPSHOT_PRODUCER_CAPABILITY_NAME: (
                    expected.to_dict()["attestation"]
                )
            },
            "attestation_errors": {},
        }
        observed = (
            normalize_pwn_runtime_snapshot_capability_attestation(
                report,
                image_digest=selected.image_digest,
                recipe_sha256=selected.recipe_sha256,
            )
        )
        self.assertEqual(observed, expected)
        self.assertEqual(
            PwnRuntimeSnapshotCapabilityAttestation.from_dict(
                observed.to_dict()
            ),
            observed,
        )

        report["attestations"][
            PWN_RUNTIME_SNAPSHOT_PRODUCER_CAPABILITY_NAME
        ] = {
            **expected.to_dict()["attestation"],
            "sha256": "0" * 64,
        }
        with self.assertRaises(
            PwnRuntimeSnapshotCapabilityAttestationError
        ):
            normalize_pwn_runtime_snapshot_capability_attestation(
                report,
                image_digest=selected.image_digest,
                recipe_sha256=selected.recipe_sha256,
            )

    def test_captured_document_is_diagnostic_and_reconstructable(self) -> None:
        selected = recipe()
        payload = captured_payload(selected)
        evaluation = evaluate_pwn_runtime_snapshot_gate(
            selected,
            stdout_payload=payload,
            receipt=receipt(selected, payload),
        )
        self.assertIs(
            evaluation.status,
            PwnRuntimeSnapshotV1Status.CAPTURED,
        )
        self.assertTrue(evaluation.captured)
        self.assertIsNone(evaluation.transport_error)
        self.assertTrue(
            all(
                value is False
                for value in evaluation.to_dict()[
                    "authorities"
                ].values()
            )
        )
        self.assertEqual(
            PwnRuntimeSnapshotGateEvaluation.from_dict(
                evaluation.to_dict(),
                recipe=selected,
            ),
            evaluation,
        )

    def test_typed_inconclusive_and_error_are_not_transport_errors(
        self,
    ) -> None:
        selected = recipe()
        for reason, expected_status in (
            (
                "target_exited_before_expected_signal",
                PwnRuntimeSnapshotV1Status.INCONCLUSIVE,
            ),
            (
                "ptrace_unavailable",
                PwnRuntimeSnapshotV1Status.ERROR,
            ),
        ):
            with self.subTest(reason=reason):
                payload = build_pwn_runtime_snapshot_v1_failure(
                    reason_code=reason,
                    **bindings(selected),
                ).canonical_bytes()
                evaluation = evaluate_pwn_runtime_snapshot_gate(
                    selected,
                    stdout_payload=payload,
                    receipt=receipt(selected, payload),
                )
                self.assertIs(evaluation.status, expected_status)
                self.assertIsNotNone(evaluation.semantic_result)
                self.assertIsNone(evaluation.transport_error)
                self.assertFalse(evaluation.captured)

    def test_malformed_document_is_a_distinct_transport_failure(self) -> None:
        selected = recipe()
        payload = b'{"not":"the contract"}\n'
        evaluation = evaluate_pwn_runtime_snapshot_gate(
            selected,
            stdout_payload=payload,
            receipt=receipt(selected, payload),
        )
        self.assertIs(
            evaluation.status,
            PwnRuntimeSnapshotV1Status.ERROR,
        )
        self.assertIsNone(evaluation.semantic_result)
        self.assertEqual(
            evaluation.transport_error.code,
            "producer_document_rejected",
        )
        self.assertTrue(
            evaluation.reason_code.startswith("transport_")
        )

    def test_receipt_binding_and_stream_tamper_fail_transport(self) -> None:
        selected = recipe()
        payload = captured_payload(selected)
        valid = receipt(selected, payload)
        self.assertEqual(
            PwnRuntimeSnapshotReceiptMetadata.from_dict(
                valid.to_dict()
            ),
            valid,
        )
        for field, changed in (
            ("stderr_artifact_id", "../stderr"),
            ("stderr_artifact_sha256", "0"),
            ("stderr_artifact_size_bytes", -1),
            ("stderr_capture_placeholder", 0),
        ):
            with self.subTest(field=field):
                tampered = valid.to_dict()
                tampered[field] = changed
                with self.assertRaises(ValueError):
                    PwnRuntimeSnapshotReceiptMetadata.from_dict(
                        tampered
                    )
        image_changed = replace(
            valid,
            image_digest="sha256:" + ("a" * 64),
        )
        self.assertEqual(
            evaluate_pwn_runtime_snapshot_gate(
                selected,
                stdout_payload=payload,
                receipt=image_changed,
            ).transport_error.code,
            "receipt_binding_mismatch",
        )
        self.assertEqual(
            evaluate_pwn_runtime_snapshot_gate(
                selected,
                stdout_payload=payload + b"x",
                receipt=valid,
            ).transport_error.code,
            "stdout_size_binding_mismatch",
        )
        hash_changed = replace(
            valid,
            stdout_artifact_sha256="f" * 64,
        )
        self.assertEqual(
            evaluate_pwn_runtime_snapshot_gate(
                selected,
                stdout_payload=payload,
                receipt=hash_changed,
            ).transport_error.code,
            "stdout_hash_binding_mismatch",
        )


if __name__ == "__main__":
    unittest.main()
