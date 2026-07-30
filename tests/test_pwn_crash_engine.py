from __future__ import annotations

import copy
import hashlib
import json
import unittest
from dataclasses import replace

from ctf_os.capabilities import REQUIRED_MANAGED_ATTESTATIONS
from ctf_os.contracts.pwn_crash_v1 import (
    PWN_CRASH_V1_CONTRACT_FINGERPRINT,
    PWN_CRASH_V1_CONTRACT_ID,
    PWN_CRASH_V1_CONTRACT_VERSION,
    PWN_CRASH_V1_PROTOCOL,
    PWN_CRASH_V1_SCHEMA_VERSION,
    PwnCrashV1Verdict,
    pwn_crash_v1_canonical_json_bytes,
    pwn_crash_v1_contract_descriptor,
)
from ctf_os.engine.pwn_crash import (
    PWN_CRASH_ARGV_TEMPLATE,
    PWN_CRASH_CAPABILITY_PROBE_CONTRACT,
    PWN_CRASH_INPUT_DESTINATION_LOCATOR,
    PWN_CRASH_INPUT_ARGUMENT,
    PWN_CRASH_NETWORK_POLICY,
    PWN_CRASH_PRODUCER_CAPABILITY_NAME,
    PWN_CRASH_PRODUCER_FILE_SHA256,
    PWN_CRASH_PRODUCER_INTERPRETER_PATH,
    PWN_CRASH_PRODUCER_PATH,
    PWN_CRASH_SANDBOX_METHOD,
    PwnCrashCapabilityAttestation,
    PwnCrashCapabilityAttestationError,
    PwnCrashGateEvaluation,
    PwnCrashGateEvaluationError,
    PwnCrashReceiptMetadata,
    PwnCrashRecipe,
    PwnCrashRecipeError,
    PwnCrashTransportError,
    evaluate_pwn_crash_evidence,
    evaluate_pwn_crash_gate,
    normalize_pwn_crash_capability_attestation,
)


POC = b"A" * 64
SOURCE = b"\x7fELF-engine-owned-pwn-crash-recipe"
SOURCE_SHA256 = hashlib.sha256(SOURCE).hexdigest()
MANIFEST_SHA256 = hashlib.sha256(b"source-manifest").hexdigest()
PRODUCER_SHA256 = PWN_CRASH_PRODUCER_FILE_SHA256
IMAGE_DIGEST = "sha256:" + ("1" * 64)
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def canonical_bytes(value: object) -> bytes:
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


def make_recipe(**overrides: object) -> PwnCrashRecipe:
    values: dict[str, object] = {
        "configuration_epoch": 7,
        "experiment_id": "E-pwn-crash-1",
        "hypothesis_id": "H-pwn-crash-1",
        "primary_elf_locator": "bin/challenge",
        "source_manifest_sha256": MANIFEST_SHA256,
        "source_sha256": SOURCE_SHA256,
        "source_size_bytes": len(SOURCE),
        "payload_artifact_id": "A-builder-run-1",
        "payload_source_run_id": "builder-run-1",
        "payload_artifact_locator": (
            "artifacts/snapshots/A-builder-run-1.bin"
        ),
        "payload_sha256": hashlib.sha256(POC).hexdigest(),
        "payload_size_bytes": len(POC),
        "image_reference": "ctf-os:test",
        "image_digest": IMAGE_DIGEST,
        "producer_file_sha256": PRODUCER_SHA256,
    }
    values.update(overrides)
    return PwnCrashRecipe(**values)


def observation(
    recipe: PwnCrashRecipe,
    ordinal: int,
    *,
    termination: str,
    exit_code: int | None,
    signal_number: int | None,
) -> bytes:
    binding = recipe.attempt_input_binding(ordinal)
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
                "exit_code": exit_code,
                "signal_number": signal_number,
                "termination": termination,
            },
        }
    )


def confirming_payloads(recipe: PwnCrashRecipe) -> tuple[bytes, ...]:
    return tuple(
        observation(
            recipe,
            ordinal,
            termination="signaled" if ordinal <= 3 else "exited",
            exit_code=None if ordinal <= 3 else 0,
            signal_number=11 if ordinal <= 3 else None,
        )
        for ordinal in range(1, 7)
    )


def receipts(
    recipe: PwnCrashRecipe,
    payloads: tuple[bytes, ...],
) -> tuple[PwnCrashReceiptMetadata, ...]:
    capability = PwnCrashCapabilityAttestation(
        image_digest=recipe.image_digest,
        recipe_sha256=recipe.recipe_sha256,
    )
    return tuple(
        PwnCrashReceiptMetadata(
            ordinal=ordinal,
            receipt_id=f"receipt-{ordinal}",
            run_id=f"run-{ordinal}",
            outcome="succeeded",
            exit_code=0,
            timed_out=False,
            clean_workspace=True,
            one_shot=True,
            sandbox_method=PWN_CRASH_SANDBOX_METHOD,
            network=PWN_CRASH_NETWORK_POLICY,
            configuration_epoch=recipe.configuration_epoch,
            image_digest=recipe.image_digest,
            recipe_sha256=recipe.recipe_sha256,
            request_sha256=hashlib.sha256(
                f"request-{ordinal}".encode("ascii")
            ).hexdigest(),
            execution_contract_sha256=hashlib.sha256(
                f"execution-contract-{ordinal}".encode("ascii")
            ).hexdigest(),
            capability_attestation_artifact_id=(
                "A-pwn-crash-capability"
            ),
            capability_attestation_sha256=capability.evidence_sha256,
            producer_capability_name=(
                PWN_CRASH_PRODUCER_CAPABILITY_NAME
            ),
            producer_file_sha256=recipe.producer_file_sha256,
            stdout_artifact_id=f"stdout-artifact-{ordinal}",
            stdout_artifact_sha256=hashlib.sha256(payload).hexdigest(),
            stdout_artifact_size_bytes=len(payload),
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
        for ordinal, payload in enumerate(payloads, start=1)
    )


class PwnCrashRecipeTests(unittest.TestCase):
    def test_recipe_binds_all_engine_owned_execution_fields(self) -> None:
        recipe = make_recipe()
        value = recipe.to_dict()
        content = copy.deepcopy(value)
        supplied_hash = content.pop("recipe_sha256")

        self.assertEqual(
            supplied_hash,
            hashlib.sha256(canonical_bytes(content)).hexdigest(),
        )
        self.assertEqual(value["schema_version"], 1)
        self.assertEqual(value["protocol"], PWN_CRASH_V1_PROTOCOL)
        self.assertEqual(
            value["contract"],
            {
                "fingerprint": PWN_CRASH_V1_CONTRACT_FINGERPRINT,
                "id": PWN_CRASH_V1_CONTRACT_ID,
                "version": PWN_CRASH_V1_CONTRACT_VERSION,
            },
        )
        self.assertEqual(value["configuration_epoch"], 7)
        self.assertEqual(value["experiment_id"], "E-pwn-crash-1")
        self.assertEqual(value["hypothesis_id"], "H-pwn-crash-1")
        self.assertEqual(
            value["source"],
            {
                "kind": "immutable_primary_elf",
                "locator": "bin/challenge",
                "manifest_sha256": MANIFEST_SHA256,
                "sha256": SOURCE_SHA256,
                "size_bytes": len(SOURCE),
            },
        )
        self.assertEqual(
            value["payload"],
            {
                "artifact_id": "A-builder-run-1",
                "kind": "canonical_artifact",
                "locator": (
                    "artifacts/snapshots/A-builder-run-1.bin"
                ),
                "sha256": hashlib.sha256(POC).hexdigest(),
                "size_bytes": len(POC),
                "source_run_id": "builder-run-1",
            },
        )

        runtime = value["runtime"]
        assert isinstance(runtime, dict)
        self.assertEqual(runtime["network"], "none")
        self.assertIs(runtime["one_shot"], True)
        self.assertEqual(
            runtime["argv_template"],
            list(PWN_CRASH_ARGV_TEMPLATE),
        )
        self.assertEqual(
            runtime["input_destination_locator"],
            PWN_CRASH_INPUT_DESTINATION_LOCATOR,
        )
        self.assertEqual(
            runtime["input_argument"],
            PWN_CRASH_INPUT_ARGUMENT,
        )
        self.assertEqual(runtime["sandbox_method"], "run_clean_proof")
        self.assertEqual(runtime["positive_attempts"], 3)
        self.assertEqual(runtime["control_attempts"], 3)
        self.assertEqual(runtime["target_timeout_seconds"], 5.0)
        self.assertEqual(
            runtime["execution_profile"],
            pwn_crash_v1_contract_descriptor()["execution_profile"],
        )
        self.assertEqual(
            runtime["producer"],
            {
                "capability_name": "pwn_crash_v1",
                "file_sha256": PRODUCER_SHA256,
                "interpreter_path": "/usr/bin/python3",
                "path": "/opt/ctf-templates/pwn/crash_oracle.py",
            },
        )
        plan = runtime["attempt_plan"]
        assert isinstance(plan, list)
        self.assertEqual(
            [item["phase"] for item in plan],
            ["positive"] * 3 + ["control"] * 3,
        )
        self.assertEqual(
            {
                (item["input_sha256"], item["input_size_bytes"])
                for item in plan[3:]
            },
            {(EMPTY_SHA256, 0)},
        )
        self.assertEqual(
            PwnCrashRecipe.from_dict(value),
            recipe,
        )
        self.assertTrue(recipe.canonical_bytes().endswith(b"\n"))

    def test_from_dict_detects_tampering_and_noncanonical_fields(self) -> None:
        recipe = make_recipe()
        cases = (
            (("configuration_epoch",), 8),
            (("experiment_id",), "E-other"),
            (("hypothesis_id",), "H-other"),
            (("source", "sha256"), "f" * 64),
            (("payload", "artifact_id"), "A-other"),
            (("runtime", "network"), "allow"),
            (("runtime", "one_shot"), False),
            (("runtime", "positive_attempts"), 2),
            (("runtime", "sandbox_method"), "run"),
            (("runtime", "producer", "path"), "/tmp/model.py"),
            (
                ("runtime", "producer", "capability_name"),
                "model_tool",
            ),
            (
                ("runtime", "target_timeout_seconds"),
                30.0,
            ),
            (
                ("runtime", "execution_profile", "target_shell"),
                True,
            ),
            (("contract", "version"), 2),
            (("protocol",), "other"),
        )
        for path, replacement in cases:
            altered = copy.deepcopy(recipe.to_dict())
            cursor = altered
            for component in path[:-1]:
                next_value = cursor[component]
                assert isinstance(next_value, dict)
                cursor = next_value
            cursor[path[-1]] = replacement
            with self.subTest(path=path):
                with self.assertRaises(PwnCrashRecipeError):
                    PwnCrashRecipe.from_dict(altered)

        unknown = copy.deepcopy(recipe.to_dict())
        unknown["model_command"] = ["sh", "-c", "exit 0"]
        with self.assertRaisesRegex(
            PwnCrashRecipeError,
            "invalid_recipe_schema",
        ):
            PwnCrashRecipe.from_dict(unknown)

        fixed_tamper = copy.deepcopy(recipe.to_dict())
        fixed_tamper["runtime"]["network"] = "allow"
        content = copy.deepcopy(fixed_tamper)
        del content["recipe_sha256"]
        fixed_tamper["recipe_sha256"] = hashlib.sha256(
            canonical_bytes(content)
        ).hexdigest()
        with self.assertRaises(PwnCrashRecipeError):
            PwnCrashRecipe.from_dict(fixed_tamper)

        surrogate = copy.deepcopy(recipe.to_dict())
        surrogate["experiment_id"] = "\ud800"
        with self.assertRaises(PwnCrashRecipeError):
            PwnCrashRecipe.from_dict(surrogate)

        oversized_tree = copy.deepcopy(recipe.to_dict())
        oversized_tree["runtime"]["attempt_plan"] = [None] * 100_000
        with self.assertRaises(PwnCrashRecipeError):
            PwnCrashRecipe.from_dict(oversized_tree)

    def test_constructor_rejects_unsafe_or_unbound_dynamic_fields(self) -> None:
        invalid = (
            ("configuration_epoch", True),
            ("experiment_id", "bad/experiment"),
            ("hypothesis_id", ""),
            ("primary_elf_locator", "../target"),
            ("primary_elf_locator", "/challenge/target"),
            ("primary_elf_locator", "bin//target"),
            ("source_manifest_sha256", "A" * 64),
            ("source_size_bytes", 0),
            ("payload_artifact_id", "artifact/other"),
            ("payload_source_run_id", ""),
            ("payload_artifact_locator", "../payload"),
            ("payload_size_bytes", 0),
            ("payload_size_bytes", (1024 * 1024) + 1),
            ("image_reference", "ctf os:test"),
            ("image_digest", "ctf-os:test"),
            ("producer_file_sha256", "f" * 63),
            ("producer_file_sha256", "f" * 64),
        )
        for field, value in invalid:
            with self.subTest(field=field, value=value):
                with self.assertRaises(PwnCrashRecipeError):
                    make_recipe(**{field: value})

    def test_fixed_argv_has_no_model_controlled_execution_fields(self) -> None:
        recipe = make_recipe()
        positive = recipe.argv_for_attempt(1)
        control = recipe.argv_for_attempt(6)

        expected_prefix = (
            PWN_CRASH_PRODUCER_INTERPRETER_PATH,
            PWN_CRASH_PRODUCER_PATH,
            "--binary",
            "/challenge/bin/challenge",
            "--input",
            PWN_CRASH_INPUT_ARGUMENT,
        )
        self.assertEqual(positive[:6], expected_prefix)
        self.assertEqual(control[:6], expected_prefix)
        self.assertEqual(positive[positive.index("--phase") + 1], "positive")
        self.assertEqual(control[control.index("--phase") + 1], "control")
        self.assertEqual(
            positive[positive.index("--input-sha256") + 1],
            hashlib.sha256(POC).hexdigest(),
        )
        self.assertEqual(
            control[control.index("--input-sha256") + 1],
            EMPTY_SHA256,
        )
        self.assertEqual(
            control[control.index("--input-size-bytes") + 1],
            "0",
        )
        self.assertEqual(
            positive[positive.index("--recipe-sha256") + 1],
            recipe.recipe_sha256,
        )
        for forbidden in (
            "--command",
            "--target",
            "--signal",
            "--verdict",
            "--shell",
        ):
            self.assertNotIn(forbidden, positive)
        for invalid in (0, 7, True, "1"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    recipe.argv_for_attempt(invalid)


class PwnCrashCapabilityAttestationTests(unittest.TestCase):
    def _report(self) -> dict[str, object]:
        return {
            "attestation_errors": {},
            "attestations": {
                PWN_CRASH_PRODUCER_CAPABILITY_NAME: copy.deepcopy(
                    REQUIRED_MANAGED_ATTESTATIONS[
                        PWN_CRASH_PRODUCER_CAPABILITY_NAME
                    ]
                )
            },
            "available": [PWN_CRASH_PRODUCER_CAPABILITY_NAME],
            "image_digest": IMAGE_DIGEST,
            "ok": True,
        }

    def test_live_probe_normalizes_to_exact_canonical_record(self) -> None:
        recipe = make_recipe()
        result = normalize_pwn_crash_capability_attestation(
            self._report(),
            image_digest=recipe.image_digest,
            recipe_sha256=recipe.recipe_sha256,
        )

        self.assertEqual(
            result.to_dict(),
            {
                "attestation": REQUIRED_MANAGED_ATTESTATIONS[
                    PWN_CRASH_PRODUCER_CAPABILITY_NAME
                ],
                "capability_name": PWN_CRASH_PRODUCER_CAPABILITY_NAME,
                "image_digest": recipe.image_digest,
                "probe_contract": PWN_CRASH_CAPABILITY_PROBE_CONTRACT,
                "recipe_sha256": recipe.recipe_sha256,
                "schema_version": 1,
            },
        )
        self.assertEqual(
            result.canonical_bytes(),
            canonical_bytes(result.to_dict()),
        )
        self.assertEqual(
            result.evidence_sha256,
            hashlib.sha256(result.canonical_bytes()).hexdigest(),
        )
        self.assertEqual(
            PwnCrashCapabilityAttestation.from_dict(
                result.to_dict()
            ),
            result,
        )
        hash(result)

    def test_probe_and_persisted_record_fail_closed(self) -> None:
        recipe = make_recipe()
        cases: tuple[tuple[str, object], ...] = (
            ("ok", False),
            ("image_digest", "sha256:" + ("2" * 64)),
            ("available", []),
            ("attestations", {}),
            (
                "attestation_errors",
                {PWN_CRASH_PRODUCER_CAPABILITY_NAME: "changed"},
            ),
        )
        for field, replacement in cases:
            report = self._report()
            report[field] = replacement
            with self.subTest(field=field):
                with self.assertRaises(
                    PwnCrashCapabilityAttestationError
                ):
                    normalize_pwn_crash_capability_attestation(
                        report,
                        image_digest=recipe.image_digest,
                        recipe_sha256=recipe.recipe_sha256,
                    )

        valid = PwnCrashCapabilityAttestation(
            image_digest=recipe.image_digest,
            recipe_sha256=recipe.recipe_sha256,
        ).to_dict()
        for field, replacement in (
            ("probe_contract", "other"),
            ("recipe_sha256", "2" * 63),
            ("capability_name", "other"),
        ):
            altered = copy.deepcopy(valid)
            altered[field] = replacement
            with self.subTest(persisted_field=field):
                with self.assertRaises(
                    PwnCrashCapabilityAttestationError
                ):
                    PwnCrashCapabilityAttestation.from_dict(altered)


class PwnCrashEvidenceTests(unittest.TestCase):
    def test_six_transport_complete_attempts_delegate_to_semantics(self) -> None:
        recipe = make_recipe()
        values = confirming_payloads(recipe)
        metadata = receipts(recipe, values)

        result = evaluate_pwn_crash_evidence(
            recipe,
            poc_input=POC,
            stdout_payloads=values,
            receipts=metadata,
        )

        self.assertIs(result.verdict, PwnCrashV1Verdict.CONFIRMED)
        self.assertTrue(result.passed)
        self.assertEqual(result.recipe_sha256, recipe.recipe_sha256)
        self.assertEqual(len(result.observations), 6)
        self.assertEqual(
            PwnCrashReceiptMetadata.from_dict(
                metadata[0].to_dict()
            ),
            metadata[0],
        )

    def test_semantic_inconclusive_is_not_a_transport_failure(self) -> None:
        recipe = make_recipe()
        values = tuple(
            observation(
                recipe,
                ordinal,
                termination="exited",
                exit_code=139 if ordinal <= 3 else 0,
                signal_number=None,
            )
            for ordinal in range(1, 7)
        )
        result = evaluate_pwn_crash_evidence(
            recipe,
            poc_input=POC,
            stdout_payloads=values,
            receipts=receipts(recipe, values),
        )
        self.assertIs(result.verdict, PwnCrashV1Verdict.INCONCLUSIVE)
        self.assertEqual(result.reason_code, "no_positive_fault_observed")

    def test_transport_failures_never_reach_semantic_classification(self) -> None:
        recipe = make_recipe()
        values = confirming_payloads(recipe)
        base = list(receipts(recipe, values))
        cases = (
            (
                "producer execution",
                0,
                {"outcome": "failed", "exit_code": 1},
                "producer_execution_unsuccessful",
            ),
            (
                "timeout",
                0,
                {"timed_out": True},
                "producer_execution_timed_out",
            ),
            (
                "not clean",
                0,
                {"clean_workspace": False},
                "clean_workspace_required",
            ),
            (
                "not one shot",
                0,
                {"one_shot": False},
                "one_shot_sandbox_mismatch",
            ),
            (
                "wrong network",
                0,
                {"network": "target"},
                "network_policy_mismatch",
            ),
            (
                "wrong epoch",
                0,
                {"configuration_epoch": 8},
                "configuration_epoch_mismatch",
            ),
            (
                "wrong image",
                0,
                {"image_digest": "sha256:" + ("2" * 64)},
                "image_binding_mismatch",
            ),
            (
                "wrong recipe",
                0,
                {"recipe_sha256": "2" * 64},
                "recipe_binding_mismatch",
            ),
            (
                "wrong producer",
                0,
                {"producer_file_sha256": "2" * 64},
                "producer_binding_mismatch",
            ),
            (
                "capture incomplete",
                0,
                {"stdout_capture_complete": False},
                "stdout_capture_incomplete",
            ),
            (
                "truncation unknown",
                0,
                {"stdout_truncation_known": False},
                "stdout_truncation_unknown",
            ),
            (
                "truncated",
                0,
                {"stdout_truncated": True},
                "stdout_capture_truncated",
            ),
            (
                "stream error",
                0,
                {"stream_capture_error": "read failed"},
                "transport_error",
            ),
            (
                "not durable",
                0,
                {"durable_stdout_artifact_complete": False},
                "durable_stdout_artifact_incomplete",
            ),
            (
                "wrong size",
                0,
                {"stdout_stored_bytes": len(values[0]) - 1},
                "stdout_size_binding_mismatch",
            ),
            (
                "wrong hash",
                0,
                {"stdout_artifact_sha256": "2" * 64},
                "stdout_hash_binding_mismatch",
            ),
            (
                "duplicate run",
                1,
                {"run_id": base[0].run_id},
                "duplicate_run_id",
            ),
            (
                "duplicate request",
                1,
                {"request_sha256": base[0].request_sha256},
                "duplicate_request_sha256",
            ),
            (
                "duplicate execution contract",
                1,
                {
                    "execution_contract_sha256": (
                        base[0].execution_contract_sha256
                    )
                },
                "duplicate_execution_contract_sha256",
            ),
            (
                "different capability artifact",
                1,
                {
                    "capability_attestation_artifact_id": (
                        "A-other-capability"
                    )
                },
                "capability_attestation_binding_mismatch",
            ),
            (
                "wrong capability hash",
                0,
                {"capability_attestation_sha256": "2" * 64},
                "capability_attestation_binding_mismatch",
            ),
        )
        for label, index, changes, code in cases:
            altered = list(base)
            altered[index] = replace(altered[index], **changes)
            with self.subTest(label=label):
                with self.assertRaises(PwnCrashTransportError) as caught:
                    evaluate_pwn_crash_evidence(
                        recipe,
                        poc_input=POC,
                        stdout_payloads=values,
                        receipts=altered,
                    )
                self.assertEqual(caught.exception.code, code)

    def test_counts_payload_binding_and_receipt_schema_fail_closed(self) -> None:
        recipe = make_recipe()
        values = confirming_payloads(recipe)
        metadata = receipts(recipe, values)

        with self.assertRaises(PwnCrashTransportError) as caught:
            evaluate_pwn_crash_evidence(
                recipe,
                poc_input=POC + b"x",
                stdout_payloads=values,
                receipts=metadata,
            )
        self.assertEqual(caught.exception.code, "payload_binding_mismatch")

        for payload_values, receipt_values, code in (
            (
                values[:5],
                metadata,
                "stdout_attempt_count_mismatch",
            ),
            (
                values,
                metadata[:5],
                "receipt_attempt_count_mismatch",
            ),
        ):
            with self.subTest(code=code):
                with self.assertRaises(PwnCrashTransportError) as caught:
                    evaluate_pwn_crash_evidence(
                        recipe,
                        poc_input=POC,
                        stdout_payloads=payload_values,
                        receipts=receipt_values,
                    )
                self.assertEqual(caught.exception.code, code)

        invalid_mapping = metadata[0].to_dict()
        invalid_mapping["command"] = ["sh"]
        with self.assertRaisesRegex(ValueError, "schema"):
            PwnCrashReceiptMetadata.from_dict(invalid_mapping)

        invalid_identifier = metadata[0].to_dict()
        invalid_identifier["receipt_id"] = "\ud800"
        with self.assertRaisesRegex(ValueError, "receipt_id"):
            PwnCrashReceiptMetadata.from_dict(invalid_identifier)


class PwnCrashGateEvaluationTests(unittest.TestCase):
    def test_semantic_result_has_stable_roundtrip_and_hash(self) -> None:
        recipe = make_recipe()
        values = confirming_payloads(recipe)
        result = evaluate_pwn_crash_gate(
            recipe,
            poc_input=POC,
            stdout_payloads=values,
            receipts=receipts(recipe, values),
        )

        self.assertIs(result.verdict, PwnCrashV1Verdict.CONFIRMED)
        self.assertTrue(result.passed)
        self.assertIsNotNone(result.semantic_evaluation)
        self.assertIsNone(result.transport_error)
        self.assertEqual(result.failures, ())
        self.assertEqual(
            PwnCrashGateEvaluation.from_dict(result.to_dict()),
            result,
        )
        self.assertEqual(
            result.evidence_sha256,
            hashlib.sha256(result.canonical_bytes()).hexdigest(),
        )
        hash(result)

    def test_transport_failure_is_an_error_envelope(self) -> None:
        recipe = make_recipe()
        values = confirming_payloads(recipe)
        metadata = list(receipts(recipe, values))
        metadata[0] = replace(
            metadata[0],
            outcome="failed",
            exit_code=1,
        )

        result = evaluate_pwn_crash_gate(
            recipe,
            poc_input=POC,
            stdout_payloads=values,
            receipts=metadata,
        )

        self.assertIs(result.verdict, PwnCrashV1Verdict.ERROR)
        self.assertFalse(result.passed)
        self.assertEqual(
            result.reason_code,
            "transport_producer_execution_unsuccessful",
        )
        self.assertIsNone(result.semantic_evaluation)
        assert result.transport_error is not None
        self.assertEqual(
            result.transport_error.code,
            "producer_execution_unsuccessful",
        )
        self.assertEqual(result.transport_error.ordinal, 1)
        self.assertEqual(
            PwnCrashGateEvaluation.from_dict(result.to_dict()),
            result,
        )

    def test_untrusted_gate_state_rejects_projection_tampering(self) -> None:
        recipe = make_recipe()
        values = confirming_payloads(recipe)
        result = evaluate_pwn_crash_gate(
            recipe,
            poc_input=POC,
            stdout_payloads=values,
            receipts=receipts(recipe, values),
        )
        valid = result.to_dict()

        cases: list[dict[str, object]] = []
        extra = copy.deepcopy(valid)
        extra["evidence_sha256"] = result.evidence_sha256
        cases.append(extra)
        wrong_passed = copy.deepcopy(valid)
        wrong_passed["passed"] = False
        cases.append(wrong_passed)
        both_branches = copy.deepcopy(valid)
        both_branches["transport_error"] = {
            "code": "transport_error",
            "ordinal": 1,
        }
        cases.append(both_branches)
        wrong_stats = copy.deepcopy(valid)
        semantic = wrong_stats["semantic_evaluation"]
        assert isinstance(semantic, dict)
        stats = semantic["stats"]
        assert isinstance(stats, dict)
        stats["control_abnormal_terminations"] = 1
        cases.append(wrong_stats)

        for index, altered in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(PwnCrashGateEvaluationError):
                    PwnCrashGateEvaluation.from_dict(altered)


if __name__ == "__main__":
    unittest.main()
