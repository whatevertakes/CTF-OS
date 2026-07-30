from __future__ import annotations

import copy
import hashlib
import json
import unittest
from dataclasses import replace

from ctf_os.contracts.pwn_leak_requirement_v1 import (
    PwnLeakRequirementV1Dependency,
    PwnLeakRequirementV1ElfProfile,
    PwnLeakRequirementV1Strategy,
    PwnLeakRequirementV1Verdict,
)
from ctf_os.engine.pwn_disclosure import evaluate_pwn_disclosure
from ctf_os.engine.pwn_leak import (
    PWN_LEAK_REPLAY_COUNT,
    PwnLeakPreissuedReplayIdentity,
    PwnLeakReplayEvidence,
    PwnLeakResult,
    PwnLeakStatus,
    PwnLeakTrustedReplayExpectation,
    build_pwn_leak_trusted_replay_expectation,
    derive_pwn_leak_plan,
    evaluate_pwn_leak,
    evaluate_pwn_leak_strategy_advisory,
    validate_pwn_leak_plan_document,
    validate_pwn_leak_result,
)
from ctf_os.engine.pwn_runtime_snapshot import (
    PWN_RUNTIME_SNAPSHOT_NETWORK_POLICY,
    PWN_RUNTIME_SNAPSHOT_ONE_SHOT,
    PWN_RUNTIME_SNAPSHOT_PRODUCER_CAPABILITY_NAME,
    PWN_RUNTIME_SNAPSHOT_SANDBOX_METHOD,
    PwnRuntimeSnapshotCapabilityAttestation,
    PwnRuntimeSnapshotReceiptMetadata,
    PwnRuntimeSnapshotRecipe,
    evaluate_pwn_runtime_snapshot_gate,
)
from tests.test_pwn_disclosure import (
    MANIFEST_SHA256,
    PAYLOAD,
    SOURCE_SHA256,
    fixture as disclosure_fixture,
    snapshot_document,
)


_BASELINE_STREAMS = (
    b"leak=0x7f4100001234\n",
    b"leak=0x7f4200001234\n",
    b"leak=0x7f4300001234\n",
    b"leak=0x7f4400001234\n",
)
_BASES = (
    0x7F5100000000,
    0x7F5200000000,
    0x7F5300000000,
)
_RELATIVE_OFFSET = 0x1234
_PREEXISTING_ARTIFACT_IDS = tuple(sorted((
    "A-payload",
    "A-crash-capability",
    "A-crash-stdout-1",
    "A-crash-stderr-1",
    "A-crash-stdout-2",
    "A-crash-stderr-2",
    "A-crash-stdout-3",
    "A-crash-stderr-3",
    "A-snapshot-capability",
    "A-snapshot-stdout",
    "A-snapshot-stderr",
)))


def _snapshot_receipt(
    recipe: PwnRuntimeSnapshotRecipe,
    ordinal: int,
    stdout: bytes,
    stderr: bytes,
    *,
    clean_workspace: bool = True,
) -> PwnRuntimeSnapshotReceiptMetadata:
    attestation = PwnRuntimeSnapshotCapabilityAttestation(
        image_digest=recipe.image_digest,
        recipe_sha256=recipe.recipe_sha256,
    )
    return PwnRuntimeSnapshotReceiptMetadata(
        receipt_id=f"receipt-leak-{ordinal}",
        run_id=f"run-leak-{ordinal}",
        outcome="succeeded",
        exit_code=0,
        timed_out=False,
        clean_workspace=clean_workspace,
        one_shot=PWN_RUNTIME_SNAPSHOT_ONE_SHOT,
        sandbox_method=PWN_RUNTIME_SNAPSHOT_SANDBOX_METHOD,
        network=PWN_RUNTIME_SNAPSHOT_NETWORK_POLICY,
        configuration_epoch=recipe.configuration_epoch,
        image_digest=recipe.image_digest,
        recipe_sha256=recipe.recipe_sha256,
        request_sha256=hashlib.sha256(
            f"request-leak-{ordinal}".encode("ascii")
        ).hexdigest(),
        execution_contract_sha256=hashlib.sha256(
            f"execution-leak-{ordinal}".encode("ascii")
        ).hexdigest(),
        capability_attestation_artifact_id=(
            f"A-leak-capability-{ordinal}"
        ),
        capability_attestation_sha256=attestation.evidence_sha256,
        producer_capability_name=(
            PWN_RUNTIME_SNAPSHOT_PRODUCER_CAPABILITY_NAME
        ),
        producer_file_sha256=recipe.producer_file_sha256,
        stdout_artifact_id=f"A-leak-stdout-{ordinal}",
        stdout_artifact_sha256=hashlib.sha256(stdout).hexdigest(),
        stdout_artifact_size_bytes=len(stdout),
        stderr_artifact_id=f"A-leak-stderr-{ordinal}",
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


def _baseline(
    *,
    payload: bytes = PAYLOAD,
) -> tuple[
    object,
    PwnRuntimeSnapshotRecipe,
    bytes,
    object,
]:
    fixture = disclosure_fixture(
        _BASELINE_STREAMS,
        payload=payload,
    )
    disclosure = evaluate_pwn_disclosure(**fixture)
    recipe = fixture["snapshot_recipe"]
    assert isinstance(recipe, PwnRuntimeSnapshotRecipe)
    plan = derive_pwn_leak_plan(
        disclosure,
        recipe,
        payload,
        candidate_byte_offset=5,
        candidate_hex_width=12,
        nonce_offset=32,
        nonce_width_bytes=8,
    )
    return disclosure, recipe, payload, plan


def _maps(
    base: int,
    *,
    pathname: bytes = b"[heap]",
) -> bytes:
    return (
        f"{base:016x}-{base + 0x100000:016x} rw-p "
        "0000000000000000 00:00 0 "
    ).encode("ascii") + pathname + b"\n"


def _replay(
    plan: object,
    baseline_recipe: PwnRuntimeSnapshotRecipe,
    ordinal: int,
    *,
    base: int,
    relative_offset: int = _RELATIVE_OFFSET,
    pathname: bytes = b"[heap]",
    value: int | None = None,
    stderr: bytes | None = None,
    maps_data: bytes | None = None,
    clean_workspace: bool = True,
) -> PwnLeakReplayEvidence:
    payload = plan.payloads[ordinal - 1]
    run_id = f"run-leak-{ordinal}"
    recipe = replace(
        baseline_recipe,
        payload_artifact_id=f"A-leak-input-{ordinal}",
        payload_source_run_id=run_id,
        payload_artifact_locator=f"artifacts/leak-input-{ordinal}.bin",
        payload_sha256=hashlib.sha256(payload).hexdigest(),
        payload_size_bytes=len(payload),
    )
    observed = base + relative_offset if value is None else value
    if stderr is None:
        stderr = f"leak=0x{observed:012x}\n".encode("ascii")
    if maps_data is None:
        maps_data = _maps(base, pathname=pathname)
    stdout = snapshot_document(
        recipe,
        captured=True,
        maps_data=maps_data,
    )
    receipt = _snapshot_receipt(
        recipe,
        ordinal,
        stdout,
        stderr,
        clean_workspace=clean_workspace,
    )
    evaluation = evaluate_pwn_runtime_snapshot_gate(
        recipe,
        stdout_payload=stdout,
        receipt=receipt,
    )
    return PwnLeakReplayEvidence(
        ordinal=ordinal,
        payload=payload,
        recipe=recipe,
        evaluation=evaluation,
        receipt=receipt,
        stdout_payload=stdout,
        stderr_payload=stderr,
    )


def _replays(
    plan: object,
    baseline_recipe: PwnRuntimeSnapshotRecipe,
    *,
    bases: tuple[int, int, int] = _BASES,
    relative_offsets: tuple[int, int, int] = (
        _RELATIVE_OFFSET,
        _RELATIVE_OFFSET,
        _RELATIVE_OFFSET,
    ),
    pathnames: tuple[bytes, bytes, bytes] = (
        b"[heap]",
        b"[heap]",
        b"[heap]",
    ),
) -> tuple[PwnLeakReplayEvidence, ...]:
    return tuple(
        _replay(
            plan,
            baseline_recipe,
            ordinal,
            base=base,
            relative_offset=relative_offset,
            pathname=pathname,
        )
        for ordinal, (base, relative_offset, pathname) in enumerate(
            zip(bases, relative_offsets, pathnames, strict=True),
            start=1,
        )
    )


def _evaluate(
    baseline: tuple[object, PwnRuntimeSnapshotRecipe, bytes, object],
    replays: tuple[PwnLeakReplayEvidence, ...],
    *,
    trusted_replay_expectation: (
        PwnLeakTrustedReplayExpectation | None
    ) = None,
) -> PwnLeakResult:
    disclosure, recipe, payload, plan = baseline
    if trusted_replay_expectation is None:
        trusted_replay_expectation = _trusted_expectation(replays)
    return evaluate_pwn_leak(
        disclosure=disclosure,
        baseline_snapshot_recipe=recipe,
        baseline_payload=payload,
        plan=plan,
        trusted_replay_expectation=trusted_replay_expectation,
        replays=replays,
    )


def _trusted_expectation(
    replays: tuple[PwnLeakReplayEvidence, ...],
) -> PwnLeakTrustedReplayExpectation:
    return build_pwn_leak_trusted_replay_expectation(
        replay_recipes=tuple(replay.recipe for replay in replays),
        preissued_identities=_preissued_identities(replays),
        preexisting_artifact_ids=_PREEXISTING_ARTIFACT_IDS,
    )


def _preissued_identities(
    replays: tuple[PwnLeakReplayEvidence, ...],
) -> tuple[PwnLeakPreissuedReplayIdentity, ...]:
    return tuple(
        PwnLeakPreissuedReplayIdentity(
            ordinal=replay.ordinal,
            run_id=replay.receipt.run_id,
            receipt_id=replay.receipt.receipt_id,
            request_sha256=replay.receipt.request_sha256,
            execution_contract_sha256=(
                replay.receipt.execution_contract_sha256
            ),
            capability_attestation_artifact_id=(
                replay.receipt.capability_attestation_artifact_id
            ),
            stdout_artifact_id=(
                replay.receipt.stdout_artifact_id or ""
            ),
            output_artifact_id=replay.receipt.stderr_artifact_id,
        )
        for replay in replays
    )


class PwnLeakTests(unittest.TestCase):
    def test_three_clean_runtime_varied_replays_prove_only_leak(self) -> None:
        baseline = _baseline()
        _, recipe, _, plan = baseline
        result = _evaluate(baseline, _replays(plan, recipe))

        self.assertIs(result.status, PwnLeakStatus.PROVEN)
        self.assertEqual(
            result.reason_code,
            "runtime_address_disclosure_reproduced",
        )
        self.assertEqual(len(result.replays), PWN_LEAK_REPLAY_COUNT)
        self.assertEqual(result.distinct_mapping_base_count, 3)
        self.assertEqual(result.distinct_runtime_value_count, 3)
        authorities = result.to_dict()["authorities"]
        self.assertEqual(
            {
                key for key, value in authorities.items() if value
            },
            {
                "leak_proven",
            },
        )
        self.assertFalse(authorities["primitive_proven"])
        self.assertFalse(
            authorities["runtime_address_disclosure_proven"]
        )
        self.assertFalse(authorities["exploit_proven"])
        self.assertFalse(authorities["proof_satisfied"])
        self.assertFalse(authorities["auto_submit_authorized"])
        self.assertFalse(authorities["stage_advance_authorized"])

        persisted = result.canonical_bytes()
        self.assertNotIn(b"0x7f", persisted.lower())
        self.assertNotIn(b"[heap]", persisted)
        self.assertNotIn(b"rw-p", persisted)
        self.assertEqual(
            PwnLeakResult.from_dict(
                result.to_dict(),
                expected_result=result,
            ),
            result,
        )
        self.assertEqual(
            validate_pwn_leak_result(
                result.to_dict(),
                expected_result=result,
            ),
            result,
        )

    def test_plan_is_exact_nonce_only_and_raw_free(self) -> None:
        _, recipe, payload, plan = _baseline()
        document = plan.to_dict()
        self.assertEqual(
            validate_pwn_leak_plan_document(document),
            document,
        )
        encoded = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        self.assertNotIn(b"payloads", encoded)
        self.assertNotIn(b"nonces", encoded)
        for nonce, variant in zip(
            plan.nonces,
            plan.payloads,
            strict=True,
        ):
            self.assertEqual(
                variant[: plan.nonce_offset],
                payload[: plan.nonce_offset],
            )
            self.assertEqual(
                variant[
                    plan.nonce_offset + plan.nonce_width_bytes :
                ],
                payload[
                    plan.nonce_offset + plan.nonce_width_bytes :
                ],
            )
            self.assertEqual(
                variant[
                    plan.nonce_offset :
                    plan.nonce_offset + plan.nonce_width_bytes
                ],
                nonce,
            )
            self.assertNotIn(nonce, encoded)
            self.assertNotIn(repr(nonce), repr(plan))
        self.assertEqual(plan.payloads[0], plan.payloads[1])
        self.assertNotEqual(plan.payloads[0], plan.payloads[2])
        replay = _replays(plan, recipe)[0]
        self.assertNotIn(repr(payload), repr(plan))
        self.assertNotIn("[heap]", repr(replay))
        self.assertNotIn("leak=0x", repr(replay))

    def test_fixed_runtime_base_is_unverifiable(self) -> None:
        baseline = _baseline()
        _, recipe, _, plan = baseline
        result = _evaluate(
            baseline,
            _replays(
                plan,
                recipe,
                bases=(_BASES[0], _BASES[0], _BASES[2]),
            ),
        )
        self.assertIs(result.status, PwnLeakStatus.UNVERIFIABLE)
        self.assertEqual(
            result.reason_code,
            "paired_control_runtime_state_not_varied",
        )
        self.assertFalse(result.leak_proven)

    def test_changed_relative_offset_is_unverifiable(self) -> None:
        baseline = _baseline()
        _, recipe, _, plan = baseline
        result = _evaluate(
            baseline,
            _replays(
                plan,
                recipe,
                relative_offsets=(
                    _RELATIVE_OFFSET,
                    _RELATIVE_OFFSET + 1,
                    _RELATIVE_OFFSET,
                ),
            ),
        )
        self.assertEqual(result.reason_code, "relative_offset_changed")

    def test_changed_mapping_identity_is_unverifiable(self) -> None:
        baseline = _baseline()
        _, recipe, _, plan = baseline
        result = _evaluate(
            baseline,
            _replays(
                plan,
                recipe,
                pathnames=(
                    b"[heap]",
                    b"/challenge/libc.so.6",
                    b"[heap]",
                ),
            ),
        )
        self.assertEqual(result.reason_code, "mapping_identity_changed")

    def test_unmapped_value_and_invalid_maps_are_unverifiable(self) -> None:
        for expected, first in (
            (
                "pointer_unmapped",
                _replay,
            ),
            (
                "maps_invalid",
                _replay,
            ),
        ):
            baseline = _baseline()
            _, recipe, _, plan = baseline
            replays = list(_replays(plan, recipe))
            if expected == "pointer_unmapped":
                replays[0] = first(
                    plan,
                    recipe,
                    1,
                    base=_BASES[0],
                    value=_BASES[0] + 0x200000,
                )
            else:
                replays[0] = first(
                    plan,
                    recipe,
                    1,
                    base=_BASES[0],
                    maps_data=b"not-a-proc-map\n",
                )
            with self.subTest(expected=expected):
                result = _evaluate(baseline, tuple(replays))
                self.assertEqual(result.reason_code, expected)

    def test_pointer_at_different_output_locus_is_unverifiable(self) -> None:
        baseline = _baseline()
        _, recipe, _, plan = baseline
        replays = list(_replays(plan, recipe))
        replays[0] = _replay(
            plan,
            recipe,
            1,
            base=_BASES[0],
            stderr=b"prefix=0x7f5100001234\n",
        )
        result = _evaluate(baseline, tuple(replays))
        self.assertEqual(result.reason_code, "stable_locus_missing")

    def test_exact_payload_binding_rejects_outside_nonce_mutation(self) -> None:
        baseline = _baseline()
        _, recipe, _, plan = baseline
        replays = list(_replays(plan, recipe))
        mutated = b"B" + replays[0].payload[1:]
        replays[0] = replace(replays[0], payload=mutated)
        result = _evaluate(baseline, tuple(replays))
        self.assertEqual(result.reason_code, "input_variant_mismatch")

    def test_payload_derived_pointer_is_unverifiable(self) -> None:
        value = _BASES[0] + _RELATIVE_OFFSET
        encodings = (
            f"0x{value:x}".encode("ascii"),
            f"{value:x}".encode("ascii"),
            f"{value:016x}".encode("ascii"),
            str(value).encode("ascii"),
            value.to_bytes(8, "little"),
            value.to_bytes(8, "big"),
        )
        for encoding in encodings:
            with self.subTest(encoding=encoding.hex()):
                payload = encoding + (b"A" * 64)
                baseline = _baseline(payload=payload)
                _, recipe, _, plan = baseline
                result = _evaluate(
                    baseline,
                    _replays(plan, recipe),
                )
                self.assertEqual(
                    result.reason_code,
                    "pointer_payload_derived",
                )

    def test_dirty_receipt_and_reused_execution_identity_fail_closed(
        self,
    ) -> None:
        baseline = _baseline()
        _, recipe, _, plan = baseline

        dirty_replays = list(_replays(plan, recipe))
        dirty_expectation = _trusted_expectation(
            tuple(dirty_replays)
        )
        original = dirty_replays[0]
        dirty_receipt = replace(
            original.receipt,
            clean_workspace=False,
        )
        dirty_evaluation = evaluate_pwn_runtime_snapshot_gate(
            original.recipe,
            stdout_payload=original.stdout_payload,
            receipt=dirty_receipt,
        )
        dirty_replays[0] = replace(
            original,
            receipt=dirty_receipt,
            evaluation=dirty_evaluation,
        )
        dirty = _evaluate(
            baseline,
            tuple(dirty_replays),
            trusted_replay_expectation=dirty_expectation,
        )
        self.assertEqual(
            dirty.reason_code,
            "replay_receipt_binding_mismatch",
        )

        reused_replays = list(_replays(plan, recipe))
        reused_expectation = _trusted_expectation(
            tuple(reused_replays)
        )
        reused_receipt = replace(
            reused_replays[1].receipt,
            request_sha256=(
                reused_replays[0].receipt.request_sha256
            ),
        )
        reused_evaluation = evaluate_pwn_runtime_snapshot_gate(
            reused_replays[1].recipe,
            stdout_payload=reused_replays[1].stdout_payload,
            receipt=reused_receipt,
        )
        reused_replays[1] = replace(
            reused_replays[1],
            receipt=reused_receipt,
            evaluation=reused_evaluation,
        )
        reused = _evaluate(
            baseline,
            tuple(reused_replays),
            trusted_replay_expectation=reused_expectation,
        )
        self.assertEqual(
            reused.reason_code,
            "trusted_replay_expectation_mismatch",
        )

    def test_preissued_expectation_rejects_artifact_id_collision(
        self,
    ) -> None:
        _, recipe, _, plan = _baseline()
        replays = _replays(plan, recipe)
        identities = list(_preissued_identities(replays))
        identities[1] = replace(
            identities[1],
            stdout_artifact_id=identities[0].output_artifact_id,
        )
        with self.assertRaisesRegex(
            ValueError,
            "artifact identity collision",
        ):
            build_pwn_leak_trusted_replay_expectation(
                replay_recipes=tuple(
                    replay.recipe for replay in replays
                ),
                preissued_identities=tuple(identities),
                preexisting_artifact_ids=(
                    _PREEXISTING_ARTIFACT_IDS
                ),
            )

    def test_preissued_expectation_rejects_prior_artifact_collision(
        self,
    ) -> None:
        _, recipe, _, plan = _baseline()
        replays = _replays(plan, recipe)
        identities = list(_preissued_identities(replays))
        identities[0] = replace(
            identities[0],
            capability_attestation_artifact_id=(
                "A-snapshot-capability"
            ),
        )
        with self.assertRaisesRegex(
            ValueError,
            "artifact identity collision",
        ):
            build_pwn_leak_trusted_replay_expectation(
                replay_recipes=tuple(
                    replay.recipe for replay in replays
                ),
                preissued_identities=tuple(identities),
                preexisting_artifact_ids=(
                    _PREEXISTING_ARTIFACT_IDS
                ),
            )

    def test_receipt_must_match_preissued_request_and_artifact_ids(
        self,
    ) -> None:
        baseline = _baseline()
        _, recipe, _, plan = baseline
        replays = list(_replays(plan, recipe))
        expectation = _trusted_expectation(tuple(replays))
        original = replays[0]
        changed_receipt = replace(
            original.receipt,
            receipt_id="receipt-not-preissued",
            stdout_artifact_id="A-stdout-not-preissued",
        )
        changed_evaluation = evaluate_pwn_runtime_snapshot_gate(
            original.recipe,
            stdout_payload=original.stdout_payload,
            receipt=changed_receipt,
        )
        replays[0] = replace(
            original,
            receipt=changed_receipt,
            evaluation=changed_evaluation,
        )
        result = _evaluate(
            baseline,
            tuple(replays),
            trusted_replay_expectation=expectation,
        )
        self.assertEqual(
            result.reason_code,
            "trusted_replay_expectation_mismatch",
        )

    def test_three_replays_are_mandatory_and_gate_is_recomputed(self) -> None:
        baseline = _baseline()
        _, recipe, _, plan = baseline
        replays = _replays(plan, recipe)
        expectation = _trusted_expectation(replays)
        missing = _evaluate(
            baseline,
            replays[:2],
            trusted_replay_expectation=expectation,
        )
        self.assertEqual(
            missing.reason_code,
            "replay_recipe_binding_mismatch",
        )

        changed = list(replays)
        changed[0] = replace(
            changed[0],
            evaluation=changed[1].evaluation,
        )
        result = _evaluate(baseline, tuple(changed))
        self.assertEqual(
            result.reason_code,
            "replay_receipt_binding_mismatch",
        )

    def test_plan_and_result_tampering_are_rejected(self) -> None:
        baseline = _baseline()
        _, recipe, _, plan = baseline
        plan_document = copy.deepcopy(plan.to_dict())
        plan_document["binding"]["nonce_width_bytes"] += 1
        with self.assertRaises(ValueError):
            validate_pwn_leak_plan_document(plan_document)

        result = _evaluate(baseline, _replays(plan, recipe))
        with self.assertRaisesRegex(
            ValueError,
            "requires exact recomputation",
        ):
            PwnLeakResult.from_dict(result.to_dict())

        forged_summary = copy.deepcopy(result.to_dict())
        forged_summary["replays"][1][
            "observed_value_sha256"
        ] = forged_summary["replays"][0]["observed_value_sha256"]
        forged_summary["summary"][
            "distinct_runtime_value_count"
        ] = 2
        with self.assertRaises(ValueError):
            PwnLeakResult.from_dict(
                forged_summary,
                expected_result=result,
            )

        result_document = copy.deepcopy(result.to_dict())
        result_document["authorities"]["primitive_proven"] = True
        with self.assertRaises(ValueError):
            PwnLeakResult.from_dict(
                result_document,
                expected_result=result,
            )

    def test_json_bool_integer_aliases_are_rejected(self) -> None:
        baseline = _baseline()
        _, recipe, _, plan = baseline
        replays = _replays(plan, recipe)
        expectation = _trusted_expectation(replays)
        result = _evaluate(
            baseline,
            replays,
            trusted_replay_expectation=expectation,
        )

        plan_document = copy.deepcopy(plan.to_dict())
        plan_document["schema_version"] = True
        unsigned = dict(plan_document)
        unsigned.pop("recipe_sha256")
        plan_document["recipe_sha256"] = hashlib.sha256(
            (
                json.dumps(
                    unsigned,
                    allow_nan=False,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n"
            ).encode("ascii")
        ).hexdigest()
        with self.assertRaises(ValueError):
            validate_pwn_leak_plan_document(plan_document)

        plan_document = copy.deepcopy(plan.to_dict())
        plan_document["contract"]["version"] = True
        unsigned = dict(plan_document)
        unsigned.pop("recipe_sha256")
        plan_document["recipe_sha256"] = hashlib.sha256(
            (
                json.dumps(
                    unsigned,
                    allow_nan=False,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n"
            ).encode("ascii")
        ).hexdigest()
        with self.assertRaises(ValueError):
            validate_pwn_leak_plan_document(plan_document)

        plan_document = copy.deepcopy(plan.to_dict())
        plan_document["replays"][0]["ordinal"] = True
        unsigned = dict(plan_document)
        unsigned.pop("recipe_sha256")
        plan_document["recipe_sha256"] = hashlib.sha256(
            (
                json.dumps(
                    unsigned,
                    allow_nan=False,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n"
            ).encode("ascii")
        ).hexdigest()
        with self.assertRaises(ValueError):
            validate_pwn_leak_plan_document(plan_document)

        expectation_document = copy.deepcopy(expectation.to_dict())
        expectation_document["schema_version"] = True
        with self.assertRaises(ValueError):
            PwnLeakTrustedReplayExpectation.from_dict(
                expectation_document
            )

        result_document = copy.deepcopy(result.to_dict())
        result_document["schema_version"] = True
        with self.assertRaises(ValueError):
            PwnLeakResult.from_dict(
                result_document,
                expected_result=result,
            )

        result_document = copy.deepcopy(result.to_dict())
        result_document["contract"]["version"] = True
        with self.assertRaises(ValueError):
            PwnLeakResult.from_dict(
                result_document,
                expected_result=result,
            )

        result_document = copy.deepcopy(result.to_dict())
        result_document["authorities"] = {
            key: int(value)
            for key, value in result_document["authorities"].items()
        }
        with self.assertRaises(ValueError):
            PwnLeakResult.from_dict(
                result_document,
                expected_result=result,
            )

    def test_disclosure_without_usable_candidate_cannot_make_plan(
        self,
    ) -> None:
        fixture = disclosure_fixture(
            (
                b"no pointer\n",
                b"no pointer\n",
                b"no pointer\n",
                b"no pointer\n",
            )
        )
        disclosure = evaluate_pwn_disclosure(**fixture)
        with self.assertRaisesRegex(
            ValueError,
            "disclosure_not_eligible",
        ):
            derive_pwn_leak_plan(
                disclosure,
                fixture["snapshot_recipe"],
                PAYLOAD,
                candidate_byte_offset=5,
                candidate_hex_width=12,
                nonce_offset=32,
                nonce_width_bytes=8,
            )

    def test_leak_na_is_only_per_strategy_advisory(self) -> None:
        strategy = PwnLeakRequirementV1Strategy(
            strategy_id="ret2text-relative",
            dependencies=(
                PwnLeakRequirementV1Dependency(
                    dependency_id="primary-target",
                    purpose="control_flow",
                    object_kind="primary_elf",
                    address_mode="relative",
                ),
            ),
        )
        profile = PwnLeakRequirementV1ElfProfile(
            e_type="ET_DYN",
            has_interp=True,
            status="supported",
            source_manifest_sha256=MANIFEST_SHA256,
            source_sha256=SOURCE_SHA256,
            source_size_bytes=4096,
            profile_evidence_sha256=hashlib.sha256(
                b"elf-profile"
            ).hexdigest(),
        )
        advisory = evaluate_pwn_leak_strategy_advisory(
            strategy,
            dependency_id="primary-target",
            elf_profile=profile,
        )
        self.assertIs(
            advisory.verdict,
            PwnLeakRequirementV1Verdict.CONDITIONAL_NOT_APPLICABLE,
        )
        self.assertEqual(
            advisory.reason_code,
            "relative_address_dependency",
        )
        self.assertTrue(
            all(
                value is False
                for value in advisory.to_dict()["claims"].values()
            )
        )
        self.assertFalse(
            advisory.to_dict()["claims"][
                "global_leak_not_applicable_proven"
            ]
        )


if __name__ == "__main__":
    unittest.main()
