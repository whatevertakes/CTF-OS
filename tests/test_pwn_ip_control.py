from __future__ import annotations

import hashlib
import unittest
from dataclasses import replace

from ctf_os.contracts.pwn_runtime_snapshot_v1 import (
    PWN_RUNTIME_SNAPSHOT_V1_REGISTER_NAMES,
    PwnRuntimeSnapshotV1Maps,
    PwnRuntimeSnapshotV1Registers,
    build_pwn_runtime_snapshot_v1_result,
)
from ctf_os.engine.pwn_ip_control import (
    PWN_IP_CONTROL_REPLAY_COUNT,
    PWN_IP_CONTROL_TARGET_MASK,
    PWN_IP_CONTROL_TARGET_PREFIX,
    PWN_IP_CONTROL_WIDTH_BYTES,
    PwnIpControlEvidenceError,
    PwnIpControlPlanError,
    PwnIpControlReplayEvidence,
    PwnIpControlResult,
    PwnIpControlStatus,
    derive_pwn_ip_control_plan,
    evaluate_pwn_ip_control,
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
from tests.test_pwn_disclosure import fixture as _disclosure_fixture


ORIGINAL_RIP = 0x0000414243444546
ORIGINAL_RIP_BYTES = ORIGINAL_RIP.to_bytes(8, "little")
CONTROLLED_OFFSET = 40
ORIGINAL_PAYLOAD = (
    b"prefix:" + (b"A" * (CONTROLLED_OFFSET - len(b"prefix:")))
    + ORIGINAL_RIP_BYTES
    + b":suffix"
)
BASE_MAPS = (
    b"0000000000400000-0000000000500000 r-xp "
    b"0000000000000000 00:00 0 /challenge/bin\n"
    b"00007f0000000000-0000800000000000 rw-p "
    b"0000000000000000 00:00 0 [stack]\n"
)
_PARENT_FIXTURE = _disclosure_fixture(
    (b"", b"", b"", b""),
    payload=ORIGINAL_PAYLOAD,
)
PARENT_CRASH_RECIPE = _PARENT_FIXTURE["crash_recipe"]
PARENT_CRASH_EVALUATION = _PARENT_FIXTURE["crash_evaluation"]


def _recipe(
    payload: bytes,
    ordinal: int,
    *,
    parent_evaluation_sha256: str | None = None,
) -> PwnRuntimeSnapshotRecipe:
    parent = PARENT_CRASH_RECIPE
    parent_evaluation = PARENT_CRASH_EVALUATION
    payload_artifact_id = (
        parent.payload_artifact_id
        if ordinal == 0
        else f"A-ip-control-payload-{ordinal}"
    )
    payload_source_run_id = (
        parent.payload_source_run_id
        if ordinal == 0
        else f"R-ip-control-payload-{ordinal}"
    )
    payload_artifact_locator = (
        parent.payload_artifact_locator
        if ordinal == 0
        else f"artifacts/ip-control/{ordinal}/payload.bin"
    )
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
        payload_artifact_id=payload_artifact_id,
        payload_source_run_id=payload_source_run_id,
        payload_artifact_locator=payload_artifact_locator,
        payload_sha256=hashlib.sha256(payload).hexdigest(),
        payload_size_bytes=len(payload),
        parent_crash_recipe_sha256=parent.recipe_sha256,
        parent_crash_evaluation_sha256=(
            parent_evaluation.evidence_sha256
            if parent_evaluation_sha256 is None
            else parent_evaluation_sha256
        ),
        expected_signal_number=11,
        image_reference=parent.image_reference,
        image_digest=parent.image_digest,
        producer_file_sha256=PWN_RUNTIME_SNAPSHOT_PRODUCER_FILE_SHA256,
    )


def _snapshot_stdout(
    recipe: PwnRuntimeSnapshotRecipe,
    rip: int,
    *,
    maps: bytes = BASE_MAPS,
) -> bytes:
    values = []
    for index, name in enumerate(
        PWN_RUNTIME_SNAPSHOT_V1_REGISTER_NAMES
    ):
        value = rip if name == "rip" else index
        values.append((name, f"{value:016x}"))
    result = build_pwn_runtime_snapshot_v1_result(
        registers=PwnRuntimeSnapshotV1Registers(tuple(values)),
        maps=PwnRuntimeSnapshotV1Maps(maps),
        expected_source_manifest_sha256=recipe.source_manifest_sha256,
        expected_source_sha256=recipe.source_sha256,
        expected_source_size_bytes=recipe.source_size_bytes,
        expected_payload_sha256=recipe.payload_sha256,
        expected_payload_size_bytes=recipe.payload_size_bytes,
        expected_parent_crash_recipe_sha256=(
            recipe.parent_crash_recipe_sha256
        ),
        expected_parent_crash_evaluation_sha256=(
            recipe.parent_crash_evaluation_sha256
        ),
        expected_signal_number=recipe.expected_signal_number,
        expected_snapshot_recipe_sha256=recipe.recipe_sha256,
    )
    return result.canonical_bytes()


def _receipt(
    recipe: PwnRuntimeSnapshotRecipe,
    stdout: bytes,
    ordinal: int,
) -> PwnRuntimeSnapshotReceiptMetadata:
    attestation = PwnRuntimeSnapshotCapabilityAttestation(
        image_digest=recipe.image_digest,
        recipe_sha256=recipe.recipe_sha256,
    )
    return PwnRuntimeSnapshotReceiptMetadata(
        receipt_id=f"RCPT-ip-control-{ordinal}",
        run_id=f"R-ip-control-{ordinal}",
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
        request_sha256=hashlib.sha256(
            f"request-{ordinal}".encode()
        ).hexdigest(),
        execution_contract_sha256=hashlib.sha256(
            f"execution-{ordinal}".encode()
        ).hexdigest(),
        capability_attestation_artifact_id=(
            f"A-ip-control-capability-{ordinal}"
        ),
        capability_attestation_sha256=attestation.evidence_sha256,
        producer_capability_name=(
            PWN_RUNTIME_SNAPSHOT_PRODUCER_CAPABILITY_NAME
        ),
        producer_file_sha256=recipe.producer_file_sha256,
        stdout_artifact_id=f"A-ip-control-stdout-{ordinal}",
        stdout_artifact_sha256=hashlib.sha256(stdout).hexdigest(),
        stdout_artifact_size_bytes=len(stdout),
        stderr_artifact_id=f"A-ip-control-stderr-{ordinal}",
        stderr_artifact_sha256=hashlib.sha256(b"").hexdigest(),
        stderr_artifact_size_bytes=0,
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


def _evidence(
    payload: bytes,
    rip: int,
    ordinal: int,
    *,
    maps: bytes = BASE_MAPS,
    parent_evaluation_sha256: str | None = None,
) -> PwnIpControlReplayEvidence:
    recipe = _recipe(
        payload,
        ordinal,
        parent_evaluation_sha256=parent_evaluation_sha256,
    )
    stdout = _snapshot_stdout(recipe, rip, maps=maps)
    receipt = _receipt(recipe, stdout, ordinal)
    evaluation = evaluate_pwn_runtime_snapshot_gate(
        recipe,
        stdout_payload=stdout,
        receipt=receipt,
    )
    return PwnIpControlReplayEvidence(
        ordinal=ordinal,
        payload=payload,
        recipe=recipe,
        evaluation=evaluation,
        receipt=receipt,
        stdout_payload=stdout,
    )


def _valid_evidence() -> tuple[
    PwnIpControlReplayEvidence,
    tuple[PwnIpControlReplayEvidence, ...],
]:
    baseline = _evidence(ORIGINAL_PAYLOAD, ORIGINAL_RIP, 0)
    plan = derive_pwn_ip_control_plan(
        baseline.recipe,
        baseline.evaluation,
        baseline.payload,
    )
    replays = tuple(
        _evidence(payload, target, ordinal)
        for ordinal, (payload, target) in enumerate(
            zip(plan.payloads, plan.targets, strict=True),
            start=1,
        )
    )
    return baseline, replays


def _evaluate(
    *,
    baseline: PwnIpControlReplayEvidence,
    replays: tuple[PwnIpControlReplayEvidence, ...],
):
    return evaluate_pwn_ip_control(
        parent_crash_recipe=PARENT_CRASH_RECIPE,
        parent_crash_evaluation=PARENT_CRASH_EVALUATION,
        baseline=baseline,
        replays=replays,
    )


class PwnIpControlTests(unittest.TestCase):
    def test_plan_uses_three_full_width_engine_derived_variants(
        self,
    ) -> None:
        baseline = _evidence(ORIGINAL_PAYLOAD, ORIGINAL_RIP, 0)
        first = derive_pwn_ip_control_plan(
            baseline.recipe,
            baseline.evaluation,
            baseline.payload,
        )
        second = derive_pwn_ip_control_plan(
            baseline.recipe,
            baseline.evaluation,
            baseline.payload,
        )
        self.assertEqual(first, second)
        self.assertEqual(first.controlled_offset, CONTROLLED_OFFSET)
        self.assertEqual(len(first.targets), PWN_IP_CONTROL_REPLAY_COUNT)
        self.assertEqual(len(set(first.targets)), 3)
        plan_document = first.to_dict()
        self.assertEqual(
            plan_document["recipe_sha256"],
            first.recipe_sha256,
        )
        encoded_plan = str(plan_document).encode()
        for target, payload in zip(
            first.targets,
            first.payloads,
            strict=True,
        ):
            self.assertEqual(
                target & ~PWN_IP_CONTROL_TARGET_MASK,
                PWN_IP_CONTROL_TARGET_PREFIX,
            )
            self.assertEqual(len(payload), len(ORIGINAL_PAYLOAD))
            self.assertEqual(
                payload[:CONTROLLED_OFFSET],
                ORIGINAL_PAYLOAD[:CONTROLLED_OFFSET],
            )
            self.assertEqual(
                payload[
                    CONTROLLED_OFFSET + PWN_IP_CONTROL_WIDTH_BYTES :
                ],
                ORIGINAL_PAYLOAD[
                    CONTROLLED_OFFSET + PWN_IP_CONTROL_WIDTH_BYTES :
                ],
            )
            self.assertEqual(
                payload[
                    CONTROLLED_OFFSET : CONTROLLED_OFFSET
                    + PWN_IP_CONTROL_WIDTH_BYTES
                ],
                target.to_bytes(8, "little"),
            )
            self.assertNotIn(f"{target:016x}".encode(), encoded_plan)
            self.assertNotIn(payload, encoded_plan)

    def test_three_exact_clean_replays_prove_only_narrow_primitive(
        self,
    ) -> None:
        baseline, replays = _valid_evidence()
        result = _evaluate(
            baseline=baseline,
            replays=replays,
        )
        self.assertIs(result.status, PwnIpControlStatus.PROVEN)
        self.assertTrue(result.instruction_pointer_control_proven)
        document = result.to_dict()
        self.assertTrue(
            document["authorities"][
                "instruction_pointer_control_proven"
            ]
        )
        self.assertTrue(document["authorities"]["primitive_proven"])
        for authority in (
            "exploit_proven",
            "flag_proven",
            "proof_satisfied",
            "stage_advance_authorized",
        ):
            self.assertFalse(document["authorities"][authority])
        self.assertEqual(
            PwnIpControlResult.from_dict(document),
            result,
        )
        plan = derive_pwn_ip_control_plan(
            baseline.recipe,
            baseline.evaluation,
            baseline.payload,
        )
        self.assertEqual(
            document["binding"]["plan_recipe_sha256"],
            plan.recipe_sha256,
        )

    def test_result_is_raw_free_and_commits_exact_artifacts(self) -> None:
        baseline, replays = _valid_evidence()
        result = _evaluate(
            baseline=baseline,
            replays=replays,
        )
        encoded = result.canonical_bytes()
        for forbidden in (
            ORIGINAL_RIP_BYTES,
            BASE_MAPS.rstrip(b"\n"),
            b"/challenge/bin",
            b"[stack]",
        ):
            self.assertNotIn(forbidden, encoded)
        for target in derive_pwn_ip_control_plan(
            baseline.recipe,
            baseline.evaluation,
            baseline.payload,
        ).targets:
            self.assertNotIn(f"{target:016x}".encode(), encoded)
            self.assertNotIn(str(target).encode(), encoded)
        self.assertEqual(
            result.baseline.stdout_artifact_id,
            baseline.receipt.stdout_artifact_id,
        )
        self.assertEqual(
            [item.stdout_artifact_id for item in result.replays],
            [
                replay.receipt.stdout_artifact_id
                for replay in replays
            ],
        )

    def test_one_or_partial_marker_match_never_proves(self) -> None:
        baseline, replays = _valid_evidence()
        with self.assertRaisesRegex(
            ValueError,
            "three ordered replay",
        ):
            _evaluate(
                baseline=baseline,
                replays=replays[:1],
            )

        plan = derive_pwn_ip_control_plan(
            baseline.recipe,
            baseline.evaluation,
            baseline.payload,
        )
        partial_rip = (ORIGINAL_RIP & ~0xFF) | (
            plan.targets[0] & 0xFF
        )
        partial = _evidence(plan.payloads[0], partial_rip, 1)
        result = _evaluate(
            baseline=baseline,
            replays=(partial, *replays[1:]),
        )
        self.assertIs(
            result.status,
            PwnIpControlStatus.UNVERIFIABLE,
        )
        self.assertEqual(
            result.reason_code,
            "instruction_pointer_mismatch",
        )
        self.assertFalse(result.instruction_pointer_control_proven)

    def test_payload_must_change_only_exact_eight_byte_slice(self) -> None:
        baseline, replays = _valid_evidence()
        changed = bytearray(replays[0].payload)
        changed[0] ^= 1
        semantic = replays[0].evaluation.semantic_result
        assert semantic is not None
        assert semantic.registers is not None
        observed_rip = int(semantic.registers.to_dict()["rip"], 16)
        bad = _evidence(bytes(changed), observed_rip, 1)
        result = _evaluate(
            baseline=baseline,
            replays=(bad, *replays[1:]),
        )
        self.assertEqual(
            result.reason_code,
            "replay_payload_not_exact_variant",
        )

    def test_reused_run_or_artifact_identity_fails_closed(self) -> None:
        baseline, replays = _valid_evidence()
        duplicated = replace(
            replays[0],
            receipt=replace(
                replays[0].receipt,
                run_id=baseline.receipt.run_id,
            ),
        )
        result = _evaluate(
            baseline=baseline,
            replays=(duplicated, *replays[1:]),
        )
        self.assertEqual(result.reason_code, "replay_identity_reused")

    def test_receipt_tamper_is_recomputed_not_trusted(self) -> None:
        baseline, replays = _valid_evidence()
        tampered = replace(
            replays[0],
            receipt=replace(
                replays[0].receipt,
                clean_workspace=False,
            ),
        )
        result = _evaluate(
            baseline=baseline,
            replays=(tampered, *replays[1:]),
        )
        self.assertEqual(result.reason_code, "replay_gate_changed")
        self.assertFalse(result.instruction_pointer_control_proven)

    def test_capability_attestation_commitment_is_required(self) -> None:
        baseline, replays = _valid_evidence()
        tampered = replace(
            replays[0],
            receipt=replace(
                replays[0].receipt,
                capability_attestation_sha256="f" * 64,
            ),
        )
        # The underlying snapshot gate does not consume the attestation
        # artifact itself.  The primitive oracle must add that exact binding.
        self.assertEqual(
            evaluate_pwn_runtime_snapshot_gate(
                tampered.recipe,
                stdout_payload=tampered.stdout_payload,
                receipt=tampered.receipt,
            ),
            tampered.evaluation,
        )
        result = _evaluate(
            baseline=baseline,
            replays=(tampered, *replays[1:]),
        )
        self.assertEqual(
            result.reason_code,
            "replay_receipt_binding_mismatch",
        )
        self.assertFalse(result.instruction_pointer_control_proven)

    def test_missing_durable_stdout_is_a_stable_fail_closed_error(
        self,
    ) -> None:
        baseline, replays = _valid_evidence()
        malformed = replace(
            replays[0],
            receipt=replace(
                replays[0].receipt,
                stdout_artifact_id=None,
                stdout_artifact_sha256=None,
                stdout_artifact_size_bytes=None,
            ),
        )
        with self.assertRaises(PwnIpControlEvidenceError) as raised:
            _evaluate(
                baseline=baseline,
                replays=(malformed, *replays[1:]),
            )
        self.assertEqual(
            raised.exception.code,
            "durable_stdout_unavailable",
        )

    def test_target_must_be_unmapped_in_each_replay(self) -> None:
        baseline, replays = _valid_evidence()
        target = derive_pwn_ip_control_plan(
            baseline.recipe,
            baseline.evaluation,
            baseline.payload,
        ).targets[0]
        maps = (
            BASE_MAPS.splitlines(keepends=True)[0]
            + (
                f"{target:016x}-{target + 0x1000:016x} rw-p "
                "0000000000000000 00:00 0 [marker]\n"
            ).encode()
            + BASE_MAPS.splitlines(keepends=True)[1]
        )
        mapped = _evidence(replays[0].payload, target, 1, maps=maps)
        result = _evaluate(
            baseline=baseline,
            replays=(mapped, *replays[1:]),
        )
        self.assertEqual(result.reason_code, "target_address_mapped")

    def test_parent_and_source_binding_cannot_change(self) -> None:
        baseline, replays = _valid_evidence()
        changed = _evidence(
            replays[0].payload,
            int(
                replays[0]
                .evaluation.semantic_result.registers.to_dict()["rip"],
                16,
            ),
            1,
            parent_evaluation_sha256="f" * 64,
        )
        result = _evaluate(
            baseline=baseline,
            replays=(changed, *replays[1:]),
        )
        self.assertEqual(
            result.reason_code,
            "cross_replay_binding_mismatch",
        )

    def test_confirmed_parent_crash_and_exact_hashes_are_mandatory(
        self,
    ) -> None:
        baseline, replays = _valid_evidence()
        different_parent = replace(
            PARENT_CRASH_RECIPE,
            payload_sha256="f" * 64,
        )
        result = evaluate_pwn_ip_control(
            parent_crash_recipe=different_parent,
            parent_crash_evaluation=PARENT_CRASH_EVALUATION,
            baseline=baseline,
            replays=replays,
        )
        self.assertEqual(
            result.reason_code,
            "parent_crash_binding_mismatch",
        )

        unconfirmed = _disclosure_fixture(
            (b"", b"", b"", b""),
            payload=ORIGINAL_PAYLOAD,
            crash_confirmed=False,
        )
        result = evaluate_pwn_ip_control(
            parent_crash_recipe=unconfirmed["crash_recipe"],
            parent_crash_evaluation=unconfirmed["crash_evaluation"],
            baseline=baseline,
            replays=replays,
        )
        self.assertEqual(
            result.reason_code,
            "parent_crash_not_confirmed",
        )

    def test_missing_or_ambiguous_baseline_rip_is_inapplicable(
        self,
    ) -> None:
        for payload, reason in (
            (b"A" * 80, "rip_not_payload_derived"),
            (
                b"A" * 8
                + ORIGINAL_RIP_BYTES
                + b"B" * 8
                + ORIGINAL_RIP_BYTES,
                "rip_offset_ambiguous",
            ),
        ):
            with self.subTest(reason=reason):
                baseline = _evidence(payload, ORIGINAL_RIP, 0)
                with self.assertRaises(PwnIpControlPlanError) as raised:
                    derive_pwn_ip_control_plan(
                        baseline.recipe,
                        baseline.evaluation,
                        baseline.payload,
                    )
                self.assertEqual(raised.exception.code, reason)


if __name__ == "__main__":
    unittest.main()
