from __future__ import annotations

import copy
import hashlib
import json
import struct
import unittest
from dataclasses import replace

from ctf_os.contracts.pwn_interaction_v1 import (
    PWN_INTERACTION_V1_CONTRACT_FINGERPRINT,
    PWN_INTERACTION_V1_CONTRACT_ID,
    PWN_INTERACTION_V1_CONTRACT_VERSION,
    PWN_INTERACTION_V1_PROTOCOL,
    PWN_INTERACTION_V1_SENTINEL_REF,
    pwn_interaction_v1_canonical_json_bytes,
)
from ctf_os.engine.pwn_interaction import (
    PWN_INTERACTION_PRODUCER_CONTRACT_ID,
    PWN_INTERACTION_PRODUCER_CONTRACT_VERSION,
    PWN_INTERACTION_PRODUCER_PROTOCOL,
    PWN_INTERACTION_SENTINEL_COMMAND,
    PwnInteractionEvaluationError,
    PwnInteractionExpectedBinding,
    PwnInteractionReplayEvidence,
    evaluate_pwn_interaction_replays,
    parse_pwn_interaction_producer_document,
)


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


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


def _recipe() -> bytes:
    return pwn_interaction_v1_canonical_json_bytes(
        {
            "contract": {
                "id": PWN_INTERACTION_V1_CONTRACT_ID,
                "protocol": PWN_INTERACTION_V1_PROTOCOL,
                "version": PWN_INTERACTION_V1_CONTRACT_VERSION,
            },
            "effect": {
                "address_ref": "effect_address",
                "control_value": 0,
                "sentinel_ref": PWN_INTERACTION_V1_SENTINEL_REF,
                "success_stream": "stdout_or_stderr",
            },
            "schema_version": 1,
            "steps": [
                {
                    "data": {"encoding": "utf8", "value": "ready> "},
                    "id": "expect-ready",
                    "max_read_bytes": 64,
                    "op": "expect_exact",
                },
                {
                    "id": "set-effect",
                    "name": "effect_address",
                    "op": "set_u64",
                    "value": 0x4142434445464748,
                },
                {
                    "id": "pack-effect",
                    "name": "effect_packed",
                    "op": "pack_u64",
                    "value": {"ref": "effect_address"},
                },
                {
                    "id": "send-effect",
                    "mode": "raw",
                    "op": "send",
                    "parts": [{"ref": "effect_packed"}],
                },
                {
                    "id": "send-sentinel-command",
                    "mode": "raw",
                    "op": "send",
                    "parts": [{"ref": PWN_INTERACTION_V1_SENTINEL_REF}],
                },
                {"id": "close", "op": "shutdown_stdin"},
            ],
            "timeout_milliseconds": 30_000,
        }
    )


def _binding(recipe: bytes) -> PwnInteractionExpectedBinding:
    return PwnInteractionExpectedBinding(
        configuration_epoch=17,
        image_digest="sha256:" + "1" * 64,
        preissue_sha256="2" * 64,
        producer_sha256="3" * 64,
        recipe_sha256=_sha(recipe),
        recipe_size_bytes=len(recipe),
        source_manifest_sha256="4" * 64,
        source_sha256="5" * 64,
        source_size_bytes=4096,
    )


def _event(
    sequence: int,
    *,
    direction: str,
    stream: str,
    offset: int,
    data: bytes,
) -> dict[str, object]:
    return {
        "data_hex": data.hex(),
        "direction": direction,
        "offset": offset,
        "sequence": sequence,
        "sha256": _sha(data),
        "size_bytes": len(data),
        "stream": stream,
    }


def _artifact_path(
    binding: PwnInteractionExpectedBinding,
    phase: str,
    ordinal: int,
    name: str,
) -> str:
    return (
        f".ctf/pwn-interaction-v1/{binding.recipe_sha256}/"
        f"{phase}-{ordinal}/{name}"
    )


def _make_replay(
    binding: PwnInteractionExpectedBinding,
    phase: str,
    ordinal: int,
    *,
    target_signal: int = 11,
) -> PwnInteractionReplayEvidence:
    positive = phase == "attack"
    effect_value = 0x4142434445464748 if positive else 0
    packed = struct.pack("<Q", effect_value)
    sentinel = (
        b"CTFOS_PWN_INTERACTION_V1_"
        + hashlib.sha256(f"{phase}-{ordinal}".encode()).hexdigest().encode()
        + b"\n"
    )
    prompt = b"ready> "
    stdout = prompt + (sentinel if positive else b"")
    stderr = b""
    events = [
        _event(
            1,
            direction="receive",
            stream="stdout",
            offset=0,
            data=prompt,
        ),
        _event(
            2,
            direction="send",
            stream="stdin",
            offset=0,
            data=packed,
        ),
        _event(
            3,
            direction="send",
            stream="stdin",
            offset=8,
            data=PWN_INTERACTION_SENTINEL_COMMAND,
        ),
    ]
    if positive:
        events.append(
            _event(
                4,
                direction="receive",
                stream="stdout",
                offset=len(prompt),
                data=sentinel,
            )
        )
    transcript = _canonical(
        {
            "binding": {
                "ordinal": ordinal,
                "phase": phase,
                "recipe_sha256": binding.recipe_sha256,
            },
            "events": events,
            "schema_version": 1,
        }
    )
    dag = _canonical(
        {
            "binding": {
                "ordinal": ordinal,
                "phase": phase,
                "recipe_sha256": binding.recipe_sha256,
            },
            "nodes": [
                {
                    "control_substituted": not positive,
                    "dependencies": ["effect_address"],
                    "name": "effect_address",
                    "op": "set_u64",
                    "sha256": _sha(packed),
                    "size_bytes": 8,
                    "step_id": "set-effect",
                    "type": "u64",
                    "u64": effect_value,
                },
                {
                    "control_substituted": False,
                    "dependencies": [
                        "effect_address",
                        "effect_packed",
                    ],
                    "name": "effect_packed",
                    "op": "pack_u64",
                    "sha256": _sha(packed),
                    "size_bytes": 8,
                    "step_id": "pack-effect",
                    "type": "bytes",
                },
            ],
            "schema_version": 1,
        }
    )
    base_binding = {
        "configuration_epoch": binding.configuration_epoch,
        "image_digest": binding.image_digest,
        "network": "none",
        "ordinal": ordinal,
        "phase": phase,
        "preissue_sha256": binding.preissue_sha256,
        "producer_sha256": binding.producer_sha256,
        "recipe_sha256": binding.recipe_sha256,
        "recipe_size_bytes": binding.recipe_size_bytes,
        "source_manifest_sha256": binding.source_manifest_sha256,
        "source_sha256": binding.source_sha256,
        "source_size_bytes": binding.source_size_bytes,
    }
    observation = {
        "control_substitution_applied": not positive,
        "derivation_dag_path": _artifact_path(
            binding, phase, ordinal, "derivation-dag.json"
        ),
        "derivation_dag_sha256": _sha(dag),
        "derivation_dag_size_bytes": len(dag),
        "elapsed_milliseconds": 7,
        "process_group_cleaned": True,
        "sentinel_occurrences": 1 if positive else 0,
        "sentinel_sha256": _sha(sentinel),
        "stderr_path": _artifact_path(
            binding, phase, ordinal, "target.stderr.bin"
        ),
        "stderr_sha256": _sha(stderr),
        "stderr_size_bytes": len(stderr),
        "stdout_path": _artifact_path(
            binding, phase, ordinal, "target.stdout.bin"
        ),
        "stdout_sha256": _sha(stdout),
        "stdout_size_bytes": len(stdout),
        "target_exit_code": None,
        "target_signal": target_signal,
        "timed_out": False,
        "transcript_path": _artifact_path(
            binding, phase, ordinal, "transcript.json"
        ),
        "transcript_sha256": _sha(transcript),
        "transcript_size_bytes": len(transcript),
    }
    document = _canonical(
        {
            "binding": base_binding,
            "contract": {
                "id": PWN_INTERACTION_PRODUCER_CONTRACT_ID,
                "protocol": PWN_INTERACTION_PRODUCER_PROTOCOL,
                "recipe_contract_fingerprint": (
                    PWN_INTERACTION_V1_CONTRACT_FINGERPRINT
                ),
                "version": PWN_INTERACTION_PRODUCER_CONTRACT_VERSION,
            },
            "observation": observation,
            "reason_code": (
                "unpredictable_sentinel_emitted"
                if positive
                else "sentinel_not_emitted"
            ),
            "schema_version": 1,
            "status": "effect_observed" if positive else "effect_absent",
        }
    )
    return PwnInteractionReplayEvidence(
        document_bytes=document,
        stdout_bytes=stdout,
        stderr_bytes=stderr,
        transcript_bytes=transcript,
        derivation_dag_bytes=dag,
    )


def _fixture() -> tuple[
    bytes,
    PwnInteractionExpectedBinding,
    list[PwnInteractionReplayEvidence],
]:
    recipe = _recipe()
    binding = _binding(recipe)
    evidence = [
        *(_make_replay(binding, "attack", ordinal) for ordinal in range(1, 4)),
        *(_make_replay(binding, "control", ordinal) for ordinal in range(1, 4)),
    ]
    return recipe, binding, evidence


def _mutate_json(
    payload: bytes,
    mutate,
) -> bytes:
    value = json.loads(payload)
    mutate(value)
    return _canonical(value)


def _refresh_artifact(
    evidence: PwnInteractionReplayEvidence,
    name: str,
    payload: bytes,
) -> PwnInteractionReplayEvidence:
    field = (
        "derivation_dag_bytes"
        if name == "derivation_dag"
        else f"{name}_bytes"
    )
    changed = replace(evidence, **{field: payload})

    def mutate(document: dict) -> None:
        document["observation"][f"{name}_sha256"] = _sha(payload)
        document["observation"][f"{name}_size_bytes"] = len(payload)

    return replace(
        changed,
        document_bytes=_mutate_json(changed.document_bytes, mutate),
    )


class PwnInteractionEvaluationTests(unittest.TestCase):
    def test_three_positive_three_control_receipts_pass(self) -> None:
        recipe, binding, evidence = _fixture()
        result = evaluate_pwn_interaction_replays(
            evidence,
            expected_binding=binding,
            recipe_bytes=recipe,
        )
        self.assertTrue(result.passed)
        self.assertEqual(len(result.attack_receipts), 3)
        self.assertEqual(len(result.control_receipts), 3)
        self.assertEqual(
            [receipt.ordinal for receipt in result.attack_receipts],
            [1, 2, 3],
        )
        self.assertTrue(
            all(
                receipt.control_substitution_applied
                for receipt in result.control_receipts
            )
        )
        decoded = json.loads(result.canonical_bytes())
        self.assertEqual(
            decoded["protocol"],
            "ctfos.pwn.interaction.evaluation.v1",
        )
        self.assertEqual(decoded, result.to_dict())

    def test_parser_rejects_noncanonical_contract_and_extra_keys(self) -> None:
        _recipe_bytes, binding, evidence = _fixture()
        valid = evidence[0].document_bytes
        with self.assertRaisesRegex(
            PwnInteractionEvaluationError, "producer_document_invalid"
        ):
            parse_pwn_interaction_producer_document(
                json.dumps(json.loads(valid)).encode(),
                expected_binding=binding,
                expected_phase="attack",
                expected_ordinal=1,
            )
        changed = _mutate_json(
            valid,
            lambda value: value["contract"].__setitem__(
                "protocol", "different"
            ),
        )
        with self.assertRaisesRegex(
            PwnInteractionEvaluationError, "producer_contract_mismatch"
        ):
            parse_pwn_interaction_producer_document(
                changed,
                expected_binding=binding,
                expected_phase="attack",
                expected_ordinal=1,
            )
        extra = _mutate_json(
            valid, lambda value: value.__setitem__("claim", True)
        )
        with self.assertRaisesRegex(
            PwnInteractionEvaluationError,
            "producer_document_schema_invalid",
        ):
            parse_pwn_interaction_producer_document(
                extra,
                expected_binding=binding,
                expected_phase="attack",
                expected_ordinal=1,
            )

    def test_every_binding_authority_is_exact(self) -> None:
        _recipe_bytes, binding, evidence = _fixture()
        mutations = {
            "configuration_epoch": 18,
            "image_digest": "sha256:" + "a" * 64,
            "network": "host",
            "ordinal": 2,
            "phase": "control",
            "preissue_sha256": "a" * 64,
            "producer_sha256": "b" * 64,
            "recipe_sha256": "c" * 64,
            "recipe_size_bytes": binding.recipe_size_bytes + 1,
            "source_manifest_sha256": "d" * 64,
            "source_sha256": "e" * 64,
            "source_size_bytes": binding.source_size_bytes + 1,
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                changed = _mutate_json(
                    evidence[0].document_bytes,
                    lambda value, field=field, replacement=replacement: (
                        value["binding"].__setitem__(field, replacement)
                    ),
                )
                with self.assertRaisesRegex(
                    PwnInteractionEvaluationError,
                    "producer_binding_mismatch",
                ):
                    parse_pwn_interaction_producer_document(
                        changed,
                        expected_binding=binding,
                        expected_phase="attack",
                        expected_ordinal=1,
                    )

    def test_raw_artifact_tamper_truncation_and_path_fail(self) -> None:
        recipe, binding, evidence = _fixture()
        evidence[0] = replace(
            evidence[0], stdout_bytes=evidence[0].stdout_bytes[:-1]
        )
        with self.assertRaisesRegex(
            PwnInteractionEvaluationError, "stdout_artifact_mismatch"
        ):
            evaluate_pwn_interaction_replays(
                evidence,
                expected_binding=binding,
                recipe_bytes=recipe,
            )

        recipe, binding, evidence = _fixture()
        evidence[0] = replace(
            evidence[0],
            document_bytes=_mutate_json(
                evidence[0].document_bytes,
                lambda value: value["observation"].__setitem__(
                    "transcript_path", "elsewhere/transcript.json"
                ),
            ),
        )
        with self.assertRaisesRegex(
            PwnInteractionEvaluationError, "transcript_path_mismatch"
        ):
            evaluate_pwn_interaction_replays(
                evidence,
                expected_binding=binding,
                recipe_bytes=recipe,
            )

    def test_transcript_sequence_offset_hash_and_coverage_fail(self) -> None:
        for label, mutate, code in (
            (
                "sequence",
                lambda value: value["events"][1].__setitem__("sequence", 9),
                "transcript_sequence_invalid",
            ),
            (
                "offset",
                lambda value: value["events"][2].__setitem__("offset", 0),
                "transcript_event_mismatch",
            ),
            (
                "hash",
                lambda value: value["events"][1].__setitem__(
                    "sha256", "0" * 64
                ),
                "transcript_event_mismatch",
            ),
            (
                "coverage",
                lambda value: value["events"].pop(),
                "transcript_stream_mismatch",
            ),
        ):
            with self.subTest(label=label):
                recipe, binding, evidence = _fixture()
                transcript = _mutate_json(
                    evidence[0].transcript_bytes, mutate
                )
                evidence[0] = _refresh_artifact(
                    evidence[0], "transcript", transcript
                )
                with self.assertRaisesRegex(
                    PwnInteractionEvaluationError, code
                ):
                    evaluate_pwn_interaction_replays(
                        evidence,
                        expected_binding=binding,
                        recipe_bytes=recipe,
                    )

        recipe, binding, evidence = _fixture()

        def reorder_before_observation(value: dict) -> None:
            prompt = value["events"].pop(0)
            value["events"].insert(1, prompt)
            for sequence, event in enumerate(value["events"], start=1):
                event["sequence"] = sequence

        transcript = _mutate_json(
            evidence[0].transcript_bytes,
            reorder_before_observation,
        )
        evidence[0] = _refresh_artifact(
            evidence[0], "transcript", transcript
        )
        with self.assertRaisesRegex(
            PwnInteractionEvaluationError, "transcript_send_mismatch"
        ):
            evaluate_pwn_interaction_replays(
                evidence,
                expected_binding=binding,
                recipe_bytes=recipe,
            )

    def test_sentinel_shape_hash_count_and_reuse_fail(self) -> None:
        recipe, binding, evidence = _fixture()
        prompt = b"ready> "
        malformed_sentinel = evidence[0].stdout_bytes[len(prompt) : -1] + b"x"
        malformed = prompt + malformed_sentinel
        evidence[0] = _refresh_artifact(
            evidence[0], "stdout", malformed
        )
        transcript = _mutate_json(
            evidence[0].transcript_bytes,
            lambda value: value["events"][-1].update(
                _event(
                    4,
                    direction="receive",
                    stream="stdout",
                    offset=len(prompt),
                    data=malformed_sentinel,
                )
            ),
        )
        evidence[0] = _refresh_artifact(
            evidence[0], "transcript", transcript
        )
        with self.assertRaisesRegex(
            PwnInteractionEvaluationError, "positive_observation_invalid"
        ):
            evaluate_pwn_interaction_replays(
                evidence,
                expected_binding=binding,
                recipe_bytes=recipe,
            )

        recipe, binding, evidence = _fixture()
        first_hash = json.loads(evidence[0].document_bytes)[
            "observation"
        ]["sentinel_sha256"]
        evidence[3] = replace(
            evidence[3],
            document_bytes=_mutate_json(
                evidence[3].document_bytes,
                lambda value: value["observation"].__setitem__(
                    "sentinel_sha256", first_hash
                ),
            ),
        )
        with self.assertRaisesRegex(
            PwnInteractionEvaluationError, "sentinel_reused"
        ):
            evaluate_pwn_interaction_replays(
                evidence,
                expected_binding=binding,
                recipe_bytes=recipe,
            )

    def test_dag_dependency_value_hash_and_substitution_fail(self) -> None:
        cases = (
            (
                lambda value: value["nodes"][1].__setitem__(
                    "dependencies", ["effect_packed"]
                ),
                "derivation_dag_node_mismatch",
            ),
            (
                lambda value: value["nodes"][0].__setitem__("u64", 1),
                "derivation_dag_node_mismatch",
            ),
            (
                lambda value: value["nodes"][0].__setitem__(
                    "sha256", "0" * 64
                ),
                "derivation_dag_node_mismatch",
            ),
            (
                lambda value: value["nodes"][0].__setitem__(
                    "control_substituted", False
                ),
                "derivation_dag_node_mismatch",
            ),
        )
        for mutate, code in cases:
            recipe, binding, evidence = _fixture()
            dag = _mutate_json(evidence[3].derivation_dag_bytes, mutate)
            evidence[3] = _refresh_artifact(
                evidence[3], "derivation_dag", dag
            )
            with self.assertRaisesRegex(
                PwnInteractionEvaluationError, code
            ):
                evaluate_pwn_interaction_replays(
                    evidence,
                    expected_binding=binding,
                    recipe_bytes=recipe,
                )

    def test_phase_ordinal_terminal_and_process_cleanliness_fail(self) -> None:
        recipe, binding, evidence = _fixture()
        evidence[2] = replace(
            evidence[2],
            document_bytes=_mutate_json(
                evidence[2].document_bytes,
                lambda value: value["binding"].__setitem__(
                    "ordinal", 2
                ),
            ),
        )
        with self.assertRaisesRegex(
            PwnInteractionEvaluationError, "producer_binding_mismatch"
        ):
            evaluate_pwn_interaction_replays(
                evidence,
                expected_binding=binding,
                recipe_bytes=recipe,
            )

        recipe, binding, evidence = _fixture()
        evidence[-1] = _make_replay(
            binding, "control", 3, target_signal=6
        )
        with self.assertRaisesRegex(
            PwnInteractionEvaluationError,
            "terminal_metadata_mismatch",
        ):
            evaluate_pwn_interaction_replays(
                evidence,
                expected_binding=binding,
                recipe_bytes=recipe,
            )

        recipe, binding, evidence = _fixture()
        evidence[0] = replace(
            evidence[0],
            document_bytes=_mutate_json(
                evidence[0].document_bytes,
                lambda value: value["observation"].__setitem__(
                    "process_group_cleaned", False
                ),
            ),
        )
        with self.assertRaisesRegex(
            PwnInteractionEvaluationError, "process_completion_invalid"
        ):
            evaluate_pwn_interaction_replays(
                evidence,
                expected_binding=binding,
                recipe_bytes=recipe,
            )

    def test_recipe_binding_replay_count_and_order_are_fixed(self) -> None:
        recipe, binding, evidence = _fixture()
        with self.assertRaisesRegex(
            PwnInteractionEvaluationError, "recipe_binding_mismatch"
        ):
            evaluate_pwn_interaction_replays(
                evidence,
                expected_binding=binding,
                recipe_bytes=recipe + b"x",
            )
        with self.assertRaisesRegex(
            PwnInteractionEvaluationError, "replay_count_mismatch"
        ):
            evaluate_pwn_interaction_replays(
                evidence[:-1],
                expected_binding=binding,
                recipe_bytes=recipe,
            )
        reordered = copy.copy(evidence)
        reordered[0], reordered[3] = reordered[3], reordered[0]
        with self.assertRaisesRegex(
            PwnInteractionEvaluationError, "producer_binding_mismatch"
        ):
            evaluate_pwn_interaction_replays(
                reordered,
                expected_binding=binding,
                recipe_bytes=recipe,
            )


if __name__ == "__main__":
    unittest.main()
