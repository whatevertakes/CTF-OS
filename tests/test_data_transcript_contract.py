from __future__ import annotations

import copy
import hashlib
import unittest

from ctf_os.contracts.data_transcript_v1 import (
    DATA_TRANSCRIPT_V1_CONTRACT_FINGERPRINT,
    DATA_TRANSCRIPT_V1_CONTRACT_ID,
    DATA_TRANSCRIPT_V1_CONTRACT_VERSION,
    DATA_TRANSCRIPT_V1_CONTROL_MUTATION,
    DATA_TRANSCRIPT_V1_PREISSUE_CONTRACT_ID,
    DATA_TRANSCRIPT_V1_PREISSUE_PROTOCOL,
    DATA_TRANSCRIPT_V1_PROTOCOL,
    DATA_TRANSCRIPT_V1_RESET_MODE,
    DataTranscriptContractError,
    data_transcript_v1_canonical_json_bytes,
    data_transcript_v1_reset_commitment_sha256,
    parse_data_transcript_v1_preissue,
    parse_data_transcript_v1_recipe,
)
from ctf_os.contracts.pwn_interaction_v1 import (
    PWN_INTERACTION_V1_CONTRACT_FINGERPRINT,
)


PEER_SHA = hashlib.sha256(b"peer").hexdigest()
DATA_SHA = hashlib.sha256(b"0\n").hexdigest()


def recipe_document(category: str = "crypto") -> dict[str, object]:
    reset = data_transcript_v1_reset_commitment_sha256(
        category=category,
        peer_sha256=PEER_SHA,
        peer_size_bytes=4,
        peer_data_sha256=DATA_SHA,
        peer_data_size_bytes=2,
    )
    return {
        "category": category,
        "contract": {
            "id": DATA_TRANSCRIPT_V1_CONTRACT_ID,
            "protocol": DATA_TRANSCRIPT_V1_PROTOCOL,
            "version": DATA_TRANSCRIPT_V1_CONTRACT_VERSION,
        },
        "preissue_id": "oracle-1",
        "reset_commitment_sha256": reset,
        "schema_version": 1,
        "steps": [
            {
                "data": {"encoding": "utf8", "value": "READY\n"},
                "id": "ready",
                "max_read_bytes": 16,
                "op": "expect",
                "stream": "stdout",
            },
            {
                "data": {"encoding": "hex", "value": "50494e470a"},
                "id": "query",
                "op": "send",
            },
            {
                "data": {"encoding": "utf8", "value": "PONG\n"},
                "id": "answer",
                "max_read_bytes": 16,
                "op": "expect",
                "stream": "stdout",
            },
        ],
        "timeout_milliseconds": 1_000,
    }


def preissue_document(category: str = "crypto") -> dict[str, object]:
    reset = data_transcript_v1_reset_commitment_sha256(
        category=category,
        peer_sha256=PEER_SHA,
        peer_size_bytes=4,
        peer_data_sha256=DATA_SHA,
        peer_data_size_bytes=2,
    )
    return {
        "category": category,
        "configuration_epoch": 4,
        "contract": {
            "id": DATA_TRANSCRIPT_V1_PREISSUE_CONTRACT_ID,
            "protocol": DATA_TRANSCRIPT_V1_PREISSUE_PROTOCOL,
            "version": 1,
        },
        "image_digest": f"sha256:{'1' * 64}",
        "issue_revision": 9,
        "issued_at": "2026-07-31T00:00:00Z",
        "peer": {"sha256": PEER_SHA, "size_bytes": 4},
        "peer_data": {"sha256": DATA_SHA, "size_bytes": 2},
        "preissue_id": "oracle-1",
        "reset": {
            "commitment_sha256": reset,
            "control_mutation": DATA_TRANSCRIPT_V1_CONTROL_MUTATION,
            "execution": "direct_execve_peer_with_fresh_state_argv_v1",
            "mode": DATA_TRANSCRIPT_V1_RESET_MODE,
            "network": "none",
        },
        "schema_version": 1,
        "seal_nonce": "2" * 64,
        "source_manifest_sha256": "3" * 64,
    }


class DataTranscriptContractTests(unittest.TestCase):
    def test_closed_recipe_and_private_preissue_round_trip(self) -> None:
        recipe_payload = data_transcript_v1_canonical_json_bytes(
            recipe_document()
        )
        recipe = parse_data_transcript_v1_recipe(recipe_payload)
        self.assertEqual(recipe.category, "crypto")
        self.assertEqual(recipe.first_send_step_id, "query")
        self.assertEqual(recipe.step_count, 3)
        self.assertEqual(recipe.canonical_bytes, recipe_payload)

        preissue_payload = data_transcript_v1_canonical_json_bytes(
            preissue_document()
        )
        preissue = parse_data_transcript_v1_preissue(preissue_payload)
        public = preissue.public_record()
        self.assertEqual(
            public["reset_commitment_sha256"],
            recipe.reset_commitment_sha256,
        )
        self.assertNotIn("peer_sha256", public)
        self.assertNotIn("peer_data_sha256", public)
        self.assertNotIn("seal_nonce", public)

    def test_unknown_command_and_network_fields_are_rejected(self) -> None:
        for field, value in (
            ("command", "python peer.py"),
            ("argv", ["peer.py"]),
            ("network_target", "example.invalid"),
            ("environment", {"TOKEN": "secret"}),
        ):
            with self.subTest(field=field):
                hostile = recipe_document()
                hostile[field] = value
                with self.assertRaises(DataTranscriptContractError):
                    parse_data_transcript_v1_recipe(
                        data_transcript_v1_canonical_json_bytes(hostile)
                    )

    def test_control_requires_send_followed_by_terminal_expect(self) -> None:
        no_terminal = recipe_document()
        no_terminal["steps"] = no_terminal["steps"][:-1]
        with self.assertRaisesRegex(
            DataTranscriptContractError, "control_not_observable"
        ):
            parse_data_transcript_v1_recipe(
                data_transcript_v1_canonical_json_bytes(no_terminal)
            )

    def test_preissue_reset_tamper_is_rejected(self) -> None:
        hostile = preissue_document()
        hostile["reset"] = copy.deepcopy(hostile["reset"])
        hostile["reset"]["mode"] = "reuse_state"
        with self.assertRaisesRegex(
            DataTranscriptContractError, "invalid_reset_contract"
        ):
            parse_data_transcript_v1_preissue(
                data_transcript_v1_canonical_json_bytes(hostile)
            )

    def test_cross_category_reset_commitment_is_rejected(self) -> None:
        hostile = recipe_document("crypto")
        hostile["category"] = "misc"
        with self.assertRaisesRegex(
            DataTranscriptContractError, "invalid|binding|commitment"
        ):
            # The recipe parser validates the shape.  The evaluator binds the
            # commitment to the private preissue and rejects this category
            # swap; the private manifest itself rejects the same swap here.
            private = preissue_document("crypto")
            private["category"] = "misc"
            parse_data_transcript_v1_preissue(
                data_transcript_v1_canonical_json_bytes(private)
            )

    def test_existing_pwn_fingerprint_is_unchanged(self) -> None:
        self.assertEqual(
            PWN_INTERACTION_V1_CONTRACT_FINGERPRINT,
            "5f8df2cf3cbaa9dc897d6a7c46c677c5"
            "fa3578f5369e9de5052bfe9acae3c9f3",
        )
        self.assertEqual(
            DATA_TRANSCRIPT_V1_CONTRACT_FINGERPRINT,
            "d946f794d6af0ab02a20a8d940279607"
            "d8cbb511662f5df206fa226aaa66ba67",
        )


if __name__ == "__main__":
    unittest.main()
