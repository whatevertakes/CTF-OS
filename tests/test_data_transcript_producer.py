from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from ctf_os.contracts.data_transcript_v1 import (
    DATA_TRANSCRIPT_V1_CONTRACT_ID,
    DATA_TRANSCRIPT_V1_CONTRACT_VERSION,
    DATA_TRANSCRIPT_V1_PROTOCOL,
    data_transcript_v1_canonical_json_bytes,
    data_transcript_v1_reset_commitment_sha256,
)
from ctf_os.engine.data_transcript import (
    DataTranscriptEvaluationError,
    DataTranscriptExpectedBinding,
    DataTranscriptReplayEvidence,
    evaluate_data_transcript_replays,
)


ROOT = Path(__file__).resolve().parents[1]
PRODUCER = (
    ROOT / "ctf-os-image/templates/common/data_transcript.py"
)
PEER_SOURCE = b"""#!/usr/bin/python3
import pathlib
import sys

state = pathlib.Path(sys.argv[1])
value = int(state.read_text(encoding="ascii").strip())
state.write_text(str(value + 1) + "\\n", encoding="ascii")
sys.stdout.buffer.write(f"STATE:{value}\\n".encode("ascii"))
sys.stdout.buffer.flush()
query = sys.stdin.buffer.readline()
sys.stdout.buffer.write(b"PONG\\n" if query == b"PING\\n" else b"NO\\n")
sys.stdout.buffer.flush()
"""


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _recipe(
    *,
    category: str,
    reset: str,
    timeout_milliseconds: int = 2_000,
    steps: list[dict[str, object]] | None = None,
) -> bytes:
    document = {
        "category": category,
        "contract": {
            "id": DATA_TRANSCRIPT_V1_CONTRACT_ID,
            "protocol": DATA_TRANSCRIPT_V1_PROTOCOL,
            "version": DATA_TRANSCRIPT_V1_CONTRACT_VERSION,
        },
        "preissue_id": "preissued-oracle",
        "reset_commitment_sha256": reset,
        "schema_version": 1,
        "steps": steps
        or [
            {
                "data": {"encoding": "utf8", "value": "STATE:0\n"},
                "id": "state",
                "max_read_bytes": 16,
                "op": "expect",
                "stream": "stdout",
            },
            {
                "data": {"encoding": "utf8", "value": "PING\n"},
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
        "timeout_milliseconds": timeout_milliseconds,
    }
    return data_transcript_v1_canonical_json_bytes(document)


class DataTranscriptProducerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.peer = self.root / "peer"
        self.peer.write_bytes(PEER_SOURCE)
        self.peer.chmod(0o700)
        self.seed = self.root / "seed.bin"
        self.seed.write_bytes(b"0\n")
        self.producer_sha = _sha(PRODUCER.read_bytes())

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _binding(
        self,
        recipe: bytes,
        *,
        category: str = "crypto",
    ) -> tuple[DataTranscriptExpectedBinding, str]:
        reset = data_transcript_v1_reset_commitment_sha256(
            category=category,
            peer_sha256=_sha(PEER_SOURCE),
            peer_size_bytes=len(PEER_SOURCE),
            peer_data_sha256=_sha(b"0\n"),
            peer_data_size_bytes=2,
        )
        expected = DataTranscriptExpectedBinding(
            category=category,
            configuration_epoch=7,
            image_digest=f"sha256:{'1' * 64}",
            preissue_id="preissued-oracle",
            preissue_sha256="2" * 64,
            producer_sha256=self.producer_sha,
            recipe_sha256=_sha(recipe),
            recipe_size_bytes=len(recipe),
            peer_sha256=_sha(PEER_SOURCE),
            peer_size_bytes=len(PEER_SOURCE),
            peer_data_sha256=_sha(b"0\n"),
            peer_data_size_bytes=2,
            reset_commitment_sha256=reset,
        )
        return expected, reset

    def _run_one(
        self,
        recipe: bytes,
        expected: DataTranscriptExpectedBinding,
        phase: str,
        ordinal: int,
        *,
        peer: Path | None = None,
        peer_sha: str | None = None,
        peer_size: int | None = None,
    ) -> tuple[subprocess.CompletedProcess[bytes], DataTranscriptReplayEvidence]:
        recipe_path = self.root / f"recipe-{phase}-{ordinal}.json"
        recipe_path.write_bytes(recipe)
        command = [
            sys.executable,
            str(PRODUCER),
            "--peer",
            str(peer or self.peer),
            "--peer-data",
            str(self.seed),
            "--recipe",
            str(recipe_path),
            "--work-root",
            str(self.root / "work"),
            "--category",
            expected.category,
            "--phase",
            phase,
            "--ordinal",
            str(ordinal),
            "--preissue-id",
            expected.preissue_id,
            "--preissue-sha256",
            expected.preissue_sha256,
            "--producer-sha256",
            expected.producer_sha256,
            "--recipe-sha256",
            expected.recipe_sha256,
            "--recipe-size-bytes",
            str(expected.recipe_size_bytes),
            "--peer-sha256",
            peer_sha or expected.peer_sha256,
            "--peer-size-bytes",
            str(peer_size or expected.peer_size_bytes),
            "--peer-data-sha256",
            expected.peer_data_sha256,
            "--peer-data-size-bytes",
            str(expected.peer_data_size_bytes),
            "--reset-commitment-sha256",
            expected.reset_commitment_sha256,
            "--image-digest",
            expected.image_digest,
            "--configuration-epoch",
            str(expected.configuration_epoch),
        ]
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            timeout=10,
        )
        if not result.stdout:
            return result, DataTranscriptReplayEvidence(
                b"", b"", b"", b"", b""
            )
        document = json.loads(result.stdout)
        observation = document["observation"]
        work = self.root / "work"
        evidence = DataTranscriptReplayEvidence(
            document_bytes=result.stdout,
            stdout_bytes=(work / observation["stdout_path"]).read_bytes(),
            stderr_bytes=(work / observation["stderr_path"]).read_bytes(),
            transcript_bytes=(
                work / observation["transcript_path"]
            ).read_bytes(),
            reset_proof_bytes=(
                work / observation["reset_proof_path"]
            ).read_bytes(),
        )
        return result, evidence

    def test_stateful_peer_is_fresh_for_three_plus_three(self) -> None:
        reset = data_transcript_v1_reset_commitment_sha256(
            category="crypto",
            peer_sha256=_sha(PEER_SOURCE),
            peer_size_bytes=len(PEER_SOURCE),
            peer_data_sha256=_sha(b"0\n"),
            peer_data_size_bytes=2,
        )
        recipe = _recipe(category="crypto", reset=reset)
        expected, _ = self._binding(recipe)
        evidence: list[DataTranscriptReplayEvidence] = []
        for phase in ("positive", "control"):
            for ordinal in range(1, 4):
                result, item = self._run_one(
                    recipe, expected, phase, ordinal
                )
                self.assertEqual(
                    result.returncode,
                    0,
                    result.stderr.decode(errors="replace"),
                )
                self.assertIn(b"STATE:0\n", item.stdout_bytes)
                evidence.append(item)
        evaluation = evaluate_data_transcript_replays(
            evidence,
            expected_binding=expected,
            recipe_bytes=recipe,
        )
        self.assertTrue(evaluation.passed)
        self.assertEqual(len(evaluation.positive_receipts), 3)
        self.assertEqual(len(evaluation.control_receipts), 3)
        self.assertEqual(
            len(
                {
                    item.fresh_instance_nonce_sha256
                    for item in (
                        *evaluation.positive_receipts,
                        *evaluation.control_receipts,
                    )
                }
            ),
            6,
        )

    def test_transcript_tamper_fails_closed(self) -> None:
        reset = data_transcript_v1_reset_commitment_sha256(
            category="crypto",
            peer_sha256=_sha(PEER_SOURCE),
            peer_size_bytes=len(PEER_SOURCE),
            peer_data_sha256=_sha(b"0\n"),
            peer_data_size_bytes=2,
        )
        recipe = _recipe(category="crypto", reset=reset)
        expected, _ = self._binding(recipe)
        evidence = []
        for phase in ("positive", "control"):
            for ordinal in range(1, 4):
                _result, item = self._run_one(
                    recipe, expected, phase, ordinal
                )
                evidence.append(item)
        evidence[0] = DataTranscriptReplayEvidence(
            document_bytes=evidence[0].document_bytes,
            stdout_bytes=evidence[0].stdout_bytes,
            stderr_bytes=evidence[0].stderr_bytes,
            transcript_bytes=evidence[0].transcript_bytes + b" ",
            reset_proof_bytes=evidence[0].reset_proof_bytes,
        )
        with self.assertRaises(DataTranscriptEvaluationError):
            evaluate_data_transcript_replays(
                evidence,
                expected_binding=expected,
                recipe_bytes=recipe,
            )

    def test_symlinked_peer_is_rejected_before_exec(self) -> None:
        reset = data_transcript_v1_reset_commitment_sha256(
            category="crypto",
            peer_sha256=_sha(PEER_SOURCE),
            peer_size_bytes=len(PEER_SOURCE),
            peer_data_sha256=_sha(b"0\n"),
            peer_data_size_bytes=2,
        )
        recipe = _recipe(category="crypto", reset=reset)
        expected, _ = self._binding(recipe)
        linked_peer = self.root / "linked-peer"
        linked_peer.symlink_to(self.peer)
        result, _evidence = self._run_one(
            recipe,
            expected,
            "positive",
            1,
            peer=linked_peer,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"bound_input_unavailable", result.stderr)

    def test_timeout_is_unverifiable(self) -> None:
        sleeper = self.root / "sleeper"
        payload = b"""#!/usr/bin/python3
import sys
import time
sys.stdin.buffer.read(1)
time.sleep(5)
"""
        sleeper.write_bytes(payload)
        sleeper.chmod(0o700)
        reset = data_transcript_v1_reset_commitment_sha256(
            category="crypto",
            peer_sha256=_sha(payload),
            peer_size_bytes=len(payload),
            peer_data_sha256=_sha(b"0\n"),
            peer_data_size_bytes=2,
        )
        recipe = _recipe(
            category="crypto",
            reset=reset,
            timeout_milliseconds=50,
            steps=[
                {
                    "data": {"encoding": "utf8", "value": "X"},
                    "id": "query",
                    "op": "send",
                },
                {
                    "data": {"encoding": "utf8", "value": "Y"},
                    "id": "answer",
                    "max_read_bytes": 1,
                    "op": "expect",
                    "stream": "stdout",
                },
            ],
        )
        expected, _ = self._binding(recipe)
        expected = replace(
            expected,
            peer_sha256=_sha(payload),
            peer_size_bytes=len(payload),
            reset_commitment_sha256=reset,
        )
        result, evidence = self._run_one(
            recipe,
            expected,
            "positive",
            1,
            peer=sleeper,
            peer_sha=_sha(payload),
            peer_size=len(payload),
        )
        self.assertEqual(result.returncode, 1)
        document = json.loads(evidence.document_bytes)
        self.assertEqual(document["reason_code"], "peer_timeout")
        self.assertTrue(document["observation"]["timed_out"])

    def test_stream_truncation_is_unverifiable(self) -> None:
        flood = self.root / "flood"
        payload = b"""#!/usr/bin/python3
import os
import sys
import time
sys.stdin.buffer.read(1)
chunk = b"A" * 65536
for _ in range(18):
    os.write(1, chunk)
time.sleep(5)
"""
        flood.write_bytes(payload)
        flood.chmod(0o700)
        reset = data_transcript_v1_reset_commitment_sha256(
            category="misc",
            peer_sha256=_sha(payload),
            peer_size_bytes=len(payload),
            peer_data_sha256=_sha(b"0\n"),
            peer_data_size_bytes=2,
        )
        recipe = _recipe(
            category="misc",
            reset=reset,
            timeout_milliseconds=2_000,
            steps=[
                {
                    "data": {"encoding": "utf8", "value": "X"},
                    "id": "query",
                    "op": "send",
                },
                {
                    "data": {"encoding": "utf8", "value": "Y"},
                    "id": "answer",
                    "max_read_bytes": 1,
                    "op": "expect",
                    "stream": "stderr",
                },
            ],
        )
        base, _ = self._binding(recipe, category="misc")
        expected = replace(
            base,
            peer_sha256=_sha(payload),
            peer_size_bytes=len(payload),
            reset_commitment_sha256=reset,
        )
        result, evidence = self._run_one(
            recipe,
            expected,
            "positive",
            1,
            peer=flood,
            peer_sha=_sha(payload),
            peer_size=len(payload),
        )
        self.assertEqual(result.returncode, 1)
        document = json.loads(evidence.document_bytes)
        self.assertEqual(document["reason_code"], "stream_truncated")
        self.assertTrue(document["observation"]["truncated"])

    def test_cross_category_expected_binding_is_rejected(self) -> None:
        reset = data_transcript_v1_reset_commitment_sha256(
            category="crypto",
            peer_sha256=_sha(PEER_SOURCE),
            peer_size_bytes=len(PEER_SOURCE),
            peer_data_sha256=_sha(b"0\n"),
            peer_data_size_bytes=2,
        )
        recipe = _recipe(category="crypto", reset=reset)
        expected, _ = self._binding(recipe)
        wrong = replace(expected, category="misc")
        with self.assertRaisesRegex(
            DataTranscriptEvaluationError,
            "recipe_preissue_binding_mismatch",
        ):
            evaluate_data_transcript_replays(
                (),
                expected_binding=wrong,
                recipe_bytes=recipe,
            )


if __name__ == "__main__":
    unittest.main()
