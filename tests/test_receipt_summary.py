from __future__ import annotations

import hashlib
import json
import stat
import tempfile
import unittest
from pathlib import Path

from ctf_os.engine.receipt_summary import (
    MAX_RECEIPT_STREAM_EVIDENCE_BYTES,
    ReceiptSummaryError,
    build_receipt_preview,
    summarize_stream_snapshot,
)
from ctf_os.sandbox import SandboxResult


class ReceiptSummaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def snapshot(self, payload: bytes, *, name: str = "stdout.log") -> Path:
        path = self.root / name
        path.write_bytes(payload)
        path.chmod(0o400)
        return path

    @staticmethod
    def result(
        *,
        stdout_bytes: int,
        stdout_stored_bytes: int | None = None,
        stdout_truncated: bool | None = None,
        stdout_truncation_known: bool = False,
        stdout_capture_complete: bool = False,
        stdout_summary: str = "",
    ) -> SandboxResult:
        return SandboxResult(
            run_id="run-1",
            status="completed",
            exit_code=0,
            timed_out=False,
            duration_ms=1,
            stdout_summary=stdout_summary,
            stderr_summary="",
            stdout_bytes=stdout_bytes,
            stderr_bytes=0,
            stdout_path="/work/raw/stdout.log",
            stderr_path="/work/raw/stderr.log",
            stdout_stored_bytes=stdout_stored_bytes,
            stderr_stored_bytes=0,
            stdout_limit_bytes=4096,
            stderr_limit_bytes=4096,
            stdout_truncated=stdout_truncated,
            stderr_truncated=False,
            stdout_truncation_known=stdout_truncation_known,
            stderr_truncation_known=True,
            stdout_capture_complete=stdout_capture_complete,
            stderr_capture_complete=True,
        )

    def summarize(
        self,
        path: Path,
        result: SandboxResult,
        *,
        sample_bytes: int = 32,
    ) -> dict[str, object]:
        return summarize_stream_snapshot(
            path,
            artifact_id="A-run-stdout",
            artifact_path="artifacts/snapshots/A-run-stdout.log",
            artifact_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            result=result,
            stream="stdout",
            sample_bytes=sample_bytes,
        )

    def test_verified_head_tail_is_deterministic_and_pointer_backed(
        self,
    ) -> None:
        payload = (
            b"ORACLE route-count=7\n"
            + b"x" * 200
            + b"\nTAIL accepted=false\n"
        )
        path = self.snapshot(payload)
        result = self.result(
            stdout_bytes=len(payload),
            stdout_stored_bytes=len(payload),
            stdout_truncated=False,
            stdout_truncation_known=True,
            stdout_capture_complete=True,
            stdout_summary="UNTRUSTED TRANSPORT TAIL",
        )

        first = self.summarize(path, result)
        second = self.summarize(path, result)

        self.assertEqual(first, second)
        self.assertEqual(first["coverage"], "complete_stream")
        self.assertEqual(first["path"], "artifacts/snapshots/A-run-stdout.log")
        self.assertEqual(
            first["sha256"],
            hashlib.sha256(payload).hexdigest(),
        )
        self.assertEqual(first["head"]["byte_start"], 0)
        self.assertEqual(first["head"]["byte_end"], 32)
        self.assertEqual(
            first["tail"]["byte_start"],
            len(payload) - 32,
        )
        self.assertEqual(first["tail"]["byte_end"], len(payload))
        self.assertEqual(first["omitted_stored_bytes"], len(payload) - 64)
        self.assertIn("ORACLE route-count=7", first["head"]["text"])
        self.assertIn("TAIL accepted=false", first["tail"]["text"])
        self.assertNotIn("UNTRUSTED TRANSPORT TAIL", json.dumps(first))

    def test_credential_label_is_redacted_but_canary_reaches_preview(
        self,
    ) -> None:
        secret = "must-not-reach-model"
        payload = (
            b"RECEIPT_CANARY route-count=7\n"
            + f"Authorization: Bearer {secret}\n".encode()
        )
        path = self.snapshot(payload)
        result = self.result(
            stdout_bytes=len(payload),
            stdout_stored_bytes=len(payload),
            stdout_truncated=False,
            stdout_truncation_known=True,
            stdout_capture_complete=True,
        )

        evidence = self.summarize(path, result, sample_bytes=128)
        serialized = json.dumps(evidence, sort_keys=True)
        preview = build_receipt_preview(
            exit_code=0,
            stdout_bytes=len(payload),
            stderr_bytes=0,
            stdout_evidence=evidence,
        )

        self.assertIn("RECEIPT_CANARY route-count=7", serialized)
        self.assertIn("[REDACTED]", serialized)
        self.assertNotIn(secret, serialized)
        self.assertIn("RECEIPT_CANARY route-count=7", preview)
        self.assertNotIn(secret, preview)
        self.assertLessEqual(len(preview), 160)
        self.assertEqual(evidence["redaction_count"], 1)

    def test_binary_sample_is_omitted_instead_of_base64_encoded(self) -> None:
        payload = b"\x00\xff\x80private-binary\x00"
        path = self.snapshot(payload)
        evidence = self.summarize(
            path,
            self.result(stdout_bytes=len(payload)),
            sample_bytes=64,
        )

        head = evidence["head"]
        self.assertEqual(head["encoding"], "binary-omitted")
        self.assertIn("sample_sha256", head)
        self.assertNotIn("text", head)
        self.assertTrue(evidence["binary_sample_omitted"])
        self.assertNotIn("private-binary", json.dumps(evidence))

    def test_truncated_capture_is_explicitly_a_retained_prefix(self) -> None:
        payload = b"x" * 100
        path = self.snapshot(payload)
        evidence = self.summarize(
            path,
            self.result(
                stdout_bytes=200,
                stdout_stored_bytes=100,
                stdout_truncated=True,
                stdout_truncation_known=True,
                stdout_capture_complete=True,
            ),
        )

        self.assertEqual(evidence["coverage"], "retained_prefix_only")
        self.assertTrue(evidence["truncated"])
        self.assertEqual(evidence["drained_bytes"], 200)
        self.assertEqual(evidence["stored_bytes"], 100)

    def test_legacy_result_never_claims_complete_capture(self) -> None:
        payload = b"legacy output\n"
        path = self.snapshot(payload)
        evidence = self.summarize(
            path,
            self.result(stdout_bytes=len(payload)),
        )

        self.assertEqual(evidence["coverage"], "unknown")
        self.assertFalse(evidence["capture_complete"])
        self.assertFalse(evidence["truncation_known"])
        self.assertIsNone(evidence["truncated"])

    def test_writable_hash_mismatch_and_inconsistent_metadata_fail_closed(
        self,
    ) -> None:
        payload = b"bounded\n"
        path = self.snapshot(payload)
        result = self.result(stdout_bytes=len(payload))

        path.chmod(0o600)
        with self.assertRaisesRegex(ReceiptSummaryError, "writable"):
            self.summarize(path, result)
        path.chmod(0o400)

        with self.assertRaisesRegex(ReceiptSummaryError, "SHA-256"):
            summarize_stream_snapshot(
                path,
                artifact_id="A-run-stdout",
                artifact_path="artifacts/snapshots/A-run-stdout.log",
                artifact_sha256="0" * 64,
                result=result,
                stream="stdout",
            )

        inconsistent = self.result(
            stdout_bytes=len(payload),
            stdout_stored_bytes=len(payload) + 1,
        )
        with self.assertRaisesRegex(
            ReceiptSummaryError,
            "stored byte count",
        ):
            self.summarize(path, inconsistent)

    def test_text_and_serialized_evidence_have_strict_caps(self) -> None:
        payload = (b'quote=" slash=\\\\ ' * 200) + b"\n"
        path = self.snapshot(payload)
        evidence = self.summarize(
            path,
            self.result(stdout_bytes=len(payload)),
            sample_bytes=1024,
        )
        encoded = json.dumps(
            evidence,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")

        self.assertLessEqual(
            len(encoded),
            MAX_RECEIPT_STREAM_EVIDENCE_BYTES,
        )
        self.assertTrue(evidence["head"]["text_truncated"])
        self.assertLessEqual(
            len(
                json.dumps(
                    evidence["head"]["text"],
                    ensure_ascii=True,
                    separators=(",", ":"),
                )
            ),
            512,
        )

    def test_snapshot_mode_remains_read_only(self) -> None:
        path = self.snapshot(b"mode\n")
        self.summarize(path, self.result(stdout_bytes=5))
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)


if __name__ == "__main__":
    unittest.main()
