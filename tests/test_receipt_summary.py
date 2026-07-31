from __future__ import annotations

import hashlib
import json
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ctf_os.engine.receipt_summary import (
    MAX_RECEIPT_STRUCTURE_JSON_BYTES,
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
        stdout_limit_bytes: int = 4096,
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
            stdout_limit_bytes=stdout_limit_bytes,
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

    def test_json_prefixed_environment_and_known_tokens_are_redacted(
        self,
    ) -> None:
        environment_secret = "engine-environment-secret-value"
        values = (
            "quoted-json-secret",
            environment_secret,
            "ctfd-token-secret",
            "sk-proj-ABCDEFGHIJKLMNOPQRSTUV",
        )
        payload = (
            b'{"api_key":"quoted-json-secret","status":"ok"}\n'
            + f"OPENAI_API_KEY={environment_secret}\n".encode()
            + b"CTFD_TOKEN=ctfd-token-secret\n"
            + b"token sk-proj-ABCDEFGHIJKLMNOPQRSTUV\n"
        )
        path = self.snapshot(payload)
        result = self.result(
            stdout_bytes=len(payload),
            stdout_stored_bytes=len(payload),
            stdout_truncated=False,
            stdout_truncation_known=True,
            stdout_capture_complete=True,
        )

        with mock.patch.dict(
            "os.environ",
            {"CTFOS_ENGINE_TEST_TOKEN": environment_secret},
        ):
            evidence = self.summarize(path, result, sample_bytes=1024)
            preview = build_receipt_preview(
                exit_code=0,
                stdout_bytes=len(payload),
                stderr_bytes=0,
                stdout_evidence=evidence,
            )

        serialized = json.dumps(evidence, sort_keys=True)
        for secret in values:
            self.assertNotIn(secret, serialized)
            self.assertNotIn(secret, preview)
        self.assertIn("[REDACTED]", serialized)
        self.assertGreaterEqual(evidence["redaction_count"], len(values))
        self.assertEqual(
            evidence["sha256"],
            hashlib.sha256(payload).hexdigest(),
        )

    def test_environment_secret_crossing_sample_boundary_is_omitted(
        self,
    ) -> None:
        secret = "environment-secret-crossing-the-tail-boundary"
        payload = b"safe\n" + b"x" * 40 + secret.encode() + b"\n"
        sample_bytes = 24
        tail_start = len(payload) - sample_bytes
        secret_start = payload.index(secret.encode())
        self.assertLess(secret_start, tail_start)
        self.assertLess(tail_start, secret_start + len(secret))
        path = self.snapshot(payload)

        with mock.patch.dict(
            "os.environ",
            {"CTFOS_ENGINE_TEST_TOKEN": secret},
        ):
            evidence = self.summarize(
                path,
                self.result(stdout_bytes=len(payload)),
                sample_bytes=sample_bytes,
            )

        tail = evidence["tail"]
        self.assertEqual(tail["encoding"], "binary-omitted")
        self.assertNotIn("text", tail)
        self.assertNotIn(
            payload[tail_start:].decode(),
            json.dumps(evidence, sort_keys=True),
        )

    def test_tail_omits_authorization_value_split_across_boundary(
        self,
    ) -> None:
        sample_bytes = 24
        secret = b"must-not-leak-across-tail-boundary"
        payload = b"safe\nAuthorization: Bearer " + secret + b"\n"
        tail_start = len(payload) - sample_bytes
        value_start = payload.index(b"Bearer ") + len(b"Bearer ")
        self.assertLess(value_start, tail_start)
        self.assertLess(tail_start, len(payload) - 1)

        path = self.snapshot(payload)
        evidence = self.summarize(
            path,
            self.result(stdout_bytes=len(payload)),
            sample_bytes=sample_bytes,
        )

        tail = evidence["tail"]
        self.assertEqual(tail["byte_start"], tail_start)
        self.assertEqual(tail["byte_end"], len(payload))
        self.assertEqual(tail["encoding"], "binary-omitted")
        self.assertEqual(
            tail["sample_sha256"],
            hashlib.sha256(payload[tail_start:]).hexdigest(),
        )
        self.assertNotIn("text", tail)
        self.assertNotIn(
            payload[tail_start:].decode().strip(),
            json.dumps(evidence, sort_keys=True),
        )

    def test_head_omits_bare_jwt_and_url_userinfo_crossing_boundary(
        self,
    ) -> None:
        jwt = (
            b"eyJ"
            + b"A" * 40
            + b"."
            + b"B" * 40
            + b"."
            + b"C" * 40
        )
        cases = {
            "jwt": b"prefix " + jwt + b"\n" + b"x" * 96,
            "url_userinfo": (
                b"https://alice:super-long-password-value@example.test/path\n"
                + b"x" * 96
            ),
        }
        sample_bytes = 32

        for name, payload in cases.items():
            with self.subTest(name=name):
                path = self.snapshot(payload, name=f"head-{name}.log")
                evidence = self.summarize(
                    path,
                    self.result(stdout_bytes=len(payload)),
                    sample_bytes=sample_bytes,
                )

                head = evidence["head"]
                self.assertEqual(head["byte_start"], 0)
                self.assertEqual(head["byte_end"], sample_bytes)
                self.assertEqual(head["encoding"], "binary-omitted")
                self.assertEqual(
                    head["sample_sha256"],
                    hashlib.sha256(payload[:sample_bytes]).hexdigest(),
                )
                self.assertNotIn("text", head)
                self.assertNotIn(
                    payload[:sample_bytes].decode(),
                    json.dumps(evidence, sort_keys=True),
                )

    def test_invalid_omitted_context_fails_closed_for_text_samples(
        self,
    ) -> None:
        sample_bytes = 16
        payload = (
            b"safe-head-line\n"
            + b"x" * 40
            + b"\xff"
            + b"x" * 40
            + b"\nsafe-tail-line\n"
        )
        path = self.snapshot(payload)

        evidence = self.summarize(
            path,
            self.result(stdout_bytes=len(payload)),
            sample_bytes=sample_bytes,
        )

        for sample_name, expected in (
            ("head", payload[:sample_bytes]),
            ("tail", payload[-sample_bytes:]),
        ):
            sample = evidence[sample_name]
            self.assertEqual(sample["encoding"], "binary-omitted")
            self.assertNotIn("text", sample)
            self.assertEqual(
                sample["sample_sha256"],
                hashlib.sha256(expected).hexdigest(),
            )

    def test_tail_omits_query_and_jwt_split_across_boundary(self) -> None:
        jwt = (
            b"eyJ"
            + b"A" * 40
            + b"."
            + b"B" * 40
            + b"."
            + b"C" * 40
        )
        cases = {
            "query": (
                b"safe\nGET /cb?access_token="
                + b"query-secret-" * 6
                + b" HTTP/1.1\n"
            ),
            "jwt": b"safe\nJWT=" + jwt + b"\n",
        }
        sample_bytes = 32

        for name, payload in cases.items():
            with self.subTest(name=name):
                tail_start = len(payload) - sample_bytes
                path = self.snapshot(payload, name=f"{name}.log")
                evidence = self.summarize(
                    path,
                    self.result(stdout_bytes=len(payload)),
                    sample_bytes=sample_bytes,
                )

                tail = evidence["tail"]
                self.assertEqual(tail["byte_start"], tail_start)
                self.assertEqual(tail["encoding"], "binary-omitted")
                self.assertEqual(
                    tail["sample_sha256"],
                    hashlib.sha256(payload[tail_start:]).hexdigest(),
                )
                self.assertNotIn("text", tail)
                self.assertNotIn(
                    payload[tail_start:].decode().strip(),
                    json.dumps(evidence, sort_keys=True),
                )

    def test_tail_omits_private_key_body_when_begin_is_before_tail(
        self,
    ) -> None:
        tail_block = (
            b"B" * 40
            + b"\n-----END PRIVATE KEY-----\n"
        )
        payload = (
            b"safe\n-----BEGIN PRIVATE KEY-----\n"
            + b"A" * 96
            + b"\n"
            + tail_block
        )
        sample_bytes = len(tail_block)
        tail_start = len(payload) - sample_bytes
        self.assertEqual(payload[tail_start - 1 : tail_start], b"\n")

        path = self.snapshot(payload)
        evidence = self.summarize(
            path,
            self.result(stdout_bytes=len(payload)),
            sample_bytes=sample_bytes,
        )

        tail = evidence["tail"]
        self.assertEqual(tail["byte_start"], tail_start)
        self.assertEqual(tail["byte_end"], len(payload))
        self.assertEqual(tail["encoding"], "binary-omitted")
        self.assertEqual(
            tail["sample_sha256"],
            hashlib.sha256(tail_block).hexdigest(),
        )
        self.assertNotIn("text", tail)
        serialized = json.dumps(evidence, sort_keys=True)
        self.assertNotIn("B" * 20, serialized)
        self.assertNotIn("END PRIVATE KEY", serialized)

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
        self.assertEqual(
            evidence["structured_summary"],
            {
                "version": 1,
                "kind": "binary",
                "scope": "stored_snapshot",
                "bytes_analyzed": len(payload),
                "details_omitted": False,
            },
        )

    def test_json_structure_reports_shape_without_values(self) -> None:
        payload = json.dumps(
            {
                "api_key": "must-not-appear-in-structure",
                "rows": [{"id": 1}, {"id": 2}],
                "success": True,
            },
            separators=(",", ":"),
        ).encode()
        path = self.snapshot(payload)
        evidence = self.summarize(
            path,
            self.result(
                stdout_bytes=len(payload),
                stdout_stored_bytes=len(payload),
                stdout_truncated=False,
                stdout_truncation_known=True,
                stdout_capture_complete=True,
                stdout_limit_bytes=len(payload),
            ),
            sample_bytes=16,
        )

        structure = evidence["structured_summary"]
        self.assertEqual(evidence["schema_version"], 2)
        self.assertEqual(structure["kind"], "json")
        self.assertEqual(structure["scope"], "complete_stream")
        self.assertEqual(structure["top_level"], "object")
        self.assertEqual(
            structure["key_types"],
            {
                "api_key": "string",
                "rows": "array",
                "success": "boolean",
            },
        )
        self.assertNotIn(
            "must-not-appear-in-structure",
            json.dumps(structure, sort_keys=True),
        )

    def test_long_json_reports_shape_and_pointer_without_middle_values(
        self,
    ) -> None:
        opaque_marker = "middle-only-opaque-challenge-payload"
        payload = json.dumps(
            {
                "records": [{"id": 1}, {"id": 2}],
                "opaque": (
                    ("x" * 128_000)
                    + opaque_marker
                    + ("y" * 128_000)
                ),
                "status": "complete",
            },
            separators=(",", ":"),
        ).encode()
        path = self.snapshot(payload)
        evidence = self.summarize(
            path,
            self.result(
                stdout_bytes=len(payload),
                stdout_stored_bytes=len(payload),
                stdout_truncated=False,
                stdout_truncation_known=True,
                stdout_capture_complete=True,
                stdout_limit_bytes=len(payload),
            ),
            sample_bytes=64,
        )

        structure = evidence["structured_summary"]
        serialized = json.dumps(evidence, sort_keys=True)
        self.assertEqual(structure["kind"], "json")
        self.assertEqual(structure["bytes_analyzed"], len(payload))
        self.assertEqual(
            structure["key_types"],
            {
                "opaque": "string",
                "records": "array",
                "status": "string",
            },
        )
        self.assertNotIn(opaque_marker, serialized)
        self.assertEqual(path.read_bytes(), payload)
        self.assertEqual(evidence["path"], "artifacts/snapshots/A-run-stdout.log")
        self.assertEqual(
            evidence["sha256"],
            hashlib.sha256(payload).hexdigest(),
        )
        self.assertLessEqual(
            len(serialized.encode("utf-8")),
            MAX_RECEIPT_STREAM_EVIDENCE_BYTES,
        )

    def test_redacted_json_key_collisions_remain_self_consistent(
        self,
    ) -> None:
        shared_prefix = "A" * 120
        payload = json.dumps(
            {
                shared_prefix + "-first": 1,
                shared_prefix + "-second": "two",
            },
            separators=(",", ":"),
        ).encode()
        path = self.snapshot(payload)
        evidence = self.summarize(
            path,
            self.result(
                stdout_bytes=len(payload),
                stdout_stored_bytes=len(payload),
                stdout_truncated=False,
                stdout_truncation_known=True,
                stdout_capture_complete=True,
            ),
        )

        structure = evidence["structured_summary"]
        self.assertEqual(structure["kind"], "json")
        self.assertEqual(structure["key_count"], 2)
        self.assertEqual(len(structure["key_types"]), 1)
        self.assertEqual(structure["keys_omitted"], 1)
        self.assertEqual(
            structure["key_count"],
            len(structure["key_types"]) + structure["keys_omitted"],
        )

    def test_http_html_structure_reports_status_title_and_tags(self) -> None:
        payload = (
            b"HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n"
            b"<!doctype html><html><head><title>"
            b"Authorization: Bearer must-not-leak"
            b"</title></head><body><a>x</a><a>y</a></body></html>"
        )
        path = self.snapshot(payload)
        evidence = self.summarize(
            path,
            self.result(
                stdout_bytes=len(payload),
                stdout_stored_bytes=len(payload),
                stdout_truncated=False,
                stdout_truncation_known=True,
                stdout_capture_complete=True,
            ),
            sample_bytes=16,
        )

        structure = evidence["structured_summary"]
        self.assertEqual(structure["kind"], "html")
        self.assertEqual(structure["http_status"], "HTTP/1.1 404 Not Found")
        self.assertEqual(structure["title"], "Authorization: [REDACTED]")
        self.assertEqual(structure["tag_counts"]["a"], 2)
        self.assertNotIn("must-not-leak", json.dumps(structure))

    def test_tsv_structure_reports_columns_and_exact_row_count(self) -> None:
        payload = b"name\tstatus\tbytes\nalpha\tok\t12\nbeta\tfail\t99\n"
        path = self.snapshot(payload)
        evidence = self.summarize(
            path,
            self.result(
                stdout_bytes=len(payload),
                stdout_stored_bytes=len(payload),
                stdout_truncated=False,
                stdout_truncation_known=True,
                stdout_capture_complete=True,
            ),
        )

        structure = evidence["structured_summary"]
        self.assertEqual(structure["kind"], "delimited_text")
        self.assertEqual(structure["delimiter"], "tab")
        self.assertEqual(
            structure["columns"],
            ["name", "status", "bytes"],
        )
        self.assertEqual(structure["row_count"], 2)
        self.assertTrue(structure["row_count_exact"])
        self.assertLessEqual(
            len(
                json.dumps(
                    structure,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("ascii")
            ),
            MAX_RECEIPT_STRUCTURE_JSON_BYTES,
        )

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
        self.assertEqual(
            evidence["structured_summary"]["scope"],
            "retained_prefix",
        )
        self.assertFalse(
            evidence["structured_summary"]["line_count_exact"],
        )

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
