from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPOSITORY = Path(__file__).resolve().parent.parent
SCRIPT = REPOSITORY / "scripts" / "check-release-acceptance.py"
SPEC = importlib.util.spec_from_file_location("ctfos_release_acceptance", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load release acceptance runner")
release = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release
SPEC.loader.exec_module(release)


IMAGE_DIGEST = "sha256:" + "a" * 64
COMMIT = "b" * 40
SOURCE = {"clean": True, "commit": COMMIT}
BINDING = {"image": "ctf-os:core", "image_digest": IMAGE_DIGEST}
IMAGE = {
    "digest": IMAGE_DIGEST,
    "inspected_id": IMAGE_DIGEST,
    "tag": "ctf-os:core",
    "tag_inspected_id": IMAGE_DIGEST,
}


def _stream_metadata(payload: bytes) -> dict[str, object]:
    return {
        "captured_bytes": len(payload),
        "captured_sha256": release._sha256(payload),
        "locator": "fake.log",
        "sha256": release._sha256(payload),
        "stream_bytes": len(payload),
        "truncated": False,
    }


def _outcome(
    identifier: str,
    *,
    stdout: bytes = b"",
    status: str = "passed",
    exit_code: int | None = 0,
) -> object:
    return release.CommandOutcome(
        record={
            "command": [identifier],
            "duration_ms": 0,
            "exit_code": exit_code,
            "failure_reason": None if status == "passed" else "exit_1",
            "id": identifier,
            "status": status,
            "stderr": _stream_metadata(b""),
            "stdout": _stream_metadata(stdout),
            "timed_out": False,
        },
        stdout=stdout,
    )


def _doctor_stdout(*, warnings: list[object] | None = None) -> bytes:
    return release._canonical_json(
        {
            "image": {
                "configured_digest": IMAGE_DIGEST,
                "execution_available": True,
                "id": IMAGE_DIGEST,
                "pin_status": "matched",
                "pinned_image": {"id": IMAGE_DIGEST},
            },
            "managed_capabilities": {
                "image_digest": IMAGE_DIGEST,
                "ok": True,
                "status": "ready",
            },
            "ok": True,
            "warnings": [] if warnings is None else warnings,
        }
    )


class ReleaseAcceptanceRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.artifact_root = self.root / "release-acceptance" / "run-test"
        self.matrix_root = self.root / "release-matrix"

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _arguments(self) -> argparse.Namespace:
        return argparse.Namespace(
            image_digest=IMAGE_DIGEST,
            output_dir=None,
            timeout_seconds=60,
        )

    def _matrix_stdout(self) -> bytes:
        report_path = self.matrix_root / "run-test" / "report.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        tasks = []
        for identifier, (categories, network_contract, script) in (
            release.EXPECTED_TASKS.items()
        ):
            tasks.append(
                {
                    "categories": list(categories),
                    "command": [
                        sys.executable,
                        str(REPOSITORY / script),
                        "--image-digest",
                        IMAGE_DIGEST,
                    ],
                    "id": identifier,
                    "network_contract": network_contract,
                    "status": "passed",
                    "summary_sha256": release._sha256(identifier.encode()),
                }
            )
        report_payload = release._canonical_json(
            {
                "categories_passed": list(release.EXPECTED_CATEGORIES),
                "command_contract_sha256": (
                    release._expected_matrix_contract_sha256()
                ),
                "image": {
                    "digest": IMAGE_DIGEST,
                    "inspected_id": IMAGE_DIGEST,
                },
                "ok": True,
                "policy": {
                    "automatic_challenge_selection": False,
                    "automatic_challenge_switch": False,
                    "automatic_submission": False,
                    "model_requests": False,
                    "remote_ctf_requests": False,
                    "source_and_image_stable": True,
                },
                "protocol": "ctfos.all_category_release_matrix.v1",
                "schema_version": 1,
                "source": dict(SOURCE),
                "tasks": tasks,
            }
        )
        report_path.write_bytes(report_payload)
        return release._canonical_json(
            {
                "ok": True,
                "report": str(report_path.resolve()),
                "report_sha256": release._sha256(report_payload),
            }
        )

    def _successful_commands(self):
        matrix_stdout = self._matrix_stdout()

        def fake_run(
            identifier: str,
            _command: object,
            *,
            artifact_root: Path,
            timeout_seconds: int,
        ) -> object:
            self.assertEqual(artifact_root, self.artifact_root)
            self.assertEqual(timeout_seconds, 60)
            if identifier == "fresh-clone":
                return _outcome(identifier)
            if identifier == "doctor":
                return _outcome(identifier, stdout=_doctor_stdout())
            if identifier == "matrix":
                return _outcome(identifier, stdout=matrix_stdout)
            self.fail(f"unexpected release acceptance command: {identifier}")

        return fake_run

    def _run_with_preflight(
        self,
        *,
        source_side_effect: object = None,
        image_side_effect: object = None,
        binding_side_effect: object = None,
        run_command: object | None = None,
    ) -> tuple[Path, dict[str, object]]:
        if source_side_effect is None:
            source_side_effect = [dict(SOURCE), dict(SOURCE)]
        if image_side_effect is None:
            image_side_effect = [dict(IMAGE), dict(IMAGE)]
        if binding_side_effect is None:
            binding_side_effect = [dict(BINDING), dict(BINDING)]
        if run_command is None:
            run_command = self._successful_commands()
        self.artifact_root.mkdir(parents=True, exist_ok=True)
        with (
            mock.patch.object(
                release,
                "_new_artifact_root",
                return_value=self.artifact_root,
            ),
            mock.patch.object(
                release,
                "MATRIX_ARTIFACT_PARENT",
                self.matrix_root,
            ),
            mock.patch.object(
                release,
                "_configured_image_binding",
                side_effect=binding_side_effect,
            ),
            mock.patch.object(
                release,
                "_source_snapshot",
                side_effect=source_side_effect,
            ),
            mock.patch.object(
                release,
                "_inspect_image_binding",
                side_effect=image_side_effect,
            ),
            mock.patch.object(
                release,
                "_run_command",
                side_effect=run_command,
            ),
        ):
            return release.run_acceptance(self._arguments())

    def test_dirty_source_preflight_fails_closed_and_skips_commands(self) -> None:
        receipt_path, report = self._run_with_preflight(
            source_side_effect=release.ReleaseAcceptanceError(
                "release acceptance requires a clean source tree"
            )
        )

        self.assertFalse(report["ok"])
        self.assertFalse(report["preflight"]["ok"])
        self.assertIn("clean source tree", report["preflight"]["failure_reason"])
        self.assertEqual(
            {record["status"] for record in report["commands"].values()},
            {"skipped"},
        )
        self.assertEqual(json.loads(receipt_path.read_text()), report)

    def test_configured_pin_mismatch_fails_before_source_or_commands(
        self,
    ) -> None:
        with mock.patch.object(
            release,
            "_new_artifact_root",
            return_value=self.artifact_root,
        ), mock.patch.object(
            release,
            "_configured_image_binding",
            side_effect=release.ReleaseAcceptanceError("configured pin mismatch"),
        ), mock.patch.object(
            release,
            "_source_snapshot",
        ) as source_snapshot, mock.patch.object(
            release,
            "_run_command",
        ) as run_command:
            self.artifact_root.mkdir(parents=True)
            receipt_path, report = release.run_acceptance(self._arguments())

        self.assertFalse(report["ok"])
        self.assertIn("pin mismatch", report["preflight"]["failure_reason"])
        source_snapshot.assert_not_called()
        run_command.assert_not_called()
        self.assertTrue(receipt_path.is_file())

    def test_command_failure_fails_closed_and_does_not_run_later_gates(self) -> None:
        calls: list[str] = []

        def failed_fresh(
            identifier: str,
            _command: object,
            **_kwargs: object,
        ) -> object:
            calls.append(identifier)
            return _outcome(identifier, status="failed", exit_code=1)

        _receipt_path, report = self._run_with_preflight(run_command=failed_fresh)

        self.assertEqual(calls, ["fresh-clone"])
        self.assertFalse(report["ok"])
        self.assertEqual(report["commands"]["fresh_clone"]["status"], "failed")
        self.assertEqual(report["commands"]["doctor"]["status"], "skipped")
        self.assertEqual(report["commands"]["matrix"]["status"], "skipped")
        self.assertTrue(report["policy"]["source_image_pin_runtime_stable"])

    def test_doctor_warning_is_a_release_failure_and_blocks_matrix(self) -> None:
        calls: list[str] = []

        def warning_doctor(
            identifier: str,
            _command: object,
            **_kwargs: object,
        ) -> object:
            calls.append(identifier)
            if identifier == "fresh-clone":
                return _outcome(identifier)
            if identifier == "doctor":
                return _outcome(
                    identifier,
                    stdout=_doctor_stdout(warnings=["capacity warning"]),
                )
            self.fail("matrix must not run after doctor warnings")

        _receipt_path, report = self._run_with_preflight(
            run_command=warning_doctor
        )

        self.assertEqual(calls, ["fresh-clone", "doctor"])
        self.assertFalse(report["ok"])
        self.assertEqual(report["commands"]["doctor"]["status"], "failed")
        self.assertFalse(report["commands"]["doctor"]["validation"]["ok"])
        self.assertEqual(report["commands"]["matrix"]["status"], "skipped")

    def test_negative_matrix_envelope_fails_closed(self) -> None:
        valid_envelope = json.loads(self._matrix_stdout())
        valid_envelope["ok"] = False
        matrix_stdout = release._canonical_json(valid_envelope)

        def negative_matrix(
            identifier: str,
            _command: object,
            **_kwargs: object,
        ) -> object:
            if identifier == "fresh-clone":
                return _outcome(identifier)
            if identifier == "doctor":
                return _outcome(identifier, stdout=_doctor_stdout())
            if identifier == "matrix":
                return _outcome(identifier, stdout=matrix_stdout)
            self.fail(f"unexpected command: {identifier}")

        _receipt_path, report = self._run_with_preflight(
            run_command=negative_matrix
        )

        self.assertFalse(report["ok"])
        self.assertEqual(report["commands"]["matrix"]["status"], "failed")
        self.assertIsNone(report["matrix_report"])

    def test_matrix_task_contract_mismatch_fails_closed(self) -> None:
        envelope = json.loads(self._matrix_stdout())
        report_path = Path(envelope["report"])
        matrix_report = json.loads(report_path.read_text())
        matrix_report["tasks"][0]["network_contract"] = "unexpected"
        payload = release._canonical_json(matrix_report)
        report_path.write_bytes(payload)
        envelope["report_sha256"] = release._sha256(payload)
        matrix_stdout = release._canonical_json(envelope)

        def mismatched_matrix(
            identifier: str,
            _command: object,
            **_kwargs: object,
        ) -> object:
            if identifier == "fresh-clone":
                return _outcome(identifier)
            if identifier == "doctor":
                return _outcome(identifier, stdout=_doctor_stdout())
            if identifier == "matrix":
                return _outcome(identifier, stdout=matrix_stdout)
            self.fail(f"unexpected command: {identifier}")

        _receipt_path, report = self._run_with_preflight(
            run_command=mismatched_matrix
        )

        self.assertFalse(report["ok"])
        self.assertEqual(report["commands"]["matrix"]["status"], "failed")

    def test_postflight_source_drift_invalidates_an_otherwise_passing_run(self) -> None:
        changed_source = {"clean": True, "commit": "c" * 40}
        _receipt_path, report = self._run_with_preflight(
            source_side_effect=[dict(SOURCE), changed_source]
        )

        self.assertFalse(report["ok"])
        self.assertEqual(report["commands"]["matrix"]["status"], "passed")
        self.assertFalse(report["policy"]["source_image_pin_runtime_stable"])
        self.assertEqual(
            report["policy"]["stability_error"],
            "source_or_image_or_pin_or_runtime_changed",
        )

    def test_good_run_writes_strict_receipt_schema(self) -> None:
        receipt_path, report = self._run_with_preflight()

        self.assertTrue(report["ok"], report)
        self.assertEqual(
            set(report),
            {
                "artifact_root",
                "completed_at",
                "commands",
                "configured_pin",
                "image",
                "matrix_report",
                "ok",
                "policy",
                "postflight",
                "preflight",
                "protocol",
                "requested_image_digest",
                "runtime",
                "schema_version",
                "source",
                "started_at",
            },
        )
        self.assertEqual(report["configured_pin"], IMAGE_DIGEST)
        self.assertEqual(report["matrix_report"]["sha256"], release._sha256(
            Path(report["matrix_report"]["path"]).read_bytes()
        ))
        for record in report["commands"].values():
            self.assertEqual(record["status"], "passed")
            for stream in (record["stdout"], record["stderr"]):
                self.assertEqual(set(stream), {
                    "captured_bytes",
                    "captured_sha256",
                    "locator",
                    "sha256",
                    "stream_bytes",
                    "truncated",
                })
                self.assertTrue(str(stream["sha256"]).startswith("sha256:"))
        self.assertEqual(json.loads(receipt_path.read_text()), report)

    def test_run_command_bounds_both_streams_and_keeps_full_hashes(self) -> None:
        output = b"x" * (release.CAPTURE_LIMIT_BYTES + 1)
        errors = b"e" * (release.CAPTURE_LIMIT_BYTES + 1)
        self.artifact_root.mkdir(parents=True)
        outcome = release._run_command(
            "bounded",
            (
                sys.executable,
                "-c",
                "import sys; sys.stdout.write('x' * 1048577); "
                "sys.stderr.write('e' * 1048577)",
            ),
            artifact_root=self.artifact_root,
            timeout_seconds=60,
        )

        self.assertEqual(outcome.record["status"], "passed")
        for name, expected in (("stdout", output), ("stderr", errors)):
            metadata = outcome.record[name]
            self.assertIsInstance(metadata, dict)
            self.assertTrue(metadata["truncated"])
            self.assertLessEqual(
                metadata["captured_bytes"],
                release.CAPTURE_LIMIT_BYTES,
            )
            self.assertEqual(metadata["stream_bytes"], len(expected))
            self.assertEqual(metadata["sha256"], release._sha256(expected))
            retained = self.artifact_root / str(metadata["locator"])
            self.assertTrue(retained.is_file())
            self.assertLessEqual(retained.stat().st_size, release.CAPTURE_LIMIT_BYTES)
            self.assertEqual(
                metadata["captured_sha256"],
                release._sha256(retained.read_bytes()),
            )


if __name__ == "__main__":
    unittest.main()
