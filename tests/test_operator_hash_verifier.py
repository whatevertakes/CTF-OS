from __future__ import annotations

import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from ctf_os import cli
from ctf_os.config import EngineConfig
from ctf_os.engine.challenge import ChallengeEngine
from ctf_os.models import ChallengeIdentity
from ctf_os.operator_hash_verifier import main, verify_candidate


class OperatorHashVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.identity = ChallengeIdentity(
            "CTFTINY_OPERATOR_FIXTURE",
            "crypto",
            "operator_fixture",
        )
        self.secret = "CSAW{operator_only_fixture}"
        self.engine = ChallengeEngine(
            self.root,
            config=EngineConfig(workspace_root=self.root),
        )
        self.engine.add_challenge(
            self.identity,
            prompt="public prompt",
            budget_seconds=1800,
            exist_ok=False,
        )
        state = self.engine.record_candidate(
            self.identity,
            self.secret,
            print_immediately=False,
        )
        self.candidate_id = state.candidates[0].id
        self.reference = (
            self.root
            / ".ctfos"
            / "benchmarks"
            / "external-pilots"
            / "private"
            / "ctftiny"
            / "fixture"
            / "verifier-reference.json"
        )
        self.reference.parent.mkdir(parents=True)
        self.expected_hash = hashlib.sha256(self.secret.encode()).hexdigest()
        self._write_reference(self.expected_hash)

    def _write_reference(self, expected_hash: str) -> None:
        self.reference.write_text(
            json.dumps(
                {
                    "benchmark": "CTFTiny",
                    "private_value": {
                        "json_pointer": "/flag",
                        "text_sha256": expected_hash,
                        "type": "string",
                        "value_embedded": False,
                    },
                    "task_id": "cry/synthetic/operator_fixture",
                }
            ),
            encoding="utf-8",
        )
        self.reference.chmod(0o600)

    def _arguments(self) -> list[str]:
        return [
            "--workspace-root",
            str(self.root),
            "--contest",
            self.identity.contest_id,
            "--category",
            self.identity.category,
            "--challenge",
            self.identity.challenge_id,
            "--candidate-id",
            self.candidate_id,
            "--reference",
            str(self.reference),
        ]

    def _ctfos_arguments(self) -> list[str]:
        return [
            "benchmark",
            "ctftiny-verify",
            self.identity.contest_id,
            self.identity.category,
            self.identity.challenge_id,
            "--candidate-id",
            self.candidate_id,
            "--reference",
            str(self.reference),
        ]

    def _file_snapshot(self) -> dict[str, bytes]:
        return {
            str(path.relative_to(self.root)): path.read_bytes()
            for path in self.root.rglob("*")
            if path.is_file() and not path.is_symlink()
        }

    def test_matching_candidate_emits_only_bounded_result_without_mutation(
        self,
    ) -> None:
        state_path = self.engine.store.challenge_paths(self.identity).state
        before = state_path.read_bytes()
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = main(self._arguments())
        self.assertEqual(status, 0)
        self.assertEqual(stderr.getvalue(), "")
        result = json.loads(stdout.getvalue())
        self.assertEqual(
            result,
            {
                "candidate_id": self.candidate_id,
                "error": None,
                "matched": True,
            },
        )
        self.assertEqual(state_path.read_bytes(), before)
        self.assertNotIn(self.secret, stdout.getvalue())
        self.assertNotIn(self.expected_hash, stdout.getvalue())

    def test_mismatch_emits_no_candidate_or_expected_value(self) -> None:
        self._write_reference(hashlib.sha256(b"different").hexdigest())
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            status = main(self._arguments())
        self.assertEqual(status, 1)
        result = json.loads(stdout.getvalue())
        self.assertEqual(result["candidate_id"], self.candidate_id)
        self.assertIs(result["matched"], False)
        self.assertIsNone(result["error"])
        self.assertNotIn(self.secret, stdout.getvalue())

    def test_private_reference_requires_exact_mode(self) -> None:
        self.reference.chmod(0o644)
        result = verify_candidate(
            workspace_root=self.root,
            identity=self.identity,
            candidate_id=self.candidate_id,
            reference_path=self.reference,
        )
        self.assertEqual(result.candidate_id, self.candidate_id)
        self.assertIsNone(result.matched)
        self.assertEqual(result.error, "private_reference_permissions")

    def test_reference_identity_and_candidate_id_fail_closed(self) -> None:
        wrong_identity = ChallengeIdentity(
            self.identity.contest_id,
            "rev",
            "whataxor",
        )
        mismatch = verify_candidate(
            workspace_root=self.root,
            identity=wrong_identity,
            candidate_id=self.candidate_id,
            reference_path=self.reference,
        )
        self.assertEqual(mismatch.error, "reference_identity_mismatch")
        invalid = verify_candidate(
            workspace_root=self.root,
            identity=self.identity,
            candidate_id="not canonical\nsecret",
            reference_path=self.reference,
        )
        self.assertIsNone(invalid.candidate_id)
        self.assertIsNone(invalid.matched)
        self.assertEqual(invalid.error, "invalid_candidate_id")

    def test_ctfos_parser_exposes_operator_only_benchmark_command(self) -> None:
        parsed = cli.build_parser().parse_args(self._ctfos_arguments())
        self.assertEqual(parsed.command, "benchmark")
        self.assertEqual(parsed.benchmark_command, "ctftiny-verify")
        self.assertEqual(parsed.contest, self.identity.contest_id)
        self.assertEqual(parsed.category, self.identity.category)
        self.assertEqual(parsed.challenge, self.identity.challenge_id)
        self.assertEqual(parsed.candidate_id, self.candidate_id)
        self.assertEqual(parsed.reference, self.reference)

    def test_ctfos_verifier_is_read_only_and_does_not_build_engine(self) -> None:
        before = self._file_snapshot()
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            patch(
                "ctf_os.cli.ChallengeEngine",
                side_effect=AssertionError("mutable engine must not be built"),
            ),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            status = cli.main(self._ctfos_arguments(), root=self.root)

        self.assertEqual(status, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(
            json.loads(stdout.getvalue()),
            {
                "candidate_id": self.candidate_id,
                "error": None,
                "matched": True,
            },
        )
        self.assertEqual(self._file_snapshot(), before)
        self.assertNotIn(self.secret, stdout.getvalue())
        self.assertNotIn(self.expected_hash, stdout.getvalue())

    def test_ctfos_verifier_exit_codes_fail_closed(self) -> None:
        self._write_reference(hashlib.sha256(b"different").hexdigest())
        mismatch_stdout = io.StringIO()
        with redirect_stdout(mismatch_stdout):
            mismatch_status = cli.main(
                self._ctfos_arguments(),
                root=self.root,
            )
        self.assertEqual(mismatch_status, 1)
        self.assertIs(json.loads(mismatch_stdout.getvalue())["matched"], False)

        self.reference.chmod(0o644)
        error_stdout = io.StringIO()
        with redirect_stdout(error_stdout):
            error_status = cli.main(
                self._ctfos_arguments(),
                root=self.root,
            )
        self.assertEqual(error_status, 2)
        self.assertEqual(
            json.loads(error_stdout.getvalue())["error"],
            "private_reference_permissions",
        )


if __name__ == "__main__":
    unittest.main()
