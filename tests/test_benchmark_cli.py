from __future__ import annotations

import io
import hashlib
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from ctf_os import cli


PROMOTION_CATEGORIES = (
    "pwn",
    "web",
    "rev",
    "crypto",
    "forensics",
    "misc",
)


def _attempt(
    attempt: int,
    seconds: float,
    *,
    run_id: str,
) -> dict[str, object]:
    return {
        "attempt": attempt,
        "run_id": run_id,
        "solved": True,
        "proof_evaluated": True,
        "proof_passed": True,
        "reproduction_evaluated": True,
        "reproduced": True,
        "first_valid_result_seconds": seconds,
        "solve_wall_seconds_used": seconds,
        "model_calls_used": 4,
        "total_tokens_used": 50_000,
        "human_interventions": 0,
    }


def _promotion_evidence(*, improve_live: bool = True) -> dict[str, object]:
    cases_by_split = {
        "dev": (("dev-pwn", "pwn"),),
        "regression": (("regression-web", "web"),),
        "blind": tuple(
            (f"blind-{category}", category)
            for category in PROMOTION_CATEGORIES
        ),
        "live": tuple(
            (f"live-{category}", category)
            for category in PROMOTION_CATEGORIES
        ),
    }
    splits = [
        {
            "name": name,
            "cases": [
                {
                    "case_id": case_id,
                    "category": category,
                    "input_manifest_sha256": hashlib.sha256(
                        case_id.encode("utf-8")
                    ).hexdigest(),
                }
                for case_id, category in cases
            ],
            "trajectory_visible": name == "dev",
            "answers_visible": False,
            "prior_engine_runs": 1 if name == "regression" else 0,
            "evidence_complete": True,
        }
        for name, cases in cases_by_split.items()
    ]

    def results(*, candidate: bool) -> list[dict[str, object]]:
        return [
            {
                "case_id": case_id,
                "attempts": [
                    _attempt(
                        attempt,
                        (
                            5.0
                            if candidate
                            and improve_live
                            and name == "live"
                            else 10.0
                        ),
                        run_id=(
                            f"{'candidate' if candidate else 'baseline'}-"
                            f"{case_id}-{attempt}"
                        ),
                    )
                    for attempt in (1, 2, 3)
                ],
                "evidence_complete": True,
            }
            for name, cases in cases_by_split.items()
            for case_id, _category in cases
        ]

    fingerprint = {
        "tool_manifest_sha256": "1" * 64,
        "image_sha256": "2" * 64,
        "model_config_sha256": "3" * 64,
        "engine_source_sha256": "4" * 64,
    }
    budget = {
        "wall_seconds": 60,
        "model_call_limit": 8,
        "total_token_limit": 100_000,
    }
    safety = {
        "orphan_runs": 0,
        "false_proofs": 0,
        "target_violations": 0,
        "secret_or_flag_leaks": 0,
        "complete_run_records": 1,
        "terminal_run_records": 1,
    }
    return {
        "schema_version": 3,
        "splits": splits,
        "baseline": {
            "system": "thin_scaffold",
            "model_id": "same-model",
            "budget": budget,
            "results": results(candidate=False),
            "safety": safety,
            "evidence_complete": True,
            "execution_fingerprint": fingerprint,
        },
        "candidate": {
            "system": "ctf_os",
            "model_id": "same-model",
            "budget": budget,
            "results": results(candidate=True),
            "safety": safety,
            "evidence_complete": True,
            "execution_fingerprint": fingerprint,
        },
        "evidence_complete": True,
    }


class BenchmarkPromotionCLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def run_cli(self, evidence: Path) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = cli.main(
                [
                    "benchmark",
                    "promotion",
                    "--evidence",
                    str(evidence),
                ],
                root=self.root,
            )
        return status, stdout.getvalue(), stderr.getvalue()

    def write_evidence(
        self,
        *,
        improve_live: bool = True,
        name: str = "promotion.json",
    ) -> Path:
        path = self.root / name
        path.write_text(
            json.dumps(
                _promotion_evidence(improve_live=improve_live),
                ensure_ascii=False,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        return path

    def test_parser_exposes_nested_read_only_promotion_command(self) -> None:
        evidence = self.root / "evidence.json"
        args = cli.build_parser().parse_args(
            [
                "benchmark",
                "promotion",
                "--evidence",
                str(evidence),
            ]
        )

        self.assertEqual(args.command, "benchmark")
        self.assertEqual(args.benchmark_command, "promotion")
        self.assertEqual(args.evidence, evidence)

    def test_eligible_evaluation_is_stable_and_never_changes_defaults(
        self,
    ) -> None:
        evidence = self.write_evidence()
        evidence_before = evidence.read_bytes()

        first_status, first_output, first_errors = self.run_cli(evidence)
        second_status, second_output, second_errors = self.run_cli(evidence)

        self.assertEqual(first_status, 0, first_errors)
        self.assertEqual(second_status, 0, second_errors)
        self.assertEqual(first_output, second_output)
        result = json.loads(first_output)
        self.assertEqual(
            result["decision"],
            "eligible_for_manual_promotion",
        )
        self.assertTrue(result["promotion_eligible"])
        self.assertFalse(result["default_changed"])
        self.assertEqual(evidence.read_bytes(), evidence_before)
        self.assertFalse((self.root / ".ctfos").exists())

    def test_do_not_promote_is_a_successful_completed_evaluation(self) -> None:
        evidence = self.write_evidence(improve_live=False)

        status, output, errors = self.run_cli(evidence)

        self.assertEqual(status, 0, errors)
        result = json.loads(output)
        self.assertEqual(result["decision"], "do_not_promote")
        self.assertFalse(result["promotion_eligible"])
        self.assertFalse(result["default_changed"])

    def test_duplicate_keys_and_non_finite_numbers_are_rejected(self) -> None:
        malformed_payloads = {
            "duplicate.json": (
                b'{"schema_version":1,"schema_version":1}'
            ),
            "nan.json": b'{"schema_version":NaN}',
            "infinity.json": b'{"schema_version":Infinity}',
        }
        for name, payload in malformed_payloads.items():
            with self.subTest(name=name):
                path = self.root / name
                path.write_bytes(payload)

                status, output, errors = self.run_cli(path)

                self.assertNotEqual(status, 0)
                self.assertEqual(output, "")
                if name == "duplicate.json":
                    self.assertIn("duplicate JSON object key", errors)
                else:
                    self.assertIn("non-finite JSON number", errors)

    def test_oversized_and_symlink_evidence_are_rejected(self) -> None:
        oversized = self.root / "oversized.json"
        with oversized.open("wb") as stream:
            stream.truncate(cli.MAX_PROMOTION_EVIDENCE_BYTES + 1)
        target = self.write_evidence(name="target.json")
        link = self.root / "link.json"
        link.symlink_to(target)

        for path in (oversized, link):
            with self.subTest(path=path.name):
                status, output, errors = self.run_cli(path)

                self.assertNotEqual(status, 0)
                self.assertEqual(output, "")
                self.assertIn("오류:", errors)


if __name__ == "__main__":
    unittest.main()
